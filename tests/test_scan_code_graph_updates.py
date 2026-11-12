"""Durable scan CodeGraph toggles and acknowledged Agent synchronization."""

from backend.application import get_runtime
import backend.agents.rpc as backend_agents_rpc
import backend.scans.configuration as backend_scans_configuration
import backend.scans.projection as backend_scans_projection
import backend.agents.directory as backend_agents_directory
import backend.agents.gateway as backend_agents_gateway
import backend.application as application
import backend.scans.agent_binding as backend_scans_agent_binding
import asyncio
import os
import uuid
import httpx
import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from fastapi import FastAPI
from backend import code_graph
from backend.api import agent as agent_api, scan as scan_api
from backend.auth import get_current_user
from backend.models import AgentInfo, AgentMcpConfig, ScanItemStatus, ScanMeta, ScanStatus, User
from backend.store.sqlite import SqliteScanStore


async def direct_store(store, operation, *args, **kwargs):
    return getattr(store, operation)(*args, **kwargs)


def user_dependency(user):
    async def current_user():
        return user
    return current_user


@pytest.fixture(params=["sqlite", "postgres"])
def graph_env(request, tmp_path, monkeypatch):
    if request.param == "postgres":
        dsn = os.getenv("OPENDEEPHOLE_TEST_POSTGRES_DSN")
        if not dsn:
            pytest.skip("PostgreSQL test DSN not configured")
        from backend.store.postgres import PostgresScanStore
        store = PostgresScanStore(dsn, pool_min_size=1, pool_max_size=2)
    else:
        store = SqliteScanStore(tmp_path / "scans.db")
    scan_id = "graph-update-" + uuid.uuid4().hex
    owner = User(user_id=scan_id + "-owner", username="owner", role="user")
    agent = AgentInfo(agent_id=scan_id + "-agent", agent_key=scan_id + "-key", name="agent",
                      ip="127.0.0.1", last_seen="2026-11-04T00:00:00Z", user_id=owner.user_id,
                      scan_code_graph_updates=True)
    scan = ScanStatus(scan_id=scan_id, project_id="project", status="analyzing", progress=.5,
                      total_candidates=2, processed_candidates=1, vulnerabilities=[])
    meta = ScanMeta(scan_items=[], created_at="2026-11-04T00:00:00Z", scan_name=scan_id,
                    user_id=owner.user_id, agent_key=agent.agent_key, agent_id=agent.agent_id,
                    project_path="/source/project")
    store.save_scan(scan, meta)
    get_runtime().store = store
    get_runtime().store_runner = direct_store
    monkeypatch.setattr(get_runtime().scans, 'running_scans', {scan_id: scan})
    monkeypatch.setattr(get_runtime().scans, 'scan_owners', {})
    monkeypatch.setattr(backend_scans_agent_binding, '_resolve_scan_agent_id', AsyncMock(return_value=None))
    monkeypatch.setattr(backend_agents_directory, 'resolve_agent_id_connection_async', AsyncMock(return_value=(agent.agent_id, agent)))
    publish = Mock()
    monkeypatch.setattr(code_graph, "publish", publish)
    monkeypatch.setattr(application, 'default_publisher', publish)
    app = FastAPI()
    app.include_router(scan_api.router)
    app.dependency_overrides[get_current_user] = user_dependency(owner)

    async def put(body):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            return await client.put(f"/api/scan/{scan_id}/code-graph", json=body)

    default = backend_scans_configuration._scan_code_graph_mcp(AgentMcpConfig(enabled=True))
    yield SimpleNamespace(store=store, scan_id=scan_id, scan=scan, meta=meta, owner=owner,
                          agent=agent, app=app, put=lambda body: asyncio.run(put(body)), default=default,
                          publish=publish, backend=request.param)
    with store._lock:
        store._conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        store._conn.commit()
    store.close()


@pytest.mark.parametrize("status", list(ScanItemStatus))
def test_toggle_offline_available_in_all_scan_states(graph_env, status):
    env = graph_env
    env.scan.status = status
    env.store.save_scan(env.scan, env.meta)
    response = env.put({"enabled": True})
    assert response.status_code == 200, response.text
    state = response.json()
    assert state["code_graph_mcp_enabled"] is True
    assert state["code_graph_mcp_revision"] == 1
    assert state["code_graph_mcp_applied_revision"] == 0
    assert state["code_graph_mcp_sync_status"] == "pending"
    assert "等待 Agent" in state["sync_message"]
    assert env.scan.code_graph_mcp_enabled is True
    stored, meta = env.store.load_scan(env.scan_id)
    assert stored.status == status
    assert stored.processed_candidates == 1
    assert meta.code_graph_mcp.local.executable == "codegraph"
    assert meta.code_graph_mcp.local.args == ["serve", "--mcp"]
    assert "code_graph_mcp" not in state
    assert env.publish.called


def test_remote_config_survives_disable_enable_and_stale_full_save(graph_env):
    env = graph_env
    remote = AgentMcpConfig(enabled=True, transport="remote", name="custom-graph",
                            remote={"url": "https://graph.example/mcp", "headers": {"Authorization": "secret"}})
    env.meta.code_graph_mcp = remote
    # Fresh row configuration may be saved at revision zero before any toggle.
    with env.store._lock:
        env.store._conn.execute("UPDATE scans SET code_graph_mcp_json = ? WHERE scan_id = ?", (remote.model_dump_json(), env.scan_id))
        env.store._conn.commit()
    response = env.put({"enabled": False})
    assert response.status_code == 200
    disabled = env.store.get_scan_meta(env.scan_id)
    assert disabled.code_graph_mcp.enabled is False
    assert disabled.code_graph_mcp.remote.headers == {"Authorization": "secret"}
    env.store.save_scan(env.scan, env.meta)
    assert env.store.get_scan_meta(env.scan_id).code_graph_mcp.enabled is False
    response = env.put({"enabled": True})
    assert response.json()["code_graph_mcp_revision"] == 2
    restored = env.store.get_scan_meta(env.scan_id)
    assert restored.code_graph_mcp == remote
    assert env.put({"enabled": True}).json()["code_graph_mcp_revision"] == 2
    assert "secret" not in response.text
    runtime, _ = env.store.load_scan_runtime(env.scan_id)
    assert runtime.code_graph_mcp_revision == 2


def test_permission_validation_and_multiversion_rollback(graph_env):
    env = graph_env
    env.app.dependency_overrides[get_current_user] = user_dependency(User(user_id="other", username="other", role="user"))
    assert env.put({"enabled": True}).status_code == 403
    env.app.dependency_overrides[get_current_user] = user_dependency(env.owner)
    assert env.put({"enabled": "true"}).status_code == 422
    assert env.put({"enabled": True, "code_graph_mcp": {}}).status_code == 422
    env.meta.scan_mode = "multi_version"
    env.store.save_scan(env.scan, env.meta)
    assert env.put({"enabled": True}).status_code == 422
    assert env.store.get_scan_meta(env.scan_id).code_graph_mcp_revision == 0
    if env.backend == "sqlite":
        assert not env.store._conn.in_transaction
    env.meta.scan_mode = "custom"
    env.store.save_scan(env.scan, env.meta)
    env.app.dependency_overrides[get_current_user] = user_dependency(User(user_id="admin", username="admin", role="admin"))
    assert env.put({"enabled": True}).status_code == 200


def test_acknowledgement_and_reconnect_are_revision_and_agent_scoped(graph_env, monkeypatch):
    env = graph_env
    env.put({"enabled": True})
    pending = asyncio.run(code_graph.code_graph_for_agent(env.agent.agent_key, {}, store=env.store))
    assert len(pending) == 1
    assert pending[0]["revision"] == 1
    assert pending[0]["project_path"] == "/source/project"
    assert asyncio.run(code_graph.code_graph_for_agent("other-agent", {}, store=env.store)) == []
    wrong_agent = env.agent.model_copy(update={"agent_key": "other"})
    ack = {"scan_id": env.scan_id, "revision": 1, "ok": True}
    asyncio.run(code_graph.accept_code_graph_result(ack, wrong_agent))
    asyncio.run(code_graph.accept_code_graph_result({**ack, "revision": 99}, env.agent))
    assert env.store.get_scan_meta(env.scan_id).code_graph_mcp_applied_revision == 0
    asyncio.run(code_graph.accept_code_graph_result(ack, env.agent))
    assert env.store.get_scan_meta(env.scan_id).code_graph_mcp_applied_revision == 1
    env.put({"enabled": False})
    asyncio.run(code_graph.accept_code_graph_result(ack, env.agent))
    assert env.store.get_scan_meta(env.scan_id).code_graph_mcp_applied_revision == 1
    assert asyncio.run(code_graph.code_graph_for_agent(env.agent.agent_key, {env.scan_id: 2}, store=env.store)) == []
    assert env.store.get_scan_meta(env.scan_id).code_graph_mcp_applied_revision == 2
    env.store.save_scan(env.scan, env.meta)
    loaded = env.store.get_scan_meta(env.scan_id)
    assert (loaded.code_graph_mcp_revision, loaded.code_graph_mcp_applied_revision) == (2, 2)


def test_live_toggle_waits_for_ack_and_repeated_request_retries(graph_env, monkeypatch):
    env = graph_env
    monkeypatch.setattr(backend_scans_agent_binding, '_resolve_scan_agent_id', AsyncMock(return_value=env.agent.agent_id))
    commands = []

    async def send(agent_id, command):
        commands.append(command)
        await backend_agents_rpc._complete_agent_response({
            "request_id": command["request_id"], "scan_id": env.scan_id,
            "revision": command["revision"], "ok": True,
        }, get_runtime().agents.code_graph_waiters)
        return True

    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', send)
    response = env.put({"enabled": True})
    assert response.json()["code_graph_mcp_sync_status"] == "synced"
    assert response.json()["code_graph_mcp_applied_revision"] == 1
    assert commands[0]["type"] == "code_graph_update"
    assert env.put({"enabled": True}).json()["code_graph_mcp_revision"] == 1
    assert len(commands) == 2
    assert not get_runtime().agents.code_graph_waiters


@pytest.mark.parametrize("mode", ["legacy", "timeout", "rejected", "send_failure"])
def test_delivery_failures_keep_saved_config_pending(graph_env, monkeypatch, mode):
    env = graph_env
    monkeypatch.setattr(backend_scans_agent_binding, '_resolve_scan_agent_id', AsyncMock(return_value=env.agent.agent_id))
    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', AsyncMock(return_value=mode != "send_failure"))
    if mode == "legacy":
        env.agent.scan_code_graph_updates = False
    elif mode == "timeout":
        monkeypatch.setattr(backend_agents_rpc, '_wait_agent_response', AsyncMock(side_effect=asyncio.TimeoutError))
    else:
        monkeypatch.setattr(backend_agents_rpc, '_wait_agent_response', AsyncMock(return_value={"ok": False}))
    response = env.put({"enabled": True})
    assert response.status_code == 200
    assert response.json()["code_graph_mcp_sync_status"] == "pending"
    assert response.json()["sync_message"]
    assert env.store.get_scan_meta(env.scan_id).code_graph_mcp.enabled is True
    assert not get_runtime().agents.code_graph_waiters


def test_cached_scan_status_hydrates_latest_configuration(graph_env):
    env = graph_env
    env.store.update_scan_code_graph(env.scan_id, True, env.default)
    env.store.acknowledge_scan_code_graph(env.scan_id, 1, env.agent.agent_key)
    backend_scans_projection._apply_scan_metadata(env.scan, env.store.get_scan_meta(env.scan_id))
    assert env.scan.code_graph_mcp_enabled is True
    assert env.scan.code_graph_mcp_sync_status == "synced"
    assert env.scan.code_graph_mcp_revision == 1
    stale = env.store.get_scan_meta(env.scan_id).model_copy(update={"code_graph_mcp_applied_revision": 0})
    backend_scans_projection._apply_scan_metadata(env.scan, stale)
    assert env.scan.code_graph_mcp_applied_revision == 1
    assert env.scan.code_graph_mcp_sync_status == "synced"
