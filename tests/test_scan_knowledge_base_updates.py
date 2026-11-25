"""Admin global knowledge-base config, per-scan dynamic toggles/edits, and Agent sync."""

from __future__ import annotations

import asyncio
import json
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from fastapi import FastAPI

from backend import knowledge_base
import backend.agents.directory as backend_agents_directory
import backend.agents.gateway as backend_agents_gateway
import backend.application as application
import backend.scans.agent_binding as backend_scans_agent_binding
from backend.api import admin as admin_api, scan as scan_api
from backend.application import get_runtime
from backend.auth import get_current_user, require_admin
from backend.models import AgentInfo, ScanItemStatus, ScanMeta, ScanStatus, User
from backend.store.sqlite import SqliteScanStore


async def direct_store(store, operation, *args, **kwargs):
    if callable(operation):
        return operation(*args, **kwargs)
    return getattr(store, operation)(*args, **kwargs)


def user_dependency(user):
    async def current_user():
        return user
    return current_user


@pytest.fixture
def kb_env(tmp_path, monkeypatch):
    store = SqliteScanStore(tmp_path / "scans.db")
    scan_id = "kb-update-" + uuid.uuid4().hex
    owner = User(user_id=scan_id + "-owner", username="owner", role="user")
    admin = User(user_id=scan_id + "-admin", username="admin", role="admin")
    agent = AgentInfo(
        agent_id=scan_id + "-agent",
        agent_key=scan_id + "-key",
        name="agent",
        ip="127.0.0.1",
        last_seen="2026-11-25T00:00:00Z",
        user_id=owner.user_id,
        scan_knowledge_base_updates=True,
    )
    scan = ScanStatus(
        scan_id=scan_id,
        project_id="project",
        status="analyzing",
        progress=0.5,
        total_candidates=2,
        processed_candidates=1,
        vulnerabilities=[],
    )
    meta = ScanMeta(
        scan_items=[],
        created_at="2026-11-25T00:00:00Z",
        scan_name=scan_id,
        user_id=owner.user_id,
        agent_key=agent.agent_key,
        agent_id=agent.agent_id,
        project_path="/source/project",
    )
    store.save_scan(scan, meta)
    monkeypatch.setattr(get_runtime(), "store", store)
    monkeypatch.setattr(get_runtime(), "store_runner", direct_store)
    monkeypatch.setattr(get_runtime().scans, "running_scans", {scan_id: scan})
    monkeypatch.setattr(get_runtime().scans, "scan_owners", {})
    monkeypatch.setattr(get_runtime().agents, "agent_ws", {})
    monkeypatch.setattr(
        backend_scans_agent_binding,
        "_resolve_scan_agent_id",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(
        backend_agents_directory,
        "resolve_agent_id_connection_async",
        AsyncMock(return_value=(agent.agent_id, agent)),
    )
    publish = Mock()
    monkeypatch.setattr(knowledge_base, "publish", publish)
    monkeypatch.setattr(application, "default_publisher", publish)
    monkeypatch.setattr(
        application,
        "default_config_factory",
        lambda: SimpleNamespace(
            knowledge_base=SimpleNamespace(
                name="knowledge-base",
                url="",
                headers={},
                timeout_seconds=300,
                projects_tool="",
                set_project_tool="",
            ),
        ),
    )

    app = FastAPI()
    app.include_router(admin_api.router)
    app.include_router(scan_api.router)

    current = {"user": owner}

    async def current_user():
        return current["user"]

    async def current_admin():
        from fastapi import HTTPException

        if current["user"].role != "admin":
            raise HTTPException(status_code=403, detail="Admin access required")
        return current["user"]

    app.dependency_overrides[get_current_user] = current_user
    app.dependency_overrides[require_admin] = current_admin

    def request_sync(method: str, path: str, body: dict | None = None, *, as_admin: bool = False):
        prev = current["user"]
        current["user"] = admin if as_admin else owner

        async def run():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                return await client.request(method, path, json=body)

        try:
            return asyncio.run(run())
        finally:
            current["user"] = prev

    yield SimpleNamespace(
        store=store,
        scan_id=scan_id,
        scan=scan,
        meta=meta,
        owner=owner,
        admin=admin,
        agent=agent,
        app=app,
        current=current,
        request=request_sync,
        publish=publish,
    )
    store.close()


def test_admin_knowledge_base_config_redaction_retention_and_broadcast(kb_env, monkeypatch) -> None:
    env = kb_env
    # Non-admin denied on admin routes, allowed on public status route
    assert env.request("GET", "/api/admin/knowledge-base").status_code == 403
    assert env.request("PUT", "/api/admin/knowledge-base", {"url": "http://kb.test/mcp"}).status_code == 403
    status_resp = env.request("GET", "/api/knowledge-base/status")
    assert status_resp.status_code == 200
    assert status_resp.json() == {"configured": False, "name": "knowledge-base"}

    # Register an online agent to observe broadcast
    sent: list[tuple[str, dict]] = []

    async def fake_send(agent_id: str, payload: dict) -> bool:
        sent.append((agent_id, payload))
        return True

    monkeypatch.setattr(get_runtime().agents, "agent_ws", {env.agent.agent_id: object()})
    monkeypatch.setattr(backend_agents_gateway, "send_agent_command", fake_send)

    # Admin configures URL + secret header
    save_resp = env.request(
        "PUT",
        "/api/admin/knowledge-base",
        {
            "url": "https://kb.internal/mcp",
            "name": "corp-kb",
            "timeout_seconds": 180,
            "headers": {"Authorization": "Bearer super-secret-token"},
        },
        as_admin=True,
    )
    assert save_resp.status_code == 200, save_resp.text
    saved = save_resp.json()
    assert saved["configured"] is True
    assert saved["url"] == "https://kb.internal/mcp"
    assert saved["name"] == "corp-kb"
    assert saved["timeout_seconds"] == 180
    assert saved["header_keys"] == ["Authorization"]
    assert saved["revision"] == 1
    assert "super-secret-token" not in save_resp.text

    # Broadcast pushed to online Agent with full credentials
    assert len(sent) == 1
    assert sent[0][0] == env.agent.agent_id
    assert sent[0][1]["type"] == "platform_knowledge_base_update"
    assert sent[0][1]["platform_knowledge_base"]["url"] == "https://kb.internal/mcp"
    assert sent[0][1]["platform_knowledge_base"]["headers"] == {
        "Authorization": "Bearer super-secret-token",
    }

    # Public status exposes ONLY configured + name (never URL/headers)
    pub = env.request("GET", "/api/knowledge-base/status").json()
    assert pub == {"configured": True, "name": "corp-kb"}
    assert "kb.internal" not in json.dumps(pub)
    assert "super-secret-token" not in json.dumps(pub)

    # Updating URL while passing blank value for existing key preserves secret
    save_2 = env.request(
        "PUT",
        "/api/admin/knowledge-base",
        {
            "url": "https://kb-v2.internal/mcp",
            "name": "corp-kb",
            "timeout_seconds": 240,
            "headers": {"Authorization": ""},
        },
        as_admin=True,
    )
    assert save_2.status_code == 200
    assert save_2.json()["revision"] == 2
    assert sent[-1][1]["platform_knowledge_base"]["headers"] == {
        "Authorization": "Bearer super-secret-token",
    }

    # Clearing headers works
    save_3 = env.request(
        "PUT",
        "/api/admin/knowledge-base",
        {
            "url": "https://kb-v2.internal/mcp",
            "name": "corp-kb",
            "timeout_seconds": 240,
            "clear_headers": True,
        },
        as_admin=True,
    )
    assert save_3.status_code == 200
    assert save_3.json()["header_keys"] == []
    assert sent[-1][1]["platform_knowledge_base"]["headers"] == {}

    # Validation errors
    assert env.request("PUT", "/api/admin/knowledge-base", {"url": "ftp://bad"}, as_admin=True).status_code == 422
    assert env.request("PUT", "/api/admin/knowledge-base", {"url": "https://kb.test/mcp", "name": "codegraph"}, as_admin=True).status_code == 422
    assert env.request("PUT", "/api/admin/knowledge-base", {"url": "https://kb.test/mcp", "headers": {"Bad Header": "v"}}, as_admin=True).status_code == 422


def test_existing_scan_enable_edit_disable_and_stale_save_protection(kb_env) -> None:
    env = kb_env
    # Enabling before admin configures URL returns 422
    resp = env.request("PUT", f"/api/scan/{env.scan_id}/knowledge-base", {"enabled": True, "project_id": "mae"})
    assert resp.status_code == 422
    assert "知识库 MCP 链接" in resp.json()["detail"]

    # Admin configures global KB MCP URL
    assert env.request(
        "PUT",
        "/api/admin/knowledge-base",
        {"url": "http://kb.test/mcp", "headers": {"Authorization": "Bearer kb-secret"}},
        as_admin=True,
    ).status_code == 200

    # Blank project_id rejected
    assert env.request(
        "PUT",
        f"/api/scan/{env.scan_id}/knowledge-base",
        {"enabled": True, "project_id": "   "},
    ).status_code == 422

    # Enable on existing scan while Agent is offline
    enabled_resp = env.request(
        "PUT",
        f"/api/scan/{env.scan_id}/knowledge-base",
        {"enabled": True, "project_id": "mae"},
    )
    assert enabled_resp.status_code == 200, enabled_resp.text
    state = enabled_resp.json()
    assert state["knowledge_base_enabled"] is True
    assert state["knowledge_base_project_id"] == "mae"
    assert state["knowledge_base_mcp_revision"] == 1
    assert state["knowledge_base_mcp_applied_revision"] == 0
    assert state["knowledge_base_mcp_sync_status"] == "pending"
    assert "kb-secret" not in enabled_resp.text
    assert "kb.test" not in enabled_resp.text

    # Public scan snapshot exposes project_id but never URL/headers
    loaded_scan, loaded_meta = env.store.load_scan(env.scan_id)
    assert loaded_scan.knowledge_base_enabled is True
    assert loaded_scan.knowledge_base_project_id == "mae"
    assert loaded_scan.knowledge_base_mcp_revision == 1
    public_json = json.dumps(loaded_scan.model_dump(mode="json"))
    assert "kb-secret" not in public_json
    assert "kb.test" not in public_json
    assert loaded_meta.knowledge_base_mcp is not None
    assert loaded_meta.knowledge_base_mcp.project_id == "mae"

    # Edit project_id while enabled
    edited_resp = env.request(
        "PUT",
        f"/api/scan/{env.scan_id}/knowledge-base",
        {"enabled": True, "project_id": "mae-v2"},
    )
    assert edited_resp.status_code == 200
    assert edited_resp.json()["knowledge_base_project_id"] == "mae-v2"
    assert edited_resp.json()["knowledge_base_mcp_revision"] == 2

    # Stale full save_scan cannot undo newer revision
    env.store.save_scan(env.scan, env.meta)
    after_stale = env.store.get_scan_meta(env.scan_id)
    assert after_stale.knowledge_base_enabled is True
    assert after_stale.knowledge_base_mcp.project_id == "mae-v2"
    assert after_stale.knowledge_base_mcp_revision == 2

    # Disable preserves project_id for convenient re-enabling
    disabled_resp = env.request(
        "PUT",
        f"/api/scan/{env.scan_id}/knowledge-base",
        {"enabled": False},
    )
    assert disabled_resp.status_code == 200
    assert disabled_resp.json()["knowledge_base_enabled"] is False
    assert disabled_resp.json()["knowledge_base_project_id"] == "mae-v2"
    assert disabled_resp.json()["knowledge_base_mcp_revision"] == 3

    # Re-enable with no project_id reuses preserved project_id
    reenabled = env.request(
        "PUT",
        f"/api/scan/{env.scan_id}/knowledge-base",
        {"enabled": True},
    )
    assert reenabled.status_code == 200
    assert reenabled.json()["knowledge_base_enabled"] is True
    assert reenabled.json()["knowledge_base_project_id"] == "mae-v2"
    assert reenabled.json()["knowledge_base_mcp_revision"] == 4


def test_agent_reconnect_reconciliation_ack_and_admin_hot_merge(kb_env, monkeypatch) -> None:
    env = kb_env
    assert env.request(
        "PUT",
        "/api/admin/knowledge-base",
        {"url": "http://kb-old.test/mcp", "headers": {"X-Key": "old-secret"}},
        as_admin=True,
    ).status_code == 200

    # Enable while agent offline -> pending
    assert env.request(
        "PUT",
        f"/api/scan/{env.scan_id}/knowledge-base",
        {"enabled": True, "project_id": "mae"},
    ).status_code == 200

    # Admin updates global URL after scan enabled KB
    assert env.request(
        "PUT",
        "/api/admin/knowledge-base",
        {"url": "http://kb-new.test/mcp", "name": "kb-next", "headers": {"X-Key": "new-secret"}},
        as_admin=True,
    ).status_code == 200

    # Reconnect reconciliation merges LATEST admin URL/headers into scan update
    updates = asyncio.run(knowledge_base.knowledge_base_for_agent(env.agent.agent_key, {}))
    assert len(updates) == 1
    assert updates[0]["scan_id"] == env.scan_id
    assert updates[0]["revision"] == 1
    assert updates[0]["knowledge_base_mcp"]["remote"]["url"] == "http://kb-new.test/mcp"
    assert updates[0]["knowledge_base_mcp"]["remote"]["headers"] == {"X-Key": "new-secret"}
    assert updates[0]["knowledge_base_mcp"]["name"] == "kb-next"
    assert updates[0]["knowledge_base_mcp"]["project_id"] == "mae"

    # Agent sends ACK -> transitions to synced
    asyncio.run(knowledge_base.accept_knowledge_base_result(
        {"ok": True, "scan_id": env.scan_id, "revision": 1},
        env.agent,
    ))
    meta = env.store.get_scan_meta(env.scan_id)
    assert meta.knowledge_base_mcp_applied_revision == 1
    assert knowledge_base.knowledge_base_response(env.scan_id, meta).knowledge_base_mcp_sync_status == "synced"

    # Admin clears global URL -> effective_scan_knowledge_base_mcp degrades gracefully to disabled
    assert env.request(
        "PUT",
        "/api/admin/knowledge-base",
        {"url": ""},
        as_admin=True,
    ).status_code == 200
    effective = knowledge_base.effective_scan_knowledge_base_mcp(meta, env.store)
    assert effective is not None
    assert effective.enabled is False


def test_multiversion_and_non_owner_rejected(kb_env) -> None:
    env = kb_env
    assert env.request(
        "PUT",
        "/api/admin/knowledge-base",
        {"url": "http://kb.test/mcp"},
        as_admin=True,
    ).status_code == 200

    # Non-owner gets 403
    env.current["user"] = User(user_id="other-user", username="other", role="user")
    async def call_other():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=env.app),
            base_url="http://test",
        ) as client:
            return await client.put(
                f"/api/scan/{env.scan_id}/knowledge-base",
                json={"enabled": True, "project_id": "mae"},
            )
    assert asyncio.run(call_other()).status_code == 403
    env.current["user"] = env.owner

    # Multi-version scan gets 422
    with env.store._lock:
        env.store._conn.execute(
            "UPDATE scans SET scan_mode = ? WHERE scan_id = ?",
            ("multi_version", env.scan_id),
        )
        env.store._conn.commit()
    resp = env.request(
        "PUT",
        f"/api/scan/{env.scan_id}/knowledge-base",
        {"enabled": True, "project_id": "mae"},
    )
    assert resp.status_code == 422
    assert "多版本" in resp.json()["detail"]
