"""Exercise persistence-to-Agent delivery, not just command construction."""

from backend.application import get_runtime
import backend.agents.rpc as backend_agents_rpc
import backend.scans.agent_binding as backend_scans_agent_binding
import backend.scans.creation as backend_scans_creation
import backend.scans.creation_config as creation_config
import backend.agents.artifacts as backend_agents_artifacts
import backend.agents.configuration as backend_agents_configuration
import backend.agents.directory as backend_agents_directory
import backend.agents.gateway as backend_agents_gateway
import backend.agents.runtime_updates as backend_agents_runtime_updates
import backend.application as application
import backend.scans.configuration as backend_scans_configuration
import asyncio
import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock
from backend import review_notes
from backend.models import (
    AgentInfo,
    AgentRemoteConfig,
    CreateScanRequest,
    ScanMeta,
    ScanStatus,
    User,
)
from backend.store.sqlite import SqliteScanStore
from deephole_client.review_notes import get_review_notes_dir, sync_review_notes


@pytest.fixture
def notes_env(tmp_path, monkeypatch):
    store = SqliteScanStore(tmp_path / "scan.db")
    store.save_scan(
        ScanStatus(scan_id="scan-notes", project_id="project", status="complete",
                   progress=1, total_candidates=0, processed_candidates=0, vulnerabilities=[]),
        ScanMeta(scan_items=[], created_at="2026-11-02T00:00:00Z", user_id="owner",
                 agent_key="stable-agent", agent_id="live-agent"),
    )
    entry = store.create_review_note("owner", "业务约束", "入口已检查长度。")
    store.set_scan_review_notes("scan-notes", "owner", True, [entry["id"]])
    monkeypatch.setattr(review_notes, "get_scan_store", lambda: store)
    monkeypatch.setattr(application, 'default_store_factory', lambda: store)
    monkeypatch.setattr(backend_scans_agent_binding, '_resolve_scan_agent_id', AsyncMock(return_value="live-agent"))
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "agent-home")
    yield store, entry
    store.close()


def test_edit_delete_and_disable_update_the_same_agent_directory(notes_env, monkeypatch):
    store, entry = notes_env
    commands = []

    async def deliver(agent_id, command):
        assert agent_id == "live-agent"
        commands.append(command)
        revision = sync_review_notes(command)
        await backend_agents_rpc._complete_agent_response({
            "type": "review_notes_result", "request_id": command["request_id"],
            "scan_id": command["scan_id"], "revision": revision, "ok": True,
        }, get_runtime().agents.review_notes_waiters)
        return True

    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', deliver)
    assert asyncio.run(review_notes.sync_scan_review_notes("scan-notes")) == "synced"
    directory = get_review_notes_dir("scan-notes")
    assert (directory / "业务约束.md").is_file()
    store.update_review_note("owner", entry["id"], "长度约束", "需要核查其他调用者。")
    assert asyncio.run(review_notes.sync_scan_review_notes("scan-notes")) == "synced"
    assert [p.name for p in directory.iterdir()] == ["长度约束.md"]
    assert "需要核查其他调用者" in (directory / "长度约束.md").read_text()
    store.set_scan_review_notes("scan-notes", "owner", False, [entry["id"]])
    assert asyncio.run(review_notes.sync_scan_review_notes("scan-notes")) == "synced"
    assert list(directory.iterdir()) == []
    assert get_review_notes_dir("scan-notes") is None
    store.set_scan_review_notes("scan-notes", "owner", True, [entry["id"]])
    asyncio.run(review_notes.sync_scan_review_notes("scan-notes"))
    store.delete_review_note("owner", entry["id"])
    asyncio.run(review_notes.sync_scan_review_notes("scan-notes"))
    assert list(directory.iterdir()) == []
    assert len(commands) == 5
    assert not get_runtime().agents.review_notes_waiters


def test_offline_change_is_included_on_reconnect_even_after_main_scan_completed(
    notes_env,
    monkeypatch,
):
    store, entry = notes_env
    original = store.get_scan_review_notes("scan-notes")
    monkeypatch.setattr(backend_scans_agent_binding, '_resolve_scan_agent_id', AsyncMock(return_value=None))
    store.update_review_note("owner", entry["id"], "新标题", "离线修改")
    assert asyncio.run(review_notes.sync_scan_review_notes("scan-notes")) == "pending"
    states = asyncio.run(review_notes.review_notes_for_agent(
        "stable-agent", {"scan-notes": original["revision"]}, store=store,
    ))
    assert len(states) == 1
    assert states[0]["entries"][0]["content"] == "离线修改"
    assert asyncio.run(review_notes.review_notes_for_agent(
        "stable-agent", {"scan-notes": states[0]["revision"]}, store=store,
    )) == []
    assert asyncio.run(review_notes.review_notes_for_agent("another-agent", {}, store=store)) == []


@pytest.mark.parametrize("ack", [
    {"ok": False, "scan_id": "scan-notes", "revision": 1, "error": "disk full"},
    {"ok": True, "scan_id": "wrong-scan", "revision": 1},
    {"ok": True, "scan_id": "scan-notes", "revision": 0},
])
def test_socket_delivery_is_not_success_without_matching_applied_ack(notes_env, monkeypatch, ack):
    async def deliver(_agent_id, command):
        await backend_agents_rpc._complete_agent_response({**ack, "request_id": command["request_id"]}, get_runtime().agents.review_notes_waiters)
        return True

    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', deliver)
    assert asyncio.run(review_notes.sync_scan_review_notes("scan-notes")) == "error"
    assert not get_runtime().agents.review_notes_waiters


def test_timeout_and_send_failure_leave_no_rpc_waiter(notes_env, monkeypatch):
    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', AsyncMock(return_value=False))
    assert asyncio.run(review_notes.sync_scan_review_notes("scan-notes")) == "pending"
    assert not get_runtime().agents.review_notes_waiters
    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', AsyncMock(return_value=True))
    monkeypatch.setattr(backend_agents_rpc, '_wait_agent_response', AsyncMock(side_effect=asyncio.TimeoutError))
    assert asyncio.run(review_notes.sync_scan_review_notes("scan-notes")) == "pending"
    assert not get_runtime().agents.review_notes_waiters


def test_new_scan_default_does_not_add_agent_files(notes_env):
    store, _ = notes_env
    assert asyncio.run(review_notes.scan_review_notes_payload("unconfigured", store=store)) is None


@pytest.mark.parametrize("invalid", [False, True, "deleted"])
def test_create_scan_persists_and_dispatches_selected_notes(notes_env, monkeypatch, invalid):
    store, entry = notes_env
    agent = AgentInfo(agent_id="live-agent", agent_key="stable-agent", name="agent",
                      ip="127.0.0.1", last_seen="2026-11-02T00:00:00Z", user_id="owner")
    monkeypatch.setattr(application, 'default_store_factory', lambda: store)
    monkeypatch.setattr(get_runtime().scans, 'running_scans', {})
    monkeypatch.setattr(get_runtime().scans, 'scan_owners', {})
    monkeypatch.setattr(creation_config, '_resolve_scan_mining_engines', lambda *args, **kwargs: [])
    monkeypatch.setattr(creation_config, '_resolve_threat_analysis_enabled', lambda *args, **kwargs: True)
    monkeypatch.setattr(creation_config, '_resolve_threat_analysis_method', lambda *args, **kwargs: ("deephole_threat_analysis", None))
    monkeypatch.setattr(creation_config, '_resolve_fp_review_method', lambda *args, **kwargs: ("adversarial", None))
    monkeypatch.setattr(backend_agents_directory, 'resolve_agent_connection_async', AsyncMock(return_value=(agent.agent_id, agent)))
    monkeypatch.setattr(backend_agents_runtime_updates, 'ensure_agent_accepting_tasks_async', AsyncMock())
    monkeypatch.setattr(backend_agents_configuration, 'get_scan_agent_config_async', AsyncMock(return_value=AgentRemoteConfig(
        model_pool={"models": [{"id": "ready", "model": "provider/model", "enabled": True}]},
    )))
    monkeypatch.setattr(backend_agents_artifacts, 'create_agent_task_runtime_update_payload_async', AsyncMock(return_value=None))
    async def successful_path_probe(_agent_id, _agent, targets):
        return [{key: target[key] for key in ("project_path", "code_scan_path", "code_scan_paths")}
                for target in targets]
    monkeypatch.setattr(backend_agents_gateway, 'request_agent_scan_paths', successful_path_probe)
    send = AsyncMock(return_value=True)
    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', send)
    body = CreateScanRequest(agent_key=agent.agent_key, project_path="/repo/project", scan_name="notes-create",
                             threat_analysis_enabled=True, mining_engines=[], review_notes_enabled=True,
                             review_note_ids=["missing" if invalid is True else entry["id"]])
    if invalid == "deleted":
        original_set = store.set_scan_review_notes

        def deleted_before_selection(*args):
            store.delete_review_note("owner", entry["id"])
            return original_set(*args)

        monkeypatch.setattr(store, "set_scan_review_notes", deleted_before_selection)

    async def create():
        return await backend_scans_creation.create_agent_scan(body, "http://test",
                                               User(user_id="owner", username="owner", role="user"))

    if invalid:
        from backend.application import ApplicationError as HTTPException
        with pytest.raises(HTTPException) as error:
            asyncio.run(create())
        assert error.value.status_code == 422
        assert len(store.list_scans()) == 1
        send.assert_not_awaited()
    else:
        result = asyncio.run(create())
        expected = store.get_scan_review_notes(result.scan_id)
        assert expected["enabled"] is True and expected["entries"] == [entry]
        assert send.await_args.args[1]["review_notes"] == expected


def test_offline_stable_agent_does_not_send_notes_to_same_named_agent(monkeypatch):
    other = AgentInfo(agent_id="other-agent", agent_key="other-key", name="same-name",
                      ip="127.0.0.1", last_seen="2026-11-02T00:00:00Z", user_id="other-user")
    monkeypatch.setattr(get_runtime().agents, 'registered_agents', {other.agent_id: other})
    monkeypatch.setattr(get_runtime().agents, 'agent_ws', {other.agent_id: object()})
    monkeypatch.setattr(backend_agents_directory, 'resolve_agent_connection_async', AsyncMock(return_value=None))
    monkeypatch.setattr(application, 'default_store_factory', lambda: SimpleNamespace(distributed=False))
    meta = ScanMeta(scan_items=[], created_at="2026-11-02T00:00:00Z", user_id="owner",
                    agent_key="offline-key", agent_name="same-name")
    assert asyncio.run(backend_scans_agent_binding._resolve_scan_agent_id(meta)) is None
    # Old scans without a stable key may fall back by name, but only within
    # the owning user's Agents.
    meta.agent_key = ""
    assert asyncio.run(backend_scans_agent_binding._resolve_scan_agent_id(meta)) is None
    other.user_id = "owner"
    assert asyncio.run(backend_scans_agent_binding._resolve_scan_agent_id(meta)) == other.agent_id
    meta.agent_key = "offline-key"
    assert asyncio.run(backend_scans_agent_binding._resolve_scan_agent_id(meta)) is None
