from __future__ import annotations
from deephole_client.server import _probe_scan_paths, handle_scan_paths_probe
from deephole_client.task_manager import TaskManager
from pathlib import Path
from unittest.mock import AsyncMock
import asyncio
import pytest
import backend.agents.directory as backend_agents_directory
import backend.agents.gateway as backend_agents_gateway
import backend.agents.rpc as backend_agents_rpc
from backend.application import ApplicationError as HTTPException, get_runtime
from backend.models import AgentInfo


def _agent(**values):
    return AgentInfo(agent_id="agent-1", name="agent", ip="127.0.0.1", last_seen="now", scan_paths_probe=values.get("supported", True))


def test_probe_mixed_files_and_directories_and_single_file(tmp_path):
    selected = tmp_path / "src"
    selected.mkdir()
    header = tmp_path / "include" / "a.h"
    header.parent.mkdir()
    header.write_text("int a;\n")
    result = asyncio.run(handle_scan_paths_probe("req", [{
        "project_path": str(tmp_path), "code_scan_paths": [str(selected), str(header)],
    }]))
    assert result["request_id"] == "req"
    assert result["type"] == "scan_paths_probe_result"
    assert result["ok"] is True
    assert result["targets"] == [{"project_path": str(tmp_path), "code_scan_path": str(tmp_path), "code_scan_paths": [str(selected), str(header)]}]
    single = _probe_scan_paths([{"project_path": str(tmp_path), "code_scan_paths": [str(header)]}])
    assert single["targets"][0]["code_scan_path"] == str(header.parent)


def test_probe_collects_errors_across_all_versions(tmp_path):
    result = _probe_scan_paths([
        {"version_name": "v1", "project_path": str(tmp_path), "code_scan_paths": [str(tmp_path / "missing-a"), str(tmp_path / "missing-b")]},
        {"version_name": "v2", "project_path": str(tmp_path / "missing-project"), "code_scan_paths": [str(tmp_path / "missing-project" / "c.c")]},
    ])
    assert result["ok"] is False
    assert result["targets"] == []
    errors = "\n".join(result["errors"])
    assert all(value in errors for value in ("v1", "v2", "missing-a", "missing-b", "missing-project", "c.c"))


def test_probe_unresolvable_project_does_not_abort_other_versions(tmp_path):
    loop = tmp_path / "loop"
    loop.symlink_to(loop, target_is_directory=True)
    result = _probe_scan_paths([
        {"version_name": "v1", "project_path": str(loop)},
        {"version_name": "v2", "project_path": str(tmp_path), "code_scan_paths": [str(tmp_path / "missing.c")]},
    ])
    assert result["ok"] is False
    assert result["targets"] == []
    assert any("v1" in error and "loop" in error for error in result["errors"])
    assert any("v2" in error and "missing.c" in error for error in result["errors"])


def test_old_agent_refused_without_dispatch(monkeypatch):
    send = AsyncMock()
    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', send)
    with pytest.raises(HTTPException) as error:
        asyncio.run(backend_agents_gateway.request_agent_scan_paths("agent-1", _agent(supported=False), [{}]))
    assert error.value.status_code == 409
    send.assert_not_awaited()


@pytest.mark.parametrize("reply,status", [
    ({"ok": False, "errors": ["missing-a", "missing-b"]}, 422),
    ({"ok": True, "targets": []}, 502),
    ({"ok": True, "targets": [{"project_path": "/repo", "code_scan_path": "/repo", "code_scan_paths": []}]}, 502),
])
def test_rpc_failures_cleanup_waiters(monkeypatch, reply, status):
    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', AsyncMock(return_value=True))
    monkeypatch.setattr(backend_agents_rpc, '_wait_agent_response', AsyncMock(return_value=reply))
    with pytest.raises(HTTPException) as error:
        asyncio.run(backend_agents_gateway.request_agent_scan_paths("agent-1", _agent(), [{}]))
    assert error.value.status_code == status
    if status == 422:
        assert "missing-a" in error.value.detail and "missing-b" in error.value.detail
    assert not get_runtime().agents.scan_paths_probe_waiters


@pytest.mark.parametrize("sent,status", [(False, 502), (True, 504)])
def test_rpc_disconnect_and_timeout_fail_closed(monkeypatch, sent, status):
    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', AsyncMock(return_value=sent))
    wait = AsyncMock(side_effect=asyncio.TimeoutError)
    monkeypatch.setattr(backend_agents_rpc, '_wait_agent_response', wait)
    with pytest.raises(HTTPException) as error:
        asyncio.run(backend_agents_gateway.request_agent_scan_paths("agent-1", _agent(), [{}]))
    assert error.value.status_code == status
    if sent:
        assert wait.await_args.kwargs["timeout"] == 10.0
    assert not get_runtime().agents.scan_paths_probe_waiters


def test_rpc_accepts_response_while_send_unwinds(monkeypatch):
    target = {"project_path": "/repo", "code_scan_path": "/repo", "code_scan_paths": ["/repo/a", "/repo/b.c"]}

    async def send(agent_id, command):
        assert agent_id == "agent-1"
        assert command["type"] == "scan_paths_probe"
        await backend_agents_rpc._complete_agent_response({
            "request_id": command["request_id"], "ok": True, "targets": [target],
        }, get_runtime().agents.scan_paths_probe_waiters)
        return True

    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', send)
    assert asyncio.run(backend_agents_gateway.request_agent_scan_paths("agent-1", _agent(), [target])) == [target]
    assert not get_runtime().agents.scan_paths_probe_waiters


def test_shared_agent_session_retains_probe_capability():
    agent = backend_agents_directory._agent_info_from_shared_session({
        "agent_id": "agent-1", "agent_key": "key", "name": "agent", "machine_name": "machine",
        "last_seen": "now", "user_id": "user", "protocol_version": 2, "scan_paths_probe": 1,
    })
    assert agent.scan_paths_probe is True


def test_task_snapshots_keep_scope_list():
    async def run():
        manager = TaskManager()
        task = manager.create("scan", "/repo", "/repo", [], "name", code_scan_paths=["/repo/src", "/repo/header.h"])
        marker = asyncio.get_running_loop().create_future()
        task.asyncio_task = marker
        try:
            assert task.code_scan_paths == [Path("/repo/src"), Path("/repo/header.h")]
            assert manager.active_snapshots()[0]["code_scan_paths"] == ["/repo/src", "/repo/header.h"]
        finally:
            marker.cancel()
    asyncio.run(run())


def test_resume_inherits_or_replaces_scope_list(monkeypatch):
    from deephole_client import server
    manager = TaskManager()
    monkeypatch.setattr(server, "_task_manager", manager)
    monkeypatch.setattr(server, "_run", AsyncMock())

    async def run():
        manager.create("scan", "/repo", "/repo", [], "name", code_scan_paths=["/repo/a", "/repo/b.c"])
        await server.handle_resume("scan")
        task = manager.get("scan")
        assert task.code_scan_paths == [Path("/repo/a"), Path("/repo/b.c")]
        await task.asyncio_task
        await server.handle_resume("scan", project_path="/repo", code_scan_path="/repo", code_scan_paths=["/repo/c.c"])
        task = manager.get("scan")
        assert task.code_scan_paths == [Path("/repo/c.c")]
        await task.asyncio_task
    asyncio.run(run())


def test_runtime_update_pending_snapshot_retains_scope(monkeypatch):
    from deephole_client import updater
    command = {
        "type": "resume", "scan_id": "scan", "project_path": "/repo", "code_scan_path": "/repo",
        "code_scan_paths": ["/repo/a", "/repo/b.c"],
        "multi_versions": [{"version_name": "v1", "project_path": "/repo", "code_scan_paths": ["/repo/a"]}],
    }
    monkeypatch.setattr(updater, "load_pending_commands", lambda **kwargs: [command])
    snapshot = updater.pending_scan_snapshots()[0]
    assert snapshot["code_scan_paths"] == command["code_scan_paths"]
    assert snapshot["multi_versions"] == command["multi_versions"]


def test_sqlite_legacy_schema_adds_paths_column_and_preserves_scope(tmp_path):
    import sqlite3
    from backend.models import ScanMeta, ScanStatus
    from backend.store.sqlite import SqliteScanStore
    path = tmp_path / "store.db"
    store = SqliteScanStore(path)
    store.save_scan(ScanStatus(scan_id="old", status="pending", progress=0, total_candidates=0, processed_candidates=0, vulnerabilities=[]), ScanMeta(
        scan_items=[], created_at="2026-11-04T00:00:00+00:00", project_path="/repo", code_scan_path="/repo/src",
    ))
    store.close()
    with sqlite3.connect(path) as conn:
        conn.execute("ALTER TABLE scans DROP COLUMN code_scan_paths_json")
    store = SqliteScanStore(path)
    try:
        scan, meta = store.load_scan("old")
        assert meta.code_scan_paths == scan.code_scan_paths == ["/repo/src"]
        meta.code_scan_paths = ["/repo/src", "/repo/include/a.h"]
        store.save_scan(scan, meta)
        assert store.load_scan_runtime("old")[0].code_scan_paths == meta.code_scan_paths
    finally:
        store.close()


def test_postgres_scope_and_probe_capability_roundtrip():
    import os
    import uuid
    from datetime import datetime, timezone
    from backend.models import ScanMeta, ScanStatus
    from backend.store.postgres import PostgresScanStore

    dsn = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN", "")
    if not dsn:
        pytest.skip("OPENDEEPHOLE_TEST_POSTGRES_DSN is not configured")
    store = PostgresScanStore(dsn)
    peer = PostgresScanStore(dsn)
    suffix = uuid.uuid4().hex
    scan_id, agent_id, worker_id = (f"paths-{part}-{suffix}" for part in ("scan", "agent", "worker"))
    try:
        paths = ["/repo/src", "/repo/include/a.h"]
        store.save_scan(ScanStatus(
            scan_id=scan_id, status="complete", progress=1,
            total_candidates=0, processed_candidates=0, vulnerabilities=[],
        ), ScanMeta(
            scan_items=[], created_at="2026-11-04T00:00:00+00:00", project_path="/repo",
            code_scan_path="/repo", code_scan_paths=paths,
        ))
        assert peer.load_scan_runtime(scan_id)[0].code_scan_paths == paths
        assert peer.get_scan_meta(scan_id).code_scan_paths == paths
        agent = AgentInfo(
            agent_id=agent_id, agent_key=agent_id, name="paths", ip="127.0.0.1",
            last_seen=datetime.now(timezone.utc).isoformat(), scan_paths_probe=True,
        )
        store.register_worker(worker_id)
        store.register_agent_session(agent, worker_id)
        session = peer.get_live_agent_session(agent_id=agent_id)
        assert session["scan_paths_probe"] == 1
        assert backend_agents_directory._agent_info_from_shared_session(session).scan_paths_probe
    finally:
        store.delete_scan(scan_id)
        store._conn.execute("DELETE FROM agent_sessions WHERE agent_id = ?", (agent_id,))
        store._conn.execute("DELETE FROM backend_workers WHERE worker_id = ?", (worker_id,))
        store._conn.commit()
        peer.close()
        store.close()


def test_runtime_update_empty_legacy_scope_has_no_empty_path(monkeypatch):
    from deephole_client import updater
    monkeypatch.setattr(updater, "load_pending_commands", lambda **kwargs: [{"type": "task", "scan_id": "scan"}])
    assert updater.pending_scan_snapshots()[0]["code_scan_paths"] == []
