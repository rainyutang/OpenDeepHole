from __future__ import annotations

import asyncio
import hashlib
import io
import threading
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

import backend.agents.artifacts as backend_agents_artifacts
import backend.agents.connections as backend_agents_connections
import backend.agents.runtime_updates as backend_agents_runtime_updates
from backend.application import ApplicationError, get_runtime
from backend.models import (
    AgentInfo,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    User,
)
from backend.store.sqlite import SqliteScanStore
import deephole_client.updater as updater
from deephole_client.runtime_update_coordinator import (
    RuntimeUpdateCoordinator,
    reset_runtime_update_coordinator,
)
from task_agent import model_pool
from task_agent.config_reload import (
    ConfigReloadCoordinator,
    get_config_reload_coordinator,
)
from task_agent.model_pool import (
    acquire_model_lease,
    model_pool_snapshot,
    notify_model_pool_config_changed,
    refresh_configured_model_pool,
    release_model_lease,
)


@pytest.fixture(autouse=True)
def _isolated_model_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(model_pool, "_condition", asyncio.Condition())
    for name in (
        "_running_by_model", "_last_used", "_stats_by_scope", "_global_stats_by_model",
        "_options_by_id", "_model_health_by_id", "_scope_updated_at", "_active_tasks",
        "_completed_tasks_by_scope", "_completed_task_count_by_scope",
        "_token_usage_by_scope", "_peak_total_tasks_by_scope", "_planned_tasks",
        "_planned_task_ids_by_key",
    ):
        monkeypatch.setattr(model_pool, name, {})
    monkeypatch.setattr(model_pool, "_change_waiters", set())
    monkeypatch.setattr(model_pool, "_pending_requests", [])
    monkeypatch.setattr(model_pool, "_global_running", 0)
    monkeypatch.setattr(model_pool, "_completed_task_sink", None)


def _model_pool_config(max_concurrency: int = 1) -> SimpleNamespace:
    return SimpleNamespace(
        model="provider/model-1",
        models=[
            SimpleNamespace(
                id="m1",
                model="provider/model-1",
                capability="high",
                weight=1.0,
                max_concurrency=max_concurrency,
                enabled=True,
                timeout=None,
                idle_timeout=None,
                max_retries=None,
                time_windows=[],
            )
        ],
    )


def _make_runtime_zip(files: dict[str, bytes]) -> tuple[bytes, str, dict]:
    ordered = sorted(files.items(), key=lambda item: item[0])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arcname, content in ordered:
            zf.writestr(arcname, content)
    archive_bytes = buf.getvalue()
    digest = hashlib.sha256()
    for arcname, content in ordered:
        digest.update(arcname.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0")
    runtime_hash = digest.hexdigest()
    manifest = {
        "runtime_hash": runtime_hash,
        "hash_scope": updater.runtime_hash_scope(),
        "files": [
            {
                "path": arcname,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
            for arcname, content in ordered
        ],
    }
    return archive_bytes, runtime_hash, manifest


def _store_with_agent(
    tmp_path: Path,
    *,
    graceful: bool = True,
    runtime_hash: str = "old-runtime",
) -> tuple[SqliteScanStore, User]:
    store = SqliteScanStore(tmp_path / "scans.db")
    user = User(user_id="user-1", username="owner", role="user")
    store.create_user(user.user_id, user.username, "hash", user.role, "token")
    store.upsert_agent_record(
        agent_key="stable-agent",
        user_id=user.user_id,
        ip="127.0.0.1",
        machine_name="machine",
        display_name="agent",
        agent_id="live-agent",
        last_seen="2026-11-23T00:00:00+00:00",
    )
    get_runtime().agents.registered_agents["live-agent"] = AgentInfo(
        agent_id="live-agent",
        agent_key="stable-agent",
        name="agent",
        machine_name="machine",
        ip="127.0.0.1",
        last_seen="2026-11-23T00:00:00+00:00",
        user_id="user-1",
        runtime_hash=runtime_hash,
        agent_session_id="sess-old",
        graceful_runtime_update=graceful,
        server_url="http://server.example",
    )
    get_runtime().agents.agent_ws["live-agent"] = object()
    return store, user


def _save_agent_scan(
    store: SqliteScanStore,
    scan_id: str,
    status: ScanItemStatus,
    *,
    error_message: str | None = None,
    execution_agent_session_id: str = "sess-old",
) -> None:
    store.save_scan(
        ScanStatus(
            scan_id=scan_id,
            project_id="project-1",
            status=status,
            progress=0.25,
            total_candidates=4,
            processed_candidates=1,
            vulnerabilities=[],
            error_message=error_message,
            agent_name="agent",
        ),
        ScanMeta(
            scan_items=["npd"],
            created_at="2026-11-23T00:00:00+00:00",
            agent_id="live-agent",
            agent_key="stable-agent",
            agent_name="agent",
            user_id="user-1",
            execution_agent_session_id=execution_agent_session_id,
        ),
    )
    if execution_agent_session_id:
        store.begin_scan_execution(
            scan_id,
            agent_id="live-agent",
            agent_session_id=execution_agent_session_id,
        )


def _cleanup_agent_globals() -> None:
    get_runtime().agents.registered_agents.clear()
    get_runtime().agents.agent_ws.clear()
    get_runtime().agents.agent_ws_locks.clear()
    get_runtime().agents.agent_opencode_pool_latest.clear()
    get_runtime().agents.legacy_runtime_update_attempts.clear()
    get_runtime().agents.legacy_stop_settle_until.clear()
    backend_agents_runtime_updates.reset_runtime_update_stat_check_clock()


def test_runtime_update_hold_pauses_new_leases_and_suspends_nested_local_work() -> None:
    async def run() -> None:
        cfg = _model_pool_config(max_concurrency=2)
        await refresh_configured_model_pool(cfg)
        coordinator = get_config_reload_coordinator()
        coordinator.release_admission_hold("runtime_update")

        try:
            # Admit one running task before holding admission.
            coordinator.admit_task("admitted-task")
            coordinator.hold_admission("runtime_update")
            await notify_model_pool_config_changed()

            assert coordinator.admission("admitted-task") is True
            assert coordinator.admission("new-task") is False

            # A coroutine inside track_local_work (e.g. post-lease dedup or validator)
            # that waits on acquire_model_lease while admission is closed must suspend
            # its local-work hold so drain cannot deadlock.
            cancel_event = threading.Event()
            nested_entered = asyncio.Event()
            nested_acquired = asyncio.Event()

            async def nested_worker() -> None:
                with coordinator.track_local_work("post_lease_settlement"):
                    nested_entered.set()
                    lease = await acquire_model_lease(
                        cfg,
                        required_capability="high",
                        task_id="nested-dedup",
                        stats_scope_id="scan-1",
                        cancel_event=cancel_event,
                        admission_allowed=lambda: coordinator.admission("nested-dedup"),
                        on_admitted=lambda: coordinator.admit_task("nested-dedup"),
                    )
                    assert lease is not None
                    nested_acquired.set()
                    await release_model_lease(lease)

            task = asyncio.create_task(nested_worker())
            await nested_entered.wait()
            for _ in range(20):
                if coordinator.active_local_work_count() == 0:
                    break
                await asyncio.sleep(0.01)

            assert coordinator.active_local_work_count() == 0
            assert not nested_acquired.is_set()

            snapshot = model_pool_snapshot("scan-1")
            assert snapshot["queued_tasks"]
            assert "等待当前在途任务完成后更新 Agent" in snapshot["queued_tasks"][0]["blocked_reason"]

            # Once admitted task finishes, coordinator has zero pending work even while
            # nested_worker is parked waiting for a new session.
            coordinator.release_task("admitted-task")
            assert coordinator.has_pending_work() is False

            # If update aborts and hold releases, nested_worker immediately resumes.
            coordinator.release_admission_hold("runtime_update")
            await notify_model_pool_config_changed()
            await asyncio.wait_for(nested_acquired.wait(), timeout=2.0)
            await task
        finally:
            coordinator.release_admission_hold("runtime_update")
            coordinator.release_task("admitted-task")
            coordinator.release_task("nested-dedup")

    asyncio.run(run())


def test_config_reload_waits_for_runtime_update_hold_before_restarting_serve() -> None:
    async def run() -> None:
        coordinator = ConfigReloadCoordinator()
        applied: list[str] = []

        async def apply(_payload, rev: str) -> None:
            applied.append(rev)

        coordinator.hold_admission("runtime_update")
        with patch.object(coordinator, "_notify_model_pool", new=AsyncMock()):
            coordinator.stage("rev-1", {"k": "v"}, apply)
            await asyncio.sleep(0.05)
            assert applied == []
            assert coordinator.status()["state"] == "draining"

            coordinator.release_admission_hold("runtime_update")
            for _ in range(20):
                if applied:
                    break
                await asyncio.sleep(0.02)
            assert applied == ["rev-1"]
            assert coordinator.status()["state"] == "active"

    asyncio.run(run())


def test_staged_runtime_update_skips_pip_when_requirements_unchanged(tmp_path: Path) -> None:
    root = tmp_path / "agent_root"
    (root / "deephole_client").mkdir(parents=True)
    (root / "deephole_client" / "sample.py").write_text("v1\n", encoding="utf-8")
    (root / "requirements-agent.txt").write_text("httpx==0.28.0\n", encoding="utf-8")

    archive_same_req, hash_same_req, manifest_same_req = _make_runtime_zip({
        "deephole_client/sample.py": b"v2\n",
        "requirements-agent.txt": b"httpx==0.28.0\n",
    })
    archive_new_req, hash_new_req, manifest_new_req = _make_runtime_zip({
        "deephole_client/sample.py": b"v3\n",
        "requirements-agent.txt": b"httpx==0.28.1\n",
    })

    pip_calls: list[str] = []

    async def run() -> None:
        with (
            patch("deephole_client.updater.runtime_root", return_value=root),
            patch("deephole_client.updater._download_update", new=AsyncMock(return_value=archive_same_req)),
            patch("deephole_client.updater._install_requirements_if_needed", side_effect=lambda: pip_calls.append("pip")),
        ):
            staged = await updater.stage_runtime_update(
                {"hash": hash_same_req, "manifest": manifest_same_req, "download_url": "/api/agent/runtime/download"},
                fallback_server_url="http://server.example",
            )
            assert staged is not None
            updater.install_staged_runtime_update(staged)

        assert (root / "deephole_client" / "sample.py").read_text(encoding="utf-8") == "v2\n"
        assert pip_calls == []

        with (
            patch("deephole_client.updater.runtime_root", return_value=root),
            patch("deephole_client.updater._download_update", new=AsyncMock(return_value=archive_new_req)),
            patch("deephole_client.updater._install_requirements_if_needed", side_effect=lambda: pip_calls.append("pip")),
        ):
            staged = await updater.stage_runtime_update(
                {"hash": hash_new_req, "manifest": manifest_new_req, "download_url": "/api/agent/runtime/download"},
                fallback_server_url="http://server.example",
            )
            assert staged is not None
            updater.install_staged_runtime_update(staged)

        assert (root / "deephole_client" / "sample.py").read_text(encoding="utf-8") == "v3\n"
        assert pip_calls == ["pip"]

    asyncio.run(run())


def test_runtime_update_coordinator_drains_flushes_and_restarts_without_cancelling_scans(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        reload_coordinator = get_config_reload_coordinator()
        reload_coordinator.release_admission_hold("runtime_update")
        coordinator = reset_runtime_update_coordinator(
            RuntimeUpdateCoordinator(quiescence_seconds=0.02, flush_timeout_seconds=5.0)
        )

        statuses: list[dict] = []
        steps: list[str] = []
        scan_events: list[tuple[str, str]] = []
        scan_cancel = threading.Event()

        async def send_status(payload: dict) -> None:
            statuses.append(payload)

        class FakeReporter:
            async def send_event(self, scan_id: str, event) -> None:
                scan_events.append((scan_id, event.message))

            async def flush_for_restart(self, timeout: float = 30.0) -> bool:
                steps.append("flush_for_restart")
                return True

            async def close(self) -> None:
                steps.append("reporter_close")

        class FakeTaskManager:
            def active_snapshots(self) -> list[dict]:
                return [{"scan_id": "scan-live"}]

        staged = updater.StagedRuntimeUpdate(
            target_hash="hash-v2",
            tmp_dir=tmp_path / "staged",
            archive_paths=["deephole_client/main.py"],
        )
        staged.tmp_dir.mkdir(parents=True, exist_ok=True)

        coordinator.bind_connection(
            send_status=send_status,
            reporter=FakeReporter(),
            task_manager=FakeTaskManager(),
        )

        # Simulate an active admitted OpenCode task before update arrives.
        reload_coordinator.admit_task("opencode-task-1")

        try:
            with (
                patch("deephole_client.updater.compute_runtime_hash", return_value="hash-v1"),
                patch("deephole_client.updater.stage_runtime_update", new=AsyncMock(return_value=staged)),
                patch(
                    "deephole_client.updater.install_staged_runtime_update",
                    side_effect=lambda _s: steps.append("install_staged"),
                ),
                patch(
                    "deephole_client.updater._restart_process",
                    side_effect=lambda reason="runtime_update": steps.append(f"restart:{reason}"),
                ),
                patch.object(
                    coordinator,
                    "_shutdown_opencode",
                    new=AsyncMock(side_effect=lambda: steps.append("shutdown_opencode")),
                ),
                patch.object(coordinator, "_notify_model_pool", new=AsyncMock()),
            ):
                accepted = coordinator.stage_update(
                    {"hash": "hash-v2", "download_url": "http://server/api/agent/runtime/download"},
                    server_url="http://server",
                )
                assert accepted is True
                # Admission must be closed synchronously before awaiting anything.
                assert reload_coordinator.has_admission_hold("runtime_update") is True
                assert reload_coordinator.admission("opencode-task-1") is True
                assert reload_coordinator.admission("opencode-task-2") is False

                await asyncio.sleep(0.05)
                assert steps == []
                assert any(s["state"] == "draining" and s["active_tasks"] == 1 for s in statuses)

                # Finish the active OpenCode task and briefly enter post-lease settlement.
                with reload_coordinator.track_local_work("post_lease_settlement"):
                    reload_coordinator.release_task("opencode-task-1")
                    await asyncio.sleep(0.05)
                    assert steps == []

                assert coordinator._worker is not None
                await asyncio.wait_for(coordinator._worker, timeout=2.0)

            assert steps == [
                "flush_for_restart",
                "shutdown_opencode",
                "install_staged",
                "reporter_close",
                "restart:runtime_update",
            ]
            assert not scan_cancel.is_set()
            assert any(s["state"] == "updating" and s["active_tasks"] == 0 for s in statuses)
            assert any(scan_id == "scan-live" for scan_id, _ in scan_events)
        finally:
            reload_coordinator.release_task("opencode-task-1")
            reload_coordinator.release_admission_hold("runtime_update")
            await coordinator.shutdown()

    asyncio.run(run())


def test_runtime_update_coordinator_reopens_admission_when_staging_fails() -> None:
    async def run() -> None:
        reload_coordinator = get_config_reload_coordinator()
        reload_coordinator.release_admission_hold("runtime_update")
        coordinator = reset_runtime_update_coordinator(
            RuntimeUpdateCoordinator(quiescence_seconds=0.01)
        )
        statuses: list[dict] = []

        async def send_status(payload: dict) -> None:
            statuses.append(payload)

        coordinator.bind_connection(send_status=send_status)

        try:
            with (
                patch("deephole_client.updater.compute_runtime_hash", return_value="hash-v1"),
                patch(
                    "deephole_client.updater.stage_runtime_update",
                    new=AsyncMock(side_effect=RuntimeError("checksum mismatch")),
                ),
                patch.object(coordinator, "_notify_model_pool", new=AsyncMock()),
            ):
                coordinator.stage_update({"hash": "hash-v2"})
                assert reload_coordinator.has_admission_hold("runtime_update") is True
                assert coordinator._worker is not None
                await asyncio.wait_for(coordinator._worker, timeout=2.0)

            assert reload_coordinator.has_admission_hold("runtime_update") is False
            assert coordinator.status()["state"] == "failed"
            assert any(s["state"] == "failed" and "checksum mismatch" in s["error"] for s in statuses)
        finally:
            reload_coordinator.release_admission_hold("runtime_update")
            await coordinator.shutdown()

    asyncio.run(run())


def test_cached_runtime_hash_avoids_rehashing_when_stat_signature_unchanged(tmp_path: Path) -> None:
    f1 = tmp_path / "a.py"
    f1.write_text("hello", encoding="utf-8")
    hash_calls = 0

    def fake_iter():
        yield "deephole_client/a.py", f1

    original_hash = backend_agents_artifacts._ORIGINAL_AGENT_RUNTIME_HASH

    def counting_hash() -> str:
        nonlocal hash_calls
        hash_calls += 1
        return original_hash()

    backend_agents_artifacts.invalidate_agent_runtime_hash_cache()
    try:
        with (
            patch.object(backend_agents_artifacts, "_iter_agent_runtime_files", side_effect=fake_iter),
            patch.object(backend_agents_artifacts, "_agent_runtime_hash", new=counting_hash),
            patch.object(backend_agents_artifacts, "_ORIGINAL_AGENT_RUNTIME_HASH", new=counting_hash),
        ):
            first = backend_agents_artifacts.get_cached_agent_runtime_hash(check_stat=False)
            second = backend_agents_artifacts.get_cached_agent_runtime_hash(check_stat=False)
            third = backend_agents_artifacts.get_cached_agent_runtime_hash(check_stat=True)
            assert first == second == third
            assert hash_calls == 1

            # Changing file content/size changes stat signature -> recomputes once.
            f1.write_text("hello-updated", encoding="utf-8")
            fourth = backend_agents_artifacts.get_cached_agent_runtime_hash(check_stat=True)
            assert fourth != first
            assert hash_calls == 2
    finally:
        backend_agents_artifacts.invalidate_agent_runtime_hash_cache()


def test_backend_auto_triggers_drain_update_for_busy_and_idle_graceful_agents(
    tmp_path: Path,
) -> None:
    store, _user = _store_with_agent(tmp_path, graceful=True, runtime_hash="old-runtime")
    _save_agent_scan(store, "scan-1", ScanItemStatus.AUDITING)
    send = AsyncMock(return_value=True)
    payload = {"hash": "new-runtime", "token": "tok-1", "download_url": "http://server.example/api/agent/runtime/download"}
    try:
        with (
            patch("backend.application.default_store_factory", return_value=store),
            patch("backend.agents.artifacts._agent_runtime_hash", return_value="new-runtime"),
            patch("backend.agents.artifacts.create_agent_runtime_update_payload", return_value=payload),
            patch("backend.agents.gateway.send_agent_command", new=send),
        ):
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())

        send.assert_awaited_once_with(
            "live-agent",
            {
                "type": "runtime_update",
                "mode": "drain",
                "agent_runtime_update": payload,
            },
        )
        record = store.get_agent_record("stable-agent")
        assert record["runtime_update_status"] == "draining"
        assert record["runtime_update_target_hash"] == "new-runtime"

        # New task submission is rejected during draining.
        with (
            patch("backend.application.default_store_factory", return_value=store),
            pytest.raises(ApplicationError) as exc_info,
        ):
            asyncio.run(backend_agents_runtime_updates.ensure_agent_accepting_tasks_async("stable-agent"))
        assert exc_info.value.status_code == 409
        assert "等待当前在途任务完成" in str(exc_info.value.detail)

        # Idle graceful Agent also auto-updates immediately into updating state.
        store.update_scan_progress("scan-1", status=ScanItemStatus.COMPLETE)
        store.set_agent_runtime_update_record("stable-agent", status="")
        send.reset_mock()
        with (
            patch("backend.application.default_store_factory", return_value=store),
            patch("backend.agents.artifacts._agent_runtime_hash", return_value="new-runtime"),
            patch("backend.agents.artifacts.create_agent_runtime_update_payload", return_value=payload),
            patch("backend.agents.gateway.send_agent_command", new=send),
        ):
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())
        send.assert_awaited_once()
        assert store.get_agent_record("stable-agent")["runtime_update_status"] == "updating"
    finally:
        _cleanup_agent_globals()
        store.close()


def test_backend_failed_auto_update_does_not_loop_until_newer_hash(tmp_path: Path) -> None:
    store, _user = _store_with_agent(tmp_path, graceful=True, runtime_hash="old-runtime")
    agent = get_runtime().agents.registered_agents["live-agent"]
    send = AsyncMock(return_value=True)
    payload_v3 = {"hash": "hash-v3", "token": "tok-3", "download_url": "http://server.example/api/agent/runtime/download"}
    try:
        with patch("backend.application.default_store_factory", return_value=store):
            asyncio.run(
                backend_agents_runtime_updates.handle_agent_runtime_update_status(
                    agent,
                    {"state": "failed", "target_hash": "hash-v2", "error": "network error"},
                )
            )
            assert store.get_agent_record("stable-agent")["runtime_update_status"] == "failed"
            assert backend_agents_runtime_updates.is_agent_accepting_tasks("stable-agent") is True

        # Same hash-v2 must not auto-retry.
        with (
            patch("backend.application.default_store_factory", return_value=store),
            patch("backend.agents.artifacts._agent_runtime_hash", return_value="hash-v2"),
            patch("backend.agents.gateway.send_agent_command", new=send),
        ):
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())
        send.assert_not_awaited()

        # A newer hash-v3 triggers a fresh automatic update.
        with (
            patch("backend.application.default_store_factory", return_value=store),
            patch("backend.agents.artifacts._agent_runtime_hash", return_value="hash-v3"),
            patch("backend.agents.artifacts.create_agent_runtime_update_payload", return_value=payload_v3),
            patch("backend.agents.gateway.send_agent_command", new=send),
        ):
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())
        send.assert_awaited_once()
        assert store.get_agent_record("stable-agent")["runtime_update_target_hash"] == "hash-v3"
    finally:
        _cleanup_agent_globals()
        store.close()


def test_websocket_hello_auto_updates_outdated_agent_and_recovers_after_upgrade(
    tmp_path: Path,
) -> None:
    store = SqliteScanStore(tmp_path / "scans.db")
    user = User(user_id="user-1", username="owner", role="user")
    store.create_user(user.user_id, user.username, "hash", user.role, "owner-tok")
    store.upsert_agent_record(
        agent_key="stable-agent",
        user_id=user.user_id,
        ip="127.0.0.1",
        machine_name="machine",
        display_name="agent",
        agent_id="prev-agent",
        last_seen="2026-11-23T00:00:00+00:00",
    )
    _save_agent_scan(
        store,
        "scan-active",
        ScanItemStatus.AUDITING,
        execution_agent_session_id="sess-old",
    )
    _save_agent_scan(
        store,
        "scan-stopped",
        ScanItemStatus.CANCELLED,
        error_message="用户手动停止",
        execution_agent_session_id="sess-old",
    )

    class FakeClient:
        host = "127.0.0.1"

    class FakeWebSocket:
        client = FakeClient()
        base_url = "ws://server.example/"

        def __init__(self, messages: list[dict], *, wait_after: float = 0.05) -> None:
            self.sent: list[dict] = []
            self.messages = list(messages)
            self.wait_after = wait_after
            self.runtime_update_received = asyncio.Event()

        async def accept(self) -> None:
            return None

        async def receive_json(self):
            if self.messages:
                msg = self.messages.pop(0)
                if msg.get("type") == "runtime_update_status":
                    await asyncio.wait_for(self.runtime_update_received.wait(), timeout=2.0)
                return msg
            await asyncio.sleep(self.wait_after)
            from starlette.websockets import WebSocketDisconnect

            raise WebSocketDisconnect()

        async def send_json(self, payload: dict) -> None:
            self.sent.append(payload)
            if payload.get("type") == "runtime_update":
                self.runtime_update_received.set()

        async def close(self, code: int = 1000) -> None:
            return None

    payload = {
        "hash": "new-runtime",
        "token": "tok-new",
        "download_url": "http://server.example/api/agent/runtime/download",
    }

    try:
        # 1) Old Agent reconnects after backend restart with an active scan:
        #    backend reattaches the scan, sends drain runtime_update, and defers recovery.
        ws_old = FakeWebSocket([
            {
                "type": "hello",
                "name": "agent",
                "machine_name": "machine",
                "owner_token": "owner-tok",
                "protocol_versions": [2, 1],
                "capabilities": {"graceful_runtime_update": True},
                "runtime_hash": "old-runtime",
                "agent_session_id": "sess-old",
                "active_scans": [{"scan_id": "scan-active", "execution_revision": 1}],
            },
            {
                "type": "runtime_update_status",
                "state": "updating",
                "target_hash": "new-runtime",
                "active_tasks": 0,
            },
        ])
        recover_mock = AsyncMock()
        with (
            patch("backend.application.default_store_factory", return_value=store),
            patch("backend.agents.artifacts._agent_runtime_hash", return_value="new-runtime"),
            patch("backend.agents.artifacts.create_agent_runtime_update_payload", return_value=payload),
            patch("backend.agents.recovery._recover_missing_agent_work", new=recover_mock),
        ):
            asyncio.run(backend_agents_connections.agent_websocket(ws_old))

        assert ws_old.sent[0]["type"] == "welcome"
        assert ws_old.sent[0]["server_runtime_hash"] == "new-runtime"
        assert any(
            msg.get("type") == "runtime_update" and msg.get("mode") == "drain"
            for msg in ws_old.sent
        )
        recover_mock.assert_not_awaited()
        assert store.get_agent_record("stable-agent")["runtime_update_status"] == "updating"

        # 2) Updated Agent boots fresh (new session, active_scans=[], new runtime_hash):
        #    backend clears update status and automatically recovers scan-active (not scan-stopped).
        ws_new = FakeWebSocket([
            {
                "type": "hello",
                "name": "agent",
                "machine_name": "machine",
                "owner_token": "owner-tok",
                "protocol_versions": [2, 1],
                "capabilities": {"graceful_runtime_update": True},
                "runtime_hash": "new-runtime",
                "agent_session_id": "sess-new",
                "active_scans": [],
                "active_fp_reviews": [],
                "active_validations": [],
            },
        ])
        resumed_scans: list[tuple[str, int | None]] = []

        async def fake_continue(scan_id: str, *_args, **kwargs):
            resumed_scans.append((scan_id, kwargs.get("claimed_execution_revision")))
            return SimpleNamespace(scan_id=scan_id)

        with (
            patch("backend.application.default_store_factory", return_value=store),
            patch("backend.agents.artifacts._agent_runtime_hash", return_value="new-runtime"),
            patch("backend.scans.continuation._continue_scan", new=fake_continue),
        ):
            asyncio.run(backend_agents_connections.agent_websocket(ws_new))

        assert store.get_agent_record("stable-agent")["runtime_update_status"] == ""
        assert [scan_id for scan_id, _ in resumed_scans] == ["scan-active"]
        assert resumed_scans[0][1] == 2
        assert not any(msg.get("type") == "runtime_update" for msg in ws_new.sent)
    finally:
        for task in list(get_runtime().agents.agent_disconnect_tasks.values()):
            task.cancel()
        get_runtime().agents.agent_disconnect_tasks.clear()
        _cleanup_agent_globals()
        store.close()


def test_compact_threat_analysis_passes_local_resume_flag_on_scan_resume(tmp_path: Path) -> None:
    from contextlib import nullcontext
    from deephole_client.config import AgentConfig
    from deephole_client.scanner import run_scan

    project = tmp_path / "project"
    project.mkdir()
    observed_calls: list[tuple[str, bool]] = []

    async def fake_run_threat_analysis(**kwargs):
        observed_calls.append((kwargs["method_id"], bool(kwargs["is_resume"])))
        out = Path(kwargs["output_path"])
        out.mkdir(parents=True, exist_ok=True)
        (out / "v.json").write_text("[]", encoding="utf-8")
        (out / "t.json").write_text('{"attack_trees": []}', encoding="utf-8")
        (out / "m.json").write_text("[]", encoding="utf-8")
        return {
            "result": True,
            "value_asset_path": str(out / "v.json"),
            "attack_tree_path": str(out / "t.json"),
            "high_risk_modules_path": str(out / "m.json"),
        }

    reporter = SimpleNamespace(
        send_event=AsyncMock(),
        send_index_status=AsyncMock(),
        send_static_progress=AsyncMock(),
        report_threat_analysis_run=AsyncMock(),
        push_threat_analysis=AsyncMock(),
        finish_scan=AsyncMock(),
        get_threat_analysis=AsyncMock(return_value=None),
        publish_opencode_pool_until=AsyncMock(),
    )

    async def run() -> None:
        with (
            patch("deephole_client.scanner.Path.home", return_value=tmp_path),
            patch("deephole_client.scanner.configure_platform_runtime"),
            patch("deephole_client.scanner.opencode_task_context", return_value=nullcontext()),
            patch("deephole_client.scanner.run_threat_analysis", new=fake_run_threat_analysis),
            patch("deephole_client.scanner.prepare_coverage_inventory", new=AsyncMock()),
            patch("deephole_client.scanner.collect_json_artifacts", return_value={"artifacts": {}}),
        ):
            await run_scan(
                config=AgentConfig(),
                project_path=project,
                code_scan_path=project,
                reporter=reporter,
                scan_name="compact-resume",
                product="",
                validation_environment="",
                checker_names=[],
                scan_id="scan-compact-resume",
                cancel_event=threading.Event(),
                is_resume=True,
                resume_threat_analysis=True,
                threat_analysis_enabled=True,
                threat_analysis_method="deephole_compact_threat_analysis",
                mining_engines=[],
            )

    asyncio.run(run())
    assert observed_calls == [("deephole_compact_threat_analysis", True)]


def test_draining_status_with_active_tasks_overrides_optimistic_updating(
    tmp_path: Path,
) -> None:
    store, _user = _store_with_agent(tmp_path, graceful=True, runtime_hash="old-runtime")
    agent = get_runtime().agents.registered_agents["live-agent"]
    store.set_agent_runtime_update_record(
        "stable-agent",
        status="updating",
        target_hash="new-runtime",
        server_url="http://server.example",
        requested_at="2026-11-24T00:00:00+00:00",
        started_at="2026-11-24T00:00:00+00:00",
    )
    try:
        with patch("backend.application.default_store_factory", return_value=store):
            # active_tasks=0 does not flicker optimistic updating back to draining.
            asyncio.run(
                backend_agents_runtime_updates.handle_agent_runtime_update_status(
                    agent,
                    {"state": "draining", "target_hash": "new-runtime", "active_tasks": 0},
                )
            )
            assert store.get_agent_record("stable-agent")["runtime_update_status"] == "updating"

            # active_tasks>0 reflects actual local drain work on the Agent.
            asyncio.run(
                backend_agents_runtime_updates.handle_agent_runtime_update_status(
                    agent,
                    {"state": "draining", "target_hash": "new-runtime", "active_tasks": 2},
                )
            )
            assert store.get_agent_record("stable-agent")["runtime_update_status"] == "draining"
    finally:
        _cleanup_agent_globals()
        store.close()


def test_reconnect_reconciles_manual_update_even_when_auto_update_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENDEEPHOLE_AUTO_AGENT_UPDATE", "0")
    store, _user = _store_with_agent(tmp_path, graceful=True, runtime_hash="old-runtime")
    agent = get_runtime().agents.registered_agents["live-agent"]
    store.set_agent_runtime_update_record(
        "stable-agent",
        status="updating",
        target_hash="new-runtime",
        server_url="http://server.example",
        requested_at="2026-11-24T00:00:00+00:00",
        started_at="2026-11-24T00:00:00+00:00",
    )
    try:
        with (
            patch("backend.application.default_store_factory", return_value=store),
            patch("backend.agents.artifacts._agent_runtime_hash", return_value="new-runtime"),
        ):
            # Reconnecting while still draining keeps recovery deferred.
            defer = asyncio.run(
                backend_agents_runtime_updates.maybe_auto_trigger_agent_runtime_update_on_connect(
                    "live-agent",
                    agent,
                    {"runtime_update_state": {"state": "draining", "target_hash": "new-runtime"}},
                    server_url="http://server.example",
                )
            )
            assert defer is True
            assert store.get_agent_record("stable-agent")["runtime_update_status"] == "draining"

            # Reconnecting fresh with idle state after updating still marks failed.
            store.set_agent_runtime_update_record(
                "stable-agent",
                status="updating",
                target_hash="new-runtime",
                server_url="http://server.example",
                requested_at="2026-11-24T00:00:00+00:00",
                started_at="2026-11-24T00:00:00+00:00",
            )
            defer = asyncio.run(
                backend_agents_runtime_updates.maybe_auto_trigger_agent_runtime_update_on_connect(
                    "live-agent",
                    agent,
                    {"runtime_update_state": {"state": "idle", "target_hash": ""}},
                    server_url="http://server.example",
                )
            )
            assert defer is False
            assert store.get_agent_record("stable-agent")["runtime_update_status"] == "failed"
    finally:
        _cleanup_agent_globals()
        store.close()


def test_standalone_runtime_update_only_stages_coordinator_when_local_work_active() -> None:
    import deephole_client.main as agent_main

    staged_calls: list[tuple[dict, str]] = []
    fake_coordinator = SimpleNamespace(
        stage_update=lambda update, *, server_url="": staged_calls.append((update, server_url)) or True,
    )
    config = SimpleNamespace(server_url="http://server.example")
    with (
        patch("deephole_client.server.has_active_local_work", return_value=True),
        patch(
            "deephole_client.runtime_update_coordinator.get_runtime_update_coordinator",
            return_value=fake_coordinator,
        ),
        patch("deephole_client.updater.ensure_runtime_updated", new=AsyncMock()) as legacy_update,
    ):
        result = asyncio.run(
            agent_main._handle_command(
                {
                    "type": "task",
                    "runtime_update_only": True,
                    "agent_runtime_update": {"hash": "hash-v2"},
                },
                config,
                None,
                None,
            )
        )

    assert result is None
    legacy_update.assert_not_awaited()
    assert staged_calls == [({"hash": "hash-v2"}, "http://server.example")]
