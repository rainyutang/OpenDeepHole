from __future__ import annotations
from backend.application import get_runtime
import backend.agents.artifacts as backend_agents_artifacts
import backend.agents.runtime_updates as backend_agents_runtime_updates
import backend.api.agent_routes.runtime_updates as backend_api_agent_routes_runtime_updates
import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from backend.models import (
    AgentInfo,
    OpenCodePoolModelStats,
    OpenCodePoolStatus,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    User,
)
from backend.store.sqlite import SqliteScanStore


def _store_with_agent(tmp_path: Path) -> tuple[SqliteScanStore, User]:
    store = SqliteScanStore(tmp_path / "scans.db")
    user = User(
        user_id="user-1",
        username="owner",
        role="user",
    )
    store.create_user(user.user_id, user.username, "hash", user.role, "token")
    store.upsert_agent_record(
        agent_key="stable-agent",
        user_id=user.user_id,
        ip="127.0.0.1",
        machine_name="machine",
        display_name="agent",
        agent_id="live-agent",
        last_seen="2026-07-29T00:00:00+00:00",
    )
    return store, user


def _connect_agent() -> None:
    get_runtime().agents.registered_agents["live-agent"] = AgentInfo(
        agent_id="live-agent",
        agent_key="stable-agent",
        name="agent",
        machine_name="machine",
        ip="127.0.0.1",
        last_seen="2026-07-29T00:00:00+00:00",
        user_id="user-1",
        runtime_hash="old-runtime",
    )
    get_runtime().agents.agent_ws["live-agent"] = object()


def _save_agent_scan(
    store: SqliteScanStore,
    scan_id: str,
    status: ScanItemStatus,
    *,
    agent_key: str = "stable-agent",
) -> None:
    store.save_scan(
        ScanStatus(
            scan_id=scan_id,
            project_id="project-1",
            status=status,
            progress=0.0,
            total_candidates=0,
            processed_candidates=0,
            vulnerabilities=[],
        ),
        ScanMeta(
            scan_items=[],
            created_at="2026-07-29T00:00:00+00:00",
            agent_id="live-agent",
            agent_key=agent_key,
            user_id="user-1",
        ),
    )


def _stale_pool_status(scan_id: str) -> OpenCodePoolStatus:
    return OpenCodePoolStatus(
        global_running=1,
        global_queued=1,
        queued_tasks=[
            {
                "task_id": "task-queued",
                "scope_id": scan_id,
            }
        ],
        models=[
            OpenCodePoolModelStats(
                id="model-1",
                running=1,
                active_tasks=[
                    {
                        "task_id": "task-1",
                        "scope_id": scan_id,
                    }
                ],
            )
        ],
    )


def _cleanup_agent_globals() -> None:
    get_runtime().agents.registered_agents.clear()
    get_runtime().agents.agent_ws.clear()
    get_runtime().agents.agent_ws_locks.clear()
    get_runtime().agents.agent_opencode_pool_latest.clear()
    get_runtime().agents.legacy_runtime_update_attempts.clear()
    get_runtime().agents.legacy_stop_settle_until.clear()


def test_manual_runtime_update_request_is_persisted(tmp_path: Path) -> None:
    store, user = _store_with_agent(tmp_path)
    _connect_agent()
    request = SimpleNamespace(base_url="http://server.example/")
    try:
        with (
            patch("backend.application.default_store_factory", return_value=store),
            patch("backend.agents.artifacts._agent_runtime_hash", return_value="new-runtime"),
            patch("backend.agents.directory._is_agent_online", return_value=True),
        ):
            result = asyncio.run(
                backend_api_agent_routes_runtime_updates.request_stable_agent_runtime_update(
                    "stable-agent",
                    request,
                    user,
                )
            )

        assert result["status"] == "pending"
        record = store.get_agent_record("stable-agent")
        assert record is not None
        assert record["runtime_update_status"] == "pending"
        assert record["runtime_update_target_hash"] == "new-runtime"
        assert record["runtime_update_server_url"] == "http://server.example"
    finally:
        _cleanup_agent_globals()
        store.close()


def test_manual_runtime_update_waits_while_agent_has_active_work(
    tmp_path: Path,
) -> None:
    store, _user = _store_with_agent(tmp_path)
    _connect_agent()
    store.set_agent_runtime_update_record(
        "stable-agent",
        status="pending",
        target_hash="new-runtime",
        server_url="http://server.example",
        requested_at="2026-07-29T00:00:00+00:00",
    )
    send = AsyncMock(return_value=True)
    try:
        with (
            patch("backend.application.default_store_factory", return_value=store),
            patch("backend.agents.runtime_updates._agent_has_active_work", return_value=True),
            patch("backend.agents.gateway.send_agent_command", new=send),
        ):
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())

        send.assert_not_awaited()
        assert (
            store.get_agent_record("stable-agent")["runtime_update_status"]
            == "pending"
        )
    finally:
        _cleanup_agent_globals()
        store.close()


def test_manual_runtime_update_ignores_stale_pool_after_scan_stops(
    tmp_path: Path,
) -> None:
    store, _user = _store_with_agent(tmp_path)
    _connect_agent()
    _save_agent_scan(store, "stopped-scan", ScanItemStatus.CANCELLED)
    get_runtime().agents.agent_opencode_pool_latest["live-agent"] = _stale_pool_status(
        "stopped-scan"
    )
    store.set_agent_runtime_update_record(
        "stable-agent",
        status="pending",
        target_hash="new-runtime",
        server_url="http://server.example",
        requested_at="2026-07-29T00:00:00+00:00",
    )
    send = AsyncMock(return_value=True)
    payload = {"hash": "new-runtime", "token": "one-time"}
    try:
        with (
            patch("backend.application.default_store_factory", return_value=store),
            patch("backend.agents.artifacts._agent_runtime_hash", return_value="new-runtime"),
            patch(
                "backend.agents.artifacts.create_agent_runtime_update_payload",
                return_value=payload,
            ),
            patch("backend.agents.gateway.send_agent_command", new=send),
        ):
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())

        send.assert_awaited_once_with(
            "live-agent",
            {
                "type": "task",
                "runtime_update_only": True,
                "agent_runtime_update": payload,
            },
        )
        assert (
            store.get_agent_record("stable-agent")["runtime_update_status"]
            == "updating"
        )
    finally:
        _cleanup_agent_globals()
        store.close()


def test_manual_runtime_update_still_waits_for_durable_active_scan(
    tmp_path: Path,
) -> None:
    store, _user = _store_with_agent(tmp_path)
    _connect_agent()
    _save_agent_scan(
        store,
        "active-scan",
        ScanItemStatus.AUDITING,
        agent_key="",
    )
    try:
        with patch("backend.application.default_store_factory", return_value=store):
            assert asyncio.run(
                backend_agents_runtime_updates._agent_has_active_work("stable-agent", "live-agent")
            )
    finally:
        _cleanup_agent_globals()
        store.close()


def test_manual_runtime_update_dispatches_only_after_idle_recheck(
    tmp_path: Path,
) -> None:
    store, _user = _store_with_agent(tmp_path)
    _connect_agent()
    store.set_agent_runtime_update_record(
        "stable-agent",
        status="pending",
        target_hash="old-target",
        server_url="http://server.example",
        requested_at="2026-07-29T00:00:00+00:00",
    )
    send = AsyncMock(return_value=True)
    payload = {"hash": "new-runtime", "token": "one-time"}
    try:
        with (
            patch("backend.application.default_store_factory", return_value=store),
            patch("backend.agents.runtime_updates._agent_has_active_work", return_value=False),
            patch("backend.agents.artifacts._agent_runtime_hash", return_value="new-runtime"),
            patch(
                "backend.agents.artifacts.create_agent_runtime_update_payload",
                return_value=payload,
            ),
            patch("backend.agents.gateway.send_agent_command", new=send),
        ):
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())

        send.assert_awaited_once_with(
            "live-agent",
            {
                "type": "task",
                "runtime_update_only": True,
                "agent_runtime_update": payload,
            },
        )
        record = store.get_agent_record("stable-agent")
        assert record["runtime_update_status"] == "updating"
        assert record["runtime_update_target_hash"] == "new-runtime"
        with patch("backend.application.default_store_factory", return_value=store):
            assert not backend_agents_runtime_updates.is_agent_accepting_tasks("stable-agent")
    finally:
        _cleanup_agent_globals()
        store.close()


def test_manual_runtime_update_returns_to_pending_if_new_work_wins_race(
    tmp_path: Path,
) -> None:
    store, _user = _store_with_agent(tmp_path)
    _connect_agent()
    store.set_agent_runtime_update_record(
        "stable-agent",
        status="pending",
        target_hash="new-runtime",
        server_url="http://server.example",
        requested_at="2026-07-29T00:00:00+00:00",
    )
    send = AsyncMock(return_value=True)
    try:
        with (
            patch("backend.application.default_store_factory", return_value=store),
            patch(
                "backend.agents.runtime_updates._agent_has_active_work",
                side_effect=[False, True],
            ),
            patch("backend.agents.artifacts._agent_runtime_hash", return_value="new-runtime"),
            patch("backend.agents.gateway.send_agent_command", new=send),
        ):
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())

        send.assert_not_awaited()
        assert (
            store.get_agent_record("stable-agent")["runtime_update_status"]
            == "pending"
        )
        with patch("backend.application.default_store_factory", return_value=store):
            assert backend_agents_runtime_updates.is_agent_accepting_tasks("stable-agent")
    finally:
        _cleanup_agent_globals()
        store.close()


def test_manual_runtime_update_clears_when_target_agent_reconnects(
    tmp_path: Path,
) -> None:
    store, _user = _store_with_agent(tmp_path)
    _connect_agent()
    get_runtime().agents.registered_agents["live-agent"].runtime_hash = "new-runtime"
    store.set_agent_runtime_update_record(
        "stable-agent",
        status="updating",
        target_hash="new-runtime",
        server_url="http://server.example",
        requested_at="2026-07-29T00:00:00+00:00",
        started_at="2026-07-29T00:00:01+00:00",
    )
    try:
        with patch("backend.application.default_store_factory", return_value=store):
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())
        record = store.get_agent_record("stable-agent")
        assert record["runtime_update_status"] == ""
        assert record["runtime_update_target_hash"] == ""
        with patch("backend.application.default_store_factory", return_value=store):
            assert backend_agents_runtime_updates.is_agent_accepting_tasks("stable-agent")
    finally:
        _cleanup_agent_globals()
        store.close()


def test_ordinary_task_does_not_bypass_pending_idle_update(
    tmp_path: Path,
) -> None:
    store, _user = _store_with_agent(tmp_path)
    store.set_agent_runtime_update_record(
        "stable-agent",
        status="pending",
        target_hash="new-runtime",
        server_url="http://server.example",
        requested_at="2026-07-29T00:00:00+00:00",
    )
    try:
        with (
            patch("backend.application.default_store_factory", return_value=store),
            patch(
                "backend.agents.artifacts.create_agent_runtime_update_payload",
            ) as create_payload,
        ):
            payload = backend_agents_artifacts.create_agent_task_runtime_update_payload(
                "http://server.example",
                "stable-agent",
            )

        assert payload is None
        create_payload.assert_not_called()
    finally:
        store.close()


def test_ordinary_task_keeps_automatic_runtime_sync_without_manual_request(
    tmp_path: Path,
) -> None:
    store, _user = _store_with_agent(tmp_path)
    expected = {"runtime_hash": "new-runtime"}
    try:
        with (
            patch("backend.application.default_store_factory", return_value=store),
            patch(
                "backend.agents.artifacts.create_agent_runtime_update_payload",
                return_value=expected,
            ) as create_payload,
        ):
            payload = backend_agents_artifacts.create_agent_task_runtime_update_payload(
                "http://server.example",
                "stable-agent",
            )

        assert payload == expected
        create_payload.assert_called_once_with("http://server.example")
    finally:
        store.close()


def test_legacy_updating_agent_redispatches_after_unconsumed_deferral(
    tmp_path: Path,
) -> None:
    store, _user = _store_with_agent(tmp_path)
    _connect_agent()
    get_runtime().agents.registered_agents["live-agent"].agent_session_id = "sess-1"
    store.set_agent_runtime_update_record(
        "stable-agent",
        status="pending",
        target_hash="new-runtime",
        server_url="http://server.example",
        requested_at="2026-11-24T00:00:00+00:00",
    )
    send = AsyncMock(return_value=True)
    payloads = [
        {"hash": "new-runtime", "token": "tok-1"},
        {"hash": "new-runtime", "token": "tok-2"},
        {"hash": "new-runtime", "token": "tok-3"},
    ]
    clock = [100.0]
    try:
        with (
            patch("backend.application.default_store_factory", return_value=store),
            patch("backend.agents.artifacts._agent_runtime_hash", return_value="new-runtime"),
            patch(
                "backend.agents.artifacts.create_agent_runtime_update_payload",
                side_effect=payloads,
            ),
            patch("backend.agents.gateway.send_agent_command", new=send),
            patch("backend.agents.runtime_updates.time.monotonic", side_effect=lambda: clock[0]),
        ):
            # Initial idle dispatch moves status to updating and syncs live state.
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())
            assert send.await_count == 1
            live_agent = get_runtime().agents.registered_agents["live-agent"]
            assert live_agent.runtime_update_status == "updating"
            assert live_agent.accepting_tasks is False

            # Before 4s backoff expires, no duplicate send occurs.
            clock[0] = 102.0
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())
            assert send.await_count == 1

            # After 4s with token still unconsumed (Agent deferred due to local_work_active),
            # backend re-dispatches with a fresh token.
            clock[0] = 104.5
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())
            assert send.await_count == 2
            assert send.await_args_list[1].args[1]["agent_runtime_update"]["token"] == "tok-2"

            # Second retry backs off to 8s.
            clock[0] = 110.0
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())
            assert send.await_count == 2

            clock[0] = 113.0
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())
            assert send.await_count == 3
            assert send.await_args_list[2].args[1]["agent_runtime_update"]["token"] == "tok-3"
    finally:
        _cleanup_agent_globals()
        store.close()


def test_legacy_updating_agent_pauses_retries_after_download_and_fails_if_restart_never_happens(
    tmp_path: Path,
) -> None:
    store, _user = _store_with_agent(tmp_path)
    _connect_agent()
    get_runtime().agents.registered_agents["live-agent"].agent_session_id = "sess-1"
    store.set_agent_runtime_update_record(
        "stable-agent",
        status="pending",
        target_hash="new-runtime",
        server_url="http://server.example",
        requested_at="2026-11-24T00:00:00+00:00",
    )
    send = AsyncMock(return_value=True)
    payloads = [
        {"hash": "new-runtime", "token": "tok-1"},
        {"hash": "new-runtime", "token": "tok-2"},
    ]
    clock = [200.0]
    try:
        with (
            patch("backend.application.default_store_factory", return_value=store),
            patch("backend.agents.artifacts._agent_runtime_hash", return_value="new-runtime"),
            patch(
                "backend.agents.artifacts.create_agent_runtime_update_payload",
                side_effect=payloads,
            ),
            patch("backend.agents.gateway.send_agent_command", new=send),
            patch("backend.agents.runtime_updates.time.monotonic", side_effect=lambda: clock[0]),
        ):
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())
            assert send.await_count == 1

            # Legacy Agent downloads the archive; retries pause for 180s to allow pip install.
            clock[0] = 201.0
            backend_agents_runtime_updates.record_runtime_update_download_consumed("tok-1")
            clock[0] = 260.0
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())
            assert send.await_count == 1

            # After 180s still on the same old session, backend performs one post-download retry.
            clock[0] = 382.0
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())
            assert send.await_count == 2

            # After another 180s still stuck on the same session, mark failed instead of hanging 15m.
            clock[0] = 563.0
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())
            assert send.await_count == 2
            record = store.get_agent_record("stable-agent")
            assert record["runtime_update_status"] == "failed"
            assert "未完成重启" in record["runtime_update_error"]
            assert get_runtime().agents.registered_agents["live-agent"].accepting_tasks is True
    finally:
        _cleanup_agent_globals()
        store.close()


def test_legacy_updating_agent_handles_new_session_reconnect_with_or_without_download(
    tmp_path: Path,
) -> None:
    store, _user = _store_with_agent(tmp_path)
    _connect_agent()
    get_runtime().agents.registered_agents["live-agent"].agent_session_id = "sess-old"
    store.set_agent_runtime_update_record(
        "stable-agent",
        status="pending",
        target_hash="new-runtime",
        server_url="http://server.example",
        requested_at="2026-11-24T00:00:00+00:00",
    )
    send = AsyncMock(return_value=True)
    payloads = [
        {"hash": "new-runtime", "token": "tok-1"},
        {"hash": "new-runtime", "token": "tok-2"},
    ]
    clock = [300.0]
    try:
        with (
            patch("backend.application.default_store_factory", return_value=store),
            patch("backend.agents.artifacts._agent_runtime_hash", return_value="new-runtime"),
            patch(
                "backend.agents.artifacts.create_agent_runtime_update_payload",
                side_effect=payloads,
            ),
            patch("backend.agents.gateway.send_agent_command", new=send),
            patch("backend.agents.runtime_updates.time.monotonic", side_effect=lambda: clock[0]),
        ):
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())
            assert send.await_count == 1

            # Case 1: User restarted the legacy Agent before any download happened ->
            # backend immediately re-dispatches without waiting for backoff.
            get_runtime().agents.registered_agents["live-agent"].agent_session_id = "sess-restarted-1"
            clock[0] = 301.0
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())
            assert send.await_count == 2

            # Case 2: Agent downloaded tok-2, restarted into sess-restarted-2, still reports old hash ->
            # backend marks failed immediately to avoid restart loops.
            backend_agents_runtime_updates.record_runtime_update_download_consumed("tok-2")
            get_runtime().agents.registered_agents["live-agent"].agent_session_id = "sess-restarted-2"
            clock[0] = 302.0
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())
            assert send.await_count == 2
            record = store.get_agent_record("stable-agent")
            assert record["runtime_update_status"] == "failed"
            assert "运行版本仍未变为目标版本" in record["runtime_update_error"]
    finally:
        _cleanup_agent_globals()
        store.close()


def test_legacy_pending_update_waits_for_post_stop_settle_window(
    tmp_path: Path,
) -> None:
    store, _user = _store_with_agent(tmp_path)
    _connect_agent()
    store.set_agent_runtime_update_record(
        "stable-agent",
        status="pending",
        target_hash="new-runtime",
        server_url="http://server.example",
        requested_at="2026-11-24T00:00:00+00:00",
    )
    send = AsyncMock(return_value=True)
    payload = {"hash": "new-runtime", "token": "tok-settle"}
    clock = [500.0]
    try:
        with (
            patch("backend.application.default_store_factory", return_value=store),
            patch("backend.agents.artifacts._agent_runtime_hash", return_value="new-runtime"),
            patch(
                "backend.agents.artifacts.create_agent_runtime_update_payload",
                return_value=payload,
            ),
            patch("backend.agents.gateway.send_agent_command", new=send),
            patch("backend.agents.runtime_updates.time.monotonic", side_effect=lambda: clock[0]),
        ):
            backend_agents_runtime_updates.note_agent_stop_dispatched(
                "stable-agent",
                settle_seconds=3.0,
            )
            clock[0] = 501.5
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())
            send.assert_not_awaited()
            assert store.get_agent_record("stable-agent")["runtime_update_status"] == "pending"

            clock[0] = 503.5
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())
            send.assert_awaited_once()
            assert store.get_agent_record("stable-agent")["runtime_update_status"] == "updating"
    finally:
        _cleanup_agent_globals()
        store.close()


def test_stop_scan_with_fp_review_arms_settle_and_download_tracks_token_consumption(
    tmp_path: Path,
) -> None:
    import backend.scans.lifecycle as scan_lifecycle

    store, user = _store_with_agent(tmp_path)
    _connect_agent()
    get_runtime().agents.registered_agents["live-agent"].agent_session_id = "sess-legacy"
    _save_agent_scan(store, "scan-with-fp", ScanItemStatus.AUDITING)
    store.create_fp_review_job(
        "review-1",
        "scan-with-fp",
        2,
        "2026-11-24T00:00:00+00:00",
        method="adversarial",
    )
    store.set_agent_runtime_update_record(
        "stable-agent",
        status="pending",
        target_hash="new-runtime",
        server_url="http://server.example",
        requested_at="2026-11-24T00:00:00+00:00",
    )

    sent_commands: list[tuple[str, dict]] = []

    async def fake_send(agent_id: str, command: dict) -> bool:
        sent_commands.append((agent_id, command))
        return True

    clock = [700.0]
    try:
        with (
            patch("backend.application.default_store_factory", return_value=store),
            patch(
                "backend.agents.gateway.request_agent_scan_stop",
                new=AsyncMock(return_value={"found": True, "still_active": False, "error": ""}),
            ),
            patch("backend.agents.gateway.send_agent_command", new=fake_send),
            patch(
                "backend.agents.artifacts._read_agent_runtime_files",
                return_value=[("deephole_client/main.py", b"print('v2')\n")],
            ),
            patch("backend.agents.runtime_updates.time.monotonic", side_effect=lambda: clock[0]),
        ):
            stop_result = asyncio.run(scan_lifecycle.stop_scan("scan-with-fp", user))
            assert stop_result["fp_review_ids"] == ["review-1"]
            assert any(cmd["type"] == "fp_review_stop" for _, cmd in sent_commands)

            # Right after stop_scan sent fire-and-forget fp_review_stop, legacy update waits in pending.
            clock[0] = 701.0
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())
            assert not any(cmd.get("runtime_update_only") for _, cmd in sent_commands)
            assert store.get_agent_record("stable-agent")["runtime_update_status"] == "pending"

            # After the 3s settle window, legacy update dispatches with a real download token.
            clock[0] = 703.5
            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())
            update_cmds = [cmd for _, cmd in sent_commands if cmd.get("runtime_update_only")]
            assert len(update_cmds) == 1
            token = update_cmds[0]["agent_runtime_update"]["token"]

            # Consuming the archive through agent_runtime_download marks downloaded_at.
            clock[0] = 704.0
            response = asyncio.run(backend_agents_artifacts.agent_runtime_download(token))
            assert response.media_type == "application/zip"
            attempt = get_runtime().agents.legacy_runtime_update_attempts["stable-agent"]
            assert attempt.downloaded_at == 704.0
            assert attempt.download_count == 1
    finally:
        get_runtime().agents.runtime_download_tokens.clear()
        _cleanup_agent_globals()
        store.close()


def test_stop_scan_confirmed_without_fp_review_clears_settle_immediately(
    tmp_path: Path,
) -> None:
    import backend.scans.lifecycle as scan_lifecycle

    store, user = _store_with_agent(tmp_path)
    _connect_agent()
    _save_agent_scan(store, "scan-no-fp", ScanItemStatus.AUDITING)
    store.set_agent_runtime_update_record(
        "stable-agent",
        status="pending",
        target_hash="new-runtime",
        server_url="http://server.example",
        requested_at="2026-11-24T00:00:00+00:00",
    )
    send = AsyncMock(return_value=True)
    payload = {"hash": "new-runtime", "token": "tok-immediate"}
    try:
        with (
            patch("backend.application.default_store_factory", return_value=store),
            patch(
                "backend.agents.gateway.request_agent_scan_stop",
                new=AsyncMock(return_value={"found": True, "still_active": False, "error": ""}),
            ),
            patch("backend.agents.artifacts._agent_runtime_hash", return_value="new-runtime"),
            patch(
                "backend.agents.artifacts.create_agent_runtime_update_payload",
                return_value=payload,
            ),
            patch("backend.agents.gateway.send_agent_command", new=send),
        ):
            stop_result = asyncio.run(scan_lifecycle.stop_scan("scan-no-fp", user))
            assert stop_result["agent_stop_state"] == "confirmed"
            assert stop_result["fp_review_ids"] == []
            assert "stable-agent" not in get_runtime().agents.legacy_stop_settle_until

            asyncio.run(backend_agents_runtime_updates._process_agent_runtime_updates())
            send.assert_awaited_once()
            assert store.get_agent_record("stable-agent")["runtime_update_status"] == "updating"
    finally:
        _cleanup_agent_globals()
        store.close()
