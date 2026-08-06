from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from backend.api import agent as agent_api
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
    agent_api._registered_agents["live-agent"] = AgentInfo(
        agent_id="live-agent",
        agent_key="stable-agent",
        name="agent",
        machine_name="machine",
        ip="127.0.0.1",
        last_seen="2026-07-29T00:00:00+00:00",
        user_id="user-1",
        runtime_hash="old-runtime",
    )
    agent_api._agent_ws["live-agent"] = object()


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
    agent_api._registered_agents.clear()
    agent_api._agent_ws.clear()
    agent_api._agent_ws_locks.clear()
    agent_api._agent_opencode_pool_latest.clear()


def test_manual_runtime_update_request_is_persisted(tmp_path: Path) -> None:
    store, user = _store_with_agent(tmp_path)
    _connect_agent()
    request = SimpleNamespace(base_url="http://server.example/")
    try:
        with (
            patch("backend.api.agent.get_scan_store", return_value=store),
            patch("backend.api.agent._agent_runtime_hash", return_value="new-runtime"),
            patch("backend.api.agent._is_agent_online", return_value=True),
        ):
            result = asyncio.run(
                agent_api.request_stable_agent_runtime_update(
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
            patch("backend.api.agent.get_scan_store", return_value=store),
            patch("backend.api.agent._agent_has_active_work", return_value=True),
            patch("backend.api.agent.send_agent_command", new=send),
        ):
            asyncio.run(agent_api._process_agent_runtime_updates())

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
    agent_api._agent_opencode_pool_latest["live-agent"] = _stale_pool_status(
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
            patch("backend.api.agent.get_scan_store", return_value=store),
            patch("backend.api.agent._agent_runtime_hash", return_value="new-runtime"),
            patch(
                "backend.api.agent.create_agent_runtime_update_payload",
                return_value=payload,
            ),
            patch("backend.api.agent.send_agent_command", new=send),
        ):
            asyncio.run(agent_api._process_agent_runtime_updates())

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
        with patch("backend.api.agent.get_scan_store", return_value=store):
            assert asyncio.run(
                agent_api._agent_has_active_work("stable-agent", "live-agent")
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
            patch("backend.api.agent.get_scan_store", return_value=store),
            patch("backend.api.agent._agent_has_active_work", return_value=False),
            patch("backend.api.agent._agent_runtime_hash", return_value="new-runtime"),
            patch(
                "backend.api.agent.create_agent_runtime_update_payload",
                return_value=payload,
            ),
            patch("backend.api.agent.send_agent_command", new=send),
        ):
            asyncio.run(agent_api._process_agent_runtime_updates())

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
        with patch("backend.api.agent.get_scan_store", return_value=store):
            assert not agent_api.is_agent_accepting_tasks("stable-agent")
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
            patch("backend.api.agent.get_scan_store", return_value=store),
            patch(
                "backend.api.agent._agent_has_active_work",
                side_effect=[False, True],
            ),
            patch("backend.api.agent._agent_runtime_hash", return_value="new-runtime"),
            patch("backend.api.agent.send_agent_command", new=send),
        ):
            asyncio.run(agent_api._process_agent_runtime_updates())

        send.assert_not_awaited()
        assert (
            store.get_agent_record("stable-agent")["runtime_update_status"]
            == "pending"
        )
        with patch("backend.api.agent.get_scan_store", return_value=store):
            assert agent_api.is_agent_accepting_tasks("stable-agent")
    finally:
        _cleanup_agent_globals()
        store.close()


def test_manual_runtime_update_clears_when_target_agent_reconnects(
    tmp_path: Path,
) -> None:
    store, _user = _store_with_agent(tmp_path)
    _connect_agent()
    agent_api._registered_agents["live-agent"].runtime_hash = "new-runtime"
    store.set_agent_runtime_update_record(
        "stable-agent",
        status="updating",
        target_hash="new-runtime",
        server_url="http://server.example",
        requested_at="2026-07-29T00:00:00+00:00",
        started_at="2026-07-29T00:00:01+00:00",
    )
    try:
        with patch("backend.api.agent.get_scan_store", return_value=store):
            asyncio.run(agent_api._process_agent_runtime_updates())
        record = store.get_agent_record("stable-agent")
        assert record["runtime_update_status"] == ""
        assert record["runtime_update_target_hash"] == ""
        with patch("backend.api.agent.get_scan_store", return_value=store):
            assert agent_api.is_agent_accepting_tasks("stable-agent")
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
            patch("backend.api.agent.get_scan_store", return_value=store),
            patch(
                "backend.api.agent.create_agent_runtime_update_payload",
            ) as create_payload,
        ):
            payload = agent_api.create_agent_task_runtime_update_payload(
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
            patch("backend.api.agent.get_scan_store", return_value=store),
            patch(
                "backend.api.agent.create_agent_runtime_update_payload",
                return_value=expected,
            ) as create_payload,
        ):
            payload = agent_api.create_agent_task_runtime_update_payload(
                "http://server.example",
                "stable-agent",
            )

        assert payload == expected
        create_payload.assert_called_once_with("http://server.example")
    finally:
        store.close()
