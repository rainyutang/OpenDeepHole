from __future__ import annotations

import asyncio
import json
import threading
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

import deephole_client.main as agent_main
import deephole_client.server as agent_server
import deephole_client.updater as updater
from deephole_client.scanner import (
    _event_candidate_index,
    _event_progress_counts,
)
from deephole_client.vulnerability_mining.engines.multi_version import engine


async def _wait_until(predicate) -> None:
    async def poll() -> None:
        while not predicate():
            await asyncio.sleep(0.005)

    await asyncio.wait_for(poll(), timeout=3)


def _versions_with_candidates():
    return [[{"version_name": "v1"}], [{"version_name": "v2"}]]


def test_async_grouping_preserves_greedy_order_threshold_and_first_ties(monkeypatch):
    candidates = [
        [{"id": "a"}, {"id": "b"}],
        [{"id": "first"}, {"id": "tie"}, {"id": "below"}],
        [{"id": "third"}],
    ]
    scores = {
        ("a", "first"): 0.74,
        ("a", "tie"): 0.74,
        ("b", "first"): 1.0,
        ("b", "below"): 0.739,
        ("b", "third"): 0.9,
    }
    monkeypatch.setattr(
        engine, "_candidate_similarity",
        lambda left, right: scores.get((left["id"], right["id"]), 0.0),
    )

    groups = asyncio.run(engine._group_candidates_async(candidates))

    assert groups == engine._group_candidates(candidates)
    assert [[item["id"] for item in group] for group in groups] == [
        ["a", "first"], ["b", "third"], ["tie"], ["below"],
    ]
    assert groups[0][0] is candidates[0][0]


def test_empty_grouping_reports_start_and_completion():
    events = []

    assert asyncio.run(engine._group_candidates_async([[], []], output=events.append)) == []

    assert [event["kind"] for event in events] == [
        "candidate_dedup_start", "candidate_dedup_complete",
    ]
    assert events[-1]["data"]["dedup_processed"] == 0
    assert events[-1]["data"]["dedup_total"] == 0
    assert events[-1]["data"]["group_count"] == 0
    assert events[-1]["data"]["comparison_count"] == 0


def test_precancelled_grouping_does_not_start_comparisons(monkeypatch):
    cancel_event = threading.Event()
    cancel_event.set()
    compare = MagicMock()
    monkeypatch.setattr(engine, "_candidate_similarity", compare)
    events = []

    assert asyncio.run(engine._group_candidates_async(
        _versions_with_candidates(), output=events.append, cancel_event=cancel_event,
    )) is None

    compare.assert_not_called()
    assert [event["kind"] for event in events] == [
        "candidate_dedup_start", "candidate_dedup_cancelled",
    ]


def test_stalled_comparison_reports_progress_without_audit_counts(monkeypatch):
    release = threading.Event()
    comparing = threading.Event()
    worker_threads = []

    def compare(*_args):
        worker_threads.append(threading.current_thread())
        comparing.set()
        assert release.wait(timeout=3)
        return 0.8

    monkeypatch.setattr(engine, "_candidate_similarity", compare)
    monkeypatch.setattr(engine, "_DEDUP_PROGRESS_SECONDS", 0.01)
    monkeypatch.setattr(engine, "_DEDUP_POLL_SECONDS", 0.005)
    events = []

    async def scenario():
        loop_thread = threading.get_ident()

        async def output(event):
            assert threading.get_ident() == loop_thread
            assert _event_progress_counts(event) is None
            assert _event_candidate_index(event) is None
            events.append(event)

        task = asyncio.create_task(engine._group_candidates_async(
            _versions_with_candidates(), output=output,
        ))
        try:
            await _wait_until(lambda: sum(
                event["kind"] == "candidate_dedup_progress" for event in events
            ) >= 2)
            assert comparing.is_set()
            assert not task.done()
            progress = [event for event in events if event["kind"] == "candidate_dedup_progress"]
            assert all(event["data"]["dedup_processed"] == 0 for event in progress)
            assert progress[-1]["data"]["elapsed_seconds"] > progress[0]["data"]["elapsed_seconds"]
        finally:
            release.set()
            await asyncio.wait_for(task, timeout=3)

    asyncio.run(scenario())

    assert worker_threads[0] is not threading.current_thread()
    assert worker_threads[0].daemon
    data = events[-1]["data"]
    assert events[-1]["kind"] == "candidate_dedup_complete"
    assert data["dedup_processed"] == data["dedup_total"] == 2
    assert data["group_count"] == data["comparison_count"] == 1


@pytest.mark.parametrize("cancel_method", ["event", "task"])
def test_cancellation_stops_worker_and_suppresses_late_results(monkeypatch, cancel_method):
    release = threading.Event()
    comparing = threading.Event()
    cancel_event = threading.Event()
    worker_threads = []
    calls = []
    events = []

    def compare(*args):
        calls.append(args)
        worker_threads.append(threading.current_thread())
        comparing.set()
        assert release.wait(timeout=3)
        return 0.8

    monkeypatch.setattr(engine, "_candidate_similarity", compare)
    monkeypatch.setattr(engine, "_DEDUP_POLL_SECONDS", 0.005)

    async def scenario():
        task = asyncio.create_task(engine._group_candidates_async(
            [[{"id": "a"}], [{"id": "b"}, {"id": "c"}]],
            output=events.append, cancel_event=cancel_event,
        ))
        try:
            await _wait_until(comparing.is_set)
            if cancel_method == "event":
                cancel_event.set()
                assert await asyncio.wait_for(task, timeout=1) is None
            else:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(task, timeout=1)
            assert worker_threads[0].is_alive()
            assert [event["kind"] for event in events] == [
                "candidate_dedup_start", "candidate_dedup_cancelled",
            ]
            count_after_cancel = len(events)
        finally:
            release.set()
            if not task.done():
                await asyncio.wait_for(task, timeout=3)
            await _wait_until(lambda: not worker_threads or not worker_threads[0].is_alive())
        assert len(events) == count_after_cancel
        assert len(calls) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("outcome", ["cancelled", "error"])
def test_engine_never_audits_partial_groups(monkeypatch, tmp_path, outcome):
    versions = []
    for name in ("v1", "v2"):
        project = tmp_path / name
        project.mkdir()
        versions.append({"version_name": name, "project_path": str(project)})
    cancel_event = threading.Event()
    events = []
    comparisons = 0

    def compare(*_args):
        nonlocal comparisons
        comparisons += 1
        if comparisons < 3:
            return 0.8
        if outcome == "cancelled":
            cancel_event.set()
            return 0.8
        raise ValueError("comparison failed")

    monkeypatch.setattr(engine, "_candidate_similarity", compare)
    monkeypatch.setattr(engine, "_scan_versions", AsyncMock(return_value=(
        "success", [[{"id": "a"}, {"id": "b"}], [{"id": "c"}, {"id": "d"}]],
    )))
    monkeypatch.setattr(engine, "_audit_threats", AsyncMock(return_value=0))
    audit = AsyncMock(return_value=(1, 0))
    monkeypatch.setattr(engine, "_audit_static_groups", audit)
    kwargs = dict(
        multi_versions=versions,
        work_dir=tmp_path / "work",
        scan_id="scan-dedup-stop",
        checker_names=["oob"],
        checker_packages=[],
        config=SimpleNamespace(opencode_concurrency=1),
        output=events.append,
        cancel_event=cancel_event,
    )

    if outcome == "cancelled":
        result = asyncio.run(engine.run(**kwargs))
        assert result["status"] == "cancelled"
        assert result["processed_candidates"] == 0
    else:
        with pytest.raises(ValueError, match="comparison failed"):
            asyncio.run(engine.run(**kwargs))
        assert "comparison failed" in events[-1]["message"]
        assert events[-1]["data"]["dedup_processed"] == 2
        assert events[-1]["data"]["group_count"] == 1

    audit.assert_not_awaited()
    assert events[-1]["kind"] == f"candidate_dedup_{outcome}"
    assert not any(event["kind"] == "candidate_dedup_complete" for event in events)


def test_real_agent_heartbeat_loop_sends_and_receives_during_cpu_comparison(monkeypatch):
    comparing = threading.Event()

    def compare(*_args):
        comparing.set()
        try:
            # Span the real watchdog's one-second minimum polling interval.
            deadline = time.monotonic() + 1.25
            while time.monotonic() < deadline:
                pass
            return 0.8
        finally:
            comparing.clear()

    monkeypatch.setattr(engine, "_candidate_similarity", compare)
    monkeypatch.setattr(agent_main, "_env_int", lambda key, default: {
        "OPENDEEPHOLE_AGENT_HEARTBEAT_INTERVAL": 0.02,
        "OPENDEEPHOLE_AGENT_WATCHDOG_TIMEOUT": 0.3,
    }.get(key, default))
    monkeypatch.setattr("deephole_client.config.remote_config_dict", lambda _config: {})
    monkeypatch.setattr(
        "deephole_client.vulnerability_validation.run_vulnerability_validation",
        AsyncMock(return_value={"catalog": []}),
    )
    for name in (
        "pending_scan_snapshots", "pending_fp_review_snapshots",
        "pending_validation_snapshots", "load_pending_commands",
    ):
        monkeypatch.setattr(updater, name, lambda **_kwargs: [])
    monkeypatch.setattr(updater, "compute_runtime_hash", lambda: "test-runtime")
    monkeypatch.setattr(agent_server, "active_fp_review_snapshots", lambda: [])
    monkeypatch.setattr(agent_server, "active_validation_snapshots", lambda: [])
    monkeypatch.setattr(agent_server, "_agent_id", None)
    command_handler = AsyncMock()
    monkeypatch.setattr(agent_main, "_handle_command", command_handler)

    async def scenario():
        ready = asyncio.Event()

        class WebSocket:
            def __init__(self):
                self.incoming = asyncio.Queue()
                self.heartbeats_during_comparison = 0
                self.acks_during_comparison = 0
                self.close_calls = []

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            async def recv(self):
                return json.dumps({"type": "welcome", "agent_id": "agent-dedup"})

            async def send(self, raw):
                if json.loads(raw)["type"] == "heartbeat":
                    if comparing.is_set():
                        self.heartbeats_during_comparison += 1
                    await self.incoming.put(json.dumps({"type": "heartbeat_ack"}))

            def __aiter__(self):
                ready.set()
                return self

            async def __anext__(self):
                raw = await self.incoming.get()
                if comparing.is_set():
                    self.acks_during_comparison += 1
                return raw

            async def close(self, **kwargs):
                self.close_calls.append(kwargs)

        websocket = WebSocket()
        connect = MagicMock(return_value=websocket)
        monkeypatch.setattr("websockets.connect", connect)
        reporter = MagicMock(agent_session_id="session-dedup")
        reporter.pending_terminal_work.return_value = []

        async def publish_pool(stop):
            await stop.wait()

        reporter.publish_agent_opencode_pool_until = publish_pool
        task_manager = SimpleNamespace(active_snapshots=lambda: [])
        config = SimpleNamespace(
            agent_name="agent-dedup", server_url="http://example.test", owner_token="",
        )
        ws_task = asyncio.create_task(agent_main._ws_loop(config, task_manager, reporter))
        try:
            await asyncio.wait_for(ready.wait(), timeout=3)
            groups = await asyncio.wait_for(engine._group_candidates_async(
                _versions_with_candidates(),
            ), timeout=3)
            assert len(groups) == 1
            assert websocket.heartbeats_during_comparison >= 3
            assert websocket.acks_during_comparison >= 3
            assert websocket.close_calls == []
            connect.assert_called_once()
            command_handler.assert_not_awaited()
        finally:
            ws_task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await ws_task

    asyncio.run(scenario())
