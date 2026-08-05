import asyncio
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from backend.api import agent as agent_api
from backend.api import scan as scan_api
from backend.models import (
    AgentFpReviewStageOutput,
    AgentInfo,
    AgentMcpConfig,
    AgentMcpRemoteConfig,
    AgentScanCandidates,
    AgentScanFinish,
    Candidate,
    FpReviewStatus,
    MiningEngineSelection,
    OpenCodePoolStatus,
    ScanCandidate,
    ScanEvent,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    ThreatAuditTask,
    User,
    Vulnerability,
)
from backend.store.sqlite import SqliteScanStore


def _scan(
    scan_id: str,
    status: ScanItemStatus,
    *,
    total: int = 0,
    processed: int = 0,
    error: str | None = None,
) -> ScanStatus:
    return ScanStatus(
        scan_id=scan_id,
        project_id="project",
        scan_items=["memleak"],
        created_at="2026-01-01T00:00:00+00:00",
        status=status,
        progress=(processed / total) if total else 0.0,
        total_candidates=total,
        processed_candidates=processed,
        vulnerabilities=[],
        error_message=error,
    )


def _meta(
    *,
    agent_id: str = "agent-old",
    agent_name: str = "agent-1",
    user_id: str = "user-1",
) -> ScanMeta:
    return ScanMeta(
        scan_items=["memleak"],
        created_at="2026-01-01T00:00:00+00:00",
        agent_id=agent_id,
        agent_name=agent_name,
        project_path="/repo/project",
        scan_name="project",
        user_id=user_id,
    )


async def _run_websocket_and_cancel_disconnect(websocket) -> None:
    await agent_api.agent_websocket(websocket)
    tasks = list(agent_api._agent_disconnect_tasks.values())
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def _direct_store_call(store, operation, *args, **kwargs):
    function = getattr(store, operation) if isinstance(operation, str) else operation
    return function(*args, **kwargs)


class AgentReconnectRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        agent_api._running_scans.clear()
        agent_api._scan_owners.clear()
        agent_api._registered_agents.clear()
        agent_api._agent_ws.clear()
        agent_api._agent_ws_locks.clear()
        agent_api._agent_disconnect_tasks.clear()
        agent_api._scan_index_statuses.clear()

    def tearDown(self) -> None:
        agent_api._running_scans.clear()
        agent_api._scan_owners.clear()
        agent_api._registered_agents.clear()
        agent_api._agent_ws.clear()
        agent_api._agent_ws_locks.clear()
        agent_api._agent_disconnect_tasks.clear()
        agent_api._scan_index_statuses.clear()

    def test_agent_websocket_heartbeat_gets_ack(self) -> None:
        class FakeClient:
            host = "127.0.0.1"

        class FakeWebSocket:
            client = FakeClient()

            def __init__(self) -> None:
                self.sent: list[dict] = []
                self.messages = [
                    {"type": "hello", "name": "agent-1", "active_scans": []},
                    {"type": "heartbeat"},
                ]

            async def accept(self) -> None:
                return None

            async def receive_json(self):
                if self.messages:
                    return self.messages.pop(0)
                raise agent_api.WebSocketDisconnect()

            async def send_json(self, payload: dict) -> None:
                self.sent.append(payload)

            async def close(self, code: int = 1000) -> None:
                return None

        ws = FakeWebSocket()
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            with patch("backend.api.agent.get_scan_store", return_value=store):
                asyncio.run(agent_api.agent_websocket(ws))

        self.assertEqual(ws.sent[0]["type"], "welcome")
        self.assertIn({"type": "heartbeat_ack"}, ws.sent)

    def test_agent_websocket_stores_reported_runtime_hash(self) -> None:
        class FakeClient:
            host = "127.0.0.1"

        class FakeWebSocket:
            client = FakeClient()

            def __init__(self) -> None:
                self.sent: list[dict] = []
                self.captured_runtime_hash = ""
                self.messages = [
                    {
                        "type": "hello",
                        "name": "agent-1",
                        "runtime_hash": "old-runtime",
                        "active_scans": [],
                    },
                ]

            async def accept(self) -> None:
                return None

            async def receive_json(self):
                if self.messages:
                    return self.messages.pop(0)
                agents = list(agent_api._registered_agents.values())
                if agents:
                    self.captured_runtime_hash = agents[0].runtime_hash
                raise agent_api.WebSocketDisconnect()

            async def send_json(self, payload: dict) -> None:
                self.sent.append(payload)

            async def close(self, code: int = 1000) -> None:
                return None

        ws = FakeWebSocket()
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            with patch("backend.api.agent.get_scan_store", return_value=store):
                asyncio.run(agent_api.agent_websocket(ws))

        self.assertEqual(ws.captured_runtime_hash, "old-runtime")

    def test_new_client_discards_reported_models_until_user_configures_it(self) -> None:
        class FakeClient:
            host = "127.0.0.1"

        class FakeWebSocket:
            client = FakeClient()

            def __init__(self) -> None:
                self.sent: list[dict] = []
                self.messages = [{
                    "type": "hello",
                    "name": "new-client",
                    "machine_name": "new-machine",
                    "active_scans": [],
                    "config": {
                        "model_pool": {
                            "models": [{
                                "id": "reported",
                                "model": "provider/reported",
                                "enabled": True,
                            }],
                        },
                    },
                }]

            async def accept(self) -> None:
                return None

            async def receive_json(self):
                if self.messages:
                    return self.messages.pop(0)
                raise agent_api.WebSocketDisconnect()

            async def send_json(self, payload: dict) -> None:
                self.sent.append(payload)

            async def close(self, code: int = 1000) -> None:
                return None

        ws = FakeWebSocket()
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.agent.run_store_call", side_effect=_direct_store_call),
            ):
                asyncio.run(_run_websocket_and_cancel_disconnect(ws))
            record = store.list_agent_records()[0]
            stored_config = json.loads(record["config_json"])
            store.close()

        self.assertEqual(ws.sent[0]["config"]["model_pool"]["models"], [])
        self.assertEqual(stored_config["model_pool"]["models"], [])

    def test_existing_client_preserves_persisted_models_on_reconnect(self) -> None:
        class FakeClient:
            host = "127.0.0.1"

        class FakeWebSocket:
            client = FakeClient()

            def __init__(self) -> None:
                self.sent: list[dict] = []
                self.messages = [{
                    "type": "hello",
                    "name": "existing-client",
                    "machine_name": "existing-machine",
                    "active_scans": [],
                    "config": {"model_pool": {"models": []}},
                }]

            async def accept(self) -> None:
                return None

            async def receive_json(self):
                if self.messages:
                    return self.messages.pop(0)
                raise agent_api.WebSocketDisconnect()

            async def send_json(self, payload: dict) -> None:
                self.sent.append(payload)

            async def close(self, code: int = 1000) -> None:
                return None

        ws = FakeWebSocket()
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.upsert_agent_record(
                agent_key="stable-client",
                user_id="",
                ip="127.0.0.1",
                machine_name="existing-machine",
                display_name="existing-client",
                agent_id="old-session",
                last_seen="2026-01-01T00:00:00+00:00",
                initial_config_json=json.dumps({
                    "model_pool": {
                        "models": [{
                            "id": "persisted",
                            "model": "provider/persisted",
                            "enabled": True,
                        }],
                    },
                }),
            )
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.agent.run_store_call", side_effect=_direct_store_call),
            ):
                asyncio.run(_run_websocket_and_cancel_disconnect(ws))
            record = store.get_agent_record("stable-client")
            store.close()

        models = ws.sent[0]["config"]["model_pool"]["models"]
        self.assertEqual(models[0]["model"], "provider/persisted")
        persisted_models = json.loads(record["config_json"])["model_pool"]["models"]
        self.assertEqual(persisted_models[0]["model"], "provider/persisted")

    def test_websocket_agent_online_requires_fresh_last_seen(self) -> None:
        fresh = datetime.now(timezone.utc).isoformat()
        stale = (
            datetime.now(timezone.utc)
            - timedelta(seconds=agent_api._WEBSOCKET_AGENT_STALE_SECONDS + 1)
        ).isoformat()
        agent_api._agent_ws["fresh"] = object()
        agent_api._agent_ws["stale"] = object()

        self.assertTrue(agent_api._is_agent_online(AgentInfo(
            agent_id="fresh",
            name="agent-1",
            ip="127.0.0.1",
            last_seen=fresh,
        )))
        self.assertFalse(agent_api._is_agent_online(AgentInfo(
            agent_id="stale",
            name="agent-1",
            ip="127.0.0.1",
            last_seen=stale,
        )))

    def test_startup_recovery_leaves_agent_owned_running_scans_alone(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(_scan("agent-scan", ScanItemStatus.AUDITING, total=5, processed=2), _meta())
            store.save_scan(
                _scan("server-scan", ScanItemStatus.AUDITING, total=5, processed=2),
                _meta(agent_id="", agent_name="", user_id=""),
            )

            recovered = store.mark_running_as_error()

            self.assertEqual(recovered, 1)
            self.assertEqual(store.load_scan("agent-scan")[0].status, ScanItemStatus.AUDITING)
            server_scan = store.load_scan("server-scan")[0]
            self.assertEqual(server_scan.status, ScanItemStatus.ERROR)
            self.assertEqual(server_scan.error_message, "Process terminated unexpectedly")

    def test_agent_disconnect_cancels_persisted_agent_scan_and_fp_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(_scan("scan-1", ScanItemStatus.AUDITING, total=5, processed=2), _meta())
            store.create_fp_review_job("review-1", "scan-1", 2, "2026-01-01T00:00:00+00:00")
            store.update_fp_review_job("review-1", status="running")

            with patch("backend.api.agent.get_scan_store", return_value=store):
                agent_api._mark_agent_scans_cancelled("agent-old")

            scan = store.load_scan("scan-1")[0]
            self.assertEqual(scan.status, ScanItemStatus.CANCELLED)
            self.assertEqual(scan.error_message, "Agent 断开连接")
            review = store.get_fp_review_job("review-1")
            self.assertIsNotNone(review)
            self.assertEqual(review.status, FpReviewStatus.ERROR)
            self.assertEqual(review.error_message, "Agent 断开连接")

    def test_offline_agent_status_query_cancels_stale_running_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(_scan("scan-1", ScanItemStatus.AUDITING, total=5, processed=2), _meta())
            store.create_fp_review_job("review-1", "scan-1", 2, "2026-01-01T00:00:00+00:00")
            store.update_fp_review_job("review-1", status="running")
            user = User(user_id="user-1", username="alice", role="user")
            started_at = (
                datetime.now(timezone.utc)
                - timedelta(seconds=agent_api._AGENT_DISCONNECT_GRACE_SECONDS + 1)
            )

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.agent._SERVER_STARTED_AT", started_at),
            ):
                scan = asyncio.run(scan_api.get_scan_status("scan-1", current_user=user))

            self.assertEqual(scan.status, ScanItemStatus.CANCELLED)
            self.assertFalse(scan.agent_online)
            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.CANCELLED)
            review = store.get_fp_review_job("review-1")
            self.assertIsNotNone(review)
            self.assertEqual(review.status, FpReviewStatus.ERROR)

    def test_active_scan_hello_reattaches_disconnect_cancelled_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(
                _scan(
                    "scan-1",
                    ScanItemStatus.CANCELLED,
                    total=8,
                    processed=3,
                    error="Agent 断开连接",
                ),
                _meta(),
            )
            info = AgentInfo(
                agent_id="agent-new",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )

            with patch("backend.api.agent.get_scan_store", return_value=store):
                agent_api._reattach_active_agent_scans(
                    "agent-new",
                    info,
                    [{"scan_id": "scan-1", "project_path": "/repo/project"}],
                )

            scan, meta = store.load_scan("scan-1")
            self.assertEqual(meta.agent_id, "agent-new")
            self.assertEqual(scan.status, ScanItemStatus.AUDITING)
            self.assertEqual(scan.error_message, "")
            self.assertIn("scan-1", agent_api._running_scans)

    def test_active_scan_hello_does_not_revive_user_stopped_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(
                _scan(
                    "scan-1",
                    ScanItemStatus.CANCELLED,
                    total=8,
                    processed=3,
                    error="用户手动停止",
                ),
                _meta(),
            )
            info = AgentInfo(
                agent_id="agent-new",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )

            with patch("backend.api.agent.get_scan_store", return_value=store):
                agent_api._reattach_active_agent_scans(
                    "agent-new",
                    info,
                    [{"scan_id": "scan-1"}],
                )

            scan, meta = store.load_scan("scan-1")
            self.assertEqual(meta.agent_id, "agent-old")
            self.assertEqual(scan.status, ScanItemStatus.CANCELLED)
            self.assertNotIn("scan-1", agent_api._running_scans)

    def test_static_analysis_event_updates_total_from_candidate_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.PENDING)
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = scan

            event = ScanEvent.create("static_analysis", "已加载 7 个缓存候选点", candidate_index=7)
            with patch("backend.api.agent.get_scan_store", return_value=store):
                asyncio.run(agent_api.agent_scan_event("scan-1", event))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.total_candidates, 7)
            self.assertEqual(stored.status, ScanItemStatus.ANALYZING)

    def test_task_output_event_is_discarded_before_scan_state_and_sse(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.PENDING)
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = scan
            published: list[tuple[str, str, dict]] = []

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch(
                    "backend.sse.publish",
                    side_effect=lambda scan_id, event_type, data: published.append(
                        (scan_id, event_type, data)
                    ),
                ),
            ):
                for message in (
                    "[threat_analysis][session-1][tool] name=read path=src/a.c",
                    "[threat_analysis][session-1][step] TOOL START",
                    "[2026-08-03 12:00:00] "
                    "[candidate_audit][session-2][task] START",
                ):
                    result = asyncio.run(agent_api.agent_scan_event(
                        "scan-1",
                        ScanEvent.create("auditing", message),
                    ))
                    self.assertEqual(result, {"ok": True, "discarded": True})

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.PENDING)
            self.assertEqual(store.get_events("scan-1"), [])
            self.assertEqual(published, [])

    def test_auditing_event_marks_static_analysis_done_if_done_push_was_missed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.ANALYZING, total=3)
            scan.static_total_files = 128
            scan.static_scanned_files = 128
            scan.static_analysis_done = False
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = scan

            published: list[tuple[str, str, dict]] = []
            event = ScanEvent.create("auditing", "[1/3] NPD a.c:1 — f", candidate_index=0)
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.sse.publish", side_effect=lambda scan_id, event_type, data: published.append((scan_id, event_type, data))),
            ):
                asyncio.run(agent_api.agent_scan_event("scan-1", event))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.AUDITING)
            self.assertTrue(stored.static_analysis_done)
            status_events = [data for _scan_id, event_type, data in published if event_type == "scan_status"]
            self.assertTrue(status_events)
            self.assertTrue(status_events[-1]["static_analysis_done"])

    def test_auditing_event_does_not_advance_processed_count_from_candidate_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.ANALYZING, total=20, processed=4)
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = scan

            event = ScanEvent.create("auditing", "[10/20] NPD z.c:1 — z", candidate_index=9)
            with patch("backend.api.agent.get_scan_store", return_value=store):
                asyncio.run(agent_api.agent_scan_event("scan-1", event))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.AUDITING)
            self.assertEqual(stored.processed_candidates, 4)
            self.assertEqual(stored.progress, 0.2)

    def test_static_progress_done_moves_scan_to_auditing_and_publishes_static_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.ANALYZING)
            scan.static_total_files = 128
            scan.static_scanned_files = 128
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = scan

            published: list[tuple[str, str, dict]] = []
            body = agent_api._StaticProgressBody(scanned=0, total=0, done=True)
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.sse.publish", side_effect=lambda scan_id, event_type, data: published.append((scan_id, event_type, data))),
            ):
                asyncio.run(agent_api.agent_push_static_progress("scan-1", body))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.AUDITING)
            self.assertTrue(stored.static_analysis_done)
            self.assertEqual(stored.static_scanned_files, 128)
            self.assertEqual(stored.static_total_files, 128)
            status_events = [data for _scan_id, event_type, data in published if event_type == "scan_status"]
            self.assertTrue(status_events)
            self.assertEqual(status_events[-1]["status"], ScanItemStatus.AUDITING)
            self.assertTrue(status_events[-1]["static_analysis_done"])
            self.assertEqual(status_events[-1]["static_scanned_files"], 128)
            self.assertEqual(status_events[-1]["static_total_files"], 128)

    def test_index_status_done_persists_stats_and_file_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.ANALYZING)
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = scan

            stats = {
                "files": 7,
                "functions": 31,
                "structs": 4,
                "global_variables": 5,
                "function_calls": 42,
                "global_variable_references": 9,
            }
            published: list[tuple[str, str, dict]] = []
            body = agent_api._IndexStatusBody(status="done", stats=stats)
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.sse.publish", side_effect=lambda scan_id, event_type, data: published.append((scan_id, event_type, data))),
            ):
                asyncio.run(agent_api.agent_push_index_status("scan-1", body))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.static_scanned_files, 7)
            self.assertEqual(stored.static_total_files, 7)
            self.assertEqual(agent_api._scan_index_statuses["scan-1"]["stats"]["function_calls"], 42)
            index_events = [data for _scan_id, event_type, data in published if event_type == "index_status"]
            self.assertTrue(index_events)
            self.assertEqual(index_events[-1]["parsed_files"], 0)
            self.assertEqual(index_events[-1]["stats"], stats)
            status_events = [data for _scan_id, event_type, data in published if event_type == "scan_status"]
            self.assertTrue(status_events)
            self.assertEqual(status_events[-1]["static_scanned_files"], 7)
            self.assertEqual(status_events[-1]["static_total_files"], 7)

    def test_index_status_done_zero_counts_does_not_clear_existing_file_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.ANALYZING)
            scan.static_total_files = 128
            scan.static_scanned_files = 127
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = scan

            published: list[tuple[str, str, dict]] = []
            body = agent_api._IndexStatusBody(status="done", parsed_files=0, total_files=0)
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.sse.publish", side_effect=lambda scan_id, event_type, data: published.append((scan_id, event_type, data))),
            ):
                asyncio.run(agent_api.agent_push_index_status("scan-1", body))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.static_scanned_files, 127)
            self.assertEqual(stored.static_total_files, 128)
            self.assertFalse([data for _scan_id, event_type, data in published if event_type == "scan_status"])

    def test_static_progress_updates_pending_scan_to_analyzing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.PENDING)
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = scan

            body = agent_api._StaticProgressBody(scanned=3, total=128, done=False)
            with patch("backend.api.agent.get_scan_store", return_value=store):
                asyncio.run(agent_api.agent_push_static_progress("scan-1", body))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.ANALYZING)
            self.assertFalse(stored.static_analysis_done)
            self.assertEqual(stored.static_scanned_files, 3)
            self.assertEqual(stored.static_total_files, 128)

    def test_late_static_progress_does_not_clear_completed_static_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.AUDITING, total=3)
            scan.static_total_files = 128
            scan.static_scanned_files = 128
            scan.static_analysis_done = True
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = scan

            published: list[tuple[str, str, dict]] = []
            body = agent_api._StaticProgressBody(scanned=127, total=128, done=False)
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.sse.publish", side_effect=lambda scan_id, event_type, data: published.append((scan_id, event_type, data))),
            ):
                asyncio.run(agent_api.agent_push_static_progress("scan-1", body))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.AUDITING)
            self.assertTrue(stored.static_analysis_done)
            self.assertEqual(stored.static_scanned_files, 127)
            status_events = [data for _scan_id, event_type, data in published if event_type == "scan_status"]
            self.assertTrue(status_events)
            self.assertTrue(status_events[-1]["static_analysis_done"])

    def test_late_static_progress_done_does_not_reopen_completed_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.COMPLETE, total=2, processed=2)
            scan.static_analysis_done = False
            store.save_scan(scan, _meta())

            body = agent_api._StaticProgressBody(scanned=0, total=0, done=True)
            with patch("backend.api.agent.get_scan_store", return_value=store):
                asyncio.run(agent_api.agent_push_static_progress("scan-1", body))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.COMPLETE)
            self.assertTrue(stored.static_analysis_done)

    def test_processed_report_updates_progress_from_processed_key_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(_scan("scan-1", ScanItemStatus.AUDITING, total=4), _meta())

            with patch("backend.api.agent.get_scan_store", return_value=store):
                asyncio.run(agent_api.agent_report_processed(
                    "scan-1",
                    {"file": "a.c", "line": 1, "function": "a", "vuln_type": "npd"},
                ))
                asyncio.run(agent_api.agent_report_processed(
                    "scan-1",
                    {"file": "b.c", "line": 2, "function": "b", "vuln_type": "npd"},
                ))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.processed_candidates, 2)
            self.assertEqual(stored.progress, 0.5)

    def test_candidate_report_persists_final_static_candidate_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.ANALYZING, total=0, processed=0)
            store.save_scan(scan, _meta())
            agent_api._running_scans["scan-1"] = scan
            published: list[tuple[str, str, dict]] = []

            body = AgentScanCandidates(candidates=[
                Candidate(
                    file="src/a.c",
                    line=10,
                    function="foo",
                    description="desc",
                    vuln_type="npd",
                    metadata={"subject": "ptr"},
                ),
                Candidate(
                    file=".",
                    line=1,
                    function="__threat_path__",
                    description="threat audit placeholder",
                    vuln_type="threat_audit",
                    metadata={"source": "threat_analysis"},
                ),
            ])

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.sse.publish", side_effect=lambda scan_id, event_type, data: published.append((scan_id, event_type, data))),
            ):
                response = asyncio.run(agent_api.agent_report_scan_candidates("scan-1", body))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(response["count"], 1)
            self.assertEqual(stored.total_candidates, 1)
            self.assertEqual(stored.candidates[0].metadata["subject"], "ptr")
            self.assertEqual(agent_api._running_scans["scan-1"].candidates[0].file, "src/a.c")
            self.assertTrue(any(event_type == "scan_candidates" for _sid, event_type, _data in published))

    def test_retry_counts_keep_static_candidates_and_threat_tasks_separate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.COMPLETE, total=1, processed=1)
            store.save_scan(scan, _meta())
            store.add_vulnerability(
                "scan-1",
                Vulnerability(
                    file="static.c",
                    line=7,
                    function="retry_static",
                    vuln_type="npd",
                    severity="unknown",
                    description="static timeout",
                    ai_analysis="timeout",
                    confirmed=False,
                    ai_verdict="timeout",
                ),
            )
            store.add_vulnerability(
                "scan-1",
                Vulnerability(
                    file=".",
                    line=1,
                    function="__threat_path__",
                    vuln_type="threat_audit",
                    severity="unknown",
                    description="threat timeout",
                    ai_analysis="timeout",
                    confirmed=False,
                    ai_verdict="timeout",
                    analysis_source="threat_audit",
                    source_task_id="threat-timeout",
                ),
            )
            store.upsert_threat_audit_task(
                "scan-1",
                ThreatAuditTask(task_id="threat-timeout", status="timeout"),
            )
            user = User(user_id="user-1", username="alice", role="user")

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.api.agent.get_scan_store", return_value=store),
            ):
                status = asyncio.run(scan_api.get_scan_status("scan-1", current_user=user))

            self.assertEqual(status.retryable_candidates_count, 1)
            self.assertEqual(status.continuable_task_count, 2)

    def test_late_opencode_pool_snapshot_is_cleared_for_completed_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.COMPLETE, total=4, processed=4)
            store.save_scan(scan, _meta())
            body = OpenCodePoolStatus(
                scope_id="scan-1",
                global_running=1,
                global_queued=2,
                total_tasks=3,
                completed_task_count=1,
                completed_tasks=[
                    {
                        "task_id": "task-done",
                        "task_type": "threat_analysis",
                        "outcome": "success",
                        "serve_session_id": "ses_task_done",
                        "prompt": "completed threat prompt",
                        "finished_at": "2026-01-01T00:02:00+00:00",
                    }
                ],
                models=[
                    {
                        "id": "deep",
                        "model": "deep-model",
                        "capability": "high",
                        "max_concurrency": 1,
                        "running": 1,
                        "queued": 2,
                        "total": 3,
                        "success": 2,
                        "last_status": "running",
                        "active_tasks": [{"task_type": "vulnerability_mining"}],
                    }
                ],
            )

            with patch("backend.api.agent.get_scan_store", return_value=store):
                asyncio.run(agent_api.agent_push_opencode_pool("scan-1", body))

            pool = store.load_scan("scan-1")[0].opencode_pool
            self.assertIsNotNone(pool)
            self.assertEqual(pool.global_running, 0)
            self.assertEqual(pool.global_queued, 0)
            self.assertEqual(pool.models[0].running, 0)
            self.assertEqual(pool.models[0].queued, 0)
            self.assertEqual(pool.models[0].active_tasks, [])
            self.assertEqual(pool.total_tasks, 3)
            self.assertEqual(pool.completed_task_count, 1)
            self.assertEqual(pool.completed_tasks[0]["task_id"], "task-done")
            self.assertEqual(pool.completed_tasks[0]["serve_session_id"], "ses_task_done")
            self.assertEqual(pool.completed_tasks[0]["prompt"], "completed threat prompt")
            summary = store.list_scans()[0]
            self.assertEqual(summary.total_task_count, 3)
            self.assertEqual(summary.completed_task_count, 1)

    def test_opencode_pool_snapshot_merges_history_across_continue_attempts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.AUDITING, total=1)
            scan.opencode_pool = OpenCodePoolStatus(
                scope_id="scan-1",
                total_tasks=1,
                completed_task_count=1,
                completed_tasks=[
                    {
                        "task_id": "old",
                        "outcome": "success",
                        "serve_session_id": "ses_old",
                        "prompt": "old prompt",
                    }
                ],
            )
            store.save_scan(scan, _meta())
            current = OpenCodePoolStatus(
                scope_id="scan-1",
                global_queued=1,
                total_tasks=2,
                completed_task_count=1,
                completed_tasks=[
                    {
                        "task_id": "new",
                        "outcome": "timeout",
                        "serve_session_id": "ses_new",
                        "prompt": "new prompt",
                    }
                ],
                queued_tasks=[{"request_id": "queued", "task_type": "fp_review"}],
            )

            with patch("backend.api.agent.get_scan_store", return_value=store):
                asyncio.run(agent_api.agent_push_opencode_pool("scan-1", current))

            pool = store.load_scan("scan-1")[0].opencode_pool
            self.assertIsNotNone(pool)
            self.assertEqual([task["task_id"] for task in pool.completed_tasks], ["old", "new"])
            self.assertEqual(
                [task["prompt"] for task in pool.completed_tasks],
                ["old prompt", "new prompt"],
            )
            self.assertEqual(
                [task["serve_session_id"] for task in pool.completed_tasks],
                ["ses_old", "ses_new"],
            )
            self.assertEqual(pool.completed_task_count, 2)
            self.assertEqual(pool.total_tasks, 3)

    def test_resume_preserves_total_candidate_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            graph = AgentMcpConfig(
                enabled=True,
                name="resume-graph",
                transport="remote",
                remote=AgentMcpRemoteConfig(url="http://graph.test/mcp"),
            )
            meta = _meta()
            meta.code_graph_mcp = graph
            store.save_scan(
                _scan(
                    "scan-1",
                    ScanItemStatus.CANCELLED,
                    total=10,
                    processed=4,
                    error="Agent 断开连接",
                ),
                meta,
            )
            agent = AgentInfo(
                agent_id="agent-old",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )
            user = User(user_id="user-1", username="alice", role="user")

            send = AsyncMock(return_value=True)
            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch.dict("backend.api.agent._registered_agents", {"agent-old": agent}, clear=True),
                patch("backend.api.agent.send_agent_command", new=send),
            ):
                request = SimpleNamespace(base_url="http://testserver/")
                asyncio.run(scan_api.resume_scan("scan-1", request=request, current_user=user))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.total_candidates, 10)
            self.assertEqual(stored.processed_candidates, 4)
            self.assertEqual(stored.status, ScanItemStatus.PENDING)
            self.assertEqual(
                send.await_args.args[1]["code_graph_mcp"],
                graph.model_dump(mode="json"),
            )

    def test_retry_incomplete_scan_dispatches_retryable_failed_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.COMPLETE, total=4, processed=4)
            meta = _meta()
            store.save_scan(scan, meta)
            vulns = [
                Vulnerability(
                    file="ok.c",
                    line=1,
                    function="ok",
                    vuln_type="npd",
                    severity="high",
                    description="confirmed",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                ),
                Vulnerability(
                    file="timeout.c",
                    line=2,
                    function="slow",
                    vuln_type="npd",
                    severity="unknown",
                    description="timed out",
                    ai_analysis="Analysis timed out",
                    confirmed=False,
                    ai_verdict="timeout",
                ),
                Vulnerability(
                    file="none.c",
                    line=3,
                    function="missing",
                    vuln_type="npd",
                    severity="unknown",
                    description="no result",
                    ai_analysis="No analysis result returned",
                    confirmed=False,
                    ai_verdict="no_result",
                ),
                Vulnerability(
                    file="failed.c",
                    line=4,
                    function="broken",
                    vuln_type="npd",
                    severity="unknown",
                    description="failed",
                    ai_analysis="OpenCode completed without submitting a result",
                    confirmed=False,
                    ai_verdict="failed",
                    failure_reason="raw opencode output",
                ),
            ]
            for vuln in vulns:
                store.add_vulnerability("scan-1", vuln)
                store.add_processed_key(
                    "scan-1",
                    (vuln.file, vuln.line, vuln.function, vuln.vuln_type),
                )
            agent = AgentInfo(
                agent_id="agent-old",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )
            user = User(user_id="user-1", username="alice", role="user")
            sent: dict = {}

            async def fake_send(_agent_id: str, payload: dict) -> bool:
                sent.update(payload)
                return True

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch.dict("backend.api.agent._registered_agents", {"agent-old": agent}, clear=True),
                patch("backend.api.agent.send_agent_command", new=AsyncMock(side_effect=fake_send)),
                patch("backend.api.agent.create_agent_runtime_update_payload", return_value=None),
            ):
                request = SimpleNamespace(base_url="http://testserver/")
                asyncio.run(scan_api.retry_incomplete_scan("scan-1", request=request, current_user=user))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.PENDING)
            self.assertEqual(stored.processed_candidates, 1)
            self.assertEqual(len(store.get_processed_keys("scan-1")), 1)
            self.assertEqual(sent["type"], "resume")
            self.assertEqual(sent["retry_total_candidates"], 4)
            self.assertEqual(sent["retry_processed_offset"], 1)
            self.assertEqual(
                [(c["file"], c["line"], c["function"]) for c in sent["retry_candidates"]],
                [("timeout.c", 2, "slow"), ("none.c", 3, "missing"), ("failed.c", 4, "broken")],
            )

    def test_resume_dispatches_unprocessed_failed_and_threat_audit_work_together(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.CANCELLED, total=3, processed=2)
            scan.static_analysis_done = True
            scan.threat_analysis_enabled = True
            scan.mining_engines = [
                MiningEngineSelection(
                    engine_id="static_candidate",
                    engine_label="静态规则扫描 + 候选点审计",
                ),
                MiningEngineSelection(
                    engine_id="threat_audit",
                    engine_label="威胁审计",
                ),
            ]
            scan.candidates = [
                ScanCandidate(idx=0, file="done.c", line=1, function="done", description="done", vuln_type="npd"),
                ScanCandidate(idx=1, file="failed.c", line=2, function="failed", description="failed", vuln_type="npd"),
                ScanCandidate(idx=2, file="pending.c", line=3, function="pending", description="pending", vuln_type="npd"),
            ]
            meta = _meta()
            meta.threat_analysis_enabled = True
            meta.mining_engines = scan.mining_engines
            store.save_scan(scan, meta)
            store.add_processed_key("scan-1", ("done.c", 1, "done", "npd"))
            store.add_processed_key("scan-1", ("failed.c", 2, "failed", "npd"))
            store.add_vulnerability(
                "scan-1",
                Vulnerability(
                    file="failed.c",
                    line=2,
                    function="failed",
                    vuln_type="npd",
                    severity="unknown",
                    description="failed",
                    ai_analysis="failed",
                    confirmed=False,
                    ai_verdict="failed",
                ),
            )
            store.upsert_threat_audit_task(
                "scan-1",
                ThreatAuditTask(
                    task_id="threat-complete",
                    status="completed",
                    surface_node_id="surface-1",
                    method_node_id="method-complete",
                ),
            )
            store.upsert_threat_audit_task(
                "scan-1",
                ThreatAuditTask(
                    task_id="threat-timeout",
                    status="timeout",
                    surface_node_id="surface-1",
                    method_node_id="method-timeout",
                ),
            )
            store.add_vulnerability(
                "scan-1",
                Vulnerability(
                    file=".",
                    line=1,
                    function="__threat_path__",
                    vuln_type="threat_audit",
                    severity="unknown",
                    description="timed out threat audit",
                    ai_analysis="timeout",
                    confirmed=False,
                    ai_verdict="timeout",
                    analysis_source="threat_audit",
                    source_task_id="threat-timeout",
                ),
            )
            self.assertEqual(store.get_incomplete_threat_audit_counts(["scan-1"]), {"scan-1": 1})
            agent = AgentInfo(
                agent_id="agent-old",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )
            user = User(user_id="user-1", username="alice", role="user")
            sent: dict = {}

            async def fake_send(_agent_id: str, payload: dict) -> bool:
                sent.update(payload)
                return True

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch.dict("backend.api.agent._registered_agents", {"agent-old": agent}, clear=True),
                patch("backend.api.agent.send_agent_command", new=AsyncMock(side_effect=fake_send)),
                patch(
                    "backend.api.agent.create_agent_runtime_update_payload",
                    return_value={"hash": "remote-runtime", "archive_sha256": "archive-hash"},
                ),
            ):
                asyncio.run(
                    scan_api.resume_scan(
                        "scan-1",
                        request=SimpleNamespace(base_url="http://testserver/"),
                        current_user=user,
                    )
                )

            self.assertEqual(
                [(item["file"], item["line"]) for item in sent["retry_candidates"]],
                [("pending.c", 3), ("failed.c", 2)],
            )
            self.assertEqual(sent["retry_processed_offset"], 1)
            self.assertTrue(sent["resume_threat_analysis"])
            self.assertEqual(sent["retry_threat_audit_task_ids"], ["threat-timeout"])
            self.assertEqual(
                sent["agent_runtime_update"],
                {"hash": "remote-runtime", "archive_sha256": "archive-hash"},
            )
            self.assertEqual(store.get_processed_keys("scan-1"), {("done.c", 1, "done", "npd")})

    def test_resume_preserves_analysis_only_empty_engine_selection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-analysis", ScanItemStatus.CANCELLED)
            scan.scan_mode = "threat_analysis_only"
            scan.threat_analysis_enabled = True
            scan.mining_engines = []
            meta = _meta()
            meta.scan_mode = "threat_analysis_only"
            meta.threat_analysis_enabled = True
            meta.mining_engines = []
            store.save_scan(scan, meta)
            agent = AgentInfo(
                agent_id="agent-old",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )
            user = User(user_id="user-1", username="alice", role="user")
            sent: dict = {}

            async def fake_send(_agent_id: str, payload: dict) -> bool:
                sent.update(payload)
                return True

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.api.scan.run_store_call",
                    side_effect=_direct_store_call,
                ),
                patch.dict(
                    "backend.api.agent._registered_agents",
                    {"agent-old": agent},
                    clear=True,
                ),
                patch(
                    "backend.api.agent.send_agent_command",
                    new=AsyncMock(side_effect=fake_send),
                ),
                patch(
                    "backend.api.agent.create_agent_task_runtime_update_payload_async",
                    new=AsyncMock(return_value=None),
                ),
                patch(
                    "backend.api.agent.get_scan_agent_config_async",
                    new=AsyncMock(return_value=object()),
                ),
                patch(
                    "backend.api.agent.agent_config_has_explicit_model",
                    return_value=True,
                ),
            ):
                asyncio.run(scan_api.resume_scan(
                    "scan-analysis",
                    request=SimpleNamespace(base_url="http://testserver/"),
                    current_user=user,
                ))

            self.assertTrue(sent["threat_analysis_enabled"])
            self.assertEqual(
                sent["threat_analysis_method"],
                "deephole_threat_analysis",
            )
            self.assertTrue(sent["resume_threat_analysis"])
            self.assertEqual(sent["mining_engines"], [])

    def test_upsert_incomplete_vulnerability_replaces_existing_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(_scan("scan-1", ScanItemStatus.AUDITING, total=1), _meta())
            timeout_vuln = Vulnerability(
                file="a.c",
                line=1,
                function="a",
                vuln_type="npd",
                severity="unknown",
                description="old",
                ai_analysis="OpenCode completed without submitting a result",
                confirmed=False,
                ai_verdict="failed",
                failure_reason="old opencode output",
            )
            store.add_vulnerability("scan-1", timeout_vuln)
            replacement = Vulnerability(
                file="a.c",
                line=1,
                function="a",
                vuln_type="npd",
                severity="high",
                description="new",
                ai_analysis="confirmed now",
                confirmed=True,
                ai_verdict="confirmed",
            )

            index = store.upsert_incomplete_vulnerability("scan-1", replacement)

            self.assertEqual(index, 0)
            stored = store.get_vulnerabilities("scan-1")
            self.assertEqual(len(stored), 1)
            self.assertEqual(stored[0].description, "new")
            self.assertEqual(stored[0].ai_verdict, "confirmed")
            self.assertEqual(stored[0].failure_reason, "")
            self.assertTrue(stored[0].confirmed)

    def test_cancel_finish_preserves_total_but_accepts_lower_processed_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(_scan("scan-1", ScanItemStatus.AUDITING, total=8, processed=5), _meta())
            agent_api._running_scans["scan-1"] = store.load_scan("scan-1")[0]

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.scan.get_scan_store", return_value=store),
            ):
                asyncio.run(agent_api.agent_finish_scan(
                    "scan-1",
                    AgentScanFinish(
                        vulnerabilities=[],
                        status="cancelled",
                        total_candidates=8,
                        processed_candidates=4,
                    ),
                    SimpleNamespace(base_url="http://testserver/"),
                ))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.CANCELLED)
            self.assertEqual(stored.total_candidates, 8)
            self.assertEqual(stored.processed_candidates, 4)

    def test_finish_scan_reconciles_missing_threat_findings_without_duplicates(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.AUDITING, total=1, processed=1)
            if hasattr(scan, "auto_fp_review"):
                scan.auto_fp_review = False
            meta = _meta()
            if hasattr(meta, "auto_fp_review"):
                meta.auto_fp_review = False
            store.save_scan(scan, meta)
            static_vuln = Vulnerability(
                file="static.c",
                line=10,
                function="static_issue",
                vuln_type="npd",
                severity="high",
                description="static issue",
                confirmed=True,
                ai_verdict="confirmed",
            )
            store.add_vulnerability("scan-1", static_vuln)
            scan.vulnerabilities = [static_vuln]
            agent_api._running_scans["scan-1"] = scan
            threat_vuln = Vulnerability(
                file="threat.c",
                line=20,
                function="threat_issue",
                vuln_type="out_of_bounds",
                severity="critical",
                description="threat-derived issue",
                confirmed=True,
                ai_verdict="confirmed",
                analysis_source="threat_audit",
                source_task_id="threat-task-1",
                threat_surface_node_id="TREE-1:NODE-1",
                threat_method_node_id="PATTERN-1",
            )
            published: list[tuple[str, str, dict]] = []
            finish = AgentScanFinish(
                vulnerabilities=[static_vuln, threat_vuln],
                status="complete",
                total_candidates=1,
                processed_candidates=1,
            )

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.sse.publish",
                    side_effect=lambda scan_id, event_type, data: published.append(
                        (scan_id, event_type, data),
                    ),
                ),
            ):
                asyncio.run(agent_api.agent_finish_scan(
                    "scan-1",
                    finish,
                    SimpleNamespace(base_url="http://testserver/"),
                ))
                asyncio.run(agent_api.agent_finish_scan(
                    "scan-1",
                    finish,
                    SimpleNamespace(base_url="http://testserver/"),
                ))

            stored = store.get_vulnerabilities("scan-1")
            self.assertEqual(len(stored), 2)
            self.assertEqual(
                [vuln.analysis_source for vuln in stored],
                ["static_candidate", "threat_audit"],
            )
            threat_events = [
                data
                for _scan_id, event_type, data in published
                if event_type == "scan_vulnerability"
                and data["vulnerability"]["analysis_source"] == "threat_audit"
            ]
            self.assertEqual(len(threat_events), 1)
            self.assertEqual(threat_events[0]["index"], 1)

    def test_report_threat_finding_is_live_and_finish_does_not_duplicate(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.AUDITING, total=1)
            if hasattr(scan, "auto_fp_review"):
                scan.auto_fp_review = False
            meta = _meta()
            if hasattr(meta, "auto_fp_review"):
                meta.auto_fp_review = False
            store.save_scan(scan, meta)
            agent_api._running_scans["scan-1"] = scan
            finding = {
                "file": "threat.c",
                "line": 20,
                "function": "threat_issue",
                "call_chain": [{
                    "function": "receive_packet",
                    "file": "network.c",
                    "line": 8,
                }],
                "vuln_type": "out_of_bounds",
                "severity": "critical",
                "description": "threat-derived issue",
                "attack_entry": "untrusted network packet",
                "confirmed": True,
                "ai_verdict": "confirmed",
                "analysis_source": "threat_audit",
                "source_task_id": "threat-task-1",
                "threat_surface_node_id": "TREE-1:NODE-1",
                "threat_method_node_id": "PATTERN-1",
            }
            published: list[tuple[str, str, dict]] = []

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.sse.publish",
                    side_effect=lambda scan_id, event_type, data: published.append(
                        (scan_id, event_type, data),
                    ),
                ),
            ):
                first_response = asyncio.run(agent_api.agent_report_vulnerability(
                    "scan-1",
                    Vulnerability(**finding),
                ))
                store.update_vulnerability(
                    "scan-1",
                    0,
                    "confirmed",
                    "verified by reviewer",
                    ticket_submitted=True,
                    ticket_id="SEC-42",
                )
                scan.vulnerabilities[0].user_verdict = "confirmed"
                scan.vulnerabilities[0].user_verdict_reason = (
                    "verified by reviewer"
                )
                scan.vulnerabilities[0].ticket_submitted = True
                scan.vulnerabilities[0].ticket_id = "SEC-42"
                replay_response = asyncio.run(
                    agent_api.agent_report_vulnerability(
                        "scan-1",
                        Vulnerability(**finding),
                    ),
                )

                self.assertEqual(first_response["index"], 0)
                self.assertEqual(replay_response["index"], 0)
                self.assertEqual(
                    scan.vulnerabilities[0].user_verdict,
                    "confirmed",
                )
                self.assertEqual(scan.vulnerabilities[0].ticket_id, "SEC-42")
                distinct_finding = {
                    **finding,
                    "call_chain": [{
                        "function": "receive_datagram",
                        "file": "udp.c",
                        "line": 18,
                    }],
                    "attack_entry": "untrusted UDP datagram",
                }
                distinct_response = asyncio.run(
                    agent_api.agent_report_vulnerability(
                        "scan-1",
                        Vulnerability(**distinct_finding),
                    ),
                )
                self.assertEqual(distinct_response["index"], 1)
                persisted_scan = store.load_scan("scan-1")[0]
                self.assertEqual(persisted_scan.status, ScanItemStatus.AUDITING)
                persisted_findings = store.get_vulnerabilities("scan-1")
                self.assertEqual(len(persisted_findings), 2)
                self.assertEqual(
                    persisted_findings[0].analysis_source,
                    "threat_audit",
                )
                self.assertEqual(
                    persisted_findings[0].user_verdict,
                    "confirmed",
                )
                self.assertEqual(
                    persisted_findings[1].attack_entry,
                    "untrusted UDP datagram",
                )
                live_scan = agent_api._running_scans["scan-1"]
                self.assertEqual(live_scan.status, ScanItemStatus.AUDITING)
                self.assertEqual(len(live_scan.vulnerabilities), 2)
                self.assertEqual(
                    live_scan.vulnerabilities[0].source_task_id,
                    "threat-task-1",
                )
                live_events = [
                    data
                    for _scan_id, event_type, data in published
                    if event_type == "scan_vulnerability"
                ]
                self.assertEqual(
                    [event["index"] for event in live_events],
                    [0, 1],
                )

                asyncio.run(agent_api.agent_finish_scan(
                    "scan-1",
                    AgentScanFinish(
                        vulnerabilities=[
                            Vulnerability(**finding),
                            Vulnerability(**distinct_finding),
                        ],
                        status="complete",
                        total_candidates=1,
                        processed_candidates=1,
                    ),
                    SimpleNamespace(base_url="http://testserver/"),
                ))

            stored = store.get_vulnerabilities("scan-1")
            self.assertEqual(len(stored), 2)
            self.assertEqual(stored[0].source_task_id, "threat-task-1")
            self.assertEqual(stored[0].user_verdict, "confirmed")
            self.assertEqual(stored[0].ticket_id, "SEC-42")
            threat_events = [
                data
                for _scan_id, event_type, data in published
                if event_type == "scan_vulnerability"
                and data["vulnerability"]["analysis_source"] == "threat_audit"
            ]
            self.assertEqual(
                [event["index"] for event in threat_events],
                [0, 1],
            )

    def test_finish_scan_keeps_same_finding_from_different_engines(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan(
                "scan-1",
                ScanItemStatus.AUDITING,
                total=1,
                processed=1,
            )
            scan.auto_fp_review = False
            selections = [
                MiningEngineSelection(
                    engine_id="engine_a",
                    engine_label="Engine A",
                ),
                MiningEngineSelection(
                    engine_id="engine_b",
                    engine_label="Engine B",
                ),
            ]
            scan.mining_engines = selections
            meta = _meta()
            meta.auto_fp_review = False
            meta.mining_engines = selections
            store.save_scan(scan, meta)

            finding_a = Vulnerability(
                file="same.c",
                line=12,
                function="same",
                vuln_type="npd",
                severity="high",
                description="same finding",
                confirmed=True,
                ai_verdict="confirmed",
                engine_id="engine_a",
                engine_label="untrusted",
            )
            finding_b = finding_a.model_copy(update={
                "engine_id": "engine_b",
                "engine_label": "also untrusted",
            })
            store.add_vulnerability(
                "scan-1",
                finding_a.model_copy(update={
                    "engine_label": "Engine A",
                }),
            )
            store._conn.execute(
                "UPDATE vulnerabilities SET fp_review_eligible = 0 "
                "WHERE scan_id = ? AND idx = ?",
                ("scan-1", 0),
            )
            store._conn.commit()
            published: list[tuple[str, str, dict]] = []
            finish = AgentScanFinish(
                vulnerabilities=[finding_a, finding_b],
                status="complete",
                total_candidates=1,
                processed_candidates=1,
            )

            with (
                patch(
                    "backend.api.agent.get_scan_store",
                    return_value=store,
                ),
                patch(
                    "backend.api.scan.get_scan_store",
                    return_value=store,
                ),
                patch(
                    "backend.sse.publish",
                    side_effect=(
                        lambda scan_id, event_type, data:
                        published.append((scan_id, event_type, data))
                    ),
                ),
            ):
                asyncio.run(agent_api.agent_finish_scan(
                    "scan-1",
                    finish,
                    SimpleNamespace(base_url="http://testserver/"),
                ))
                asyncio.run(agent_api.agent_finish_scan(
                    "scan-1",
                    finish,
                    SimpleNamespace(base_url="http://testserver/"),
                ))

            stored = store.get_vulnerabilities("scan-1")
            self.assertEqual(
                [item.engine_id for item in stored],
                ["engine_a", "engine_b"],
            )
            self.assertEqual(stored[0].engine_label, "Engine A")
            self.assertEqual(stored[1].engine_label, "Engine B")
            self.assertTrue(all(
                not hasattr(item, "fp_review_eligible")
                for item in stored
            ))
            vulnerability_events = [
                data
                for _scan_id, event_type, data in published
                if event_type == "scan_vulnerability"
            ]
            self.assertEqual(len(vulnerability_events), 1)
            self.assertEqual(
                vulnerability_events[0]["vulnerability"]["engine_id"],
                "engine_b",
            )
            self.assertNotIn(
                "fp_review_eligible",
                vulnerability_events[0]["vulnerability"],
            )

    def test_finish_scan_clears_transient_opencode_pool_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan = _scan("scan-1", ScanItemStatus.AUDITING, total=4, processed=2)
            pool = OpenCodePoolStatus(
                scope_id="scan-1",
                global_running=1,
                global_queued=1,
                queued_tasks=[{"task_type": "vulnerability_mining", "checker": "npd"}],
                models=[
                    {
                        "id": "deep",
                        "model": "deep-model",
                        "capability": "high",
                        "max_concurrency": 1,
                        "running": 1,
                        "queued": 1,
                        "total": 2,
                        "success": 1,
                        "last_status": "running",
                        "active_tasks": [{"task_type": "vulnerability_mining"}],
                    }
                ],
            )
            scan.opencode_pool = pool
            store.save_scan(scan, _meta())
            store.update_opencode_pool_status("scan-1", pool)
            agent_api._running_scans["scan-1"] = scan

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.scan.get_scan_store", return_value=store),
            ):
                asyncio.run(agent_api.agent_finish_scan(
                    "scan-1",
                    AgentScanFinish(
                        vulnerabilities=[],
                        status="complete",
                        total_candidates=4,
                        processed_candidates=4,
                    ),
                    SimpleNamespace(base_url="http://testserver/"),
                ))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.COMPLETE)
            self.assertIsNotNone(stored.opencode_pool)
            self.assertEqual(stored.opencode_pool.global_running, 0)
            self.assertEqual(stored.opencode_pool.global_queued, 0)
            self.assertEqual(stored.opencode_pool.queued_tasks, [])
            self.assertEqual(stored.opencode_pool.models[0].running, 0)
            self.assertEqual(stored.opencode_pool.models[0].queued, 0)
            self.assertEqual(stored.opencode_pool.models[0].active_tasks, [])

    def test_active_fp_review_hello_reattaches_disconnect_errored_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(_scan("scan-1", ScanItemStatus.COMPLETE, total=5, processed=5), _meta())
            store.create_fp_review_job("review-1", "scan-1", 3, "2026-01-01T00:00:00+00:00")
            store.update_fp_review_job(
                "review-1", status="error", error_message="Agent 断开连接"
            )
            info = AgentInfo(
                agent_id="agent-new",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )

            with patch("backend.api.agent.get_scan_store", return_value=store):
                agent_api._reattach_active_fp_reviews(
                    "agent-new",
                    info,
                    [{"scan_id": "scan-1", "review_id": "review-1"}],
                )

            review = store.get_fp_review_job("review-1")
            self.assertIsNotNone(review)
            self.assertEqual(review.status, FpReviewStatus.RUNNING)
            self.assertEqual(review.error_message, "")
            meta = store.load_scan("scan-1")[1]
            self.assertEqual(meta.agent_id, "agent-new")

            # The old connection's delayed disconnect-cancel must not kill the
            # review once the scan points at the new agent_id.
            with patch("backend.api.agent.get_scan_store", return_value=store):
                agent_api._mark_agent_scans_cancelled("agent-old")
            review = store.get_fp_review_job("review-1")
            self.assertEqual(review.status, FpReviewStatus.RUNNING)

    def test_active_fp_review_hello_ignores_user_cancelled_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(_scan("scan-1", ScanItemStatus.COMPLETE, total=5, processed=5), _meta())
            store.create_fp_review_job("review-1", "scan-1", 3, "2026-01-01T00:00:00+00:00")
            store.update_fp_review_job(
                "review-1", status="cancelled", error_message="用户手动停止"
            )
            info = AgentInfo(
                agent_id="agent-new",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )

            with patch("backend.api.agent.get_scan_store", return_value=store):
                agent_api._reattach_active_fp_reviews(
                    "agent-new",
                    info,
                    [{"scan_id": "scan-1", "review_id": "review-1"}],
                )

            review = store.get_fp_review_job("review-1")
            self.assertEqual(review.status, FpReviewStatus.CANCELLED)
            meta = store.load_scan("scan-1")[1]
            self.assertEqual(meta.agent_id, "agent-old")

    def test_stage_output_post_auto_recovers_disconnect_errored_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(_scan("scan-1", ScanItemStatus.COMPLETE, total=5, processed=5), _meta())
            store.create_fp_review_job("review-1", "scan-1", 3, "2026-01-01T00:00:00+00:00")
            store.update_fp_review_job(
                "review-1", status="error", error_message="Agent 断开连接"
            )

            with patch("backend.api.scan.get_scan_store", return_value=store):
                asyncio.run(scan_api.agent_fp_review_stage_output(
                    "scan-1",
                    AgentFpReviewStageOutput(
                        review_id="review-1",
                        vuln_index=2,
                        stage="prove_bug",
                        markdown="# Prove Bug\n\n正方论证",
                    ),
                ))

            review = store.get_fp_review_job("review-1")
            self.assertEqual(review.status, FpReviewStatus.RUNNING)
            self.assertEqual(review.error_message, "")
            outputs = store.list_fp_review_stage_outputs_by_review("review-1")
            self.assertEqual(len(outputs), 1)
            self.assertEqual(outputs[0].stage, "prove_bug")

    def test_fp_review_merge_keeps_stage_outputs_without_final_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.create_fp_review_job("review-1", "scan-1", 2, "2026-01-01T00:00:00+00:00")
            store.update_fp_review_job("review-1", status="running")
            store.upsert_fp_review_stage_output(
                "review-1", 3, "prove_bug", "# Prove Bug", "2026-01-01T00:01:00+00:00"
            )
            job = store.get_fp_review_job("review-1")

            with patch("backend.api.scan.get_scan_store", return_value=store):
                merged = scan_api._merge_latest_fp_review_results(job, "scan-1")

            entries = [r for r in merged.results if r.vuln_index == 3]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].reason, "")
            self.assertEqual(entries[0].stage_outputs, {"prove_bug": "# Prove Bug"})


if __name__ == "__main__":
    unittest.main()
