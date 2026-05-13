import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from backend.api import agent as agent_api
from backend.api import scan as scan_api
from backend.models import AgentInfo, AgentScanFinish, ScanEvent, ScanItemStatus, ScanMeta, ScanStatus, User
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
        scan_items=["npd"],
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
        scan_items=["npd"],
        created_at="2026-01-01T00:00:00+00:00",
        agent_id=agent_id,
        agent_name=agent_name,
        project_path="/repo/project",
        scan_name="project",
        user_id=user_id,
    )


class AgentReconnectRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        agent_api._running_scans.clear()
        agent_api._scan_owners.clear()
        agent_api._registered_agents.clear()
        agent_api._agent_ws.clear()

    def tearDown(self) -> None:
        agent_api._running_scans.clear()
        agent_api._scan_owners.clear()
        agent_api._registered_agents.clear()
        agent_api._agent_ws.clear()

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

    def test_resume_preserves_total_candidate_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(
                _scan(
                    "scan-1",
                    ScanItemStatus.CANCELLED,
                    total=10,
                    processed=4,
                    error="Agent 断开连接",
                ),
                _meta(),
            )
            agent = AgentInfo(
                agent_id="agent-old",
                name="agent-1",
                ip="127.0.0.1",
                last_seen="2026-01-01T00:01:00+00:00",
                user_id="user-1",
            )
            user = User(user_id="user-1", username="alice", role="user")

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch.dict("backend.api.agent._registered_agents", {"agent-old": agent}, clear=True),
                patch("backend.api.agent.send_agent_command", new=AsyncMock(return_value=True)),
            ):
                asyncio.run(scan_api.resume_scan("scan-1", current_user=user))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.total_candidates, 10)
            self.assertEqual(stored.processed_candidates, 4)
            self.assertEqual(stored.status, ScanItemStatus.PENDING)

    def test_cancel_finish_preserves_total_but_accepts_lower_processed_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            store.save_scan(_scan("scan-1", ScanItemStatus.AUDITING, total=8, processed=5), _meta())
            agent_api._running_scans["scan-1"] = store.load_scan("scan-1")[0]

            with patch("backend.api.agent.get_scan_store", return_value=store):
                asyncio.run(agent_api.agent_finish_scan(
                    "scan-1",
                    AgentScanFinish(
                        vulnerabilities=[],
                        status="cancelled",
                        total_candidates=8,
                        processed_candidates=4,
                    ),
                ))

            stored = store.load_scan("scan-1")[0]
            self.assertEqual(stored.status, ScanItemStatus.CANCELLED)
            self.assertEqual(stored.total_candidates, 8)
            self.assertEqual(stored.processed_candidates, 4)


if __name__ == "__main__":
    unittest.main()
