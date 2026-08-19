import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from backend.api import scan as scan_api
from backend.models import (
    FpReviewResult,
    FpReviewStatus,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    User,
    Vulnerability,
)
from backend.store.sqlite import SqliteScanStore


async def _direct_store_call(store, operation, *args, **kwargs):
    function = getattr(store, operation) if isinstance(operation, str) else operation
    return function(*args, **kwargs)


def _scan(status: ScanItemStatus) -> ScanStatus:
    return ScanStatus(
        scan_id="scan-1",
        project_id="project",
        scan_items=["npd"],
        created_at="2026-08-11T00:00:00+00:00",
        status=status,
        progress=1.0 if status == ScanItemStatus.COMPLETE else 0.5,
        total_candidates=2,
        processed_candidates=2 if status == ScanItemStatus.COMPLETE else 1,
        vulnerabilities=[],
    )


def _meta() -> ScanMeta:
    return ScanMeta(
        scan_items=["npd"],
        created_at="2026-08-11T00:00:00+00:00",
        agent_id="agent-old",
        agent_key="stable-agent",
        agent_name="agent-1",
        project_path="/repo/project",
        scan_name="project",
        user_id="user-1",
    )


def _vulnerability(index: int) -> Vulnerability:
    return Vulnerability(
        file=f"file-{index}.c",
        line=index + 1,
        function=f"function_{index}",
        vuln_type="npd",
        severity="high",
        description=f"finding {index}",
        ai_analysis="confirmed issue",
        confirmed=True,
        ai_verdict="confirmed",
    )


class ScanFpReviewLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        scan_api._running_scans.clear()
        scan_api._scan_owners.clear()

    def tearDown(self) -> None:
        scan_api._running_scans.clear()
        scan_api._scan_owners.clear()

    def test_stop_notifies_main_scan_and_all_active_fp_reviews(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            scan = _scan(ScanItemStatus.AUDITING)
            store.save_scan(scan, _meta())
            store.create_fp_review_job(
                "review-pending", "scan-1", 2, "2026-08-11T00:01:00+00:00"
            )
            store.create_fp_review_job(
                "review-running", "scan-1", 2, "2026-08-11T00:02:00+00:00"
            )
            store.update_fp_review_job("review-running", status="running")
            scan_api._running_scans["scan-1"] = scan
            send = AsyncMock(return_value=True)

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.api.scan.run_store_call", new=_direct_store_call),
                patch(
                    "backend.api.scan._resolve_scan_agent_id",
                    new=AsyncMock(return_value="agent-live"),
                ),
                patch("backend.api.agent.send_agent_command", new=send),
            ):
                response = asyncio.run(
                    scan_api.stop_scan(
                        "scan-1",
                        User(user_id="user-1", username="alice", role="user"),
                    )
                )

            self.assertTrue(response["main_scan_stopped"])
            self.assertEqual(
                response["fp_review_ids"],
                ["review-pending", "review-running"],
            )
            self.assertEqual(store.load_scan("scan-1")[0].status, ScanItemStatus.CANCELLED)
            self.assertEqual(
                [status for _, status in store.list_fp_review_states_by_scans(["scan-1"])["scan-1"]],
                ["cancelled", "cancelled"],
            )
            payloads = [call.args[1] for call in send.await_args_list]
            self.assertEqual(
                [payload["type"] for payload in payloads],
                ["stop", "fp_review_stop", "fp_review_stop"],
            )

    def test_resume_complete_scan_dispatches_only_unresolved_stopped_fp_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            store.save_scan(_scan(ScanItemStatus.COMPLETE), _meta())
            store.add_vulnerability("scan-1", _vulnerability(0))
            store.add_vulnerability("scan-1", _vulnerability(1))
            store.create_fp_review_job(
                "review-complete", "scan-1", 1, "2026-08-11T00:01:00+00:00"
            )
            store.add_fp_review_result(
                "review-complete",
                FpReviewResult(
                    vuln_index=0,
                    verdict="tp",
                    severity="high",
                    reason="confirmed",
                    created_at="2026-08-11T00:01:30+00:00",
                ),
            )
            store.update_fp_review_job("review-complete", status="complete", processed=1)
            store.create_fp_review_job(
                "review-stopped", "scan-1", 2, "2026-08-11T00:02:00+00:00"
            )
            store.update_fp_review_job("review-stopped", status="running", processed=1)
            user = User(user_id="user-1", username="alice", role="user")
            send = AsyncMock(return_value=True)

            common_patches = (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.api.scan.run_store_call", new=_direct_store_call),
                patch(
                    "backend.api.scan._resolve_scan_agent_id",
                    new=AsyncMock(return_value="agent-live"),
                ),
                patch("backend.api.agent.send_agent_command", new=send),
            )
            with common_patches[0], common_patches[1], common_patches[2], common_patches[3]:
                asyncio.run(scan_api.stop_scan("scan-1", user))

            self.assertEqual(store.load_scan("scan-1")[0].status, ScanItemStatus.COMPLETE)
            self.assertEqual(
                store.get_fp_review_job("review-stopped").status,
                FpReviewStatus.CANCELLED,
            )
            send.reset_mock()

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.api.scan.run_store_call", new=_direct_store_call),
                patch(
                    "backend.api.scan._resolve_scan_agent_id",
                    new=AsyncMock(return_value="agent-live"),
                ),
                patch(
                    "backend.api.agent.ensure_agent_accepting_tasks_async",
                    new=AsyncMock(return_value=None),
                ),
                patch(
                    "backend.api.agent.create_agent_task_runtime_update_payload_async",
                    new=AsyncMock(return_value=None),
                ),
                patch("backend.api.agent.send_agent_command", new=send),
            ):
                response = asyncio.run(
                    scan_api.resume_scan(
                        "scan-1",
                        request=SimpleNamespace(base_url="http://testserver/"),
                        current_user=user,
                    )
                )

            self.assertEqual(response.scan_id, "scan-1")
            self.assertEqual(store.load_scan("scan-1")[0].status, ScanItemStatus.COMPLETE)
            latest = store.get_fp_review_by_scan("scan-1")
            self.assertNotEqual(latest.review_id, "review-stopped")
            self.assertEqual(latest.status, FpReviewStatus.RUNNING)
            send.assert_awaited_once()
            payload = send.await_args.args[1]
            self.assertEqual(payload["type"], "fp_review")
            self.assertEqual(
                [item["index"] for item in payload["vulnerabilities"]],
                [1],
            )

    def test_resume_complete_scan_dispatches_partial_complete_fp_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            store.save_scan(_scan(ScanItemStatus.COMPLETE), _meta())
            store.add_vulnerability("scan-1", _vulnerability(0))
            store.add_vulnerability("scan-1", _vulnerability(1))
            store.create_fp_review_job(
                "review", "scan-1", 2, "2026-08-11T00:01:00+00:00"
            )
            store.add_fp_review_result(
                "review",
                FpReviewResult(
                    vuln_index=0,
                    verdict="tp",
                    severity="high",
                    reason="confirmed",
                    created_at="2026-08-11T00:01:30+00:00",
                ),
            )
            store.update_fp_review_job("review", status="complete", processed=2)
            send = AsyncMock(return_value=True)

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.api.scan.run_store_call", new=_direct_store_call),
                patch(
                    "backend.api.scan._resolve_scan_agent_id",
                    new=AsyncMock(return_value="agent-live"),
                ),
                patch(
                    "backend.api.agent.ensure_agent_accepting_tasks_async",
                    new=AsyncMock(return_value=None),
                ),
                patch(
                    "backend.api.agent.create_agent_task_runtime_update_payload_async",
                    new=AsyncMock(return_value=None),
                ),
                patch("backend.api.agent.send_agent_command", new=send),
            ):
                response = asyncio.run(
                    scan_api.resume_scan(
                        "scan-1",
                        request=SimpleNamespace(base_url="http://testserver/"),
                        current_user=User(
                            user_id="user-1",
                            username="alice",
                            role="user",
                        ),
                    )
                )

            self.assertEqual(response.scan_id, "scan-1")
            self.assertEqual(store.get_fp_review_job("review").status, FpReviewStatus.RUNNING)
            send.assert_awaited_once()
            payload = send.await_args.args[1]
            self.assertEqual(payload["type"], "fp_review")
            self.assertEqual(
                [item["index"] for item in payload["vulnerabilities"]],
                [1],
            )

    def test_resume_complete_scan_starts_fp_work_without_prior_job(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            store.save_scan(_scan(ScanItemStatus.COMPLETE), _meta())
            store.add_vulnerability("scan-1", _vulnerability(0))
            store.add_vulnerability("scan-1", _vulnerability(1))
            send = AsyncMock(return_value=True)

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.api.scan.run_store_call", new=_direct_store_call),
                patch(
                    "backend.api.scan._resolve_scan_agent_id",
                    new=AsyncMock(return_value="agent-live"),
                ),
                patch(
                    "backend.api.agent.ensure_agent_accepting_tasks_async",
                    new=AsyncMock(return_value=None),
                ),
                patch(
                    "backend.api.agent.create_agent_task_runtime_update_payload_async",
                    new=AsyncMock(return_value=None),
                ),
                patch("backend.api.agent.send_agent_command", new=send),
            ):
                response = asyncio.run(
                    scan_api.resume_scan(
                        "scan-1",
                        request=SimpleNamespace(base_url="http://testserver/"),
                        current_user=User(
                            user_id="user-1",
                            username="alice",
                            role="user",
                        ),
                    )
                )

            self.assertEqual(response.scan_id, "scan-1")
            latest = store.get_fp_review_by_scan("scan-1")
            self.assertIsNotNone(latest)
            self.assertEqual(latest.status, FpReviewStatus.RUNNING)
            send.assert_awaited_once()
            payload = send.await_args.args[1]
            self.assertEqual(payload["type"], "fp_review")
            self.assertEqual(
                [item["index"] for item in payload["vulnerabilities"]],
                [0, 1],
            )


if __name__ == "__main__":
    unittest.main()
