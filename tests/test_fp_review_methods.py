import asyncio
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from backend.api import agent as agent_api
from backend.api import scan as scan_api
from backend.models import (
    AgentFpReviewFinish,
    AgentFpReviewStageOutput,
    CreateScanRequest,
    FpReviewMethod,
    FpReviewResult,
    OutputSource,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    User,
    Vulnerability,
)
from backend.store.sqlite import SqliteScanStore


def _vulnerability(name: str = "parse") -> Vulnerability:
    return Vulnerability(
        file=f"{name}.c",
        line=10,
        function=name,
        vuln_type="out_of_bounds",
        severity="high",
        description=f"{name} issue",
        ai_analysis="analysis",
        confirmed=True,
        ai_verdict="confirmed",
    )


def _scan(
    now: str,
    *,
    status: ScanItemStatus = ScanItemStatus.COMPLETE,
    method: FpReviewMethod = FpReviewMethod.FP_CHECK,
) -> ScanStatus:
    return ScanStatus(
        scan_id="scan-1",
        project_id="project",
        scan_items=["out_of_bounds"],
        created_at=now,
        status=status,
        progress=1.0 if status == ScanItemStatus.COMPLETE else 0.5,
        total_candidates=2,
        processed_candidates=2 if status == ScanItemStatus.COMPLETE else 1,
        vulnerabilities=[_vulnerability("first"), _vulnerability("second")],
        auto_fp_review=True,
        fp_review_method=method,
    )


def _meta(now: str, method: FpReviewMethod = FpReviewMethod.FP_CHECK) -> ScanMeta:
    return ScanMeta(
        scan_items=["out_of_bounds"],
        created_at=now,
        agent_id="agent-1",
        agent_name="agent",
        project_path="/repo/project",
        scan_name="project",
        user_id="owner",
        auto_fp_review=True,
        fp_review_method=method,
    )


class FpReviewMethodTests(unittest.TestCase):
    def tearDown(self) -> None:
        scan_api._running_scans.clear()
        scan_api._scan_owners.clear()
        agent_api._running_scans.clear()

    def test_create_request_defaults_to_adversarial_and_global_auto_fallback(self) -> None:
        request = CreateScanRequest(
            project_path="/repo",
            checkers=["out_of_bounds"],
        )

        self.assertIsNone(request.auto_fp_review)
        self.assertEqual(request.fp_review_method, FpReviewMethod.ADVERSARIAL)

    def test_scan_and_job_persist_method_auto_setting_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            now = datetime.now(timezone.utc).isoformat()
            scan = _scan(now)
            scan.auto_fp_review = False
            meta = _meta(now)
            meta.auto_fp_review = False
            store.save_scan(scan, meta)
            store.create_fp_review_job(
                "review-1",
                "scan-1",
                2,
                now,
                FpReviewMethod.FP_CHECK.value,
            )
            store.update_fp_review_job(
                "review-1",
                summary_markdown="# 复核汇总",
                summary_output_source=OutputSource(model="provider/model"),
            )

            loaded_scan, loaded_meta = store.load_scan("scan-1")
            job = store.get_fp_review_job("review-1")

        self.assertFalse(loaded_scan.auto_fp_review)
        self.assertFalse(loaded_meta.auto_fp_review)
        self.assertEqual(loaded_scan.fp_review_method, FpReviewMethod.FP_CHECK)
        self.assertEqual(loaded_meta.fp_review_method, FpReviewMethod.FP_CHECK)
        self.assertEqual(job.method, FpReviewMethod.FP_CHECK)
        self.assertEqual(job.summary_markdown, "# 复核汇总")
        self.assertEqual(job.summary_output_source.model, "provider/model")

    def test_fp_check_rerun_selects_only_unresolved_then_full_batch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            now = datetime.now(timezone.utc).isoformat()
            scan = _scan(now)
            store.save_scan(scan, _meta(now))
            for vulnerability in scan.vulnerabilities:
                store.add_vulnerability("scan-1", vulnerability)
            store.create_fp_review_job(
                "review-1",
                "scan-1",
                2,
                now,
                FpReviewMethod.FP_CHECK.value,
            )
            store.add_fp_review_result(
                "review-1",
                FpReviewResult(
                    vuln_index=0,
                    verdict="fp",
                    severity="low",
                    reason="caller enforces the bound",
                    created_at=now,
                ),
            )
            with patch("backend.api.scan.get_scan_store", return_value=store):
                first = scan_api._ensure_fp_review_job_for_scan(
                    "scan-1",
                    publish_started=False,
                )
                store.add_fp_review_result(
                    "review-1",
                    FpReviewResult(
                        vuln_index=1,
                        verdict="tp",
                        severity="high",
                        reason="all six gates pass",
                        created_at=now,
                    ),
                )
                second = scan_api._ensure_fp_review_job_for_scan(
                    "scan-1",
                    publish_started=False,
                )

        self.assertEqual(
            [item["index"] for item in first["confirmed"]],
            [1],
        )
        self.assertEqual(
            [item["index"] for item in second["confirmed"]],
            [0, 1],
        )

    def test_fp_check_manual_start_is_blocked_until_scan_complete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            now = datetime.now(timezone.utc).isoformat()
            store.save_scan(
                _scan(now, status=ScanItemStatus.AUDITING),
                _meta(now),
            )
            with patch("backend.api.scan.get_scan_store", return_value=store):
                with self.assertRaises(HTTPException) as raised:
                    asyncio.run(scan_api._start_fp_review(
                        "scan-1",
                        "http://127.0.0.1:8000",
                        raise_on_error=True,
                    ))

            self.assertEqual(raised.exception.status_code, 409)
            self.assertIsNone(store.get_fp_review_by_scan("scan-1"))

    def test_fp_check_skill_preview_uses_chinese_runtime_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            now = datetime.now(timezone.utc).isoformat()
            store.save_scan(_scan(now), _meta(now))
            scan_api._scan_owners["scan-1"] = "owner"
            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.api.scan._selected_feedback_entries",
                    return_value=[],
                ),
            ):
                result = asyncio.run(scan_api.get_fp_review_skill(
                    "scan-1",
                    current_user=User(
                        user_id="owner",
                        username="owner",
                        role="user",
                    ),
                ))

        self.assertIn("# 证据门禁复核", result["content"])
        self.assertIn("# 六道门复核", result["content"])
        self.assertIn("# 数据流分析器", result["content"])

    def test_fp_check_stage_whitelist_and_batch_summary_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            now = datetime.now(timezone.utc).isoformat()
            store.create_fp_review_job(
                "review-1",
                "scan-1",
                1,
                now,
                FpReviewMethod.FP_CHECK.value,
            )
            with patch("backend.api.scan.get_scan_store", return_value=store):
                accepted = asyncio.run(scan_api.agent_fp_review_stage_output(
                    "scan-1",
                    AgentFpReviewStageOutput(
                        review_id="review-1",
                        vuln_index=0,
                        stage="claim_context",
                        markdown="# 主张与上下文",
                    ),
                ))
                with self.assertRaises(HTTPException) as rejected:
                    asyncio.run(scan_api.agent_fp_review_stage_output(
                        "scan-1",
                        AgentFpReviewStageOutput(
                            review_id="review-1",
                            vuln_index=0,
                            stage="prove_bug",
                            markdown="# wrong workflow",
                        ),
                    ))
                asyncio.run(scan_api.agent_fp_review_finish(
                    "scan-1",
                    AgentFpReviewFinish(
                        review_id="review-1",
                        status="complete",
                        summary_markdown="# 批次汇总",
                        summary_output_source=OutputSource(model="provider/model"),
                    ),
                ))

            job = store.get_fp_review_job("review-1")

        self.assertTrue(accepted["ok"])
        self.assertEqual(rejected.exception.status_code, 400)
        self.assertEqual(job.summary_markdown, "# 批次汇总")
        self.assertEqual(job.summary_output_source.model, "provider/model")

    def test_fp_check_does_not_enqueue_incremental_review_on_vulnerability_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            now = datetime.now(timezone.utc).isoformat()
            scan = _scan(now, status=ScanItemStatus.AUDITING)
            scan.vulnerabilities = []
            store.save_scan(scan, _meta(now))
            agent_api._running_scans["scan-1"] = scan
            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.scan.get_scan_store", return_value=store),
            ):
                response = asyncio.run(agent_api.agent_report_vulnerability(
                    "scan-1",
                    _vulnerability(),
                ))

        self.assertNotIn("fp_review", response)
        self.assertIsNone(store.get_fp_review_by_scan("scan-1"))
