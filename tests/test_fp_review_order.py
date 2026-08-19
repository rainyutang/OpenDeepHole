import asyncio
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from backend.api import agent as agent_api
from backend.api import scan as scan_api
from backend.store.sqlite import SqliteScanStore
from backend.api.scan import (
    _ensure_fp_review_job_for_scan,
    _fp_review_resume_state,
    _ordered_fp_review_candidates,
    _retry_incomplete_candidates,
)
from backend.models import (
    AgentFpReviewFinish,
    AgentInfo,
    BatchUnmarkRequest,
    FeedbackEntry,
    FpReviewResult,
    FpReviewStatus,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    UnmarkRequest,
    User,
    Vulnerability,
)
from backend.scan_metrics import latest_fp_review_result_map


async def _direct_store_call(store, operation, *args, **kwargs):
    function = getattr(store, operation) if isinstance(operation, str) else operation
    return function(*args, **kwargs)


class FpReviewOrderTests(unittest.TestCase):
    def tearDown(self) -> None:
        agent_api._registered_agents.clear()
        agent_api._agent_ws.clear()
        agent_api._agent_ws_locks.clear()
        scan_api._running_scans.clear()
        scan_api._scan_owners.clear()

    def test_fp_review_skill_preview_reads_process_owned_skills(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            scan_api._scan_owners["scan-1"] = "user-1"
            with (
                patch(
                    "backend.api.scan._selected_feedback_entries",
                    return_value=[],
                ),
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.api.scan.run_store_call", new=_direct_store_call),
            ):
                result = asyncio.run(
                    scan_api.get_fp_review_skill(
                        "scan-1",
                        current_user=User(
                            user_id="user-1",
                            username="alice",
                            role="user",
                        ),
                    )
                )

        self.assertIn("# Prove Bug Skill", result["content"])
        self.assertIn("# Prove False Positive Skill", result["content"])
        self.assertIn("# Final Judge Skill", result["content"])

    def test_unreviewed_findings_are_reviewed_before_existing_results(self) -> None:
        scan = ScanStatus(
            scan_id="scan-1",
            project_id="project",
            scan_items=["npd"],
            created_at="2026-01-01T00:00:00+00:00",
            status=ScanItemStatus.COMPLETE,
            progress=1.0,
            total_candidates=4,
            processed_candidates=4,
            vulnerabilities=[
                Vulnerability(
                    file="reviewed.c",
                    line=1,
                    function="reviewed",
                    vuln_type="npd",
                    severity="high",
                    description="reviewed",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                ),
                Vulnerability(
                    file="unreviewed.c",
                    line=2,
                    function="unreviewed",
                    vuln_type="npd",
                    severity="high",
                    description="unreviewed",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                ),
                Vulnerability(
                    file="manual.c",
                    line=3,
                    function="manual",
                    vuln_type="npd",
                    severity="high",
                    description="manual feedback",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                    user_verdict="confirmed",
                ),
                Vulnerability(
                    file="pending.c",
                    line=4,
                    function="pending",
                    vuln_type="npd",
                    severity="high",
                    description="pending manual analysis",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                    user_verdict="pending_analysis",
                ),
            ],
        )
        latest = latest_fp_review_result_map([
            FpReviewResult(
                vuln_index=0,
                verdict="fp",
                severity="low",
                reason="reviewed false positive",
                created_at="2026-01-01T00:01:00+00:00",
            ),
        ])

        ordered = _ordered_fp_review_candidates(scan, latest)

        self.assertEqual([item["index"] for item in ordered], [1, 3, 0])

    def test_historical_fp_flags_do_not_exclude_review_candidates(self) -> None:
        scan = ScanStatus(
            scan_id="scan-1",
            project_id="project",
            created_at="2026-01-01T00:00:00+00:00",
            status=ScanItemStatus.COMPLETE,
            progress=1.0,
            total_candidates=2,
            processed_candidates=2,
            vulnerabilities=[
                Vulnerability.model_validate(dict(
                    file="eligible.c",
                    line=1,
                    function="eligible",
                    vuln_type="npd",
                    severity="high",
                    description="eligible",
                    confirmed=True,
                    ai_verdict="confirmed",
                    fp_review_eligible=True,
                )),
                Vulnerability.model_validate(dict(
                    file="direct.c",
                    line=2,
                    function="direct",
                    vuln_type="npd",
                    severity="high",
                    description="direct output",
                    confirmed=True,
                    ai_verdict="confirmed",
                    engine_id="direct_engine",
                    engine_label="Direct engine",
                    fp_review_eligible=False,
                )),
            ],
        )

        ordered = _ordered_fp_review_candidates(scan, {})

        self.assertEqual(
            [item["index"] for item in ordered],
            [0, 1],
        )

    def test_provisional_findings_are_read_only_for_scan_actions(self) -> None:
        scan = ScanStatus(
            scan_id="scan-1",
            project_id="project",
            created_at="2026-01-01T00:00:00+00:00",
            status=ScanItemStatus.AUDITING,
            progress=0.5,
            total_candidates=3,
            processed_candidates=1,
            vulnerabilities=[
                Vulnerability(
                    file="streamed.c",
                    line=1,
                    function="streamed",
                    vuln_type="npd",
                    severity="high",
                    description="streamed",
                    confirmed=True,
                    ai_verdict="confirmed",
                    provisional=True,
                ),
                Vulnerability(
                    file="timeout.c",
                    line=2,
                    function="timeout",
                    vuln_type="npd",
                    severity="unknown",
                    description="timeout",
                    confirmed=False,
                    ai_verdict="timeout",
                    provisional=True,
                ),
                Vulnerability(
                    file="final.c",
                    line=3,
                    function="final",
                    vuln_type="npd",
                    severity="high",
                    description="final",
                    confirmed=True,
                    ai_verdict="confirmed",
                ),
            ],
        )

        self.assertEqual(
            [item["index"] for item in _ordered_fp_review_candidates(scan, {})],
            [2],
        )
        self.assertEqual(_retry_incomplete_candidates(scan), [])
        self.assertEqual(
            _fp_review_resume_state(
                scan.vulnerabilities,
                {},
                [("review-1", FpReviewStatus.ERROR.value)],
            ),
            (False, 1),
        )

    def test_provisional_finding_rejects_feedback_and_validation_mutations(self) -> None:
        scan = ScanStatus(
            scan_id="scan-1",
            project_id="project",
            created_at="2026-01-01T00:00:00+00:00",
            status=ScanItemStatus.AUDITING,
            progress=0.5,
            total_candidates=1,
            processed_candidates=1,
            vulnerabilities=[
                Vulnerability(
                    file="streamed.c",
                    line=1,
                    function="streamed",
                    vuln_type="npd",
                    severity="high",
                    description="streamed",
                    confirmed=True,
                    ai_verdict="confirmed",
                    provisional=True,
                ),
            ],
        )

        with self.assertRaises(HTTPException) as marked:
            asyncio.run(scan_api._mark_single(
                scan.scan_id,
                scan,
                object(),
                0,
                "confirmed",
                "verified",
            ))
        self.assertEqual(marked.exception.status_code, 409)

        with self.assertRaises(HTTPException) as unmarked:
            asyncio.run(scan_api._unmark_single(
                scan.scan_id,
                scan,
                object(),
                0,
            ))
        self.assertEqual(unmarked.exception.status_code, 409)

        with (
            patch("backend.api.scan.get_scan_store", return_value=object()),
            patch(
                "backend.api.scan.run_store_call",
                new=AsyncMock(return_value=(scan, SimpleNamespace())),
            ),
        ):
            with self.assertRaises(HTTPException) as validation:
                asyncio.run(scan_api._trigger_vulnerability_validation(
                    scan.scan_id,
                    0,
                    "http://testserver/",
                ))
        self.assertEqual(validation.exception.status_code, 409)

    def test_pending_analysis_does_not_block_incomplete_retry(self) -> None:
        scan = ScanStatus(
            scan_id="scan-1",
            project_id="project",
            scan_items=["npd"],
            created_at="2026-01-01T00:00:00+00:00",
            status=ScanItemStatus.COMPLETE,
            progress=1.0,
            total_candidates=2,
            processed_candidates=2,
            vulnerabilities=[
                Vulnerability(
                    file="pending.c",
                    line=1,
                    function="pending",
                    vuln_type="npd",
                    severity="unknown",
                    description="timeout pending",
                    ai_analysis="analysis",
                    confirmed=False,
                    ai_verdict="timeout",
                    user_verdict="pending_analysis",
                ),
                Vulnerability(
                    file="manual.c",
                    line=2,
                    function="manual",
                    vuln_type="npd",
                    severity="unknown",
                    description="timeout manual",
                    ai_analysis="analysis",
                    confirmed=False,
                    ai_verdict="timeout",
                    user_verdict="false_positive",
                ),
                Vulnerability(
                    file=".",
                    line=1,
                    function="__threat_path__",
                    vuln_type="threat_audit",
                    severity="unknown",
                    description="timeout threat audit",
                    ai_analysis="analysis",
                    confirmed=False,
                    ai_verdict="timeout",
                    analysis_source="threat_audit",
                ),
            ],
        )

        candidates = _retry_incomplete_candidates(scan)

        self.assertEqual([candidate.function for candidate in candidates], ["pending"])

    def test_legacy_no_result_placeholder_is_not_effective(self) -> None:
        latest = latest_fp_review_result_map([
            FpReviewResult(
                vuln_index=0,
                verdict="tp",
                severity="low",
                reason="Review incomplete — no result returned",
                created_at="2026-01-01T00:01:00+00:00",
            ),
            FpReviewResult(
                vuln_index=1,
                verdict="tp",
                severity="medium",
                reason="real result",
                created_at="2026-01-01T00:02:00+00:00",
            ),
        ])

        self.assertNotIn(0, latest)
        self.assertIn(1, latest)

    def test_manual_review_dispatches_unresolved_then_all_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            now = datetime.now(timezone.utc).isoformat()
            scan = ScanStatus(
                scan_id="scan-1",
                project_id="project",
                scan_items=["npd"],
                created_at=now,
                status=ScanItemStatus.COMPLETE,
                progress=1.0,
                total_candidates=2,
                processed_candidates=2,
                vulnerabilities=[
                    Vulnerability(
                        file="reviewed.c",
                        line=10,
                        function="reviewed",
                        vuln_type="npd",
                        severity="high",
                        description="already reviewed",
                        ai_analysis="analysis",
                        confirmed=True,
                        ai_verdict="confirmed",
                    ),
                    Vulnerability(
                        file="pending.c",
                        line=20,
                        function="pending",
                        vuln_type="npd",
                        severity="high",
                        description="awaiting review",
                        ai_analysis="analysis",
                        confirmed=True,
                        ai_verdict="confirmed",
                    ),
                ],
            )
            store.save_scan(
                scan,
                ScanMeta(scan_items=["npd"], created_at=now, user_id="owner"),
            )
            store.create_fp_review_job("review", "scan-1", 2, now)
            store.add_fp_review_result(
                "review",
                FpReviewResult(
                    vuln_index=0,
                    verdict="tp",
                    severity="high",
                    reason="first result",
                    created_at=now,
                ),
            )
            store.update_fp_review_job("review", status="complete", processed=1)

            with patch("backend.api.scan.get_scan_store", return_value=store):
                partial = _ensure_fp_review_job_for_scan(
                    "scan-1",
                    scan,
                    allow_cancelled=True,
                    publish_started=False,
                )

            self.assertEqual(
                [item["index"] for item in partial["confirmed"]],
                [1],
            )
            self.assertEqual(partial["processed"], 1)

            store.add_fp_review_result(
                "review",
                FpReviewResult(
                    vuln_index=1,
                    verdict="fp",
                    severity="low",
                    reason="second result",
                    created_at=now,
                ),
            )
            store.update_fp_review_job("review", status="complete", processed=2)
            with patch("backend.api.scan.get_scan_store", return_value=store):
                rerun = _ensure_fp_review_job_for_scan(
                    "scan-1",
                    scan,
                    allow_cancelled=True,
                    publish_started=False,
                )

            self.assertEqual(
                [item["index"] for item in rerun["confirmed"]],
                [0, 1],
            )
            self.assertEqual(rerun["processed"], 0)

    def test_trigger_fp_review_dispatches_runtime_update(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            user = User(user_id="owner", username="owner", role="user")
            now = datetime.now(timezone.utc).isoformat()
            scan = ScanStatus(
                scan_id="scan-1",
                project_id="project",
                scan_items=["npd"],
                created_at=now,
                status=ScanItemStatus.COMPLETE,
                progress=1.0,
                total_candidates=1,
                processed_candidates=1,
                vulnerabilities=[
                    Vulnerability(
                        file="a.c",
                        line=10,
                        function="parse",
                        vuln_type="npd",
                        severity="high",
                        description="desc",
                        ai_analysis="analysis",
                        confirmed=True,
                        ai_verdict="confirmed",
                    ),
                ],
            )
            meta = ScanMeta(
                scan_items=["npd"],
                created_at=now,
                agent_id="agent-1",
                agent_name="agent",
                project_path="/repo/project",
                scan_name="project",
                user_id="owner",
            )
            store.save_scan(scan, meta)
            scan_api._running_scans["scan-1"] = scan
            scan_api._scan_owners["scan-1"] = "owner"
            agent_api._registered_agents["agent-1"] = AgentInfo(
                agent_id="agent-1",
                name="agent",
                ip="127.0.0.1",
                last_seen=now,
                user_id="owner",
            )
            agent_api._agent_ws["agent-1"] = object()
            send = AsyncMock(return_value=True)

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.api.scan.run_store_call", new=_direct_store_call),
                patch("backend.api.agent.send_agent_command", send),
                patch(
                    "backend.api.agent.create_agent_task_runtime_update_payload_async",
                    new=AsyncMock(return_value={"hash": "runtime-hash"}),
                ) as runtime_update,
            ):
                result = asyncio.run(
                    scan_api.trigger_fp_review(
                        "scan-1",
                        SimpleNamespace(base_url="http://server.example/"),
                        user,
                    )
                )

            self.assertTrue(result["ok"])
            self.assertEqual(result["status"], "running")
            self.assertEqual(result["total"], 1)
            self.assertEqual(result["processed"], 0)
            runtime_update.assert_awaited_once_with("http://server.example", "")
            command = send.await_args.args[1]
            self.assertEqual(command["type"], "fp_review")
            self.assertEqual(command["agent_runtime_update"], {"hash": "runtime-hash"})

    def test_auto_fp_review_does_not_restart_when_all_findings_have_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            now = datetime.now(timezone.utc).isoformat()
            scan = ScanStatus(
                scan_id="scan-1",
                project_id="project",
                scan_items=["npd"],
                created_at=now,
                status=ScanItemStatus.COMPLETE,
                progress=1.0,
                total_candidates=1,
                processed_candidates=1,
                vulnerabilities=[
                    Vulnerability(
                        file="a.c",
                        line=10,
                        function="parse",
                        vuln_type="npd",
                        severity="high",
                        description="desc",
                        ai_analysis="analysis",
                        confirmed=True,
                        ai_verdict="confirmed",
                    ),
                ],
            )
            store.save_scan(scan, ScanMeta(scan_items=["npd"], created_at=now, user_id="owner"))
            store.create_fp_review_job("review", "scan-1", 1, now)
            store.add_fp_review_result(
                "review",
                FpReviewResult(
                    vuln_index=0,
                    verdict="tp",
                    severity="high",
                    reason="already reviewed",
                    vulnerability_report="",
                    created_at=now,
                ),
            )
            store.update_fp_review_job("review", status="complete", processed=1)

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.sse.publish") as publish,
            ):
                info = _ensure_fp_review_job_for_scan(
                    "scan-1",
                    scan,
                    require_unresolved=True,
                    publish_started=True,
                )

            self.assertIsNotNone(info)
            self.assertTrue(info["no_unresolved"])
            job = store.get_fp_review_job("review")
            self.assertIsNotNone(job)
            self.assertEqual(job.status.value, "complete")
            publish.assert_not_called()

    def test_unexpected_agent_cancel_is_retryable_for_next_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            now = datetime.now(timezone.utc).isoformat()
            scan = ScanStatus(
                scan_id="scan-1",
                project_id="project",
                scan_items=["npd"],
                created_at=now,
                status=ScanItemStatus.AUDITING,
                progress=0.5,
                total_candidates=2,
                processed_candidates=1,
                auto_fp_review=True,
                vulnerabilities=[
                    Vulnerability(
                        file="first.c",
                        line=10,
                        function="first",
                        vuln_type="npd",
                        severity="high",
                        description="first finding",
                        ai_analysis="analysis",
                        confirmed=True,
                        ai_verdict="confirmed",
                    ),
                ],
            )
            meta = ScanMeta(
                scan_items=["npd"],
                created_at=now,
                agent_id="agent-1",
                agent_name="agent",
                project_path="/repo/project",
                scan_name="project",
                user_id="owner",
                auto_fp_review=True,
            )
            store.save_scan(scan, meta)
            store.add_vulnerability("scan-1", scan.vulnerabilities[0])
            store.create_fp_review_job("review-1", "scan-1", 1, now)
            store.update_fp_review_job("review-1", status="running")
            scan_api._running_scans["scan-1"] = scan
            published: list[tuple[str, str, dict]] = []

            with (
                patch("backend.api.agent.get_scan_store", return_value=store),
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.api.agent.run_store_call",
                    new=_direct_store_call,
                ),
                patch(
                    "backend.api.scan.run_store_call",
                    new=_direct_store_call,
                ),
                patch(
                    "backend.sse.publish",
                    side_effect=lambda scan_id, event_type, data: published.append(
                        (scan_id, event_type, data)
                    ),
                ),
            ):
                asyncio.run(scan_api.agent_fp_review_finish(
                    "scan-1",
                    AgentFpReviewFinish(
                        review_id="review-1",
                        status="cancelled",
                        error_message="model task was interrupted",
                    ),
                ))
                interrupted = store.get_fp_review_job("review-1")
                self.assertEqual(interrupted.status, FpReviewStatus.ERROR)

                response = asyncio.run(agent_api.agent_report_vulnerability(
                    "scan-1",
                    Vulnerability(
                        file="second.c",
                        line=20,
                        function="second",
                        vuln_type="npd",
                        severity="high",
                        description="second finding",
                        ai_analysis="analysis",
                        confirmed=True,
                        ai_verdict="confirmed",
                    ),
                ))

            self.assertEqual(response["index"], 1)
            self.assertEqual(response["fp_review"]["review_id"], "review-1")
            self.assertTrue(response["fp_review"]["queued"])
            resumed = store.get_fp_review_job("review-1")
            self.assertEqual(resumed.status, FpReviewStatus.RUNNING)
            finish_events = [
                data
                for _scan_id, event_type, data in published
                if event_type == "fp_review_finish"
            ]
            self.assertEqual(finish_events[0]["status"], "error")

    def test_agent_finish_cannot_override_explicit_user_stop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            now = datetime.now(timezone.utc).isoformat()
            store.create_fp_review_job("review-1", "scan-1", 1, now)
            store.update_fp_review_job(
                "review-1",
                status="cancelled",
                error_message="用户手动停止",
            )

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch(
                    "backend.api.scan.run_store_call",
                    new=_direct_store_call,
                ),
                patch("backend.sse.publish") as publish,
            ):
                asyncio.run(scan_api.agent_fp_review_finish(
                    "scan-1",
                    AgentFpReviewFinish(
                        review_id="review-1",
                        status="complete",
                    ),
                ))

            job = store.get_fp_review_job("review-1")
            self.assertEqual(job.status, FpReviewStatus.CANCELLED)
            self.assertEqual(job.error_message, "用户手动停止")
            publish.assert_not_called()

    def test_unmark_removes_generated_feedback_and_readds_fp_review_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            user = User(user_id="owner", username="owner", role="user")
            now = datetime.now(timezone.utc).isoformat()
            scan = ScanStatus(
                scan_id="scan-1",
                project_id="project",
                scan_items=["npd"],
                created_at=now,
                status=ScanItemStatus.COMPLETE,
                progress=1.0,
                total_candidates=1,
                processed_candidates=1,
                vulnerabilities=[],
                feedback_ids=["feedback-1", "keep"],
            )
            meta = ScanMeta(
                scan_items=["npd"],
                created_at=now,
                feedback_ids=["feedback-1", "keep"],
                user_id="owner",
            )
            store.save_scan(scan, meta)
            store.add_vulnerability(
                "scan-1",
                Vulnerability(
                    file="a.c",
                    line=10,
                    function="parse",
                    vuln_type="npd",
                    severity="high",
                    description="desc",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                    user_verdict="confirmed",
                    user_verdict_reason="verified",
                ),
            )
            store.add_feedback(
                FeedbackEntry(
                    id="feedback-1",
                    project_id="project",
                    vuln_type="npd",
                    verdict="confirmed",
                    file="a.c",
                    line=10,
                    function="parse",
                    description="desc",
                    reason="verified",
                    source_scan_id="scan-1",
                    created_at=now,
                    updated_at=now,
                )
            )
            push = AsyncMock()

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.api.scan.run_store_call", new=_direct_store_call),
                patch("backend.api.scan._push_feedback_selection_update", push),
            ):
                result = asyncio.run(
                    scan_api.unmark_vulnerability("scan-1", UnmarkRequest(index=0), user)
                )

            self.assertEqual(result["removed_feedback_ids"], ["feedback-1"])
            loaded = store.load_scan("scan-1")
            self.assertIsNotNone(loaded)
            updated_scan, updated_meta = loaded
            self.assertEqual(updated_scan.feedback_ids, ["keep"])
            self.assertEqual(updated_meta.feedback_ids, ["keep"])
            self.assertIsNone(updated_scan.vulnerabilities[0].user_verdict)
            self.assertEqual([item["index"] for item in _ordered_fp_review_candidates(updated_scan, {})], [0])
            push.assert_awaited_once_with("scan-1", ["keep"])

    def test_batch_unmark_clears_multiple_manual_verdicts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scan.db")
            user = User(user_id="owner", username="owner", role="user")
            now = datetime.now(timezone.utc).isoformat()
            scan = ScanStatus(
                scan_id="scan-1",
                project_id="project",
                scan_items=["npd"],
                created_at=now,
                status=ScanItemStatus.COMPLETE,
                progress=1.0,
                total_candidates=2,
                processed_candidates=2,
                vulnerabilities=[],
                feedback_ids=["feedback-1", "feedback-2"],
            )
            meta = ScanMeta(
                scan_items=["npd"],
                created_at=now,
                feedback_ids=["feedback-1", "feedback-2"],
                user_id="owner",
            )
            store.save_scan(scan, meta)
            for index in range(2):
                store.add_vulnerability(
                    "scan-1",
                    Vulnerability(
                        file=f"a{index}.c",
                        line=10 + index,
                        function="parse",
                        vuln_type="npd",
                        severity="high",
                        description=f"desc {index}",
                        ai_analysis="analysis",
                        confirmed=True,
                        ai_verdict="confirmed",
                        user_verdict="confirmed",
                    ),
                )
                store.add_feedback(
                    FeedbackEntry(
                        id=f"feedback-{index + 1}",
                        project_id="project",
                        vuln_type="npd",
                        verdict="confirmed",
                        file=f"a{index}.c",
                        line=10 + index,
                        function="parse",
                        description=f"desc {index}",
                        reason="verified",
                        source_scan_id="scan-1",
                        created_at=now,
                        updated_at=now,
                    )
                )

            with (
                patch("backend.api.scan.get_scan_store", return_value=store),
                patch("backend.api.scan.run_store_call", new=_direct_store_call),
            ):
                result = asyncio.run(
                    scan_api.batch_unmark_vulnerabilities(
                        "scan-1",
                        BatchUnmarkRequest(indices=[0, 1, 1]),
                        user,
                    )
                )

            self.assertEqual(result["removed_feedback_ids"], ["feedback-1", "feedback-2"])
            updated_scan, updated_meta = store.load_scan("scan-1")
            self.assertEqual(updated_scan.feedback_ids, [])
            self.assertEqual(updated_meta.feedback_ids, [])
            self.assertEqual([v.user_verdict for v in updated_scan.vulnerabilities], [None, None])


if __name__ == "__main__":
    unittest.main()
