import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from backend.api.admin import _build_checker_dashboard, get_scoped_checker_dashboard
from backend.models import (
    FeedbackEntry,
    FpReviewResult,
    ScanItemStatus,
    ScanMeta,
    OpenCodeTokenUsage,
    ScanStatus,
    ScanSummary,
    User,
    Vulnerability,
)


class FakeScanStore:
    def __init__(self, scan: ScanStatus, meta: ScanMeta) -> None:
        self.scan = scan
        self.meta = meta

    def list_scans(self) -> list[ScanSummary]:
        return [
            ScanSummary(
                scan_id=self.scan.scan_id,
                project_id=self.scan.project_id,
                product=self.meta.product,
                status=self.scan.status,
                created_at=self.scan.created_at,
                progress=self.scan.progress,
                total_candidates=self.scan.total_candidates,
                processed_candidates=self.scan.processed_candidates,
                vulnerability_count=len(self.scan.vulnerabilities),
                scan_items=self.meta.scan_items,
                username="alice",
            )
        ]

    def load_scan(self, scan_id: str) -> tuple[ScanStatus, ScanMeta] | None:
        if scan_id != self.scan.scan_id:
            return None
        return self.scan, self.meta

    def list_fp_review_results_by_scan(self, scan_id: str) -> list[FpReviewResult]:
        if scan_id != self.scan.scan_id:
            return []
        return [
            FpReviewResult(
                vuln_index=1,
                verdict="fp",
                reason="reviewed false positive",
                created_at="2026-01-01T00:00:00+00:00",
            ),
            FpReviewResult(
                vuln_index=3,
                verdict="tp",
                reason="reviewed true positive",
                created_at="2026-01-01T00:01:00+00:00",
            ),
        ]

    def list_feedback_by_scan(self, scan_id: str) -> list[FeedbackEntry]:
        if scan_id != self.scan.scan_id:
            return []
        return [
            FeedbackEntry(
                id="feedback-1",
                project_id=self.scan.project_id,
                vuln_type="npd",
                verdict="confirmed",
                file="a.c",
                line=1,
                function="a",
                description="confirmed by llm and human",
                reason="filed",
                ticket_submitted=True,
                ticket_id="BUG-1",
                source_scan_id=scan_id,
                created_at="2026-01-01T00:00:00+00:00",
                updated_at="2026-01-01T00:00:00+00:00",
            ),
            FeedbackEntry(
                id="feedback-2",
                project_id=self.scan.project_id,
                vuln_type="npd",
                verdict="false_positive",
                file="b.c",
                line=2,
                function="b",
                description="review false positive",
                reason="not filed",
                ticket_submitted=False,
                source_scan_id=scan_id,
                created_at="2026-01-01T00:01:00+00:00",
                updated_at="2026-01-01T00:01:00+00:00",
            ),
        ]


class AdminCheckerDashboardTests(unittest.TestCase):
    def test_scoped_endpoint_passes_user_id_only_for_regular_users(self) -> None:
        store = object()
        response = object()

        async def run() -> None:
            with (
                patch("backend.api.admin.get_scan_store", return_value=store),
                patch(
                    "backend.api.admin.run_store_call",
                    new=AsyncMock(return_value=response),
                ) as call,
            ):
                self.assertIs(
                    await get_scoped_checker_dashboard(
                        current_user=User(
                            user_id="user-1",
                            username="alice",
                            role="user",
                        )
                    ),
                    response,
                )
                self.assertEqual(call.await_args.args[-1], "user-1")
                await get_scoped_checker_dashboard(
                    current_user=User(
                        user_id="admin-1",
                        username="admin",
                        role="admin",
                    )
                )
                self.assertIsNone(call.await_args.args[-1])

        asyncio.run(run())

    def test_summary_includes_review_and_effective_issue_counts(self) -> None:
        scan = ScanStatus(
            scan_id="scan-1",
            project_id="project-1",
            product="LTE",
            scan_items=["npd", "oob"],
            created_at="2026-01-01T00:00:00+00:00",
            status=ScanItemStatus.COMPLETE,
            progress=1.0,
            total_candidates=4,
            processed_candidates=4,
            vulnerabilities=[
                Vulnerability(
                    file="a.c",
                    line=1,
                    function="a",
                    vuln_type="npd",
                    severity="high",
                    description="confirmed by llm and human",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                    user_verdict="confirmed",
                ),
                Vulnerability(
                    file="b.c",
                    line=2,
                    function="b",
                    vuln_type="npd",
                    severity="medium",
                    description="review false positive",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                    user_verdict="false_positive",
                ),
                Vulnerability(
                    file="c.c",
                    line=3,
                    function="c",
                    vuln_type="npd",
                    severity="low",
                    description="not confirmed",
                    ai_analysis="analysis",
                    confirmed=False,
                    ai_verdict="not_confirmed",
                ),
                Vulnerability(
                    file="d.c",
                    line=4,
                    function="d",
                    vuln_type="oob",
                    severity="high",
                    description="review true positive",
                    ai_analysis="analysis",
                    confirmed=True,
                    ai_verdict="confirmed",
                    user_verdict="confirmed",
                ),
            ],
        )
        meta = ScanMeta(
            scan_items=["npd", "oob"],
            created_at=scan.created_at,
            project_path="/repo/project",
            scan_name="Project One",
            product="LTE",
            agent_name="agent-1",
        )
        registry = {
            "npd": SimpleNamespace(label="NPD", description="null pointer", user_created=False),
            "oob": SimpleNamespace(label="OOB", description="out of bounds", user_created=False),
        }

        with (
            patch("backend.api.admin.get_scan_store", return_value=FakeScanStore(scan, meta)),
            patch("backend.api.admin.refresh_registry", return_value=registry),
        ):
            response = _build_checker_dashboard(FakeScanStore(scan, meta))

        self.assertEqual(response.summary.static_issue_count, 4)
        self.assertEqual(response.summary.llm_issue_count, 3)
        self.assertEqual(response.summary.fp_review_issue_count, 1)
        self.assertEqual(response.summary.fp_review_false_positive_count, 1)
        self.assertEqual(response.summary.total_issue_count, 2)
        self.assertEqual(response.summary.human_confirmed_count, 2)
        self.assertEqual(response.summary.ticket_submitted_count, 1)
        self.assertEqual(response.summary.accuracy_basis_count, 2)
        self.assertEqual(response.summary.accuracy, 1.0)
        self.assertEqual(response.summary.ticket_accuracy, 0.5)
        npd = next(checker for checker in response.checkers if checker.checker == "npd")
        self.assertEqual(npd.ticket_submitted_count, 1)
        self.assertEqual(npd.ticket_accuracy, 1.0)
        self.assertEqual(npd.scans[0].product, "LTE")
        self.assertEqual(npd.scans[0].ticket_submitted_count, 1)
        self.assertEqual(npd.scans[0].ticket_accuracy, 1.0)
        oob = next(checker for checker in response.checkers if checker.checker == "oob")
        self.assertEqual(oob.ticket_accuracy, 0.0)

    def test_product_filter_excludes_other_products(self) -> None:
        scan = ScanStatus(
            scan_id="scan-1",
            project_id="project-1",
            product="LTE",
            scan_items=["npd"],
            created_at="2026-01-01T00:00:00+00:00",
            status=ScanItemStatus.COMPLETE,
            progress=1.0,
            total_candidates=0,
            processed_candidates=0,
            vulnerabilities=[],
        )
        meta = ScanMeta(
            scan_items=["npd"],
            created_at=scan.created_at,
            project_path="/repo/project",
            scan_name="Project One",
            product="LTE",
        )
        registry = {
            "npd": SimpleNamespace(label="NPD", description="null pointer", user_created=False),
        }

        with (
            patch("backend.api.admin.get_scan_store", return_value=FakeScanStore(scan, meta)),
            patch("backend.api.admin.refresh_registry", return_value=registry),
        ):
            response = _build_checker_dashboard(
                FakeScanStore(scan, meta),
                product="5G",
            )

        self.assertEqual(response.summary.scan_count, 0)
        self.assertIsNone(response.summary.ticket_accuracy)
        npd = next(checker for checker in response.checkers if checker.checker == "npd")
        self.assertEqual(npd.scan_count, 0)
        self.assertIsNone(npd.ticket_accuracy)

    def test_user_scope_and_product_filter_do_not_change_token_totals(self) -> None:
        def entry(
            scan_id: str,
            *,
            user_id: str,
            username: str,
            product: str,
            agent_key: str,
            total_tokens: int,
        ):
            scan = ScanStatus(
                scan_id=scan_id,
                project_id=f"project-{scan_id}",
                scan_items=["npd", "oob"],
                created_at="2026-01-01T00:00:00+00:00",
                status=ScanItemStatus.COMPLETE,
                progress=1.0,
                total_candidates=0,
                processed_candidates=0,
                vulnerabilities=[],
            )
            meta = ScanMeta(
                scan_items=["npd", "oob"],
                created_at=scan.created_at,
                scan_name=scan_id,
                product=product,
                agent_key=agent_key,
                agent_name=f"client-{agent_key}",
                user_id=user_id,
            )
            summary = ScanSummary(
                scan_id=scan_id,
                project_id=scan.project_id,
                product=product,
                status=scan.status,
                created_at=scan.created_at,
                progress=1.0,
                total_candidates=0,
                processed_candidates=0,
                vulnerability_count=0,
                scan_items=meta.scan_items,
                user_id=user_id,
                username=username,
            )
            usage = OpenCodeTokenUsage(
                input_tokens=total_tokens,
                total_tokens=total_tokens,
            )
            return summary, scan, meta, usage

        class ScopedStore:
            def __init__(self) -> None:
                self.entries = [
                    entry(
                        "scan-a",
                        user_id="user-1",
                        username="alice",
                        product="LTE",
                        agent_key="agent-1",
                        total_tokens=10,
                    ),
                    entry(
                        "scan-b",
                        user_id="user-1",
                        username="alice",
                        product="5G",
                        agent_key="agent-1",
                        total_tokens=20,
                    ),
                    entry(
                        "scan-c",
                        user_id="user-2",
                        username="bob",
                        product="LTE",
                        agent_key="agent-2",
                        total_tokens=30,
                    ),
                ]

            def list_scans(self):
                return [item[0] for item in self.entries]

            def list_scans_by_user(self, user_id: str):
                return [item[0] for item in self.entries if item[0].user_id == user_id]

            def load_scan(self, scan_id: str):
                for summary, scan, meta, _usage in self.entries:
                    if summary.scan_id == scan_id:
                        return scan, meta
                return None

            def get_scan_opencode_token_usage(self, scan_id: str):
                for summary, _scan, _meta, usage in self.entries:
                    if summary.scan_id == scan_id:
                        return usage
                return None

            def get_agent_record(self, agent_key: str):
                return {
                    "agent_key": agent_key,
                    "machine_name": f"machine-{agent_key}",
                    "ip": "127.0.0.1",
                }

            def list_fp_review_results_by_scan(self, _scan_id: str):
                return []

            def list_feedback_by_scan(self, _scan_id: str):
                return []

        registry = {
            "npd": SimpleNamespace(
                label="NPD", description="null pointer", user_created=False
            ),
            "oob": SimpleNamespace(
                label="OOB", description="out of bounds", user_created=False
            ),
        }
        store = ScopedStore()
        with patch("backend.api.admin.refresh_registry", return_value=registry):
            user_response = _build_checker_dashboard(
                store,
                product="LTE",
                user_id="user-1",
            )
            admin_response = _build_checker_dashboard(store, product="LTE")

        self.assertEqual(user_response.summary.scan_count, 1)
        self.assertEqual(user_response.products, ["5G", "LTE"])
        self.assertEqual(user_response.token_usage.scan_count, 2)
        self.assertEqual(user_response.token_usage.usage.total_tokens, 30)
        self.assertEqual(len(user_response.token_usage.agents), 1)
        self.assertEqual(user_response.token_usage.agents[0].scan_count, 2)
        self.assertEqual(admin_response.summary.scan_count, 2)
        self.assertEqual(admin_response.token_usage.usage.total_tokens, 60)
        self.assertEqual(len(admin_response.token_usage.agents), 2)


if __name__ == "__main__":
    unittest.main()
