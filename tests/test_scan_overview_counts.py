import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.api.scan import get_scan_overview_v2
from backend.models import (
    Candidate,
    FpReviewResult,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    User,
    Vulnerability,
    VulnerabilityValidation,
)
from backend.store.sqlite import SqliteScanStore


async def _direct_store_call(store, operation, *args, **kwargs):
    function = getattr(store, operation) if isinstance(operation, str) else operation
    return function(*args, **kwargs)


class ScanOverviewCountTests(unittest.IsolatedAsyncioTestCase):
    async def test_overview_counts_are_complete_beyond_first_detail_pages(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            scan_id = "overview-counts"
            scan = ScanStatus(
                scan_id=scan_id,
                project_id="project-1",
                scan_items=["npd"],
                created_at="2026-08-05T00:00:00+00:00",
                status=ScanItemStatus.COMPLETE,
                progress=1.0,
                total_candidates=1,
                processed_candidates=205,
                vulnerabilities=[],
            )
            meta = ScanMeta(
                scan_items=["npd"],
                created_at=scan.created_at,
                agent_id="",
                agent_name="",
                project_path="/tmp/project",
                scan_name="Overview counts",
                product="LTE",
                user_id="user-1",
            )
            try:
                store.save_scan(scan, meta)
                store.replace_scan_candidates(scan_id, [
                    Candidate(
                        file=f"src/candidate-{index}.c",
                        line=index + 1,
                        function=f"candidate_{index}",
                        description="candidate",
                        vuln_type="npd",
                    )
                    for index in range(205)
                ])
                for index in range(105):
                    confirmed = index != 2
                    store.add_vulnerability(scan_id, Vulnerability(
                        file=f"src/issue-{index}.c",
                        line=index + 1,
                        function=f"issue_{index}",
                        vuln_type="npd",
                        severity="high",
                        description="issue",
                        ai_analysis="analysis",
                        confirmed=confirmed,
                        ai_verdict="confirmed" if confirmed else "not_confirmed",
                    ))
                store.create_fp_review_job(
                    "review-1",
                    scan_id,
                    105,
                    "2026-08-05T00:01:00+00:00",
                )
                store.add_fp_review_result("review-1", FpReviewResult(
                    vuln_index=1,
                    verdict="fp",
                    severity="low",
                    reason="false positive",
                    created_at="2026-08-05T00:02:00+00:00",
                ))
                for index, status in ((0, "verified"), (1, "success"), (2, "success")):
                    store.upsert_vulnerability_validation(
                        scan_id,
                        VulnerabilityValidation(
                            vuln_index=index,
                            status=status,
                            running=False,
                        ),
                    )

                with (
                    patch("backend.api.scan.get_scan_store", return_value=store),
                    patch(
                        "backend.api.scan.run_store_call",
                        side_effect=_direct_store_call,
                    ),
                ):
                    overview = await get_scan_overview_v2(
                        scan_id,
                        User(user_id="user-1", username="ordinary", role="user"),
                    )

                self.assertEqual(overview.total_candidates, 205)
                self.assertEqual(overview.detail_counts.candidates, 205)
                self.assertEqual(overview.detail_counts.vulnerabilities, 105)
                self.assertEqual(overview.detail_counts.effective_issue_count, 103)
                self.assertEqual(overview.detail_counts.validated_issue_count, 1)
                self.assertEqual(overview.candidates, [])
                self.assertEqual(overview.vulnerabilities, [])
                self.assertEqual(
                    store.get_vulnerability_validation_states(scan_id),
                    {
                        0: ("verified", False),
                        1: ("success", False),
                        2: ("success", False),
                    },
                )
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
