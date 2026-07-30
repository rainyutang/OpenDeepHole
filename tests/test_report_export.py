import asyncio
import csv
import io
import unittest
from unittest.mock import AsyncMock, patch

from backend.api import scan as scan_api
from backend.models import (
    FpReviewResult,
    ScanItemStatus,
    ScanStatus,
    User,
    Vulnerability,
)


def _vulnerability(name: str) -> Vulnerability:
    return Vulnerability(
        file=f"src/{name}.c",
        line=10,
        function=name,
        vuln_type="out_of_bounds",
        severity="high",
        description=f"{name} issue",
        ai_analysis="analysis",
        confirmed=True,
        ai_verdict="confirmed",
    )


def _fp_result(index: int, verdict: str) -> FpReviewResult:
    return FpReviewResult(
        vuln_index=index,
        verdict=verdict,
        severity="high" if verdict == "tp" else "low",
        reason=f"{verdict} conclusion",
        created_at="2026-07-30T00:00:00+00:00",
    )


class ReportExportTests(unittest.TestCase):
    def test_csv_exports_separate_fp_vulnerability_judgment(self) -> None:
        scan = ScanStatus(
            scan_id="scan-1",
            status=ScanItemStatus.COMPLETE,
            progress=1.0,
            total_candidates=4,
            processed_candidates=4,
            vulnerabilities=[
                _vulnerability("tp"),
                _vulnerability("fp"),
                _vulnerability("uncertain"),
                _vulnerability("not-reviewed"),
            ],
        )
        fp_map = {
            0: _fp_result(0, "tp"),
            1: _fp_result(1, "fp"),
            2: _fp_result(2, "uncertain"),
        }
        user = User(user_id="owner", username="owner", role="user")

        with (
            patch.object(scan_api, "_check_scan_owner"),
            patch.object(
                scan_api,
                "get_scan_status",
                new=AsyncMock(return_value=scan),
            ),
            patch.object(scan_api, "_scan_fp_result_map", return_value=fp_map),
        ):
            response = asyncio.run(scan_api.download_report("scan-1", user))

        reader = csv.DictReader(
            io.StringIO(response.body.decode("utf-8-sig"))
        )
        rows = list(reader)

        self.assertIn("confirmed", reader.fieldnames or [])
        self.assertIn("fp_confirmed", reader.fieldnames or [])
        self.assertEqual(rows[0]["fp_verdict"], "tp")
        self.assertEqual(rows[0]["fp_confirmed"], "True")
        self.assertEqual(rows[1]["fp_verdict"], "fp")
        self.assertEqual(rows[1]["fp_confirmed"], "False")
        self.assertEqual(rows[2]["fp_verdict"], "uncertain")
        self.assertEqual(rows[2]["fp_confirmed"], "")
        self.assertEqual(rows[3]["fp_verdict"], "")
        self.assertEqual(rows[3]["fp_confirmed"], "")


if __name__ == "__main__":
    unittest.main()
