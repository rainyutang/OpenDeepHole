import asyncio
import csv
import io
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.responses import Response

from backend.api import integration as integration_api
from backend.api import scan as scan_api
from backend.models import (
    FpReviewResult,
    ScanItemStatus,
    ScanStatus,
    User,
    Vulnerability,
    VulnerabilityValidation,
)


def _vulnerability(
    name: str,
    *,
    severity: str = "high",
    vuln_type: str = "out_of_bounds",
    confirmed: bool = True,
    ai_verdict: str = "confirmed",
    engine_id: str = "static_candidate",
    audit_index: int | None = None,
) -> Vulnerability:
    return Vulnerability(
        file=f"src/{name}.c",
        line=10,
        function=name,
        vuln_type=vuln_type,
        severity=severity,
        description=f"{name} issue",
        ai_analysis="analysis",
        confirmed=confirmed,
        ai_verdict=ai_verdict,
        engine_id=engine_id,
        engine_label=engine_id,
        audit_index=audit_index,
    )


def _fp_result(index: int, verdict: str, *, reason: str | None = None) -> FpReviewResult:
    return FpReviewResult(
        vuln_index=index,
        verdict=verdict,
        severity="high" if verdict == "tp" else "low",
        reason=f"{verdict} conclusion" if reason is None else reason,
        created_at="2026-07-30T00:00:00+00:00",
    )


class ReportExportTests(unittest.TestCase):
    def _download(
        self,
        scan: ScanStatus,
        fp_map: dict[int, FpReviewResult] | None = None,
        **filters: object,
    ) -> Response:
        user = User(user_id="owner", username="owner", role="user")
        with (
            patch.object(scan_api, "_check_scan_owner", new=AsyncMock()),
            patch.object(
                scan_api,
                "get_scan_status",
                new=AsyncMock(return_value=scan),
            ),
            patch.object(scan_api, "get_scan_store", return_value=object()),
            patch.object(
                scan_api,
                "run_store_call",
                new=AsyncMock(return_value=fp_map or {}),
            ),
        ):
            return asyncio.run(
                scan_api.download_report("scan-1", user, **filters)
            )

    @staticmethod
    def _rows(response: Response) -> tuple[list[str], list[dict[str, str]]]:
        reader = csv.DictReader(io.StringIO(response.body.decode("utf-8-sig")))
        return list(reader.fieldnames or []), list(reader)

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
        fieldnames, rows = self._rows(self._download(scan, fp_map))

        self.assertIn("confirmed", fieldnames)
        self.assertIn("fp_confirmed", fieldnames)
        self.assertEqual(rows[0]["fp_verdict"], "tp")
        self.assertEqual(rows[0]["fp_confirmed"], "True")
        self.assertEqual(rows[1]["fp_verdict"], "fp")
        self.assertEqual(rows[1]["fp_confirmed"], "False")
        self.assertEqual(rows[2]["fp_verdict"], "uncertain")
        self.assertEqual(rows[2]["fp_confirmed"], "")
        self.assertEqual(rows[3]["fp_verdict"], "")
        self.assertEqual(rows[3]["fp_confirmed"], "")

    def test_scanning_csv_filters_fp_state_and_uses_audit_order(self) -> None:
        scan = ScanStatus(
            scan_id="scan-1",
            status=ScanItemStatus.AUDITING,
            progress=0.5,
            total_candidates=4,
            processed_candidates=2,
            vulnerabilities=[
                _vulnerability("pending", audit_index=30),
                _vulnerability("tp", audit_index=20),
                _vulnerability("fp", audit_index=10),
                _vulnerability(
                    "not-confirmed",
                    confirmed=False,
                    ai_verdict="not_confirmed",
                    audit_index=0,
                ),
            ],
        )
        fp_map = {
            0: _fp_result(0, "uncertain"),
            1: _fp_result(1, "tp"),
            2: _fp_result(2, "fp"),
        }

        _, rows = self._rows(self._download(scan, fp_map, filtered=True))
        self.assertEqual([row["function"] for row in rows], ["fp", "tp", "pending"])

        _, tp_rows = self._rows(self._download(
            scan,
            fp_map,
            filtered=True,
            fp_review_state="tp",
        ))
        self.assertEqual([row["function"] for row in tp_rows], ["tp"])

        _, pending_rows = self._rows(self._download(
            scan,
            fp_map,
            filtered=True,
            fp_review_state="no_conclusion",
        ))
        self.assertEqual([row["function"] for row in pending_rows], ["pending"])

        _, all_pending_rows = self._rows(self._download(
            scan,
            fp_map,
            filtered=True,
            show_all=True,
            fp_review_state="no_conclusion",
        ))
        self.assertEqual(
            [row["function"] for row in all_pending_rows],
            ["not-confirmed", "pending"],
        )

    def test_csv_combines_list_filters_and_returns_header_for_no_match(self) -> None:
        scan = ScanStatus(
            scan_id="scan-1",
            status=ScanItemStatus.AUDITING,
            progress=0.5,
            total_candidates=3,
            processed_candidates=2,
            vulnerabilities=[
                _vulnerability("running", engine_id="threat_audit", audit_index=2),
                _vulnerability("verified", engine_id="threat_audit", audit_index=1),
                _vulnerability(
                    "other",
                    severity="medium",
                    vuln_type="npd",
                    audit_index=0,
                ),
            ],
            validations=[
                VulnerabilityValidation(vuln_index=0, status="running", running=True),
                VulnerabilityValidation(vuln_index=1, status="verified", running=False),
            ],
        )

        _, rows = self._rows(self._download(
            scan,
            filtered=True,
            severity="high",
            vuln_type="out_of_bounds",
            engine_id="threat_audit",
            validation_state="verified",
            fp_review_state="no_conclusion",
        ))
        self.assertEqual([row["function"] for row in rows], ["verified"])

        fieldnames, no_rows = self._rows(self._download(
            scan,
            filtered=True,
            severity="critical",
        ))
        self.assertIn("function", fieldnames)
        self.assertEqual(no_rows, [])

    def test_filtered_csv_uses_all_server_results_not_frontend_page_size(self) -> None:
        vulnerabilities = [
            _vulnerability(f"issue-{index}", audit_index=index)
            for index in range(125)
        ]
        scan = ScanStatus(
            scan_id="scan-1",
            status=ScanItemStatus.AUDITING,
            progress=0.8,
            total_candidates=125,
            processed_candidates=100,
            vulnerabilities=vulnerabilities,
        )

        _, rows = self._rows(self._download(scan, filtered=True))
        self.assertEqual(len(rows), 125)
        self.assertEqual(rows[-1]["function"], "issue-124")

    def test_public_csv_route_forwards_filters(self) -> None:
        user = User(user_id="owner", username="owner", role="user")
        expected = Response(content="ok")
        download = AsyncMock(return_value=expected)
        with patch.object(integration_api.scan_api, "download_report", new=download):
            response = asyncio.run(integration_api.download_public_report(
                "scan-1",
                user,
                filtered=True,
                show_all=True,
                severity="high",
                vuln_type="out_of_bounds",
                engine_id="threat_audit",
                validation_state="verified",
                fp_review_state="tp",
            ))

        self.assertIs(response, expected)
        download.assert_awaited_once_with(
            "scan-1",
            user,
            filtered=True,
            show_all=True,
            severity="high",
            vuln_type="out_of_bounds",
            engine_id="threat_audit",
            validation_state="verified",
            fp_review_state="tp",
        )


if __name__ == "__main__":
    unittest.main()
