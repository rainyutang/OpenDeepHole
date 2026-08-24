import asyncio
import csv
import io
import unittest
import zipfile
from types import SimpleNamespace
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
            return asyncio.run(scan_api.download_report("scan-1", user))

    def _download_zip(
        self,
        scan: ScanStatus,
        fp_map: dict[int, FpReviewResult] | None = None,
    ) -> Response:
        user = User(user_id="owner", username="owner", role="user")
        store = SimpleNamespace(get_scan_meta=lambda _scan_id: None)
        with (
            patch.object(scan_api, "_check_scan_owner", new=AsyncMock()),
            patch.object(
                scan_api,
                "get_scan_status",
                new=AsyncMock(return_value=scan),
            ),
            patch.object(scan_api, "get_scan_store", return_value=store),
            patch.object(
                scan_api,
                "run_store_call",
                new=AsyncMock(return_value=fp_map or {}),
            ),
            patch.object(scan_api, "_fp_review_stage_titles", return_value=[]),
        ):
            return asyncio.run(scan_api.download_report_zip("scan-1", user))

    def _download_single(
        self,
        scan: ScanStatus,
        index: int,
        fp_map: dict[int, FpReviewResult] | None = None,
    ) -> Response:
        user = User(user_id="owner", username="owner", role="user")
        store = SimpleNamespace(get_scan_meta=lambda _scan_id: None)
        with (
            patch.object(scan_api, "_check_scan_owner", new=AsyncMock()),
            patch.object(
                scan_api,
                "get_scan_status",
                new=AsyncMock(return_value=scan),
            ),
            patch.object(scan_api, "get_scan_store", return_value=store),
            patch.object(
                scan_api,
                "run_store_call",
                new=AsyncMock(return_value=fp_map or {}),
            ),
            patch.object(scan_api, "_fp_review_stage_titles", return_value=[]),
        ):
            return asyncio.run(
                scan_api.download_vulnerability_report(
                    "scan-1",
                    index,
                    user,
                ),
            )

    @staticmethod
    def _rows(response: Response) -> tuple[list[str], list[dict[str, str]]]:
        reader = csv.DictReader(io.StringIO(response.body.decode("utf-8-sig")))
        return list(reader.fieldnames or []), list(reader)

    def test_csv_and_zip_export_the_same_final_tp_reports(self) -> None:
        scan = ScanStatus(
            scan_id="scan-1",
            status=ScanItemStatus.COMPLETE,
            progress=1.0,
            total_candidates=6,
            processed_candidates=6,
            vulnerabilities=[
                _vulnerability("tp-first"),
                _vulnerability("fp"),
                _vulnerability("incomplete-tp"),
                _vulnerability("tp-second", vuln_type="null_pointer"),
                _vulnerability("uncertain"),
                _vulnerability("not-reviewed"),
            ],
        )
        fp_map = {
            0: _fp_result(0, "tp"),
            1: _fp_result(1, "fp"),
            2: _fp_result(2, "tp", reason="Review incomplete: no output"),
            3: _fp_result(3, "tp"),
            4: _fp_result(4, "uncertain"),
        }
        fieldnames, rows = self._rows(self._download(scan, fp_map))

        self.assertEqual(
            fieldnames,
            ["文件", "行号", "函数", "问题类型", "问题描述", "ZIP中的问题报告"],
        )
        self.assertEqual([row["函数"] for row in rows], ["tp-first", "tp-second"])
        self.assertEqual(
            rows[0],
            {
                "文件": "src/tp-first.c",
                "行号": "10",
                "函数": "tp-first",
                "问题类型": "out_of_bounds",
                "问题描述": "tp-first issue",
                "ZIP中的问题报告": "vuln-0-src_tp-first.c_10.md",
            },
        )

        zip_response = self._download_zip(scan, fp_map)
        with zipfile.ZipFile(io.BytesIO(zip_response.body)) as archive:
            report_names = [name for name in archive.namelist() if name != "README.md"]
            self.assertEqual(
                [row["ZIP中的问题报告"] for row in rows],
                report_names,
            )
            self.assertIn(
                "共 2 个去误报最终确认问题",
                archive.read("README.md").decode("utf-8"),
            )

    def test_exports_are_empty_without_final_tp_results(self) -> None:
        scan = ScanStatus(
            scan_id="scan-1",
            status=ScanItemStatus.AUDITING,
            progress=0.5,
            total_candidates=4,
            processed_candidates=4,
            vulnerabilities=[
                _vulnerability("fp"),
                _vulnerability("uncertain"),
                _vulnerability("incomplete-tp"),
                _vulnerability("not-reviewed"),
            ],
        )
        fp_map = {
            0: _fp_result(0, "fp"),
            1: _fp_result(1, "uncertain"),
            2: _fp_result(2, "tp", reason="Review incomplete: no output"),
        }

        fieldnames, rows = self._rows(self._download(scan, fp_map))
        self.assertEqual(
            fieldnames,
            ["文件", "行号", "函数", "问题类型", "问题描述", "ZIP中的问题报告"],
        )
        self.assertEqual(rows, [])

        zip_response = self._download_zip(scan, fp_map)
        with zipfile.ZipFile(io.BytesIO(zip_response.body)) as archive:
            self.assertEqual(archive.namelist(), ["README.md"])
            self.assertIn(
                "本次扫描没有去误报最终确认为问题的漏洞",
                archive.read("README.md").decode("utf-8"),
            )

    def test_existing_duplicate_findings_are_deduplicated_only_in_reports(
        self,
    ) -> None:
        first = _vulnerability("duplicate", audit_index=7)
        first.root_cause = "unchecked pointer"
        duplicate = first.model_copy(deep=True)
        duplicate.output_source.agent_id = "agent-enriched"
        scan = ScanStatus(
            scan_id="scan-1",
            status=ScanItemStatus.COMPLETE,
            progress=1.0,
            total_candidates=1,
            processed_candidates=1,
            vulnerabilities=[first, duplicate],
            validations=[
                VulnerabilityValidation(
                    vuln_index=0,
                    status="verified",
                    updated_at="2026-07-30T00:00:00+00:00",
                    validation_output="older validation",
                ),
                VulnerabilityValidation(
                    vuln_index=1,
                    status="verified",
                    updated_at="2026-07-31T00:00:00+00:00",
                    validation_output="newer validation",
                ),
            ],
        )
        fp_map = {
            0: _fp_result(0, "uncertain", reason="incomplete conclusion"),
            1: _fp_result(1, "tp", reason="confirmed by review").model_copy(
                update={"created_at": "2026-07-31T00:00:00+00:00"},
            ),
        }

        _, rows = self._rows(self._download(scan, fp_map))
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0]["ZIP中的问题报告"],
            "vuln-0-src_duplicate.c_10.md",
        )

        zip_response = self._download_zip(scan, fp_map)
        with zipfile.ZipFile(io.BytesIO(zip_response.body)) as archive:
            names = archive.namelist()
            report_names = [name for name in names if name != "README.md"]
            self.assertEqual(len(report_names), 1)
            self.assertIn(
                "共 1 个去误报最终确认问题",
                archive.read("README.md").decode("utf-8"),
            )
            self.assertEqual(report_names, [rows[0]["ZIP中的问题报告"]])
            report_markdown = archive.read(report_names[0]).decode("utf-8")
            self.assertIn("confirmed by review", report_markdown)
            self.assertIn("newer validation", report_markdown)

        single_markdown = self._download_single(scan, 0, fp_map).body.decode(
            "utf-8",
        )
        self.assertIn("confirmed by review", single_markdown)
        self.assertIn("newer validation", single_markdown)
        self.assertEqual(len(scan.vulnerabilities), 2)

    def test_report_dedup_keeps_distinct_root_cause(self) -> None:
        first = _vulnerability("same-location", audit_index=3)
        first.root_cause = "first root cause"
        second = first.model_copy(update={"root_cause": "second root cause"})
        scan = ScanStatus(
            scan_id="scan-1",
            status=ScanItemStatus.COMPLETE,
            progress=1.0,
            total_candidates=1,
            processed_candidates=1,
            vulnerabilities=[first, second],
        )

        fp_map = {
            0: _fp_result(0, "tp"),
            1: _fp_result(1, "tp"),
        }
        _, rows = self._rows(self._download(scan, fp_map))
        self.assertEqual(len(rows), 2)

    def test_single_report_keeps_one_core_markdown_in_chinese_section_order(self) -> None:
        vulnerability = _vulnerability("markdown")
        vulnerability.vulnerability_report = """\
# 漏洞报告

## 漏洞描述

第一行
第二行

## 攻击入口

入口

## 触发条件

条件

## 漏洞代码

代码

## 漏洞根因

根因

## 漏洞调用链

调用链

## 漏洞影响

影响
"""
        scan = ScanStatus(
            scan_id="scan-1",
            status=ScanItemStatus.COMPLETE,
            progress=1.0,
            total_candidates=1,
            processed_candidates=1,
            vulnerabilities=[vulnerability],
        )

        markdown = self._download_single(scan, 0).body.decode("utf-8")

        self.assertEqual(markdown.count("# 漏洞报告"), 1)
        self.assertEqual(markdown.count("## 漏洞描述"), 1)
        self.assertNotIn("## 漏洞挖掘引擎报告", markdown)
        self.assertIn("第一行\n第二行", markdown)
        headings = [
            "## 漏洞描述",
            "## 攻击入口",
            "## 触发条件",
            "## 漏洞代码",
            "## 漏洞根因",
            "## 漏洞调用链",
            "## 漏洞影响",
        ]
        offsets = [markdown.index(heading) for heading in headings]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn("## 平台信息", markdown)

    def test_single_report_builds_one_markdown_report_from_structured_fields(self) -> None:
        vulnerability = _vulnerability("structured")
        vulnerability.vulnerability_report = ""
        vulnerability.attack_entry = "HTTP `POST /parse`"
        vulnerability.trigger_conditions = "攻击者可提交超长负载。"
        vulnerability.vulnerable_code = "```c\nunsafe(input); // SINK\n```"
        vulnerability.root_cause = "`input` 未经过长度校验。"
        vulnerability.call_chain = (
            "- Entry: handle_request (src/server.c:8)\n"
            "- Call Stack:\n"
            "handle_request (src/server.c:8)\n"
            "  → structured (src/structured.c:10)\n"
            "- Vulnerable Frame: structured (src/structured.c:10)\n"
            "- Source To Sink Stack:\n"
            "input [SOURCE]\n"
            "  → unsafe (src/structured.c:10) [SINK]"
        )
        vulnerability.impact = "可能影响可用性。"
        scan = ScanStatus(
            scan_id="scan-1",
            status=ScanItemStatus.COMPLETE,
            progress=1.0,
            total_candidates=1,
            processed_candidates=1,
            vulnerabilities=[vulnerability],
        )

        markdown = self._download_single(scan, 0).body.decode("utf-8")

        headings = [
            "## 漏洞描述",
            "## 攻击入口",
            "## 触发条件",
            "## 漏洞代码",
            "## 漏洞根因",
            "## 漏洞调用链",
            "## 漏洞影响",
        ]
        self.assertEqual([markdown.count(heading) for heading in headings], [1] * 7)
        self.assertEqual(
            [markdown.index(heading) for heading in headings],
            sorted(markdown.index(heading) for heading in headings),
        )
        self.assertIn("- Entry: handle_request", markdown)

    def test_public_csv_route_forwards_fixed_export(self) -> None:
        user = User(user_id="owner", username="owner", role="user")
        expected = Response(content="ok")
        download = AsyncMock(return_value=expected)
        with patch.object(integration_api.scan_api, "download_report", new=download):
            response = asyncio.run(integration_api.download_public_report(
                "scan-1",
                user,
            ))

        self.assertIs(response, expected)
        download.assert_awaited_once_with("scan-1", user)


if __name__ == "__main__":
    unittest.main()
