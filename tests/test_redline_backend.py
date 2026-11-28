"""Backend API, persistence, FP-review exemption, summary counts, and export tests for redlines."""

from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import openpyxl
from fastapi.testclient import TestClient

import backend.store as store_module
from backend.application import get_runtime
from backend.auth import create_token, hash_password
from backend.main import app
from backend.models import (
    MiningEngineSelection,
    REDLINE_AUDIT_ENGINE_ID,
    REDLINE_AUDIT_ENGINE_LABEL,
    RedlineAuditTask,
    ScanItemStatus,
    ScanMeta,
    ScanRedlineItem,
    ScanStatus,
    UserInDB,
    Vulnerability,
)
from backend.redlines import (
    RedlineExcelImportError,
    build_redline_template_xlsx,
    parse_redline_xlsx,
)
from backend.scans.fp_review_policy import _ordered_fp_review_candidates
from backend.store.sqlite import SqliteScanStore


def _make_user(user_id: str, username: str, role: str) -> UserInDB:
    return UserInDB(
        user_id=user_id,
        username=username,
        role=role,
        password_hash=hash_password("secret123"),
        employee_id=f"EMP-{user_id}",
    )


def _auth_header(user: UserInDB) -> dict[str, str]:
    token = create_token(user.user_id, user.username, user.role)
    return {"Authorization": f"Bearer {token}"}


def _build_excel(rows: list[list[object]]) -> bytes:
    wb = openpyxl.Workbook()
    ws = wb.active
    for row in rows:
        ws.append(row)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


class RedlineExcelParsingTests(unittest.TestCase):
    def test_template_round_trip_and_strict_column_parsing(self) -> None:
        template_bytes = build_redline_template_xlsx()
        parsed = parse_redline_xlsx(template_bytes)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["code"], "5.2.2")
        self.assertEqual(parsed[0]["security_attribute"], "产品开发、发布和安装安全")
        self.assertEqual(parsed[0]["attribute_description"], "禁止恶意软件。")
        self.assertEqual(
            parsed[0]["requirement"],
            "产品软件禁止存在发送恶意广告、吸费、恶意消耗流量等行为。",
        )
        self.assertEqual(parsed[0]["category"], "A1")

    def test_import_parses_strictly_by_column_position_and_reports_invalid_rows(self) -> None:
        valid_data = _build_excel([
            ["编号", "安全属性", "属性描述", "红线要求", "分类", "解读及指导", "备注"],
            ["5.2.2", "产品开发、发布和安装安全", "禁止恶意软件。", "产品软件禁止存在发送恶意广告、吸费、恶意消耗流量等行为。", "A1", "检查后台上报", "重点"],
            ["5.2.3", "通信安全", "禁止明文传输", "敏感凭据禁止明文网络传输。", "A2", "", ""],
        ])
        parsed = parse_redline_xlsx(valid_data)
        self.assertEqual([r["code"] for r in parsed], ["5.2.2", "5.2.3"])

        invalid_data = _build_excel([
            ["编号", "安全属性", "属性描述", "红线要求", "分类", "解读及指导", "备注"],
            ["", "安全属性", "缺少编号", "要求", "A1", "", ""],
        ])
        with self.assertRaises(RedlineExcelImportError) as exc:
            parse_redline_xlsx(invalid_data)
        self.assertIn("第 2 行", str(exc.exception))


class RedlineBackendEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmp.name) / "test.db"
        self.store = SqliteScanStore(self.db_path)
        self.admin = _make_user("admin-1", "admin_user", "admin")
        self.regular = _make_user("user-1", "normal_user", "user")
        for user in (self.admin, self.regular):
            self.store.create_user(
                user.user_id,
                user.username,
                user.password_hash,
                user.role,
                f"token-{user.user_id}",
                employee_id=user.employee_id,
            )

        self.runtime = get_runtime()
        self._old_runtime_store = self.runtime.store
        self._old_global_store = store_module._store
        self.runtime.store = self.store
        store_module._store = self.store
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.runtime.store = self._old_runtime_store
        store_module._store = self._old_global_store
        self.store.close()
        self._tmp.cleanup()

    def test_admin_crud_rbac_batch_and_excel_import(self) -> None:
        # Regular user forbidden on admin endpoints, allowed on summary
        resp = self.client.get("/api/admin/redlines", headers=_auth_header(self.regular))
        self.assertEqual(resp.status_code, 403)
        summary = self.client.get("/api/redlines/summary", headers=_auth_header(self.regular))
        self.assertEqual(summary.status_code, 200)
        self.assertEqual(summary.json(), {"total_count": 0, "enabled_count": 0})

        # Admin creates item
        created = self.client.post(
            "/api/admin/redlines",
            headers=_auth_header(self.admin),
            json={
                "code": "5.2.2",
                "security_attribute": "产品开发、发布和安装安全",
                "attribute_description": "禁止恶意软件。",
                "requirement": "产品软件禁止存在发送恶意广告、吸费、恶意消耗流量等行为。",
                "category": "A1",
                "guidance": "检查后台请求",
                "remark": "备注",
                "enabled": True,
            },
        )
        self.assertEqual(created.status_code, 201)
        item_id = created.json()["item_id"]

        # Duplicate code returns 409
        dup = self.client.post(
            "/api/admin/redlines",
            headers=_auth_header(self.admin),
            json={
                "code": "5.2.2",
                "security_attribute": "属性",
                "attribute_description": "描述",
                "requirement": "要求",
                "category": "A1",
                "guidance": "",
                "remark": "",
            },
        )
        self.assertEqual(dup.status_code, 409)

        # Toggle disabled
        updated = self.client.put(
            f"/api/admin/redlines/{item_id}",
            headers=_auth_header(self.admin),
            json={"enabled": False},
        )
        self.assertEqual(updated.status_code, 200)
        self.assertFalse(updated.json()["enabled"])

        # Upsert Excel preserves existing disabled state on 5.2.2 and creates 5.2.3 enabled
        xlsx_bytes = _build_excel([
            ["编号", "安全属性", "属性描述", "红线要求", "分类", "解读及指导", "备注"],
            ["5.2.2", "产品开发、发布和安装安全", "禁止恶意软件。", "产品软件禁止存在发送恶意广告、吸费、恶意消耗流量等行为。", "A1", "新解读", "新备注"],
            ["5.2.3", "通信安全", "禁止明文传输", "敏感凭据禁止明文传输。", "A2", "", ""],
        ])
        imported = self.client.post(
            "/api/admin/redlines/import",
            headers=_auth_header(self.admin),
            data={"mode": "upsert"},
            files={"file": ("redlines.xlsx", xlsx_bytes, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
        )
        self.assertEqual(imported.status_code, 200)
        body = imported.json()
        self.assertEqual(body["created"], 1)
        self.assertEqual(body["updated"], 1)
        self.assertEqual(body["total"], 2)
        self.assertEqual(body["enabled_count"], 1)

        # Batch enable all
        listed = self.client.get("/api/admin/redlines", headers=_auth_header(self.admin)).json()
        all_ids = [item["item_id"] for item in listed["items"]]
        batch = self.client.post(
            "/api/admin/redlines/batch-enabled",
            headers=_auth_header(self.admin),
            json={"item_ids": all_ids, "enabled": True},
        )
        self.assertEqual(batch.status_code, 200)
        self.assertEqual(batch.json()["enabled_count"], 2)

        # Download template works
        tpl = self.client.get("/api/admin/redlines/template", headers=_auth_header(self.admin))
        self.assertEqual(tpl.status_code, 200)
        self.assertTrue(len(tpl.content) > 100)

    def test_fp_review_exemption_counts_audit_source_and_exports(self) -> None:
        scan_id = "scan-redline-e2e"
        redline_snapshot = ScanRedlineItem(
            item_id="item-522",
            code="5.2.2",
            security_attribute="产品开发、发布和安装安全",
            attribute_description="禁止恶意软件。",
            requirement="产品软件禁止存在发送恶意广告、吸费、恶意消耗流量等行为。",
            category="A1",
            guidance="",
            remark="",
        )
        scan = ScanStatus(
            scan_id=scan_id,
            scan_name="Redline Test Scan",
            project_id="proj-1",
            project_path="/repo",
            code_scan_path="/repo/src",
            code_scan_paths=["/repo/src"],
            scan_mode="custom",
            product="DemoProduct",
            status=ScanItemStatus.COMPLETE,
            progress=1.0,
            total_candidates=0,
            processed_candidates=0,
            vulnerabilities=[],
            mining_engines=[
                MiningEngineSelection(
                    engine_id=REDLINE_AUDIT_ENGINE_ID,
                    engine_label=REDLINE_AUDIT_ENGINE_LABEL,
                    enabled=True,
                ),
            ],
            redline_items=[redline_snapshot],
        )
        self.store.save_scan(
            scan,
            ScanMeta(
                scan_items=[],
                scan_name=scan.scan_name,
                project_path=scan.project_path,
                code_scan_path=scan.code_scan_path,
                code_scan_paths=scan.code_scan_paths,
                scan_mode="custom",
                product=scan.product,
                mining_engines=scan.mining_engines,
                redline_items=scan.redline_items,
                user_id=self.regular.user_id,
                created_at="2026-11-28T00:00:00+00:00",
            ),
        )

        task = RedlineAuditTask(
            task_id="redline-audit-hash-round-1",
            scan_id=scan_id,
            redline_item_id="item-522",
            item_code="5.2.2",
            security_attribute=redline_snapshot.security_attribute,
            attribute_description=redline_snapshot.attribute_description,
            requirement=redline_snapshot.requirement,
            category="A1",
            iteration=1,
            max_iterations=5,
            status="completed",
            found=True,
            stop_reason="",
            validation_retries=1,
        )
        self.store.upsert_redline_audit_task(scan_id, task)

        report_md = (
            "**编号**：5.2.2\n\n"
            "**红线要求**：产品软件禁止存在发送恶意广告、吸费、恶意消耗流量等行为。\n\n"
            "**安全属性**：产品开发、发布和安装安全\n\n"
            "**属性描述**：禁止恶意软件。\n\n"
            "**分类**：A1\n\n"
            "**违规位置**：`src/bg.c:84`\n\n"
            "**所在函数**：`SendHiddenAdLoop`\n\n"
            "**问题描述**：静默循环发送广告请求。\n\n"
            "**关键证据**\n\n`src/bg.c:84`\n\n**整改建议**：移除广告上报。"
        )
        vuln = Vulnerability(
            file="src/bg.c",
            line=84,
            function="SendHiddenAdLoop",
            vuln_type="5.2.2 禁止恶意软件",
            severity="high",
            description="静默循环发送广告请求。",
            vulnerable_code="`src/bg.c:84`",
            remediation="移除广告上报。",
            vulnerability_report=report_md,
            confirmed=True,
            ai_verdict="confirmed",
            user_verdict="confirmed",
            analysis_source=REDLINE_AUDIT_ENGINE_ID,
            engine_id=REDLINE_AUDIT_ENGINE_ID,
            engine_label=REDLINE_AUDIT_ENGINE_LABEL,
            source_task_id=task.task_id,
        )
        idx = self.store.add_vulnerability(scan_id, vuln)
        self.store.link_redline_audit_task_vulnerability(scan_id, task.task_id, idx)

        # 1. Exempt from FP review
        loaded_pair = self.store.load_scan(scan_id)
        self.assertIsNotNone(loaded_pair)
        loaded, _meta = loaded_pair
        self.assertEqual(_ordered_fp_review_candidates(loaded, {}), [])

        # 2. Overview & summary counts include direct suspected redline issues without FP review
        overview_resp = self.client.get(
            f"/api/v2/scans/{scan_id}/overview",
            headers=_auth_header(self.regular),
        )
        self.assertEqual(overview_resp.status_code, 200)
        counts = overview_resp.json()["detail_counts"]
        self.assertEqual(counts["direct_suspected_issue_count"], 1)
        self.assertEqual(counts["suspected_issue_count"], 1)
        self.assertEqual(counts["human_confirmed_issue_count"], 1)
        self.assertEqual(counts["redline_audit_items_total"], 1)
        self.assertEqual(counts["redline_audit_findings"], 1)

        scans_resp = self.client.get("/api/v2/scans", headers=_auth_header(self.regular))
        self.assertEqual(scans_resp.status_code, 200)
        summary_item = scans_resp.json()["items"][0]
        self.assertEqual(summary_item["suspected_issue_count"], 1)
        self.assertEqual(summary_item["confirmed_vulnerability_count"], 1)

        # 3. Audit source resolves back to redline_audit task
        source = self.store.get_vulnerability_audit_source(scan_id, idx)
        self.assertEqual(source.status, "resolved")
        self.assertEqual(source.kind, "redline_audit")
        self.assertIsNotNone(source.redline_task)
        self.assertEqual(source.redline_task.task_id, task.task_id)

        # 4. V2 API endpoints return tasks & findings
        tasks_resp = self.client.get(
            f"/api/v2/scans/{scan_id}/redline-audit-tasks",
            headers=_auth_header(self.regular),
        )
        self.assertEqual(tasks_resp.status_code, 200)
        self.assertEqual(len(tasks_resp.json()["items"]), 1)

        results_resp = self.client.get(
            f"/api/v2/scans/{scan_id}/redline-audit-results",
            params={"task_ids": [task.task_id]},
            headers=_auth_header(self.regular),
        )
        self.assertEqual(results_resp.status_code, 200)
        self.assertEqual(results_resp.json()[0]["findings"][0]["verdict"], "confirmed")

        # 5. Single-scan Excel export includes redline issue
        report_resp = self.client.get(
            f"/api/scan/{scan_id}/report",
            headers=_auth_header(self.regular),
        )
        self.assertEqual(report_resp.status_code, 200)
        wb = openpyxl.load_workbook(io.BytesIO(report_resp.content))
        sheet = wb.active
        self.assertEqual(sheet.max_row, 2)
        self.assertIn("5.2.2", str(sheet.cell(2, 4).value))

        # 6. Admin cross-scan export includes redline issue
        candidates = self.store.list_admin_export_candidate_scans()
        self.assertEqual([c["scan_id"] for c in candidates], [scan_id])
        chunk = self.store.load_admin_export_scan_chunk([scan_id])
        self.assertIn(scan_id, chunk)
        self.assertEqual(len(chunk[scan_id][0]), 1)

        # 7. Admin user management counts include direct suspected redline issues
        users_summary = self.store.list_admin_users()
        regular_row = next(u for u in users_summary if u.user_id == self.regular.user_id)
        self.assertEqual(regular_row.scan_count, 1)
        self.assertEqual(regular_row.suspected_issue_count, 1)

    def test_scan_creation_validates_custom_mode_and_enabled_redlines(self) -> None:
        from backend.application import ApplicationError
        from backend.models import AgentRemoteConfig, CreateScanRequest, MiningEngineRequest, User
        from backend.scans.creation_config import resolve_creation_configuration

        user = User(user_id=self.regular.user_id, username=self.regular.username, role="user")
        managed = AgentRemoteConfig()

        # Non-custom mode cannot enable redline_audit
        with self.assertRaises(ApplicationError) as non_custom_exc:
            resolve_creation_configuration(
                CreateScanRequest(
                    agent_key="agent-key-1",
                    project_path="/repo",
                    code_scan_paths=["/repo/src"],
                    scan_name="Standard Redline",
                    product="Demo",
                    scan_mode="standard",
                    mining_engines=[MiningEngineRequest(engine_id=REDLINE_AUDIT_ENGINE_ID)],
                ),
                managed,
                user,
                [],
                enabled_redline_items=[
                    ScanRedlineItem(
                        item_id="item-1",
                        code="5.2.2",
                        security_attribute="属性",
                        attribute_description="描述",
                        requirement="禁止恶意软件",
                    )
                ],
            )
        self.assertEqual(non_custom_exc.exception.status_code, 422)

        # Custom mode with redline_audit and 0 enabled redline items returns 422
        with self.assertRaises(ApplicationError) as empty_exc:
            resolve_creation_configuration(
                CreateScanRequest(
                    agent_key="agent-key-1",
                    project_path="/repo",
                    code_scan_paths=["/repo/src"],
                    scan_name="Empty Redline",
                    product="Demo",
                    scan_mode="custom",
                    threat_analysis_enabled=False,
                    mining_engines=[MiningEngineRequest(engine_id=REDLINE_AUDIT_ENGINE_ID)],
                ),
                managed,
                user,
                [],
                enabled_redline_items=[],
            )
        self.assertEqual(empty_exc.exception.status_code, 422)
        self.assertIn("红线", empty_exc.exception.detail)

        # Custom mode with enabled items succeeds and freezes snapshot
        resolved = resolve_creation_configuration(
            CreateScanRequest(
                agent_key="agent-key-1",
                project_path="/repo",
                code_scan_paths=["/repo/src"],
                scan_name="Valid Redline",
                product="Demo",
                scan_mode="custom",
                threat_analysis_enabled=False,
                mining_engines=[MiningEngineRequest(engine_id=REDLINE_AUDIT_ENGINE_ID)],
            ),
            managed,
            user,
            [],
            enabled_redline_items=[
                ScanRedlineItem(
                    item_id="item-1",
                    code="5.2.2",
                    security_attribute="属性",
                    attribute_description="描述",
                    requirement="禁止恶意软件",
                )
            ],
        )
        self.assertEqual([item.code for item in resolved.redline_items], ["5.2.2"])


if __name__ == "__main__":
    unittest.main()
