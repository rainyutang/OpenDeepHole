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

    def test_all_agent_and_scan_routes_are_mounted_on_app(self) -> None:
        import importlib
        import pkgutil
        from backend.api import agent_routes, scan_routes

        mounted = {route.name for route in app.routes if hasattr(route, "name")}
        missing_agent: list[tuple[str, str, str]] = []
        for mod_info in pkgutil.iter_modules(agent_routes.__path__):
            mod = importlib.import_module(f"backend.api.agent_routes.{mod_info.name}")
            for attr in ("router", "public_router"):
                sub_router = getattr(mod, attr, None)
                if sub_router is None:
                    continue
                for route in sub_router.routes:
                    if route.name not in mounted:
                        missing_agent.append((mod_info.name, route.name, route.path))
        self.assertEqual(missing_agent, [])

        missing_scan: list[tuple[str, str, str]] = []
        for mod_info in pkgutil.iter_modules(scan_routes.__path__):
            mod = importlib.import_module(f"backend.api.scan_routes.{mod_info.name}")
            sub_router = getattr(mod, "router", None)
            if sub_router is None:
                continue
            for route in sub_router.routes:
                if route.name not in mounted:
                    missing_scan.append((mod_info.name, route.name, route.path))
        self.assertEqual(missing_scan, [])

    def test_real_engine_reporter_outbox_http_end_to_end_delivers_tasks_and_suspected_issues(self) -> None:
        import asyncio
        import threading
        from types import SimpleNamespace
        import httpx
        from deephole_client.reporter import Reporter
        from deephole_client.vulnerability_mining.dedup import VulnerabilityDeduplicator
        from deephole_client.vulnerability_mining.engines.redline_audit.engine import run as run_redline_engine
        from deephole_client.vulnerability_mining.runtime import (
            load_mining_engines,
            normalize_mining_engine_vulnerabilities,
        )
        from task_agent.api import OpenCodeResult

        scan_id = "scan-redline-real-http"
        project = Path(self._tmp.name) / "repo"
        src = project / "src"
        work = Path(self._tmp.name) / "work"
        src.mkdir(parents=True)
        work.mkdir(parents=True)
        (src / "bg.c").write_text(
            "\n".join(f"int line_{i} = {i};" for i in range(1, 100)) + "\n",
            encoding="utf-8",
        )
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
            scan_name="Real HTTP Redline Scan",
            project_id="proj-http",
            project_path=str(project),
            code_scan_path=str(src),
            code_scan_paths=[str(src)],
            scan_mode="custom",
            product="DemoProduct",
            status=ScanItemStatus.AUDITING,
            execution_revision=1,
            progress=0.0,
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
                execution_revision=1,
                execution_agent_session_id="agent-sess-1",
                created_at="2026-11-28T00:00:00+00:00",
            ),
        )
        self.store._conn.execute(
            "UPDATE scans SET execution_revision = 1, execution_agent_session_id = ? WHERE scan_id = ?",
            ("agent-sess-1", scan_id),
        )
        self.store._conn.commit()

        loaded_engine = load_mining_engines().get(REDLINE_AUDIT_ENGINE_ID)
        assert loaded_engine is not None

        async def exercise() -> dict:
            reporter = Reporter(
                "http://testserver",
                outbox_path=Path(self._tmp.name) / "e2e_outbox.sqlite3",
            )
            await reporter._client.aclose()
            reporter._client = httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://testserver",
            )
            reporter.agent_session_id = "agent-sess-1"
            reporter.set_capabilities({"server_owned_pattern_task_settlement": True})
            reporter.set_scan_execution(scan_id, 1)
            reporter.start_outbox_worker()

            dedup = VulnerabilityDeduplicator(
                scan_id=scan_id,
                project_path=project,
                required_capability="high",
                output=AsyncMock(),
            )

            async def report_values(values: list[dict]):
                normalized = normalize_mining_engine_vulnerabilities(loaded_engine, values)
                reported = []
                for vuln in normalized:
                    decision = await dedup.assess(vuln)
                    self.assertTrue(decision.accepted)
                    resp = await reporter.report_vulnerability(scan_id, vuln)
                    reported.append((vuln, resp))
                return reported

            call_count = {"n": 0}

            async def fake_llm(**kwargs):
                call_count["n"] += 1
                if call_count["n"] == 1:
                    return OpenCodeResult(
                        session_id="sess-r1",
                        status="success",
                        text="{}",
                        structured={
                            "found": True,
                            "redline_requirement": redline_snapshot.requirement,
                            "file": "src/bg.c",
                            "line": 84,
                            "function": "SendHiddenAdLoop",
                            "description": "静默循环发送广告请求。",
                            "evidence": "`src/bg.c:84`\n```c\n84 | int line_84 = 84;\n```",
                            "remediation": "移除未授权广告逻辑。",
                        },
                        model="provider/model",
                        output_source={"serve_session_id": "sess-r1"},
                    )
                return OpenCodeResult(
                    session_id="sess-r2",
                    status="success",
                    text='{"found": false}',
                    structured={"found": False},
                    model="provider/model",
                    output_source={"serve_session_id": "sess-r2"},
                )

            try:
                config = SimpleNamespace(
                    vulnerability_mining=SimpleNamespace(required_capability="high", concurrency=1),
                    opencode=SimpleNamespace(concurrency=1),
                )
                with patch(
                    "deephole_client.vulnerability_mining.engines.redline_audit.engine.run_opencode_task",
                    new=AsyncMock(side_effect=fake_llm),
                ):
                    outcome = await run_redline_engine(
                        scan_id=scan_id,
                        project_path=project,
                        code_scan_path=src,
                        code_scan_paths=[src],
                        work_dir=work,
                        config=config,
                        reporter=reporter,
                        redline_items=[redline_snapshot.model_dump()],
                        is_resume=False,
                        output=AsyncMock(),
                        cancel_event=threading.Event(),
                        report_vulnerabilities=report_values,
                    )
                for _ in range(50):
                    if reporter._outbox.pending_count() == 0:
                        break
                    await asyncio.sleep(0.05)
                self.assertEqual(reporter._outbox.pending_count(), 0)
                return outcome
            finally:
                await reporter.close()

        outcome = asyncio.run(exercise())
        self.assertEqual(outcome["status"], "success")
        self.assertEqual(outcome["processed_candidates"], 1)

        # Agent GET route works
        agent_tasks = self.client.get(f"/api/agent/scan/{scan_id}/redline-audit-tasks")
        self.assertEqual(agent_tasks.status_code, 200)
        self.assertEqual(len(agent_tasks.json()), 2)
        round1 = next(t for t in agent_tasks.json() if t["iteration"] == 1)
        self.assertEqual(round1["status"], "completed")
        self.assertIs(round1["found"], True)
        self.assertEqual(round1["result_vuln_indexes"], [0])

        # User overview, vulnerability list, live SSE item detail, and admin dashboard all see the finding
        overview = self.client.get(
            f"/api/v2/scans/{scan_id}/overview",
            headers=_auth_header(self.regular),
        )
        self.assertEqual(overview.status_code, 200)
        counts = overview.json()["detail_counts"]
        self.assertEqual(counts["suspected_issue_count"], 1)
        self.assertEqual(counts["direct_suspected_issue_count"], 1)
        self.assertEqual(counts["redline_audit_items_total"], 1)
        self.assertEqual(counts["redline_audit_items_completed"], 1)
        self.assertEqual(counts["redline_audit_findings"], 1)

        vulns = self.client.get(
            f"/api/v2/scans/{scan_id}/vulnerabilities",
            headers=_auth_header(self.regular),
        )
        self.assertEqual(vulns.status_code, 200)
        items = vulns.json()["items"]
        self.assertEqual(len(items), 1)
        v0 = items[0]["vulnerability"]
        self.assertEqual(v0["engine_id"], REDLINE_AUDIT_ENGINE_ID)
        self.assertEqual(v0["analysis_source"], REDLINE_AUDIT_ENGINE_ID)
        self.assertTrue(v0["confirmed"])
        self.assertEqual(v0["ai_verdict"], "confirmed")
        self.assertFalse(v0["provisional"])
        self.assertIn("**编号**：5.2.2", v0["vulnerability_report"])

        detail_item = self.client.get(
            f"/api/v2/scans/{scan_id}/details/vulnerabilities/0",
            headers=_auth_header(self.regular),
        )
        self.assertEqual(detail_item.status_code, 200)
        self.assertEqual(detail_item.json()["engine_id"], REDLINE_AUDIT_ENGINE_ID)

        dashboard = self.client.get(
            "/api/v2/checker-dashboard",
            headers=_auth_header(self.admin),
        )
        self.assertEqual(dashboard.status_code, 200)
        self.assertEqual(dashboard.json()["summary"]["suspected_issue_count"], 1)

    def test_outbox_404_redline_head_recovery_flushes_trapped_vulnerabilities(self) -> None:
        import asyncio
        import httpx
        from deephole_client.reporter import Reporter

        scan_id = "scan-outbox-recover"
        redline_snapshot = ScanRedlineItem(
            item_id="item-522",
            code="5.2.2",
            security_attribute="产品开发、发布和安装安全",
            attribute_description="禁止恶意软件。",
            requirement="产品软件禁止存在发送恶意广告、吸费、恶意消耗流量等行为。",
            category="A1",
        )
        scan = ScanStatus(
            scan_id=scan_id,
            scan_name="Outbox Recovery Scan",
            project_id="proj-recover",
            project_path="/repo",
            code_scan_path="/repo/src",
            code_scan_paths=["/repo/src"],
            scan_mode="custom",
            product="DemoProduct",
            status=ScanItemStatus.AUDITING,
            execution_revision=1,
            progress=0.0,
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
                execution_revision=1,
                execution_agent_session_id="agent-sess-recover",
                created_at="2026-11-28T00:00:00+00:00",
            ),
        )
        self.store._conn.execute(
            "UPDATE scans SET execution_revision = 1, execution_agent_session_id = ? WHERE scan_id = ?",
            ("agent-sess-recover", scan_id),
        )
        self.store._conn.commit()

        async def exercise() -> None:
            outbox_path = Path(self._tmp.name) / "blocked_outbox.sqlite3"
            reporter = Reporter("http://testserver", outbox_path=outbox_path)
            await reporter._client.aclose()
            reporter._client = httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://testserver",
            )
            try:
                head_task = RedlineAuditTask(
                    task_id="redline-audit-recover-round-1",
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
                )
                head_report = reporter._outbox.enqueue(
                    target_url="http://testserver",
                    stream_key=f"scan:{scan_id}",
                    dedupe_key=f"scan:{scan_id}:redline-audit-task:{head_task.task_id}:agent-sess-recover:1",
                    path=f"/api/agent/scan/{scan_id}/redline-audit-task",
                    payload={
                        **head_task.model_dump(),
                        "execution_revision": 1,
                        "report_agent_session_id": "agent-sess-recover",
                        "report_sequence": 1,
                    },
                )
                reporter._outbox.block(head_report, 'HTTP 404: {"detail":"Not Found"}')

                trapped_vuln = Vulnerability(
                    file="src/bg.c",
                    line=84,
                    function="SendHiddenAdLoop",
                    vuln_type="5.2.2 禁止恶意软件",
                    severity="high",
                    description="后台广告",
                    vulnerability_report="**编号**：5.2.2\n\n**红线要求**：禁止广告",
                    confirmed=True,
                    ai_verdict="confirmed",
                    analysis_source=REDLINE_AUDIT_ENGINE_ID,
                    engine_id=REDLINE_AUDIT_ENGINE_ID,
                    engine_label=REDLINE_AUDIT_ENGINE_LABEL,
                    source_task_id=head_task.task_id,
                )
                reporter._outbox.enqueue(
                    target_url="http://testserver",
                    stream_key=f"scan:{scan_id}",
                    dedupe_key=f"scan:{scan_id}:vulnerability:final:trapped-1",
                    path=f"/api/agent/scan/{scan_id}/vulnerability",
                    payload=trapped_vuln.model_dump(),
                )
                # Confirm head-of-line blocking prevents the trapped vulnerability from being ready
                self.assertEqual(reporter._outbox.ready("http://testserver"), [])

                # Reconnect / worker startup unblocks the historical 404 and drains both rows
                reporter.set_capabilities({})
                reporter.start_outbox_worker()
                for _ in range(50):
                    if reporter._outbox.pending_count() == 0:
                        break
                    await asyncio.sleep(0.05)
                self.assertEqual(reporter._outbox.pending_count(), 0)
            finally:
                await reporter.close()

        asyncio.run(exercise())
        vulns = self.client.get(
            f"/api/v2/scans/{scan_id}/vulnerabilities",
            headers=_auth_header(self.regular),
        )
        self.assertEqual(vulns.status_code, 200)
        self.assertEqual(len(vulns.json()["items"]), 1)
        tasks = self.client.get(
            f"/api/v2/scans/{scan_id}/redline-audit-tasks",
            headers=_auth_header(self.regular),
        )
        self.assertEqual(tasks.status_code, 200)
        self.assertEqual(tasks.json()["items"][0]["result_vuln_indexes"], [0])

    def test_stop_settlement_preserves_completed_redlines_and_cancels_unfinished(self) -> None:
        from backend.scans.resume_policy import _resume_mining_engine_ids

        scan_id = "scan-redline-stop-resume"
        items = [
            ScanRedlineItem(
                item_id="item-done",
                code="5.2.2",
                security_attribute="属性",
                attribute_description="描述1",
                requirement="要求1",
            ),
            ScanRedlineItem(
                item_id="item-running",
                code="5.2.3",
                security_attribute="属性",
                attribute_description="描述2",
                requirement="要求2",
            ),
        ]
        scan = ScanStatus(
            scan_id=scan_id,
            scan_name="Stop Resume Redline",
            project_id="proj-sr",
            project_path="/repo",
            code_scan_path="/repo/src",
            code_scan_paths=["/repo/src"],
            scan_mode="custom",
            product="Demo",
            status=ScanItemStatus.AUDITING,
            execution_revision=1,
            progress=0.0,
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
            redline_items=items,
        )
        meta = ScanMeta(
            scan_items=[],
            scan_name=scan.scan_name,
            project_path=scan.project_path,
            code_scan_path=scan.code_scan_path,
            code_scan_paths=scan.code_scan_paths,
            scan_mode="custom",
            product=scan.product,
            mining_engines=scan.mining_engines,
            redline_items=items,
            user_id=self.regular.user_id,
            execution_revision=1,
            execution_agent_session_id="sess-stop",
            created_at="2026-11-28T00:00:00+00:00",
        )
        self.store.save_scan(scan, meta)
        self.store._conn.execute(
            "UPDATE scans SET execution_revision = 1, execution_agent_session_id = ? WHERE scan_id = ?",
            ("sess-stop", scan_id),
        )
        self.store._conn.commit()
        self.store.upsert_redline_audit_task(
            scan_id,
            RedlineAuditTask(
                task_id="redline-done-round-1",
                scan_id=scan_id,
                redline_item_id="item-done",
                item_code="5.2.2",
                requirement="要求1",
                iteration=1,
                max_iterations=5,
                status="completed",
                found=False,
                stop_reason="no_finding",
            ),
            execution_revision=1,
            report_agent_session_id="sess-stop",
            report_sequence=1,
        )
        self.store.upsert_redline_audit_task(
            scan_id,
            RedlineAuditTask(
                task_id="redline-running-round-1",
                scan_id=scan_id,
                redline_item_id="item-running",
                item_code="5.2.3",
                requirement="要求2",
                iteration=1,
                max_iterations=5,
                status="running",
            ),
            execution_revision=1,
            report_agent_session_id="sess-stop",
            report_sequence=2,
        )

        self.store.update_scan_progress(
            scan_id,
            status=ScanItemStatus.CANCELLED,
            error_message="用户手动停止",
        )
        tasks_by_id = {
            t.task_id: t for t in self.store.list_redline_audit_tasks(scan_id)
        }
        self.assertEqual(tasks_by_id["redline-done-round-1"].status, "completed")
        self.assertEqual(tasks_by_id["redline-running-round-1"].status, "cancelled")

        counts = self.store.get_scan_detail_counts(scan_id)
        self.assertEqual(counts["redline_audit_items_completed"], 1)
        self.assertEqual(counts["redline_audit_items_cancelled"], 1)

        loaded_scan, loaded_meta = self.store.load_scan(scan_id)
        retry_ids = _resume_mining_engine_ids(
            loaded_scan,
            loaded_scan.mining_engines,
            continue_candidates=[],
            incomplete_threat_tasks=[],
            full_pipeline_resume=False,
            resume_threat_analysis=False,
        )
        self.assertIn(REDLINE_AUDIT_ENGINE_ID, retry_ids)
        self.assertEqual([item.item_id for item in loaded_meta.redline_items], ["item-done", "item-running"])


if __name__ == "__main__":
    unittest.main()
