"""Tests for admin cross-scan Excel issue export, DB overhead, and Excel generation."""

from __future__ import annotations

import asyncio
import io
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI
import httpx
import openpyxl
import pytest

from backend import auth
from backend.api import admin as admin_api
from backend.application import BackendRuntime, use_runtime
from backend.models import (
    FpReviewJob,
    FpReviewResult,
    FpReviewStatus,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    Vulnerability,
)
from backend.store.postgres import _is_readonly_sql
from backend.store.sqlite import SqliteScanStore
from backend.xlsx_export import (
    XLSX_MEDIA_TYPE,
    XlsxColumn,
    XlsxHyperlink,
    build_xlsx_workbook,
)


async def _direct_store_call(store, operation, *args, **kwargs):
    fn = getattr(store, operation) if isinstance(operation, str) else operation
    return fn(*args, **kwargs)


def _make_vuln(
    name: str,
    *,
    file: str | None = None,
    line: int = 10,
    vuln_type: str = "out_of_bounds",
    description: str | None = None,
    root_cause: str = "",
    user_verdict: str | None = None,
) -> Vulnerability:
    return Vulnerability(
        file=file or f"src/{name}.c",
        line=line,
        function=name,
        vuln_type=vuln_type,
        severity="high",
        description=description or f"{name} issue description",
        root_cause=root_cause,
        ai_analysis="verbose internal analysis body",
        function_source="void fn() { /* large source */ }",
        confirmed=True,
        ai_verdict="confirmed",
        user_verdict=user_verdict,
    )


def _save_scan_with_results(
    store: SqliteScanStore,
    *,
    scan_id: str,
    user_id: str,
    scan_name: str,
    product: str,
    created_at: str,
    vulns: list[Vulnerability],
    fp_results: list[FpReviewResult] | None = None,
    fp_job_created_at: str | None = None,
) -> None:
    scan = ScanStatus(
        scan_id=scan_id,
        project_id=f"proj-{scan_id}",
        scan_name=scan_name,
        product=product,
        status=ScanItemStatus.COMPLETE,
        created_at=created_at,
        progress=1.0,
        total_candidates=len(vulns),
        processed_candidates=len(vulns),
        vulnerabilities=[],
    )
    meta = ScanMeta(
        scan_id=scan_id,
        project_id=f"proj-{scan_id}",
        scan_name=scan_name,
        product=product,
        scan_items=["out_of_bounds"],
        created_at=created_at,
        user_id=user_id,
    )
    store.save_scan(scan, meta)
    for vuln in vulns:
        store.add_vulnerability(scan_id, vuln)
    if fp_results:
        review_id = f"rev-{scan_id}"
        store.create_fp_review_job(
            review_id,
            scan_id,
            len(fp_results),
            fp_job_created_at or created_at,
        )
        store.update_fp_review_job(
            review_id,
            status=FpReviewStatus.COMPLETE,
            processed=len(fp_results),
        )
        for result in fp_results:
            store.add_fp_review_result(review_id, result)


def _parse_excel(payload: bytes):
    wb = openpyxl.load_workbook(io.BytesIO(payload))
    try:
        ws = wb.active
        headers = [str(cell.value or "") for cell in ws[1]]
        rows: list[dict[str, object]] = []
        links: list[str] = []
        for row_idx in range(2, ws.max_row + 1):
            row_dict: dict[str, object] = {}
            link_target = ""
            for col_idx, header in enumerate(headers, start=1):
                cell = ws.cell(row=row_idx, column=col_idx)
                row_dict[header] = "" if cell.value is None else cell.value
                if header == "所属扫描分享链接" and cell.hyperlink is not None:
                    link_target = cell.hyperlink.target or ""
            rows.append(row_dict)
            links.append(link_target)
        return {
            "sheet_name": ws.title,
            "freeze_panes": ws.freeze_panes,
            "auto_filter": ws.auto_filter.ref,
            "headers": headers,
            "rows": rows,
            "links": links,
        }
    finally:
        wb.close()


def _make_app(store: SqliteScanStore):
    app = FastAPI()
    app.include_router(admin_api.router)
    runtime = BackendRuntime(store=store, store_runner=_direct_store_call)
    return app, runtime


def test_xlsx_writer_handles_hyperlinks_numbers_control_chars_and_formula_safety():
    huge = "A" * 40000
    payload = build_xlsx_workbook(
        sheet_name="全部/问题:列表",
        columns=(
            XlsxColumn("文本", width=20, wrap_text=True),
            XlsxColumn("行号", width=10, is_integer=True),
            XlsxColumn("链接", width=40, is_hyperlink=True),
            XlsxColumn("超长", width=20),
        ),
        rows=[
            (
                "=CMD|' /C calc'!A0\x00\x07\x1b\r\n第二行",
                42,
                XlsxHyperlink("https://example.test/shared-scan/s1/overview?token=abc"),
                huge,
            ),
            ("普通文本", 0, "", "短文本"),
        ],
    )
    wb = openpyxl.load_workbook(io.BytesIO(payload))
    try:
        ws = wb.active
        assert ws.title == "全部_问题_列表"
        assert ws.freeze_panes == "A2"
        assert ws.auto_filter.ref == "A1:D3"
        # Formula string stays literal text (not evaluated/tagged as formula).
        assert ws["A2"].data_type == "s"
        assert ws["A2"].value == "=CMD|' /C calc'!A0\n第二行"
        assert ws["B2"].value == 42
        assert isinstance(ws["B2"].value, int)
        assert ws["C2"].value == "https://example.test/shared-scan/s1/overview?token=abc"
        assert ws["C2"].hyperlink is not None
        assert ws["C2"].hyperlink.target == "https://example.test/shared-scan/s1/overview?token=abc"
        assert len(ws["D2"].value) == 32767
        assert ws["D2"].value.endswith("…")
        assert ws["B3"].value in (None, "")
        assert ws["C3"].hyperlink is None
    finally:
        wb.close()


def test_admin_export_end_to_end_filters_dedup_shares_and_rbac(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    store = SqliteScanStore(tmp_path / "export.db")
    monkeypatch.setattr(auth, "get_scan_store", lambda: store)
    try:
        store.create_user("u-admin", "admin", "h", "admin", "t-admin", employee_id="A001")
        store.create_user("u-alice", "AliceDev", "h", "user", "t-alice", employee_id="E102")
        store.create_user("u-bob", "bob_50%", "h", "user", "t-bob", employee_id="B_99!1")

        # 1) Alice scan 1: existing share link, regenerated report override, plus FP/incomplete/unreviewed.
        regenerated_md = (
            "**漏洞类型**：缓冲区越界写\n\n"
            "**漏洞位置**：`src/proto/parser.c:44`\n\n"
            "**漏洞函数**：`CopyPayload`\n\n"
            "**问题**：最终裁决重写后的准确问题描述。\n"
        )
        _save_scan_with_results(
            store,
            scan_id="scan-alice-1",
            user_id="u-alice",
            scan_name="Gateway-Core",
            product="ProdA",
            created_at="2026-11-20T01:00:00+00:00",
            vulns=[
                _make_vuln("stale_fn", file="src/wrong.c", line=999, user_verdict="confirmed"),
                _make_vuln("fp_fn"),
                _make_vuln("incomplete_fn"),
                _make_vuln("unreviewed_fn"),
            ],
            fp_results=[
                FpReviewResult(
                    vuln_index=0,
                    verdict="tp",
                    severity="high",
                    reason="confirmed tp",
                    vulnerability_report=regenerated_md,
                    created_at="2026-11-21T02:00:00+00:00",
                ),
                FpReviewResult(
                    vuln_index=1,
                    verdict="fp",
                    severity="low",
                    reason="safe",
                    created_at="2026-11-21T02:05:00+00:00",
                ),
                FpReviewResult(
                    vuln_index=2,
                    verdict="tp",
                    severity="high",
                    reason="Review incomplete: timeout",
                    created_at="2026-11-21T02:10:00+00:00",
                ),
            ],
        )
        existing_share = store.get_or_create_scan_share("scan-alice-1")
        assert existing_share is not None
        existing_token = existing_share["token"]

        # 2) Alice scan 2: same-location TP dedup (2 identical root_cause + 1 distinct root_cause).
        _save_scan_with_results(
            store,
            scan_id="scan-alice-2",
            user_id="u-alice",
            scan_name="Gateway-Edge",
            product="ProdA",
            created_at="2026-11-22T01:00:00+00:00",
            vulns=[
                _make_vuln("dup_fn", file="src/dup.c", line=20, root_cause="rc-same", user_verdict="pending_analysis"),
                _make_vuln("dup_fn", file="src/dup.c", line=20, root_cause="rc-same"),
                _make_vuln("dup_fn", file="src/dup.c", line=20, root_cause="rc-distinct", user_verdict="false_positive"),
            ],
            fp_results=[
                FpReviewResult(
                    vuln_index=0,
                    verdict="tp",
                    severity="high",
                    reason="tp-0",
                    created_at="2026-11-22T08:00:00+00:00",
                ),
                FpReviewResult(
                    vuln_index=1,
                    verdict="tp",
                    severity="high",
                    reason="tp-1",
                    created_at="2026-11-22T09:00:00+00:00",
                ),
                FpReviewResult(
                    vuln_index=2,
                    verdict="tp",
                    severity="high",
                    reason="tp-2",
                    created_at="2026-11-22T10:00:00+00:00",
                ),
            ],
        )

        # 3) Bob scan: UTC 2026-11-22T16:30:00+00:00 == UTC+8 2026-11-23 00:30:00 (crosses midnight!).
        _save_scan_with_results(
            store,
            scan_id="scan-bob-1",
            user_id="u-bob",
            scan_name="Kernel-Net",
            product="ProdB",
            created_at="2026-11-22T15:00:00+00:00",
            vulns=[_make_vuln("bob_fn", file="net/pkt.c", line=88, vuln_type="uaf")],
            fp_results=[
                FpReviewResult(
                    vuln_index=0,
                    verdict="tp",
                    severity="critical",
                    reason="real uaf",
                    created_at="2026-11-22T16:30:00+00:00",
                ),
            ],
        )

        # 4) Zero-TP scan (must never receive a share row).
        _save_scan_with_results(
            store,
            scan_id="scan-zero-tp",
            user_id="u-alice",
            scan_name="Clean-Scan",
            product="ProdA",
            created_at="2026-11-22T12:00:00+00:00",
            vulns=[_make_vuln("clean_fn")],
            fp_results=[
                FpReviewResult(
                    vuln_index=0,
                    verdict="fp",
                    severity="low",
                    reason="not a bug",
                    created_at="2026-11-22T12:05:00+00:00",
                ),
            ],
        )

        # 5) Deleted scan with TP issue (must be excluded and never receive a share row).
        _save_scan_with_results(
            store,
            scan_id="scan-deleted",
            user_id="u-alice",
            scan_name="Deleted-Scan",
            product="ProdA",
            created_at="2026-11-22T12:00:00+00:00",
            vulns=[_make_vuln("deleted_fn")],
            fp_results=[
                FpReviewResult(
                    vuln_index=0,
                    verdict="tp",
                    severity="high",
                    reason="real",
                    created_at="2026-11-22T12:10:00+00:00",
                ),
            ],
        )
        store.request_scan_deletion("scan-deleted")

        app, runtime = _make_app(store)
        admin_token = auth.create_token("u-admin", "admin", "admin")
        user_token = auth.create_token("u-alice", "AliceDev", "user")

        async def run():
            transport = httpx.ASGITransport(app=app)
            with use_runtime(runtime):
                async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                    # Non-admin user is forbidden.
                    denied = await client.get(
                        "/api/admin/issues/export",
                        headers={"Authorization": f"Bearer {user_token}"},
                    )
                    assert denied.status_code == 403

                    # Validation errors return 400.
                    bad_range = await client.get(
                        "/api/admin/issues/export",
                        params={"start_time": "2026-11-25", "end_time": "2026-11-20"},
                        headers={"Authorization": f"Bearer {admin_token}"},
                    )
                    assert bad_range.status_code == 400
                    assert "开始时间不能晚于结束时间" in bad_range.json()["detail"]

                    bad_origin = await client.get(
                        "/api/admin/issues/export",
                        params={"share_origin": "https://evil.test/extra?x=1"},
                        headers={"Authorization": f"Bearer {admin_token}"},
                    )
                    assert bad_origin.status_code == 400

                    # Filtered export (UTC+8 midnight boundary: 2026-11-23 includes scan-bob-1 ONLY).
                    # Also verifies LIKE special chars (%, _, !) match literally without wildcard bleed.
                    bob_resp = await client.get(
                        "/api/admin/issues/export",
                        params={
                            "start_time": "2026-11-23",
                            "end_time": "2026-11-23",
                            "username": "bob_50%",
                            "employee_id": "b_99!1",
                            "tz_offset_minutes": 480,
                            "share_origin": "https://deephole.corp.test",
                        },
                        headers={"Authorization": f"Bearer {admin_token}"},
                    )
                    assert bob_resp.status_code == 200
                    assert bob_resp.headers["content-type"].startswith(XLSX_MEDIA_TYPE)
                    assert bob_resp.headers["cache-control"] == "no-store"
                    assert bob_resp.headers["x-export-row-count"] == "1"
                    bob_sheet = _parse_excel(bob_resp.content)
                    assert bob_sheet["headers"] == [
                        "发现用户名",
                        "工号",
                        "发现时间",
                        "产品",
                        "所属扫描",
                        "所属扫描分享链接",
                        "文件",
                        "行号",
                        "函数",
                        "问题类型",
                        "问题描述",
                        "人工反馈",
                    ]
                    assert len(bob_sheet["rows"]) == 1
                    bob_row = bob_sheet["rows"][0]
                    assert bob_row["发现用户名"] == "bob_50%"
                    assert bob_row["工号"] == "B_99!1"
                    assert bob_row["发现时间"] == "2026-11-23 00:30:00"
                    assert bob_row["产品"] == "ProdB"
                    assert bob_row["所属扫描"] == "Kernel-Net"
                    assert bob_row["行号"] == 88
                    assert bob_row["函数"] == "bob_fn"
                    assert bob_row["所属扫描分享链接"].startswith(
                        "https://deephole.corp.test/shared-scan/scan-bob-1/overview?token="
                    )
                    assert bob_sheet["links"][0] == bob_row["所属扫描分享链接"]
                    # Filtered-out scan-alice-2 must NOT have a share created yet!
                    assert store.get_scan_share("scan-alice-2") is None
                    assert store.get_scan_share("scan-bob-1") is not None

                    # Full unfiltered export (via forwarded proxy headers).
                    all_resp = await client.get(
                        "/api/admin/issues/export",
                        params={"tz_offset_minutes": 480},
                        headers={
                            "Authorization": f"Bearer {admin_token}",
                            "X-Forwarded-Proto": "https",
                            "X-Forwarded-Host": "proxy.example.test",
                        },
                    )
                    assert all_resp.status_code == 200
                    # Expected: 1 (bob) + 2 (alice-2 after dedup) + 1 (alice-1) = 4 rows.
                    assert all_resp.headers["x-export-row-count"] == "4"
                    parsed = _parse_excel(all_resp.content)
                    assert len(parsed["rows"]) == 4

                    # Sorted descending by 发现时间 (UTC+8):
                    assert [r["发现时间"] for r in parsed["rows"]] == [
                        "2026-11-23 00:30:00",
                        "2026-11-22 18:00:00",
                        "2026-11-22 17:00:00",
                        "2026-11-21 10:00:00",
                    ]
                    # Alice scan 1 uses regenerated final-judge fields & preserves existing share token!
                    alice1_row = parsed["rows"][3]
                    assert alice1_row["发现用户名"] == "AliceDev"
                    assert alice1_row["工号"] == "E102"
                    assert alice1_row["文件"] == "src/proto/parser.c"
                    assert alice1_row["行号"] == 44
                    assert alice1_row["函数"] == "CopyPayload"
                    assert alice1_row["问题类型"] == "缓冲区越界写"
                    assert "最终裁决重写后的准确问题描述" in str(alice1_row["问题描述"])
                    assert alice1_row["人工反馈"] == "确认正报"
                    parsed_url = urlsplit(str(alice1_row["所属扫描分享链接"]))
                    assert parsed_url.scheme == "https"
                    assert parsed_url.netloc == "proxy.example.test"
                    assert parse_qs(parsed_url.query)["token"] == [existing_token]

                    # Alice scan 2 feedback labels on deduplicated + distinct rows.
                    assert parsed["rows"][1]["人工反馈"] == "实为误报"
                    assert parsed["rows"][2]["人工反馈"] == "待分析"

                    # Zero-TP and deleted scans NEVER receive share links.
                    assert store.get_scan_share("scan-zero-tp") is None
                    assert store.get_scan_share("scan-deleted") is None

                    # Empty match returns valid header-only workbook.
                    empty_resp = await client.get(
                        "/api/admin/issues/export",
                        params={"username": "nonexistent-user"},
                        headers={"Authorization": f"Bearer {admin_token}"},
                    )
                    assert empty_resp.status_code == 200
                    assert empty_resp.headers["x-export-row-count"] == "0"
                    empty_sheet = _parse_excel(empty_resp.content)
                    assert len(empty_sheet["headers"]) == 12
                    assert empty_sheet["rows"] == []

        asyncio.run(run())
    finally:
        store.close()


def test_admin_export_query_overhead_skips_heavy_tables_and_stays_pg_readonly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    store = SqliteScanStore(tmp_path / "perf.db")
    monkeypatch.setattr(auth, "get_scan_store", lambda: store)
    try:
        store.create_user("u-admin", "admin", "h", "admin", "t-admin", employee_id="A001")
        store.create_user("u-dev", "dev1", "h", "user", "t-dev", employee_id="D001")
        _save_scan_with_results(
            store,
            scan_id="scan-clean-1",
            user_id="u-dev",
            scan_name="Clean-1",
            product="P1",
            created_at="2026-11-20T01:00:00+00:00",
            vulns=[_make_vuln("clean_a")],
            fp_results=[
                FpReviewResult(
                    vuln_index=0,
                    verdict="fp",
                    severity="low",
                    reason="safe",
                    created_at="2026-11-20T02:00:00+00:00",
                ),
            ],
        )
        _save_scan_with_results(
            store,
            scan_id="scan-tp-1",
            user_id="u-dev",
            scan_name="Target-1",
            product="P1",
            created_at="2026-11-21T01:00:00+00:00",
            vulns=[
                _make_vuln("tp_a", file="src/a.c", line=10),
                _make_vuln("tp_b", file="src/b.c", line=20),
            ],
            fp_results=[
                FpReviewResult(
                    vuln_index=0,
                    verdict="tp",
                    severity="high",
                    reason="real a",
                    created_at="",  # exercises fallback to scans.created_at
                ),
                FpReviewResult(
                    vuln_index=1,
                    verdict="tp",
                    severity="high",
                    reason="real b",
                    created_at="2026-11-21T03:00:00+00:00",
                ),
            ],
        )
        # Pre-create share link so ensure_scan_shares executes zero writes!
        store.get_or_create_scan_share("scan-tp-1")

        traced_sql: list[str] = []
        store._conn.set_trace_callback(traced_sql.append)
        try:
            candidates = store.list_admin_export_candidate_scans()
            assert [item["scan_id"] for item in candidates] == ["scan-tp-1"]

            filtered_candidates = store.list_admin_export_candidate_scans(
                username="dev1", employee_id="D001"
            )
            assert [item["scan_id"] for item in filtered_candidates] == ["scan-tp-1"]

            chunk = store.load_admin_export_scan_chunk(["scan-tp-1"])
            assert "scan-tp-1" in chunk
            assert len(chunk["scan-tp-1"][0]) == 2

            tokens = store.ensure_scan_shares(["scan-tp-1"])
            assert tokens["scan-tp-1"]
        finally:
            store._conn.set_trace_callback(None)

        forbidden_tables = (
            "scan_audit_versions",
            "fp_stage_versions",
            "fp_review_stage_outputs",
            "scan_candidates",
            "events",
            "vulnerability_validations",
            "skill_reports",
        )
        for sql in traced_sql:
            lowered = sql.lower()
            for table in forbidden_tables:
                assert table not in lowered, f"Unexpected read of heavy table {table}: {sql}"
            # Zero write queries when share token already exists.
            assert not lowered.lstrip().startswith(("insert", "update", "delete")), sql
            # Every read SQL must be classified read-only by PostgresStore!
            assert _is_readonly_sql(sql), f"Not recognized as PG readonly SQL: {sql}"

        # Also exercise the legacy ready=0 fallback branch and assert PG readonly compatibility.
        store._conn.execute("UPDATE scan_summary_state SET ready = 0 WHERE scan_id = 'scan-tp-1'")
        store._conn.commit()
        legacy_sql: list[str] = []
        store._conn.set_trace_callback(legacy_sql.append)
        try:
            assert [c["scan_id"] for c in store.list_admin_export_candidate_scans()] == ["scan-tp-1"]
            assert [
                c["scan_id"]
                for c in store.list_admin_export_candidate_scans(username="dev1")
            ] == ["scan-tp-1"]
        finally:
            store._conn.set_trace_callback(None)
        assert legacy_sql
        for sql in legacy_sql:
            assert _is_readonly_sql(sql), f"Legacy fallback SQL not PG readonly: {sql}"

        # Verify fallback timestamp to scans.created_at when fp_review_results.created_at == "".
        app, runtime = _make_app(store)
        admin_token = auth.create_token("u-admin", "admin", "admin")

        async def run_fallback_check():
            transport = httpx.ASGITransport(app=app)
            with use_runtime(runtime):
                async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                    resp = await client.get(
                        "/api/admin/issues/export",
                        params={"tz_offset_minutes": 0},
                        headers={"Authorization": f"Bearer {admin_token}"},
                    )
                    assert resp.status_code == 200
                    parsed = _parse_excel(resp.content)
                    by_fn = {r["函数"]: r for r in parsed["rows"]}
                    assert by_fn["tp_a"]["发现时间"] == "2026-11-21 01:00:00"
                    assert by_fn["tp_b"]["发现时间"] == "2026-11-21 03:00:00"

        asyncio.run(run_fallback_check())
    finally:
        store.close()
