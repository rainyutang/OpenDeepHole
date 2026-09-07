"""Persisted task results, historical association, and final issue semantics."""

import asyncio
import os
import uuid

import httpx
import pytest
from fastapi import FastAPI

from backend.api import integration, scan
from backend.auth import get_current_user
from backend.models import FpReviewResult, ScanMeta, ScanStatus, ThreatAuditTask, User, Vulnerability
from backend.store.sqlite import SqliteScanStore


def save_scan(store, scan_id="s"):
    created = "2026-09-07T00:00:00+00:00"
    store.save_scan(
        ScanStatus(
            scan_id=scan_id, project_id="p", scan_items=[], created_at=created,
            status="complete", progress=1, total_candidates=0, processed_candidates=0,
            vulnerabilities=[],
        ),
        ScanMeta(scan_items=[], created_at=created, user_id="owner", public_access_token="public-test"),
    )


@pytest.fixture
def store(tmp_path):
    instance = SqliteScanStore(tmp_path / "scan.db")
    save_scan(instance)
    yield instance
    instance.close()


def task(store, task_id="t", scan_id="s", **overrides):
    value = ThreatAuditTask.model_validate({
        "task_id": task_id, "status": "completed", "surface_node_id": "tree:leaf",
        "method_node_id": "pattern", "code_path": "src/a.c", **overrides,
    })
    return store.upsert_threat_audit_task(scan_id, value)


def finding(store, task_id="t", scan_id="s", **overrides):
    return store.add_vulnerability(scan_id, Vulnerability.model_validate({
        "source_task_id": task_id, "analysis_source": "threat_audit",
        "threat_surface_node_id": "tree:leaf", "threat_method_node_id": "pattern",
        "threat_code_path": "src/a.c", "file": "src/a.c", "line": 17,
        "function": "parse", "vuln_type": "oob", "severity": "high",
        "description": "长度未经校验，外部输入可导致越界读取。",
        "ai_analysis": "large audit body", "confirmed": True, "ai_verdict": "confirmed",
        "vulnerability_report": "large vulnerability report", **overrides,
    }))


def review(store, index, verdict="tp", *, scan_id="s", created="2026-09-07T01:00:00+00:00", reason="已验证可达调用链", report=""):
    review_id = uuid.uuid4().hex
    store.create_fp_review_job(review_id, scan_id, 1, created)
    store.add_fp_review_result(review_id, FpReviewResult(
        vuln_index=index, verdict=verdict, severity="high", reason=reason,
        vulnerability_report=report, created_at=created,
    ))


def result(store, task_id="t", scan_id="s"):
    return store.get_threat_audit_task_results(scan_id, [task_id])[0]


def test_historical_links_sparse_indexes_and_multiple_results_survive_reload(store, tmp_path):
    task(store, result_vuln_indexes=[8, 8])
    original = finding(store, task_id="")
    store._conn.execute("UPDATE vulnerabilities SET idx = 8 WHERE scan_id = 's' AND idx = ?", (original,))
    store._conn.commit()
    second = finding(store)  # Source ID recovers the link missing from the task snapshot.
    review(store, 8)
    store.update_vulnerability("s", second, "false_positive", "Guard 已拦截")
    before = store._conn.total_changes
    loaded = result(store)
    assert [item.vuln_index for item in loaded.findings] == [8, second]
    assert [item.verdict for item in loaded.findings] == ["confirmed", "false_positive"]
    assert loaded.confirmed_issue_count == 1
    assert loaded.association_complete
    assert loaded.findings[0].description.startswith("长度未经校验")
    assert "vulnerability_report" not in loaded.findings[0].model_dump()
    assert store._conn.total_changes == before
    reopened = SqliteScanStore(tmp_path / "scan.db")
    try:
        assert result(reopened) == loaded
    finally:
        reopened.close()


def test_final_review_and_human_verdict_precedence(store):
    task(store)
    index = finding(store, ai_verdict="")  # Older scans only saved confirmed=True.
    assert result(store).findings[0].verdict == "unreviewed"
    assert result(store).confirmed_issue_count == 0
    review(store, index)
    assert result(store).confirmed_issue_count == 1
    review(store, index, "fp", created="2026-09-07T02:00:00+00:00")
    assert result(store).confirmed_issue_count == 0
    store.update_vulnerability("s", index, "confirmed", "人工复现")
    assert result(store).confirmed_issue_count == 1
    assert result(store).findings[0].verdict_source == "human"
    store.clear_vulnerability_user_verdict("s", index)
    assert result(store).confirmed_issue_count == 0
    review(store, index, created="2026-09-07T03:00:00+00:00")
    store.update_vulnerability("s", index, "false_positive", "人工排除")
    assert result(store).confirmed_issue_count == 0
    store.update_vulnerability("s", index, "pending_analysis", "尚待分析")
    assert result(store).confirmed_issue_count == 1
    review(store, index, "fp", created="2026-09-07T04:00:00+00:00", reason="Review incomplete: timeout")
    assert result(store).confirmed_issue_count == 1


def test_latest_effective_review_accepts_report_only_and_ignores_empty_output(store):
    task(store)
    index = finding(store)
    review(store, index, reason="")
    assert result(store).confirmed_issue_count == 0
    review(store, index, reason="", report="完整最终报告", created="2026-09-07T02:00:00+00:00")
    assert result(store).confirmed_issue_count == 1


def test_legacy_unique_path_recovery_considers_tasks_outside_requested_batch(store):
    task(store, "a", code_path="src/a.c")
    task(store, "b", code_path="src/b.c")
    index = finding(store, task_id="")
    review(store, index)
    assert result(store, "a").confirmed_issue_count == 1
    assert not result(store, "b").findings
    task(store, "other-page", code_path="src/alias.c", code_paths=[{"path": "src/a.c"}])
    ambiguous = result(store, "a")
    assert not ambiguous.findings
    assert not ambiguous.association_complete
    task(store, "a", result_vuln_indexes=[index])
    assert result(store, "a").confirmed_issue_count == 1
    assert not result(store, "other-page").findings


def test_legacy_code_paths_and_source_gate(store):
    task(store, code_path="", code_paths=[{"path": "src/a.c"}])
    index = finding(store, task_id="")
    finding(store, task_id="", analysis_source="static_candidate")
    assert [item.vuln_index for item in result(store).findings] == [index]


def test_missing_conflicting_and_corrupt_indexes_do_not_invent_findings(store):
    task(store, result_vuln_indexes=[0, 999])
    finding(store, task_id="another-task")
    loaded = result(store)
    assert not loaded.association_complete
    assert not loaded.findings
    assert loaded.confirmed_issue_count == 0
    store._conn.execute("UPDATE threat_audit_tasks SET result_vuln_indexes = 'broken' WHERE task_id = 't'")
    store._conn.commit()
    assert not result(store).association_complete
    assert not result(store, "missing").association_complete


def test_batch_is_scan_scoped_and_independent_of_vulnerability_pages(store):
    task(store)
    for _ in range(205):
        finding(store, task_id="other")
    index = finding(store)
    review(store, index)
    save_scan(store, "elsewhere")
    task(store, "foreign", scan_id="elsewhere")
    finding(store, scan_id="elsewhere", user_verdict="confirmed")
    review(store, index, "fp", scan_id="elsewhere")
    rows = store.get_threat_audit_task_results("s", ["t", "foreign", "t"])
    assert [row.task_id for row in rows] == ["t", "foreign"]
    assert [item.vuln_index for item in rows[0].findings] == [index]
    assert rows[0].confirmed_issue_count == 1
    assert not rows[1].findings
    assert not rows[1].association_complete


def test_authenticated_and_public_result_endpoints_are_bounded_and_authorized(store, monkeypatch):
    task(store)
    index = finding(store)
    review(store, index)
    monkeypatch.setattr(scan, "get_scan_store", lambda: store)
    monkeypatch.setattr(integration, "get_scan_store", lambda: store)
    # Permission checks and result reads must not hydrate the entire scan.
    monkeypatch.setattr(store, "load_scan", lambda *args: pytest.fail("Unexpected full scan read"))
    monkeypatch.setattr(store, "get_vulnerabilities", lambda *args: pytest.fail("Unexpected full result read"))
    app = FastAPI()
    app.include_router(scan.router)
    app.include_router(integration.router)
    async def owner():
        return User(user_id="owner", username="owner", role="user")

    async def other():
        return User(user_id="other", username="other", role="user")

    app.dependency_overrides[get_current_user] = owner

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            private = "/api/v2/scans/s/threat-audit-results"
            public = "/api/public/scans/s/threat-audit-results"
            for endpoint, auth in ((private, []), (public, [("token", "public-test")])):
                response = await client.get(endpoint, params=auth + [("task_ids", "t")])
                assert response.status_code == 200, response.text
                assert response.json()[0]["confirmed_issue_count"] == 1
                assert (await client.get(endpoint, params=auth)).status_code == 422
                oversized = await client.get(endpoint, params=auth + [("task_ids", str(i)) for i in range(101)])
                assert oversized.status_code == 422
            assert (await client.get(public, params={"task_ids": "t"})).status_code == 401
            assert (await client.get(public, params={"task_ids": "t", "token": "wrong"})).status_code == 403
            app.dependency_overrides[get_current_user] = other
            assert (await client.get(private, params={"task_ids": "t"})).status_code == 403
    asyncio.run(run())


@pytest.mark.skipif(not os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN"), reason="OPENDEEPHOLE_TEST_POSTGRES_DSN is not configured")
def test_postgres_task_results_round_trip():
    from backend.store.postgres import PostgresScanStore
    instance = PostgresScanStore(os.environ["OPENDEEPHOLE_TEST_POSTGRES_DSN"])
    scan_id = f"threat-result-{uuid.uuid4().hex}"
    task_id = f"task-{uuid.uuid4().hex}"
    try:
        save_scan(instance, scan_id)
        task(instance, task_id, scan_id=scan_id)
        index = finding(instance, task_id, scan_id=scan_id)
        review(instance, index, scan_id=scan_id)
        loaded = result(instance, task_id, scan_id=scan_id)
        assert loaded.confirmed_issue_count == 1
        assert loaded.findings[0].vuln_index == index
        assert loaded.association_complete
    finally:
        instance.delete_scan(scan_id)
        instance.close()
