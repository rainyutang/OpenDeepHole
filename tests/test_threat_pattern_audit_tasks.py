"""Persisted attack-pattern task state, bounded reads and exact source links."""

import backend.api.agent_routes.scan_artifacts as backend_api_agent_routes_scan_artifacts
import asyncio
import os
import uuid
import httpx
import pytest
from backend.application import get_runtime
from types import SimpleNamespace
from fastapi import FastAPI
from backend import sse
from backend.api import agent, integration, scan, sharing
from backend.auth import get_current_user
from backend.models import (
    FpReviewResult,
    ScanMeta,
    ScanStatus,
    ThreatAuditTask,
    ThreatPatternAuditTask,
    User,
    Vulnerability,
)
from backend.store.sqlite import SqliteScanStore


@pytest.fixture(params=["sqlite", "postgres"])
def environment(request, tmp_path, monkeypatch):
    if request.param == "postgres":
        dsn = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN")
        if not dsn:
            pytest.skip("OPENDEEPHOLE_TEST_POSTGRES_DSN is not configured")
        from backend.store.postgres import PostgresScanStore
        factory = lambda: PostgresScanStore(dsn)
    else:
        factory = lambda: SqliteScanStore(tmp_path / "patterns.db")
    store = factory()
    key = uuid.uuid4().hex
    created = "2026-10-16T00:00:00+00:00"
    state = ScanStatus(scan_id=key, project_id="p", scan_items=[], created_at=created,
                       status="complete", progress=1, total_candidates=0, processed_candidates=0, vulnerabilities=[])
    store.save_scan(state, ScanMeta(scan_items=[], created_at=created, user_id="owner", public_access_token="access"))
    get_runtime().store = store
    for module in (integration, sharing):
        monkeypatch.setattr(module, "get_scan_store", lambda: store)
    monkeypatch.setattr(get_runtime().scans, 'running_scans', {})
    monkeypatch.setattr(sse, "_distributed_store", None)
    yield SimpleNamespace(store=store, factory=factory, scan_id=key, created=created)
    store.delete_scan(key)
    store.close()


def task(env, suffix="a", **values):
    return env.store.upsert_threat_pattern_audit_task(env.scan_id, ThreatPatternAuditTask(
        **{"task_id": f"{env.scan_id}-{suffix}", "module_name": "认证模块", "pattern_id": "AUTH-01",
           "pattern_name": "会话伪造", "code_paths": [{"path": "src/auth"}], "created_at": env.created,
           **values},
    ))


def finding(env, source, **values):
    return env.store.add_vulnerability(env.scan_id, Vulnerability(**{
        "file": "src/auth/session.c", "line": 17, "function": "restore", "vuln_type": "auth", "severity": "high",
        "description": "身份未绑定", "analysis_source": "threat_pattern_audit", "engine_id": "threat_pattern_audit",
        "confirmed": True, "ai_verdict": "confirmed", "source_task_id": source,
        "vulnerability_report": "# Full report body", **values,
    }))


def test_round_trip_counts_verdicts_and_separate_engine_tasks(environment):
    env = environment
    value = task(env, status="completed")
    index = finding(env, value.task_id)
    env.store.upsert_threat_audit_task(env.scan_id, ThreatAuditTask(task_id=env.scan_id + "-legacy", status="running"))
    result = env.store.get_threat_pattern_audit_task_results(env.scan_id, [value.task_id])[0]
    assert result.association_complete and result.findings[0].verdict == "unreviewed"
    assert result.confirmed_issue_count == 0
    env.store.create_fp_review_job(env.scan_id, env.scan_id, 1, env.created)
    env.store.add_fp_review_result(env.scan_id, FpReviewResult(vuln_index=index, verdict="tp", reason="可复现", created_at=env.created))
    env.store.update_fp_review_job(env.scan_id, status="complete", processed=1)
    env.store.rebuild_scan_summary(env.scan_id)
    counts = env.store.get_scan_detail_counts(env.scan_id)
    assert counts["threat_pattern_audit_completed"] == 1
    assert counts["threat_pattern_audit_running"] == 0
    assert counts["threat_audit_running"] == 1
    task(env, status="timeout", failure_reason="Session timeout")
    assert env.store.get_scan_detail_counts(env.scan_id)["threat_pattern_audit_failed"] == 1
    reopened = env.factory()
    try:
        loaded = reopened.load_scan(env.scan_id)[0]
        assert len(loaded.threat_pattern_audit_tasks) == len(loaded.threat_audit_tasks) == 1
        assert loaded.threat_pattern_audit_tasks[0].failure_reason == "Session timeout"
        results = reopened.get_threat_pattern_audit_task_results(env.scan_id, [value.task_id])
        assert results[0].confirmed_issue_count == 1
        assert "vulnerability_report" not in results[0].findings[0].model_dump()
        assert reopened.get_vulnerability_audit_source(env.scan_id, index).pattern_task.task_id == value.task_id
        reopened.update_vulnerability(env.scan_id, index, "false_positive", "人工排除")
        assert reopened.get_threat_pattern_audit_task_results(env.scan_id, [value.task_id])[0].confirmed_issue_count == 0
    finally:
        reopened.close()


def test_links_handle_arrival_order_replay_conflicts_and_missing_history(environment):
    env = environment
    value = task(env)
    index = finding(env, value.task_id)
    assert env.store.link_threat_pattern_audit_task_vulnerability(env.scan_id, value.task_id, index)
    assert not env.store.link_threat_pattern_audit_task_vulnerability(env.scan_id, value.task_id, index)
    # A later lifecycle snapshot contains no returned indexes yet.
    loaded = task(env, status="completed", created_at="2099-01-01")
    assert loaded.result_vuln_indexes == [index] and loaded.created_at == env.created
    unrelated = task(env, "b", result_vuln_indexes=[index, 999])
    result = env.store.get_threat_pattern_audit_task_results(env.scan_id, [unrelated.task_id])[0]
    assert not result.findings and not result.association_complete
    assert env.store.get_vulnerability_audit_source(env.scan_id, index).pattern_task.task_id == value.task_id
    old = finding(env, "missing-source")
    assert env.store.get_vulnerability_audit_source(env.scan_id, old).status == "missing"
    no_source = finding(env, "")
    assert env.store.get_vulnerability_audit_source(env.scan_id, no_source).status == "missing"
    task(env, "c", result_vuln_indexes=[no_source])
    assert env.store.get_vulnerability_audit_source(env.scan_id, no_source).status == "resolved"
    task(env, "d", result_vuln_indexes=[no_source])
    assert env.store.get_vulnerability_audit_source(env.scan_id, no_source).status == "ambiguous"
    assert env.store.get_threat_pattern_audit_task_results(env.scan_id, ["missing"])[0].association_complete is False


def test_api_pagination_summaries_sources_and_access(environment, monkeypatch):
    env = environment
    first, second = task(env, "a"), task(env, "b")
    index = finding(env, second.task_id, user_verdict="confirmed")
    share = env.store.get_or_create_scan_share(env.scan_id)
    # Neither source lookup nor task summaries should hydrate full scan/report bodies.
    monkeypatch.setattr(env.store, "load_scan", lambda *args: pytest.fail("full scan read"))
    app = FastAPI()
    for router in (scan.router, integration.router, sharing.router):
        app.include_router(router)
    async def owner():
        return User(user_id="owner", username="owner", role="user")
    app.dependency_overrides[get_current_user] = owner

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            for prefix, auth in ((f"/api/v2/scans/{env.scan_id}", []),
                                 (f"/api/public/scans/{env.scan_id}", [("token", "access")]),
                                 (f"/api/shared/scans/{env.scan_id}", [("token", share["token"])])):
                page = await client.get(prefix + "/threat-pattern-audit-tasks", params=auth + [("limit", 1)])
                assert page.status_code == 200, page.text
                assert page.json()["items"][0]["task_id"] == first.task_id
                cursor = page.json()["next_cursor"]
                page = await client.get(prefix + "/threat-pattern-audit-tasks", params=auth + [("cursor", cursor)])
                assert [item["task_id"] for item in page.json()["items"]] == [second.task_id]
                result = await client.get(prefix + "/threat-pattern-audit-results", params=auth + [("task_ids", second.task_id)])
                assert result.status_code == 200, result.text
                assert result.json()[0]["confirmed_issue_count"] == 1
                source = await client.get(prefix + f"/vulnerabilities/{index}/audit-source", params=auth)
                assert source.json()["kind"] == "threat_pattern_audit"
                assert source.json()["pattern_task"]["task_id"] == second.task_id
                assert (await client.get(prefix + "/threat-pattern-audit-results", params=auth)).status_code == 422
                assert (await client.get(prefix + "/threat-pattern-audit-results", params=auth + [("task_ids", str(i)) for i in range(101)])).status_code == 422
                assert (await client.get(prefix + "/threat-pattern-audit-tasks", params=auth + [("cursor", "bad")])).status_code == 400
            for mode in ("public", "shared"):
                assert (await client.get(f"/api/{mode}/scans/{env.scan_id}/threat-pattern-audit-tasks", params={"token": "bad"})).status_code == 403
            async def other():
                return User(user_id="other", username="other", role="user")
            app.dependency_overrides[get_current_user] = other
            assert (await client.get(f"/api/v2/scans/{env.scan_id}/threat-pattern-audit-tasks")).status_code == 403
    asyncio.run(run())


def test_agent_upload_recovers_early_finding_and_sse_notification(environment):
    env = environment
    key = env.scan_id + "-late"
    index = finding(env, key)
    response = asyncio.run(backend_api_agent_routes_scan_artifacts.agent_upsert_threat_pattern_audit_task(env.scan_id, {
        "task_id": key, "status": "completed", "module_name": "认证模块", "pattern_name": "会话伪造",
    }))
    assert response["task"]["result_vuln_indexes"] == [index]
    assert sse.storage_notification("threat_pattern_audit_task", {"task": response["task"]}) == (
        "resource_changed", {"resource": "threat-pattern-audit-tasks", "index": None},
    )


def test_empty_history_is_read_only_and_delete_removes_tasks(environment):
    env = environment
    assert not env.store.list_threat_pattern_audit_tasks(env.scan_id)
    task(env)
    env.store.delete_scan(env.scan_id)
    assert not env.store.list_threat_pattern_audit_tasks(env.scan_id)


ITERATIVE = "threat_pattern_iterative_audit"


def test_iterative_rounds_keep_engine_counts_links_and_clues_separate(environment):
    env = environment
    original = task(env, "original", status="completed")
    first = task(env, "round-1", engine_id=ITERATIVE, iteration=1, status="completed",
                 has_more_findings=True, followup_clues="src/auth/refresh.c 的刷新入口\n" * 200)
    second = task(env, "round-2", engine_id=ITERATIVE, iteration=2,
                  parent_task_id=first.task_id, status="queued")
    index = finding(env, first.task_id, analysis_source=ITERATIVE, engine_id=ITERATIVE)
    result = env.store.get_threat_pattern_audit_task_results(env.scan_id, [first.task_id])[0]
    assert [item.vuln_index for item in result.findings] == [index]
    source = env.store.get_vulnerability_audit_source(env.scan_id, index)
    assert source.kind == "threat_pattern_audit"
    assert source.pattern_task.engine_id == ITERATIVE
    counts = env.store.get_scan_detail_counts(env.scan_id)["threat_pattern_audit_by_engine"]
    assert counts["threat_pattern_audit"]["tasks"] == 1
    assert counts[ITERATIVE]["tasks"] == 2
    assert counts[ITERATIVE]["completed"] == counts[ITERATIVE]["queued"] == 1
    assert counts[ITERATIVE]["current"] == 2
    audits = env.store.get_scan_estimation_business_stats(env.scan_id)["audits"]
    assert audits[ITERATIVE] == {"success": 1, "done": 1, "remaining": 1, "findings": 1, "remaining_findings": 0}
    assert audits["threat_pattern_audit"]["success"] == 1
    assert audits["threat_pattern_audit"]["findings"] == 0
    summaries = env.store.list_threat_pattern_audit_tasks(env.scan_id, engine_id=ITERATIVE, summary=True)
    assert {item.task_id for item in summaries} == {first.task_id, second.task_id}
    assert all(item.followup_clues == "" for item in summaries)
    full = env.store.list_threat_pattern_audit_tasks(env.scan_id, task_id=first.task_id)[0]
    assert full.followup_clues == first.followup_clues and full.has_more_findings is True
    assert env.store.get_threat_pattern_audit_task_detail(env.scan_id, first.task_id)["next_task_id"] == second.task_id
    unchanged = env.store.upsert_threat_pattern_audit_task(env.scan_id, full.model_copy(update={"updated_at": "later"}))
    assert unchanged.updated_at == full.updated_at
    # Explicit indexes must not associate a finding from a different engine.
    task(env, "original", status="completed", result_vuln_indexes=[index])
    assert not env.store.get_threat_pattern_audit_task_results(env.scan_id, [original.task_id])[0].findings
    reopened = env.factory()
    try:
        restored = reopened.list_threat_pattern_audit_tasks(env.scan_id, task_id=second.task_id)[0]
        assert restored.iteration == 2 and restored.parent_task_id == first.task_id
    finally:
        reopened.close()


def test_iterative_api_summary_details_and_shared_access(environment, monkeypatch):
    env = environment
    task(env, "old")
    value = task(env, "round", engine_id=ITERATIVE, iteration=2, parent_task_id="parent",
                 has_more_findings=True, followup_clues="private full clue " * 200)
    share = env.store.get_or_create_scan_share(env.scan_id)
    monkeypatch.setattr(env.store, "load_scan", lambda *args: pytest.fail("full scan read"))
    app = FastAPI()
    for router in (scan.router, integration.router, sharing.router):
        app.include_router(router)
    async def owner():
        return User(user_id="owner", username="owner", role="user")
    app.dependency_overrides[get_current_user] = owner

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            for prefix, auth in ((f"/api/v2/scans/{env.scan_id}", {}),
                                 (f"/api/public/scans/{env.scan_id}", {"token": "access"}),
                                 (f"/api/shared/scans/{env.scan_id}", {"token": share["token"]})):
                response = await client.get(prefix + "/threat-pattern-audit-tasks", params={**auth, "engine_id": ITERATIVE})
                assert response.status_code == 200, response.text
                values = response.json()["items"]
                assert [item["task_id"] for item in values] == [value.task_id]
                assert values[0]["iteration"] == 2 and values[0]["followup_clues"] == ""
                response = await client.get(prefix + "/threat-pattern-audit-tasks/" + value.task_id, params=auth)
                assert response.status_code == 200, response.text
                assert response.json()["followup_clues"] == value.followup_clues
                assert response.json()["parent_task_id"] == "parent"
                assert response.json()["next_task_id"] == ""
                assert (await client.get(prefix + "/threat-pattern-audit-tasks/missing", params=auth)).status_code == 404
            assert (await client.get(f"/api/public/scans/{env.scan_id}/threat-pattern-audit-tasks/" + value.task_id,
                                     params={"token": "bad"})).status_code == 403
    asyncio.run(run())


def test_iterative_sse_is_small_and_does_not_lose_saved_clues(environment, monkeypatch):
    env = environment
    events = []
    monkeypatch.setattr(get_runtime(), "publisher", lambda *args: events.append(args))
    response = asyncio.run(backend_api_agent_routes_scan_artifacts.agent_upsert_threat_pattern_audit_task(env.scan_id, {
        "task_id": env.scan_id + "-round", "engine_id": ITERATIVE, "iteration": 1,
        "status": "completed", "has_more_findings": True, "followup_clues": "next clue " * 500,
    }))
    assert response["task"]["followup_clues"]
    assert "followup_clues" not in events[-1][2]["task"]
    assert env.store.list_threat_pattern_audit_tasks(env.scan_id)[0].followup_clues == response["task"]["followup_clues"]
    repeated = asyncio.run(backend_api_agent_routes_scan_artifacts.agent_upsert_threat_pattern_audit_task(env.scan_id, response["task"]))
    assert repeated == response
    assert len(events) == 1


def test_old_pattern_table_migrates_without_losing_history_and_uses_indexes(environment):
    env = environment
    original = task(env, "legacy", status="completed")
    # Reconstruct the previous release's table on a real persisted database.
    env.store._conn.execute("DROP INDEX idx_pattern_audit_engine_cursor")
    env.store._conn.execute("DROP INDEX idx_pattern_audit_parent")
    env.store._conn.execute("DROP INDEX idx_scan_task_versions_name")
    for column in ("engine_id", "iteration", "parent_task_id", "has_more_findings", "followup_clues"):
        env.store._conn.execute(f"ALTER TABLE threat_pattern_audit_tasks DROP COLUMN {column}")
    env.store._conn.commit()
    migrated = env.factory()
    try:
        restored = migrated.list_threat_pattern_audit_tasks(env.scan_id)[0]
        assert restored.task_id == original.task_id and restored.status == "completed"
        assert restored.engine_id == "threat_pattern_audit" and restored.iteration == 1
        assert restored.parent_task_id == restored.followup_clues == ""
        assert restored.has_more_findings is None
        is_postgres = bool(getattr(migrated, "distributed", False))
        if is_postgres:
            migrated._conn.execute("SET enable_seqscan = off")
        explain = "EXPLAIN " if is_postgres else "EXPLAIN QUERY PLAN "
        plans = migrated._conn.execute(explain + (
            "SELECT task_id FROM threat_pattern_audit_tasks WHERE scan_id = ? AND engine_id = ? "
            "ORDER BY created_at, task_id LIMIT 50"
        ), (env.scan_id, ITERATIVE)).fetchall()
        assert "idx_pattern_audit_engine_cursor" in str([dict(row) for row in plans])
        plans = migrated._conn.execute(explain + (
            "SELECT task_id FROM threat_pattern_audit_tasks WHERE scan_id = ? AND engine_id = ? "
            "AND parent_task_id = ? AND parent_task_id != '' LIMIT 1"
        ), (env.scan_id, ITERATIVE, original.task_id)).fetchall()
        assert "idx_pattern_audit_parent" in str([dict(row) for row in plans])
        expression = "CAST(metadata_json AS jsonb) ->> 'task_name'" if is_postgres else "json_extract(metadata_json, '$.task_name')"
        plans = migrated._conn.execute(explain + (
            "SELECT record_id FROM scan_task_versions WHERE scan_id = ? AND (" + expression + ") = ?"
        ), (env.scan_id, "round-2")).fetchall()
        assert "idx_scan_task_versions_name" in str([dict(row) for row in plans])
        migrated._conn.commit()
    finally:
        migrated.close()
