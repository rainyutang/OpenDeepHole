"""Business ETA projections stay scan-local and use bounded metadata queries."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from backend.models import Vulnerability
from test_scan_estimation_store import sample_store  # noqa: F401 - shared database fixture


@pytest.fixture
def business(sample_store):
    store, scan_id, make_scan, *_ = sample_store
    review_ids = []

    def candidate(index, state="success", *, linked=None, scope=scan_id):
        store._conn.execute(
            "INSERT INTO scan_candidates (scan_id, idx, file, line, function, vuln_type, description, "
            "related_functions, metadata, audit_state, vulnerability_idx) "
            "VALUES (?, ?, 'a.c', 1, 'f', 'npd', '', '[]', '{}', ?, ?)",
            (scope, index, state, linked),
        )
        store._conn.commit()

    def threat(name, state="completed", *, category="threat_audit", scope=scan_id):
        task_id = scope + "-" + name
        if category == "threat_audit":
            store._conn.execute("INSERT INTO threat_audit_tasks (task_id, scan_id, status, code_path) VALUES (?, ?, ?, ?)",
                                (task_id, scope, state, name))
        else:
            store._conn.execute("INSERT INTO threat_pattern_audit_tasks (task_id, scan_id, status) VALUES (?, ?, ?)",
                                (task_id, scope, state))
        store._conn.commit()
        return task_id

    def finding(*, scope=scan_id, eligible=True, provisional=False, **fields):
        item = Vulnerability(**{
            "file": "a.c", "line": 1, "function": "f", "vuln_type": "npd", "severity": "high",
            "description": "private issue", "confirmed": True, "ai_verdict": "confirmed",
            "vulnerability_report": "private body" * 1000, **fields,
        })
        index = store.add_vulnerability(scope, item)
        store._conn.execute("UPDATE vulnerabilities SET fp_review_eligible = ?, provisional = ? WHERE scan_id = ? AND idx = ?",
                            (int(eligible), int(provisional), scope, index))
        store._conn.commit()
        return index

    def review(label, index, *, scope=scan_id, created="2026-11-01T00:00:00Z", finished="2026-11-01T01:00:00Z",
               method="adversarial", revision=1, verdict="tp", reason="usable conclusion", report=""):
        review_id = scope + "-review-" + label
        if review_id not in review_ids:
            store.create_fp_review_job(review_id, scope, 100, created, method=method)
            review_ids.append(review_id)
        store._conn.execute(
            "INSERT INTO fp_review_results (review_id, vuln_index, verdict, reason, vulnerability_report, created_at, execution_revision) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)", (review_id, index, verdict, reason, report, finished, revision),
        )
        store._conn.commit()
        return review_id

    yield SimpleNamespace(store=store, scan_id=scan_id, make_scan=make_scan, candidate=candidate,
                          threat=threat, finding=finding, review=review)
    for review_id in review_ids:
        store._conn.execute("DELETE FROM fp_review_jobs WHERE review_id = ?", (review_id,))
    store._conn.commit()


def test_audit_yield_uses_successful_associations_and_allows_multiple_findings(business):
    b = business
    b.candidate(0)
    b.candidate(1, "running")
    b.candidate(2, "failed")
    b.candidate(3, "queued")
    b.finding(audit_index=0)
    b.finding(audit_index=0, user_verdict="false_positive")  # Discovery precedes human review.
    b.finding(audit_index=0, ai_verdict="not_confirmed", confirmed=True)
    b.finding(audit_index=0, eligible=False)
    b.finding(audit_index=0, provisional=True)
    b.finding(audit_index=1)
    b.finding(audit_index=2)
    legacy = b.finding(ai_verdict="", confirmed=True)
    b.candidate(4, linked=legacy)
    completed = b.threat("complete")
    waiting = b.threat("waiting", "pending")
    b.threat("old", "superseded")
    b.threat("cancelled", "cancelled")
    b.finding(analysis_source="threat_audit", source_task_id=completed)
    b.finding(engine_id="threat_audit", source_task_id=completed)
    b.finding(analysis_source="threat_audit", source_task_id=waiting)
    pattern = b.threat("pattern", category="threat_pattern_audit")
    b.finding(analysis_source="threat_pattern_audit", source_task_id=pattern)
    result = b.store.get_scan_estimation_business_stats(b.scan_id)
    assert result["audits"] == {
        "static_candidate": {"success": 2, "done": 3, "remaining": 2, "findings": 3, "remaining_findings": 1},
        "threat_audit": {"success": 1, "done": 2, "remaining": 1, "findings": 2, "remaining_findings": 1},
        "threat_pattern_audit": {"success": 1, "done": 1, "remaining": 0, "findings": 1, "remaining_findings": 0},
    }


def test_completed_reviews_deduplicate_effective_results_and_pending_uses_business_eligibility(business):
    b = business
    complete = b.finding()
    pending = b.finding()
    b.finding(user_verdict="confirmed")
    b.finding(user_verdict="false_positive")
    b.finding(eligible=False)
    b.finding(provisional=True)
    b.finding(ai_verdict="filtered_same_pattern")
    report_only = b.finding()
    b.review("old", complete)
    latest = b.review("new", complete, created="2026-11-02T00:00:00Z", finished="2026-11-02T01:00:00Z",
                      revision=4, method="fp_check", verdict="fp")
    b.review("incomplete", complete, created="2026-11-03T00:00:00Z", reason="Review incomplete: private failure")
    b.review("empty", pending, reason="")
    only = b.review("report-only", report_only, reason="", report="private usable report" * 1000)
    result = b.store.get_scan_estimation_business_stats(b.scan_id)
    assert result["fp_pending_indexes"] == [pending]
    assert result["completed_reviews"] == [
        {"review_id": latest, "execution_revision": 4, "vuln_index": complete,
         "finished_at": "2026-11-02T01:00:00Z", "method": "fp_check"},
        {"review_id": only, "execution_revision": 1, "vuln_index": report_only,
         "finished_at": "2026-11-01T01:00:00Z", "method": "adversarial"},
    ]
    assert "private" not in str(result)


def test_reused_counts_need_only_two_queries_regardless_of_issue_count_and_do_not_cross_scans(business):
    b = business
    b.candidate(0)
    current = b.finding(audit_index=0)
    foreign = b.make_scan("other-business")
    b.candidate(0, scope=foreign)
    pending_indexes = [current]
    for index in range(20):
        pending_indexes.append(b.finding(audit_index=0))
        finding = b.finding(scope=foreign, audit_index=0)
        b.review("foreign", finding, scope=foreign)
    foreign_task = b.threat("foreign-source", scope=foreign)
    pending_indexes.append(b.finding(analysis_source="threat_audit", source_task_id=foreign_task))
    # Another scan's same vulnerability index must not resolve this scan's work.
    assert current == 0
    statements = []
    connection = b.store._conn

    def execute(sql, params=()):
        statements.append((sql, params))
        return connection.execute(sql, params)

    counts = {"candidate_audit_success": 17, "candidate_audit_failed": 3, "candidate_audit_pending": 23}
    with patch.object(b.store, "_conn", SimpleNamespace(execute=execute)), patch.object(
        b.store, "get_scan_detail_counts", side_effect=AssertionError("overview counts must be reused"),
    ):
        result = b.store.get_scan_estimation_business_stats(b.scan_id, counts=counts)
    assert len(statements) == 2
    assert all(params and set(params) == {b.scan_id} for _, params in statements)
    assert result["audits"]["static_candidate"] == {
        "success": 17, "done": 20, "remaining": 23, "findings": 21, "remaining_findings": 0,
    }
    assert result["audits"]["threat_audit"]["findings"] == 0
    assert result["completed_reviews"] == []
    assert result["fp_pending_indexes"] == pending_indexes
    assert all("SELECT *" not in sql and "task_json" not in sql and "stage_outputs" not in sql
               for sql, _ in statements)


def test_empty_scan_and_missing_scan_have_no_forecast_units(business):
    b = business
    for scan_id in (b.scan_id, "does-not-exist"):
        stats = b.store.get_scan_estimation_business_stats(scan_id, counts={})
        assert all(row == {"success": 0, "done": 0, "remaining": 0, "findings": 0, "remaining_findings": 0}
                   for row in stats["audits"].values())
        assert stats["completed_reviews"] == stats["fp_pending_indexes"] == []


@pytest.mark.parametrize("category", ["static_candidate", "threat_audit", "threat_pattern_audit"])
def test_early_findings_from_remaining_audits_do_not_inflate_completed_discovery_yield(business, category):
    b = business
    pending = []
    for index, state in enumerate(("pending", "queued", "running", "failed")):
        if category == "static_candidate":
            b.candidate(index, state)
            source = {"audit_index": index}
        else:
            task_id = b.threat(state, state, category=category)
            source = {"analysis_source": category, "source_task_id": task_id}
        pending.append(b.finding(**source))
        b.finding(**source, provisional=True)
        b.finding(**source, eligible=False)
    stats = b.store.get_scan_estimation_business_stats(b.scan_id)
    assert stats["audits"][category] == {
        "success": 0, "done": 1, "remaining": 3, "findings": 0, "remaining_findings": 3,
    }
    assert stats["fp_pending_indexes"] == pending
