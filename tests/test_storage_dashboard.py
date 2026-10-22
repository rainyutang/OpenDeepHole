import os
import sqlite3
import uuid
from unittest.mock import patch
from types import SimpleNamespace

import pytest

from backend.api.admin import _build_checker_dashboard, _build_checker_dashboard_v2
from backend.models import FeedbackEntry, FpReviewResult, ScanStatus, ScanMeta, Vulnerability, OpenCodePoolStatus, OpenCodeTokenUsage
from backend.store.sqlite import SqliteScanStore
from test_storage_history import make_store


def test_sql_dashboard_matches_legacy_with_sparse_indexes_and_scope(tmp_path):
    store = make_store(tmp_path)
    store._conn.execute("UPDATE scans SET scan_items = '[\"npd\"]', user_id = 'alice', product = 'A'")
    store._conn.commit()
    finding = Vulnerability(file="a", line=1, function="f", vuln_type="npd", description="report", severity="high", ai_verdict="confirmed", confirmed=True)
    store.add_vulnerability("s", finding)
    store._conn.execute("UPDATE vulnerabilities SET idx = 42")
    store._conn.commit()
    store.rebuild_scan_summary("s")
    for scan_id, owner, product in (("s2", "alice", "B"), ("s3", "bob", "A")):
        store.save_scan(ScanStatus(scan_id=scan_id, project_id=scan_id, scan_items=["npd"], created_at="2026-01-01", status="complete", progress=1,
                                  total_candidates=0, processed_candidates=0, vulnerabilities=[]),
                        ScanMeta(scan_items=["npd"], created_at="2026-01-01", user_id=owner, product=product, scan_name=scan_id))
    for scan_id in ("s", "s2", "s3"):
        store.upsert_scan_opencode_token_usage(scan_id=scan_id, agent_session_id="session", status=OpenCodePoolStatus(token_usage=OpenCodeTokenUsage(input_tokens=10, total_tokens=10)))
    registry = {"npd": SimpleNamespace(label="NPD", description="", user_created=False)}
    with patch("backend.api.admin.refresh_registry", return_value=registry):
        before = _build_checker_dashboard(store, "A", "alice")
        after = _build_checker_dashboard_v2(store, "A", "alice")
        assert before.summary == after.summary
        assert after.token_usage.scan_count == 2
        assert after.token_usage.usage.total_tokens == 20
        assert after.products == ["A", "B"]
        assert after.checkers[0].scans == []
        assert [row["scan_id"] for row in store.list_checker_scans_page("npd", user_id="alice", product="A")] == ["s"]
        # Both paths work during online backfill, without full ScanStatus reads.
        store._conn.execute("UPDATE scan_summary_state SET ready = 0")
        store._conn.commit()
        assert _build_checker_dashboard_v2(store, "A", "alice").summary == before.summary
    store.close()


@pytest.fixture(params=["sqlite", "postgres"])
def dashboard_store(request, tmp_path):
    if request.param == "postgres":
        dsn = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN")
        if not dsn:
            pytest.skip("isolated PostgreSQL DSN not configured")
        from backend.store.postgres import PostgresScanStore
        store = PostgresScanStore(dsn, pool_min_size=1, pool_max_size=2)
    else:
        store = SqliteScanStore(tmp_path / "dashboard.db")
    prefix = "dashboard-" + uuid.uuid4().hex
    try:
        yield store, prefix
    finally:
        with store._lock:
            for table, column in (
                ("feedback_entries", "source_scan_id"), ("fp_review_jobs", "scan_id"),
                ("scans", "scan_id"), ("scan_deletions", "scan_id"),
            ):
                store._conn.execute(f"DELETE FROM {table} WHERE {column} LIKE ?", (prefix + "%",))
            store._conn.commit()
        store.close()


def dashboard_scan(store, prefix, name, *, checkers=(), owner="alice", product="A"):
    scan_id = f"{prefix}-{name}"
    now = "2026-10-22T00:00:00+00:00"
    store.save_scan(
        ScanStatus(scan_id=scan_id, project_id=scan_id, scan_items=list(checkers), created_at=now,
                   status="complete", progress=1, total_candidates=0, processed_candidates=0, vulnerabilities=[]),
        ScanMeta(scan_items=list(checkers), created_at=now, scan_name=scan_id,
                 user_id=f"{prefix}-{owner}", product=f"{prefix}-{product}" if product else ""),
    )
    return scan_id


def dashboard_finding(store, scan_id, *, source="threat_pattern_audit", kind="authorization_bypass", human=None):
    return store.add_vulnerability(scan_id, Vulnerability(
        file=f"{kind}.c", line=1, function="parse", vuln_type=kind, severity="high",
        description="finding", vulnerability_report="report body", confirmed=True,
        ai_verdict="confirmed", analysis_source=source, engine_id=source, user_verdict=human,
    ))


def dashboard_review(store, scan_id, index, *, verdict="tp", revision=1, reason="evidence", report=""):
    now = f"2026-10-22T{revision:02}:00:00+00:00"
    review_id = f"{scan_id}-review-{revision}-{index}"
    store.create_fp_review_job(review_id, scan_id, 1, now)
    store.add_fp_review_result(review_id, FpReviewResult(
        vuln_index=index, verdict=verdict, reason=reason, vulnerability_report=report, created_at=now,
    ))
    store.update_fp_review_job(review_id, status="complete", processed=1)
    return review_id


def dashboard_ticket(store, scan_id, kind):
    entry = FeedbackEntry(
        id=f"{scan_id}-ticket-{kind}", source_scan_id=scan_id, project_id=scan_id,
        vuln_type=kind, verdict="confirmed", file=f"{kind}.c", line=1, function="parse",
        description="finding", ticket_submitted=True, ticket_id="BUG-1",
        created_at="2026-10-22", updated_at="2026-10-22",
    )
    store.add_feedback(entry)
    return entry.id


def dashboard_response(store, prefix, *, owner="alice", product="A", legacy=False):
    registry = {
        name: SimpleNamespace(label=name.upper(), description="", user_created=name == "custom_rule")
        for name in ("npd", "oob", "custom_rule")
    }
    with patch("backend.api.admin.refresh_registry", return_value=registry):
        builder = _build_checker_dashboard if legacy else _build_checker_dashboard_v2
        return builder(store,
                       product="__unconfigured__" if product == "" else f"{prefix}-{product}",
                       user_id=f"{prefix}-{owner}" if owner is not None else None)


def test_dashboard_counts_all_sources_without_changing_checker_details(dashboard_store):
    store, prefix = dashboard_store
    mixed = dashboard_scan(store, prefix, "mixed", checkers=("npd", "oob", "custom_rule"))
    for source, kind, human in (
        ("static_candidate", "npd", "confirmed"),
        ("threat_audit", "threat_path", None),
        ("threat_pattern_audit", "authorization_bypass", "pending_analysis"),
        ("custom_engine", "custom_finding", "false_positive"),
        ("static_candidate", "custom_rule", None),
    ):
        index = dashboard_finding(store, mixed, source=source, kind=kind, human=human)
        dashboard_review(store, mixed, index)
    # Independent human/ticket counts include findings that have no TP review.
    dashboard_finding(store, mixed, kind="unreviewed", human="confirmed")
    dashboard_ticket(store, mixed, "unreviewed")
    dashboard_ticket(store, mixed, "npd")
    threat = dashboard_scan(store, prefix, "threat-only")
    index = dashboard_finding(store, threat)
    dashboard_review(store, threat, index, reason="", report="report-only TP")
    dashboard_ticket(store, threat, "authorization_bypass")
    dashboard_scan(store, prefix, "empty")

    result = dashboard_response(store, prefix)
    assert result.summary.scan_count == 3
    assert result.summary.suspected_issue_count == 6
    assert result.summary.human_confirmed_count == 2
    assert result.summary.ticket_submitted_count == 3
    assert result.summary.total_issue_count == 7  # The old effective-issue field keeps its meaning.
    assert result.summary == dashboard_response(store, prefix, legacy=True).summary
    checkers = {row.checker: row for row in result.checkers}
    assert set(checkers) == {"npd", "oob", "custom_rule"}
    assert checkers["npd"].fp_review_issue_count == 1
    assert checkers["npd"].ticket_submitted_count == 1
    assert checkers["custom_rule"].fp_review_issue_count == 1
    assert checkers["oob"].fp_review_issue_count == 0
    assert [row["scan_id"] for row in store.list_checker_scans_page("npd", user_id=f"{prefix}-alice")] == [mixed]

    # Both the persisted projection and the unchanged historical fallback see
    # sources outside scan_items, and backfilling does not count them twice.
    with store._lock:
        store._conn.execute("UPDATE scan_summary_state SET ready = 0 WHERE scan_id = ?", (threat,))
        store._conn.commit()
    assert dashboard_response(store, prefix).summary == result.summary
    store.rebuild_scan_summary(threat)
    store.rebuild_scan_summary(threat)
    assert dashboard_response(store, prefix).summary == result.summary


def test_dashboard_counts_follow_review_human_and_ticket_changes(dashboard_store):
    store, prefix = dashboard_store
    scan_id = dashboard_scan(store, prefix, "changes")
    index = dashboard_finding(store, scan_id)
    assert dashboard_response(store, prefix).summary.suspected_issue_count == 0
    dashboard_review(store, scan_id, index, reason="Review incomplete: missing output")
    assert dashboard_response(store, prefix).summary.suspected_issue_count == 0
    dashboard_review(store, scan_id, index, revision=2, reason="", report="valid TP report")
    assert dashboard_response(store, prefix).summary.suspected_issue_count == 1
    # Incomplete retries must not erase the latest effective conclusion.
    dashboard_review(store, scan_id, index, revision=3, verdict="fp", reason="")
    assert dashboard_response(store, prefix).summary.suspected_issue_count == 1
    for verdict, human_count in (("confirmed", 1), ("confirmed", 1), ("false_positive", 0), ("pending_analysis", 0)):
        store.update_vulnerability(scan_id, index, verdict, "manual decision")
        summary = dashboard_response(store, prefix).summary
        assert (summary.suspected_issue_count, summary.human_confirmed_count) == (1, human_count)
    store.clear_vulnerability_user_verdict(scan_id, index)
    assert dashboard_response(store, prefix).summary.suspected_issue_count == 1

    ticket_id = dashboard_ticket(store, scan_id, "authorization_bypass")
    assert dashboard_response(store, prefix).summary.ticket_submitted_count == 1
    store.update_feedback(ticket_id, None, None, ticket_submitted=False)
    assert dashboard_response(store, prefix).summary.ticket_submitted_count == 0
    dashboard_review(store, scan_id, index, revision=4, verdict="fp")
    assert dashboard_response(store, prefix).summary.suspected_issue_count == 0
    review_id = dashboard_review(store, scan_id, index, revision=5)
    store.add_fp_review_result(review_id, FpReviewResult(
        vuln_index=index, verdict="tp", reason="same decision", created_at="2026-10-22T05:00:00+00:00",
    ))
    assert dashboard_response(store, prefix).summary.suspected_issue_count == 1
    assert dashboard_response(store, prefix).summary == dashboard_response(store, prefix, legacy=True).summary


def test_dashboard_scope_and_deletion_apply_to_all_four_counts(dashboard_store):
    store, prefix = dashboard_store
    scans = {}
    for owner, product in (("alice", "A"), ("alice", "B"), ("alice", ""), ("bob", "A")):
        scan_id = dashboard_scan(store, prefix, f"{owner}-{product}", owner=owner, product=product)
        index = dashboard_finding(store, scan_id, human="confirmed")
        dashboard_review(store, scan_id, index)
        dashboard_ticket(store, scan_id, "authorization_bypass")
        scans[owner, product] = scan_id

    def counts(response):
        summary = response.summary
        return (summary.scan_count, summary.suspected_issue_count, summary.human_confirmed_count, summary.ticket_submitted_count)

    assert counts(dashboard_response(store, prefix)) == (1, 1, 1, 1)
    assert counts(dashboard_response(store, prefix, owner=None)) == (2, 2, 2, 2)
    assert counts(dashboard_response(store, prefix, product="B")) == (1, 1, 1, 1)
    assert counts(dashboard_response(store, prefix, product="")) == (1, 1, 1, 1)
    assert counts(dashboard_response(store, prefix, product="missing")) == (0, 0, 0, 0)
    store.request_scan_deletion(scans["alice", "A"])
    assert counts(dashboard_response(store, prefix)) == (0, 0, 0, 0)
    assert counts(dashboard_response(store, prefix, owner=None)) == (1, 1, 1, 1)


def test_ready_dashboard_reads_persisted_counts_without_recomputing_findings(tmp_path):
    path = tmp_path / "persisted-dashboard.db"
    store = SqliteScanStore(path)
    prefix = "persisted"
    scan_id = dashboard_scan(store, prefix, "threat")
    index = dashboard_finding(store, scan_id, human="confirmed")
    dashboard_review(store, scan_id, index)
    dashboard_ticket(store, scan_id, "authorization_bypass")
    expected = dashboard_response(store, prefix).summary
    store.close()

    store = SqliteScanStore(path)
    reads = []

    def record_reads(action, table, column, _database, _trigger):
        if action == sqlite3.SQLITE_READ:
            reads.append((table, column))
        return sqlite3.SQLITE_OK

    try:
        store._conn.set_authorizer(record_reads)
        # SQLite may prepare the legacy branch, but it must never execute that
        # branch for ready scans. A failing function catches actual evaluation.
        def unexpected_fact_read(*_args):
            raise AssertionError("ready dashboard recomputed finding metrics")

        store._conn.create_function("SUBSTR", 3, unexpected_fact_read)
        with patch.object(store, "load_scan", side_effect=AssertionError("full scan read")), \
             patch.object(store, "rebuild_scan_summary", side_effect=AssertionError("request-time rebuild")):
            assert dashboard_response(store, prefix).summary == expected
            assert dashboard_response(store, prefix).summary == expected
        assert ("scan_checker_totals", "fp_review_issue_count") in reads
        assert not any(table in {"scan_audit_versions", "scan_task_versions", "fp_result_versions", "fp_stage_versions"} for table, _ in reads)
        assert not any(column in {"ai_analysis", "final_output", "task_json"} for _, column in reads)
    finally:
        store._conn.set_authorizer(None)
        store.close()
