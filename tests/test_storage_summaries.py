from dataclasses import asdict

from backend.models import FpReviewResult, Vulnerability, VulnerabilityValidation
from backend.scan_metrics import calculate_issue_metrics, latest_fp_review_result_map
from backend.store.summaries import metrics_from_totals
from test_storage_history import make_store


def finding(index=0, **updates):
    return Vulnerability(file=f"f{index}.c", line=index + 1, function="parse", vuln_type="npd",
                         severity="high", description="report", confirmed=True,
                         ai_verdict="confirmed", **updates)


def assert_same_metrics(store):
    vulnerabilities = store.get_vuln_stats_by_scans(["s"])["s"]
    results = latest_fp_review_result_map(store.list_fp_review_results_by_scan("s"))
    actual = store.get_scan_totals(["s"])["s"]
    assert asdict(metrics_from_totals(actual)) == asdict(calculate_issue_metrics(vulnerabilities, results))


def test_metrics_delta_tracks_sparse_indices_fp_rerun_and_human_verdict(tmp_path):
    store = make_store(tmp_path)
    try:
        store.add_vulnerability("s", finding(0))
        store.add_vulnerability("s", finding(1))
        store._conn.execute("DELETE FROM vulnerabilities WHERE scan_id = 's' AND idx = 0")
        store._conn.commit()
        now = "2026-09-07T10:00:00+00:00"
        store.create_fp_review_job("r1", "s", 1, now)
        store.add_fp_review_result("r1", FpReviewResult(vuln_index=1, verdict="fp", reason="evidence", created_at=now))
        assert_same_metrics(store)
        totals = store.get_scan_totals(["s"])["s"]
        assert totals["llm_issue_count"] == totals["fp_review_false_positive_count"] == 1
        assert store.get_vulnerabilities("s")[0].vuln_index == 1
        newer = "2026-09-07T11:00:00+00:00"
        store.create_fp_review_job("r2", "s", 1, newer)
        store.add_fp_review_result("r2", FpReviewResult(vuln_index=1, verdict="tp", reason="new evidence", created_at=newer))
        store._conn.execute("UPDATE vulnerabilities SET user_verdict = 'confirmed' WHERE scan_id = 's' AND idx = 1")
        store._conn.commit()
        assert_same_metrics(store)
        totals = store.get_scan_totals(["s"])["s"]
        assert totals["human_confirmed_issue_count"] == 1
        store.upsert_vulnerability_validation("s", VulnerabilityValidation(vuln_index=1, status="verified"))
        assert store.get_scan_totals(["s"])["s"]["validated_issue_count"] == 1
        store.upsert_vulnerability_validation("s", VulnerabilityValidation(vuln_index=1, status="running", running=True))
        assert store.get_scan_totals(["s"])["s"]["validated_issue_count"] == 0
        assert store.get_scan_detail_counts("s")["vulnerabilities"] == 1
        assert store.get_scan_detail_counts("s")["validations"] == 1
    finally:
        store.close()


def test_legacy_fallback_and_rebuild_preserve_metrics(tmp_path):
    store = make_store(tmp_path)
    try:
        store.add_vulnerability("s", finding())
        store._conn.execute("UPDATE scan_summary_state SET ready = 0 WHERE scan_id = 's'")
        store._conn.execute("DELETE FROM scan_issue_facts WHERE scan_id = 's'")
        store._conn.commit()
        assert store.get_scan_totals(["s"]) == {}
        before = store.get_scan_detail_counts("s")
        store.rebuild_scan_summary("s")
        assert store.get_scan_detail_counts("s") == before
        assert_same_metrics(store)
        # Reconciliation and repeated writes never count a finding twice.
        store.rebuild_scan_summary("s")
        assert_same_metrics(store)
    finally:
        store.close()


def test_lists_and_overview_never_fetch_completed_task_bodies(tmp_path):
    store = make_store(tmp_path)
    try:
        from test_storage_history import receipt, task
        receipt(store, task())
        queries = []
        store._conn.set_trace_callback(queries.append)
        assert store.list_scans_page(limit=50)[0].completed_task_count == 1
        assert store.load_scan_overview("s")[0].opencode_pool.completed_tasks == []
        assert not any("scan_task_versions" in query for query in queries)
        list_query = next(query for query in queries if "FROM scans s" in query)
        assert "s.*" not in list_query
    finally:
        store.close()
