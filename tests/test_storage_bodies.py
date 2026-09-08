from backend.models import Candidate, FpReviewResult
from test_storage_history import make_store
from test_storage_summaries import finding


def test_candidate_and_promoted_finding_share_body_without_changing_human_state(tmp_path):
    store = make_store(tmp_path)
    try:
        candidate = Candidate(file="f0.c", line=1, function="parse", vuln_type="npd", description="candidate")
        store.replace_scan_candidates("s", [candidate])
        result = finding(audit_index=0, vulnerability_report="完整报告" * 1000)
        store.add_vulnerability("s", result)
        stored = store.update_scan_candidate_audit("s", 0, state="success", result=result,
                                                    vulnerability_idx=0, dedup_decision={})
        assert stored.audit_result.vulnerability_report == result.vulnerability_report
        rows = store._conn.execute("SELECT audit_body_id FROM vulnerabilities UNION ALL SELECT audit_body_id FROM scan_candidates").fetchall()
        assert rows[0][0] == rows[1][0]
        assert store._conn.execute("SELECT COUNT(*) FROM scan_audit_versions").fetchone()[0] == 1
        assert store._conn.execute("SELECT vulnerability_report FROM vulnerabilities").fetchone()[0] == ""
        store._conn.execute("UPDATE vulnerabilities SET user_verdict = 'false_positive' WHERE scan_id = 's'")
        store._conn.commit()
        assert store.get_vulnerabilities("s")[0].user_verdict == "false_positive"
        assert store.list_scan_candidates("s")[0].audit_result.user_verdict is None
        assert store.get_vulnerabilities("s")[0].vulnerability_report == result.vulnerability_report
        source = store.get_vulnerability_audit_source("s", 0)
        assert source.status == "resolved"
        assert source.candidate.audit_result.vulnerability_report == result.vulnerability_report
    finally:
        store.close()


def test_fp_stage_references_are_frozen_when_review_retries(tmp_path):
    store = make_store(tmp_path)
    try:
        now = "2026-09-07T00:00:00+00:00"
        store.create_fp_review_job("r", "s", 1, now)
        store.upsert_fp_review_stage_output("r", 0, "proof", "original evidence", now)
        store.add_fp_review_result("r", FpReviewResult(vuln_index=0, verdict="tp", reason="yes", created_at=now))
        assert store._conn.execute("SELECT COUNT(*) FROM fp_stage_versions").fetchone()[0] == 1
        assert store.get_fp_review_job("r").results[0].stage_outputs["proof"] == "original evidence"
        store._conn.execute("UPDATE fp_review_jobs SET execution_revision = 2 WHERE review_id = 'r'")
        store._conn.commit()
        store.upsert_fp_review_stage_output("r", 0, "proof", "retry evidence", now, execution_revision=2)
        assert store.get_fp_review_job("r").results[0].stage_outputs["proof"] == "original evidence"
        assert store.list_fp_review_stage_outputs_by_review("r")[0].markdown == "retry evidence"
        store.add_fp_review_result("r", FpReviewResult(vuln_index=0, verdict="fp", reason="new", created_at=now, execution_revision=2))
        assert store.get_fp_review_job("r").results[0].stage_outputs["proof"] == "retry evidence"
        assert store._conn.execute("SELECT COUNT(*) FROM fp_result_versions").fetchone()[0] == 1
    finally:
        store.close()


def test_fp_result_batch_hydration_has_no_per_result_queries(tmp_path):
    store = make_store(tmp_path)
    try:
        now = "2026-09-07T00:00:00+00:00"
        store.create_fp_review_job("r", "s", 30, now)
        for index in range(30):
            store.upsert_fp_review_stage_output("r", index, "proof", f"evidence {index}", now)
            store.add_fp_review_result("r", FpReviewResult(vuln_index=index, verdict="tp", reason="yes", created_at=now))
        queries = []
        store._conn.set_trace_callback(queries.append)
        results = store.get_fp_review_job("r").results
        assert len(results) == 30
        assert all(result.stage_outputs["proof"] == f"evidence {result.vuln_index}" for result in results)
        assert len([query for query in queries if query.lstrip().startswith("SELECT")]) <= 4
    finally:
        store.close()
