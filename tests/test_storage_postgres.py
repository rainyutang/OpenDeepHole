"""Opt-in tests; point only at an isolated PostgreSQL database."""

import concurrent.futures
import os
import uuid
import json

import pytest

from backend.models import FpReviewResult, OpenCodePoolStatus, ScanMeta, ScanStatus, Vulnerability, ScanItemStatus, VulnerabilityValidation
from backend.store.postgres import PostgresScanStore


DSN = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN", "")
pytestmark = pytest.mark.skipif(not DSN, reason="isolated PostgreSQL DSN not configured")


@pytest.fixture
def pg_store():
    store = PostgresScanStore(DSN, pool_min_size=1, pool_max_size=6)
    scan_id = "storage-test-" + uuid.uuid4().hex
    now = "2026-09-07T00:00:00+00:00"
    store.save_scan(ScanStatus(scan_id=scan_id, project_id=scan_id, scan_items=[], created_at=now,
                               status="auditing", progress=0, total_candidates=0, processed_candidates=0, vulnerabilities=[]),
                    ScanMeta(scan_items=[], created_at=now, scan_name=scan_id))
    with store._lock:
        store._conn.execute(
            "INSERT INTO agents (agent_key, ip, machine_name, created_at, updated_at) VALUES (?, '127.0.0.1', ?, ?, ?)",
            (scan_id, scan_id, now, now),
        )
        store._conn.commit()
    try:
        yield store, scan_id
    finally:
        # Only fixtures belonging to this test, never unrelated scans.
        with store._lock:
            store._conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            store._conn.execute("DELETE FROM agents WHERE agent_key = ?", (scan_id,))
            store._conn.commit()
        store.close()


def test_concurrent_receipts_and_heartbeat_keep_atomic_counts(pg_store):
    store, scan_id = pg_store
    task = {"task_id": "t", "scope_id": scan_id, "revision": 3, "outcome": "success", "prompt": "正文" * 1000}

    def write(_):
        return store.upsert_opencode_task_report(agent_key=scan_id, scan_id=scan_id,
                                                 agent_session_id="session", task_id="t", revision=3, task=task)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(write, range(12)))
    assert sum(results) == 1
    store.update_opencode_pool_status(scan_id, OpenCodePoolStatus(scope_id=scan_id))
    assert store.get_opencode_pool_status(scan_id).completed_task_count == 1
    assert store.load_scan(scan_id)[0].opencode_pool.completed_tasks == [task]


def test_postgres_finding_and_fp_triggers_match_summary(pg_store):
    store, scan_id = pg_store
    finding = Vulnerability(file="a.c", line=1, function="f", vuln_type="npd", severity="high",
                            description="evidence", confirmed=True, ai_verdict="confirmed",
                            vulnerability_report="report body")
    store.add_vulnerability(scan_id, finding)
    assert store.get_scan_totals([scan_id])[scan_id]["llm_issue_count"] == 1
    now = "2026-09-07T01:00:00+00:00"
    review_id = "review-" + scan_id
    store.create_fp_review_job(review_id, scan_id, 1, now)
    store.upsert_fp_review_stage_output(review_id, 0, "proof", "original stage", now)
    store.add_fp_review_result(review_id, FpReviewResult(vuln_index=0, verdict="fp", reason="safe", created_at=now))
    totals = store.get_scan_totals([scan_id])[scan_id]
    assert totals["fp_review_false_positive_count"] == 1
    assert store.get_fp_review_job(review_id).results[0].stage_outputs["proof"] == "original stage"
    assert store.get_vulnerabilities(scan_id)[0].vulnerability_report == "report body"
    assert store.get_scan_detail_counts(scan_id)["vulnerabilities"] == 1
    # This fixture predates the new scan FK migration for FP jobs.
    with store._lock:
        store._conn.execute("DELETE FROM fp_review_jobs WHERE review_id = ?", (review_id,))
        store._conn.commit()
    assert store.get_scan_totals([scan_id])[scan_id]["fp_review_false_positive_count"] == 0


def test_postgres_migration_dashboard_cleanup_and_deletion(pg_store):
    store, scan_id = pg_store
    from deephole_client.validation_delta import validation_delta
    store.upsert_vulnerability_validation(scan_id, VulnerabilityValidation(vuln_index=42, status="pending"))
    revision = store.begin_validation_execution(scan_id, 42, agent_session_id="session")
    state, changes, _ = validation_delta({"vuln_index": 42, "status": "verified", "running": False,
        "agent_session_id": "session", "execution_revision": revision, "final_output": "historical validation", "validation_output": "historical validation"})
    store.apply_validation_delta(scan_id, state, changes, 1)
    assert store.list_vulnerability_validations(scan_id)[0].validation_output == "historical validation"
    assert store.verify_scan_history(scan_id)["ok"]
    assert store.get_checker_dashboard_aggregates()["counts"]["scan_count"] >= 1
    assert store.dashboard_token_aggregates()["groups"]
    with store._lock:
        store._conn.execute("INSERT INTO agent_commands (agent_id, target_worker, payload_json, status, created_at, delivered_at) VALUES (?, 'old', 'payload', 'delivered', '2000-01-01', '2000-01-01')", (scan_id,))
        store._conn.execute("UPDATE storage_maintenance_jobs SET next_run_at = '', lease_expires_at = ''")
        store._conn.commit()
    result = store.run_storage_maintenance("test-worker", {})
    assert result["counts"]["agent_commands"] >= 1
    store.update_scan_progress(scan_id, status=ScanItemStatus.COMPLETE)
    store.request_scan_deletion(scan_id)
    while store.process_scan_deletions(limit=2).get("status") != "complete":
        pass
    assert store.load_scan(scan_id) is None
    assert store.is_scan_deleted(scan_id)


def test_postgres_explicit_online_indexes_are_restartable(pg_store):
    store, _ = pg_store
    assert store.prepare_storage_online_indexes()["indexes"]
    assert store.prepare_storage_online_indexes()["indexes"]
    assert store.validate_storage_constraints()["validated"]
    with store._lock:
        row = store._conn.execute("SELECT convalidated FROM pg_constraint WHERE conname = 'storage_fk_fp_jobs_scan'").fetchone()
        assert row["convalidated"]
        store._conn.commit()


def test_postgres_legacy_backfill_archive_cleanup_and_rollback(pg_store):
    store, scan_id = pg_store
    raw = json.dumps({"scope_id": scan_id, "completed_task_count": 3, "total_tasks": 3,
        "completed_tasks": [{"task_id": str(n), "revision": 1, "prompt": "历史 Prompt", "session_events": [{"session_id": f"s{n}"}]} for n in range(3)],
        "unknown_checkpoint": {"position": 77}})
    with store._lock:
        store._conn.execute("UPDATE scans SET history_version = 0, opencode_pool = ? WHERE scan_id = ?", (raw, scan_id))
        store._conn.commit()
    store.upsert_vulnerability_validation(scan_id, VulnerabilityValidation(vuln_index=42, status="verified", final_output="保留输出", validation_output="保留输出"))
    while not store.backfill_storage_batch(batch_rows=1)["complete"]:
        pass
    while not store.backfill_bodies_batch(batch_rows=1)["complete"]:
        pass
    while not store.backfill_summaries_batch(batch_rows=1)["complete"]:
        pass
    assert store.verify_scan_history(scan_id)["ok"]
    with store._lock:
        store._conn.execute("UPDATE scan_legacy_payloads SET verified_at = '2000-01-01' WHERE scan_id = ?", (scan_id,))
        store._conn.commit()
    assert store.cleanup_verified_archives() == 2
    assert store.verify_scan_history(scan_id)["ok"]
    assert store.restore_legacy_scan_fields(scan_id)["restored"]
    assert len(store.load_scan(scan_id)[0].opencode_pool.completed_tasks) == 3
    assert store.list_vulnerability_validations(scan_id)[0].final_output == "保留输出"
