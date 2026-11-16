"""Reliable task lifecycle reports and bounded database-owned stop settlement."""

from concurrent.futures import ThreadPoolExecutor
import os
import threading
import uuid

import pytest

from backend.models import MiningEngineRunStatus, ScanItemStatus, ScanMeta, ScanStatus, ThreatPatternAuditTask
from backend.store.sqlite import SqliteScanStore


@pytest.fixture(params=["sqlite", "postgres"])
def execution(request, tmp_path):
    if request.param == "postgres":
        dsn = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN")
        if not dsn:
            pytest.skip("PostgreSQL test DSN not configured")
        from backend.store.postgres import PostgresScanStore
        factory = lambda: PostgresScanStore(dsn, pool_min_size=1, pool_max_size=2)
    else:
        factory = lambda: SqliteScanStore(tmp_path / "settlement.db")
    store, peer = factory(), factory()
    scan_id = "settlement-" + uuid.uuid4().hex
    store.save_scan(
        ScanStatus(scan_id=scan_id, status="auditing", progress=0, total_candidates=0,
                   processed_candidates=0, vulnerabilities=[]),
        ScanMeta(scan_items=[], created_at="2026-11-16", scan_name=scan_id),
    )
    with store._lock:
        store._conn.execute(
            "UPDATE scans SET execution_revision = 1, execution_agent_session_id = 'session-a' WHERE scan_id = ?",
            (scan_id,),
        )
        store._conn.commit()
    try:
        yield store, peer, scan_id
    finally:
        with store._lock:
            store._conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            store._conn.commit()
        peer.close()
        store.close()


def report(store, scan_id, seq=1, *, key="task", revision=1, session="session-a", **values):
    task = ThreatPatternAuditTask(task_id=scan_id + key, **values)
    return store.upsert_threat_pattern_audit_task(
        scan_id, task, execution_revision=revision, report_agent_session_id=session,
        report_sequence=seq, return_change_kind=True,
    )


def stop(store, scan_id, revision=1):
    return store.update_scan_progress(scan_id, status=ScanItemStatus.CANCELLED,
        error_message="用户手动停止", expected_revision=revision,
        expected_agent_session_id="session-a", return_settled=True)


def task(store, scan_id, key="task"):
    return store.list_threat_pattern_audit_tasks(scan_id, task_id=scan_id + key)[0]


def run(engine="threat_pattern_audit", status="running", revision=1, session="session-a"):
    return MiningEngineRunStatus(engine_id=engine, engine_label=engine, status=status,
                                execution_revision=revision, report_agent_session_id=session)


def test_duplicate_and_out_of_order_reports_preserve_terminal_results(execution):
    store, peer, scan_id = execution
    report(store, scan_id, status="pending")
    completed, changed, kind = report(store, scan_id, 3, status="completed", result_vuln_indexes=[4],
        followup_clues="saved clue", has_more_findings=True,
        output_source={"serve_session_id": "source-session"})
    assert changed and kind == "result"
    for sequence, status in ((3, "completed"), (2, "running"), (4, "cancelled"), (5, "queued")):
        actual, changed, _ = report(store, scan_id, sequence, status=status)
        assert not changed
        assert actual == completed
    assert task(peer, scan_id) == completed
    row = store._conn.execute("SELECT report_sequence FROM threat_pattern_audit_tasks WHERE task_id = ?", (scan_id + "task",)).fetchone()
    assert row["report_sequence"] == 5


def test_stop_closes_persisted_tasks_and_late_reports_cannot_reopen(execution):
    store, peer, scan_id = execution
    report(store, scan_id, status="running", output_source={"serve_session_id": "session-live"})
    report(store, scan_id, key="done", status="completed", result_vuln_indexes=[8])
    assert stop(store, scan_id) == (True, ["threat_pattern_audit"])
    assert task(peer, scan_id).status == "cancelled"
    assert task(peer, scan_id, "done").status == "completed"
    report(store, scan_id, 2, status="running", description="late details")
    actual = task(peer, scan_id)
    assert actual.status == "cancelled" and actual.description == "late details"
    assert actual.output_source.serve_session_id == "session-live"
    repeated, changed, _ = report(store, scan_id, 3, status="running", description="late details")
    assert not changed and repeated == actual
    report(store, scan_id, key="unregistered", status="pending")
    assert task(peer, scan_id, "unregistered").status == "cancelled"
    # A real result completed during the stop race is still authoritative.
    report(store, scan_id, 4, status="completed", result_vuln_indexes=[9])
    assert task(peer, scan_id).status == "completed"
    assert task(peer, scan_id).result_vuln_indexes == [9]
    assert stop(store, scan_id) == (False, [])


def test_resume_accepts_new_identity_and_rejects_old_reports_without_lock_leaks(execution):
    store, peer, scan_id = execution
    report(store, scan_id, 10, status="running")
    stop(store, scan_id)
    revision = peer.claim_scan_for_resume(scan_id, expected_revision=1, processed_candidates=0,
                                         progress=0, agent_session_id="session-a")
    assert revision == 2
    report(peer, scan_id, 1, revision=2, status="pending")
    with pytest.raises(ValueError, match="stale scan execution"):
        report(store, scan_id, 99, status="cancelled")
    # A rejected writer must not retain a SQLite write lock or PG transaction.
    report(peer, scan_id, 2, revision=2, status="running")
    assert task(store, scan_id).status == "running"
    assert stop(store, scan_id, revision=1) == (False, [])
    assert task(peer, scan_id).status == "running"


def test_missing_scan_and_cross_scan_task_rejection_release_transaction(execution):
    store, peer, scan_id = execution
    with pytest.raises(KeyError):
        report(store, "missing-" + scan_id, status="pending")
    report(peer, scan_id, status="running")
    other_id = scan_id + "-other"
    store.save_scan(ScanStatus(scan_id=other_id, status="auditing", progress=0,
        total_candidates=0, processed_candidates=0, vulnerabilities=[]),
        ScanMeta(scan_items=[], created_at="2026-11-16"))
    try:
        with pytest.raises(ValueError, match="belongs to another scan"):
            store.upsert_threat_pattern_audit_task(other_id,
                ThreatPatternAuditTask(task_id=scan_id + "task", status="cancelled"))
        report(peer, scan_id, 2, status="completed")
        assert task(store, scan_id).status == "completed"
    finally:
        with store._lock:
            store._conn.execute("DELETE FROM scans WHERE scan_id = ?", (other_id,))
            store._conn.commit()


def test_session_adoption_resets_sequence_and_preserves_artifact_provenance(execution):
    store, peer, scan_id = execution
    report(store, scan_id, 20, status="running", output_source={"agent_session_id": "artifact-session"})
    assert store.adopt_active_execution("scan", scan_id, None, previous_session_id="session-a",
                                        agent_session_id="session-b", execution_revision=1)
    report(peer, scan_id, 1, session="session-b", status="running")
    with pytest.raises(ValueError, match="stale scan execution"):
        report(store, scan_id, 21, status="cancelled")
    report(peer, scan_id, 2, session="session-b", status="completed")
    assert task(store, scan_id).output_source.agent_session_id == "artifact-session"


def test_session_adoption_does_not_reopen_terminal_engine(execution):
    store, peer, scan_id = execution
    report(store, scan_id, status="completed", result_vuln_indexes=[2])
    store.update_mining_engine_run(scan_id, run(status="success"))
    assert store.adopt_active_execution("scan", scan_id, None, previous_session_id="session-a",
                                        agent_session_id="session-b", execution_revision=1)
    report(peer, scan_id, session="session-b", status="pending")
    assert task(store, scan_id).status == "completed"
    report(peer, scan_id, key="late", session="session-b", status="pending")
    assert task(store, scan_id, "late").status == "cancelled"
    current = peer.update_mining_engine_run(scan_id, run(session="session-b"))
    assert current[0].status == "success"


def test_engine_finish_settles_only_its_tasks_and_does_not_fence_new_round(execution):
    store, peer, scan_id = execution
    report(store, scan_id, status="running")
    report(store, scan_id, key="iterative", engine_id="threat_pattern_iterative_audit", status="pending")
    runs, settled = store.update_mining_engine_run(scan_id, run(status="error"), return_settled=True)
    assert settled == ["threat_pattern_audit"]
    assert task(peer, scan_id).status == "cancelled"
    assert task(peer, scan_id, "iterative").status == "pending"
    report(peer, scan_id, key="late", status="pending")
    assert task(peer, scan_id, "late").status == "cancelled"
    assert store.update_mining_engine_run(scan_id, run(), return_settled=True) == (runs, [])
    stop(store, scan_id)
    assert peer.claim_scan_for_resume(scan_id, expected_revision=1, processed_candidates=0,
                                      progress=0, agent_session_id="session-a") == 2
    report(peer, scan_id, revision=2, status="pending")
    with pytest.raises(ValueError, match="stale scan execution"):
        store.update_mining_engine_run(scan_id, run(status="error"))
    current, settled = peer.update_mining_engine_run(scan_id, run(revision=2), return_settled=True)
    assert current[0].status == "running" and settled == []
    assert task(store, scan_id).status == "pending"


def test_concurrent_registration_and_stop_always_leave_terminal_task(execution):
    store, peer, scan_id = execution
    gate = threading.Barrier(2)
    def register():
        gate.wait(timeout=5)
        return report(store, scan_id, status="running")
    def cancel():
        gate.wait(timeout=5)
        return stop(peer, scan_id)
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = [workers.submit(register), workers.submit(cancel)]
        for result in results:
            result.result(timeout=10)
    assert task(peer, scan_id).status == "cancelled"


def test_legacy_reports_remain_supported_but_cannot_replace_versioned_task(execution):
    store, peer, scan_id = execution
    store.upsert_threat_pattern_audit_task(scan_id, ThreatPatternAuditTask(task_id=scan_id + "legacy", status="queued"))
    assert task(peer, scan_id, "legacy").status == "queued"
    report(store, scan_id, status="running")
    _, changed = store.upsert_threat_pattern_audit_task(scan_id,
        ThreatPatternAuditTask(task_id=scan_id + "task", status="pending"), return_changed=True)
    assert not changed and task(peer, scan_id).status == "running"
    assert stop(store, scan_id)[1] == ["threat_pattern_audit"]
    assert task(peer, scan_id, "legacy").status == "cancelled"


def test_stop_uses_constant_number_of_statements_and_one_commit_for_1000_tasks(execution):
    store, peer, scan_id = execution
    with store._lock:
        store._conn.executemany(
            "INSERT INTO threat_pattern_audit_tasks (task_id, scan_id, status, followup_clues) VALUES (?, ?, ?, ?)",
            [(scan_id + str(index), scan_id, "pending", "saved evidence " * 100) for index in range(1000)],
        )
        store._conn.commit()
    original = store._conn
    class RecordingConnection:
        commits = 0
        statements = []
        def __getattr__(self, name):
            return getattr(original, name)
        def execute(self, statement, *args):
            self.statements.append(statement)
            return original.execute(statement, *args)
        def commit(self):
            self.commits += 1
            return original.commit()
    recording = RecordingConnection()
    store._conn = recording
    try:
        assert stop(store, scan_id) == (True, ["threat_pattern_audit"])
    finally:
        store._conn = original
    statements = [sql for sql in recording.statements if "threat_pattern_audit_tasks" in sql]
    assert len(statements) == 2
    assert statements[0].startswith("SELECT DISTINCT engine_id")
    assert statements[1].startswith("UPDATE threat_pattern_audit_tasks")
    assert recording.commits == 1
    row = peer._conn.execute("SELECT COUNT(*) AS count FROM threat_pattern_audit_tasks WHERE scan_id = ? AND status = 'cancelled'", (scan_id,)).fetchone()
    assert row["count"] == 1000
    assert peer.get_scan_detail_counts(scan_id)["threat_pattern_audit_cancelled"] == 1000


def test_same_business_snapshot_only_advances_report_watermark(execution):
    store, peer, scan_id = execution
    first, _, _ = report(store, scan_id, status="running", created_at="2026-11-16")
    duplicate, changed, _ = report(peer, scan_id, 2, status="running", created_at="2026-11-16")
    assert not changed and duplicate.updated_at == first.updated_at
    assert peer.get_scan_detail_counts(scan_id)["threat_pattern_audit_running"] == 1


@pytest.mark.parametrize("recovery", [False, True])
def test_start_failure_closes_previous_unfinished_rows(execution, recovery):
    store, peer, scan_id = execution
    report(store, scan_id, status="pending")
    store.update_scan_progress(scan_id, status=ScanItemStatus.PENDING)
    if recovery:
        assert store.fail_scan_recovery(scan_id, agent_session_id="session-a", execution_revision=1,
            error_message="recovery failed")
    else:
        assert store.fail_scan_execution(scan_id, agent_session_id="session-a", execution_revision=1,
            error_message="startup failed", return_settled=True) == (True, ["threat_pattern_audit"])
    assert task(peer, scan_id).status == "cancelled"


def test_existing_database_adds_report_columns_without_rewriting_task_history(tmp_path):
    path = tmp_path / "old.db"
    store = SqliteScanStore(path)
    store.save_scan(ScanStatus(scan_id="old", status="auditing", progress=0, total_candidates=0,
        processed_candidates=0, vulnerabilities=[]), ScanMeta(scan_items=[], created_at="2026-11-16"))
    original = store.upsert_threat_pattern_audit_task("old", ThreatPatternAuditTask(task_id="old-task", status="completed", followup_clues="retained"))
    for column in ("execution_revision", "report_agent_session_id", "report_sequence"):
        store._conn.execute("ALTER TABLE threat_pattern_audit_tasks DROP COLUMN " + column)
    store._conn.commit()
    store.close()
    migrated = SqliteScanStore(path)
    try:
        assert migrated.list_threat_pattern_audit_tasks("old") == [original]
        row = migrated._conn.execute("SELECT execution_revision, report_agent_session_id, report_sequence FROM threat_pattern_audit_tasks").fetchone()
        assert tuple(row) == (0, "", 0)
    finally:
        migrated.close()
