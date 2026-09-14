"""Exercise resume ownership with independent PostgreSQL connections."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
import threading
import uuid

import pytest

from backend.models import Candidate, OpenCodePoolStatus, ScanItemStatus, ScanMeta, ScanStatus
from backend.store.postgres import PostgresScanStore


DSN = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN", "")
pytestmark = pytest.mark.skipif(not DSN, reason="PostgreSQL test DSN not configured")


@pytest.fixture
def execution():
    store = PostgresScanStore(DSN, pool_min_size=1, pool_max_size=4)
    peer = PostgresScanStore(DSN, pool_min_size=1, pool_max_size=2)
    scan_id = "resume-test-" + uuid.uuid4().hex
    created = "2026-09-01T00:00:00+00:00"
    store.save_scan(
        ScanStatus(scan_id=scan_id, created_at=created, status="cancelled",
                   total_candidates=2, processed_candidates=1, progress=0.5, vulnerabilities=[]),
        ScanMeta(created_at=created, agent_id="agent", scan_name=scan_id, scan_items=[]),
    )
    store.replace_scan_candidates(scan_id, [Candidate(
        file="done.c", line=1, function="f", vuln_type="npd", description="checkpoint",
    )])
    store.add_processed_key(scan_id, ("done.c", 1, "f", "npd"))
    for _ in range(8):
        store.begin_scan_execution(scan_id, agent_id="agent", agent_session_id="old-session")
    store.update_opencode_pool_status(scan_id, OpenCodePoolStatus(
        execution_revision=8, agent_session_id="old-session", global_running=1,
        models=[{"id": "model", "model": "provider/model", "max_concurrency": 1,
                 "running": 1, "active_tasks": [{"task_id": "old-running", "started_at": created}]}],
        completed_tasks=[{"task_id": "old-completed", "started_at": created}],
    ))
    try:
        yield store, peer, scan_id
    finally:
        with store._lock:
            store._conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            store._conn.commit()
        peer.close()
        store.close()


def test_concurrent_resume_claims_have_one_new_identity_and_keep_history(execution):
    store, peer, scan_id = execution
    barrier = threading.Barrier(2)

    def claim(connection):
        barrier.wait(timeout=5)
        return connection.claim_scan_for_resume(
            scan_id, expected_revision=8, agent_id="agent", agent_session_id="new-session",
            processed_candidates=1, progress=0.5,
        )

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(claim, (store, peer)))
    assert results.count(9) == 1 and results.count(None) == 1
    scan, meta = peer.load_scan(scan_id)
    assert meta.execution_revision == 9
    assert scan.status == "pending"
    assert scan.created_at == "2026-09-01T00:00:00+00:00"
    assert (scan.total_candidates, scan.processed_candidates) == (2, 1)
    assert store.get_processed_keys(scan_id) == {("done.c", 1, "f", "npd")}
    assert scan.opencode_pool.execution_revision == 9
    assert scan.opencode_pool.global_running == 0
    assert scan.opencode_pool.models[0].active_tasks == []
    assert any(task["task_id"] == "old-completed" for task in scan.opencode_pool.completed_tasks)
    assert peer.execution_matches("scan", scan_id, None, agent_session_id="new-session", execution_revision=9)
    assert not peer.execution_matches("scan", scan_id, None, agent_session_id="old-session", execution_revision=8)


def test_failed_start_and_late_reconnect_cannot_modify_newer_execution(execution):
    store, peer, scan_id = execution
    assert store.claim_scan_for_resume(
        scan_id, expected_revision=8, agent_session_id="new-session", processed_candidates=1, progress=0.5,
    ) == 9
    assert not peer.fail_scan_execution(
        scan_id, agent_session_id="old-session", execution_revision=8, error_message="late",
    )
    assert peer.fail_scan_execution(
        scan_id, agent_session_id="new-session", execution_revision=9, error_message="cleanup timeout",
    )
    scan, _ = store.load_scan(scan_id)
    assert scan.status == "error" and scan.error_message == "cleanup timeout"
    assert scan.processed_candidates == 1
    assert store.claim_scan_for_resume(
        scan_id, expected_revision=9, agent_session_id="new-session", processed_candidates=1, progress=0.5,
    ) == 10
    assert not peer.adopt_active_execution(
        "scan", scan_id, None, previous_session_id="new-session",
        agent_session_id="late-session", execution_revision=9,
    )
    assert not peer.fail_scan_execution(
        scan_id, agent_session_id="new-session", execution_revision=9, error_message="late",
    )
    assert store.load_scan(scan_id)[0].status == "pending"


def test_recovery_claim_retains_reserved_revision(execution):
    store, peer, scan_id = execution
    store.update_scan_progress(scan_id, status=ScanItemStatus.PENDING)
    revision = store.claim_scan_for_agent_recovery(
        scan_id, previous_session_id="old-session", agent_id="agent", agent_session_id="new-session",
        error_message="Agent 进程已重启，正在自动断点恢复",
    )
    assert revision == 9
    assert peer.claim_scan_for_resume(
        scan_id, expected_revision=revision, claimed_revision=revision,
        agent_id="agent", agent_session_id="new-session", processed_candidates=1, progress=0.5,
    ) == 9
    assert store.get_scan_meta(scan_id).execution_revision == 9
