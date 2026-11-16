"""Persistence and cross-connection fencing for scan-wide continuation rounds."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import threading
import uuid

import pytest

from backend.models import CreateScanRequest, ScanMeta, ScanStatus, ScanItemStatus
from backend.store.sqlite import SqliteScanStore


@pytest.fixture(params=['sqlite', 'postgres'])
def execution(request, tmp_path):
    if request.param == 'postgres':
        dsn = os.environ.get('OPENDEEPHOLE_TEST_POSTGRES_DSN')
        if not dsn:
            pytest.skip('PostgreSQL test DSN not configured')
        from backend.store.postgres import PostgresScanStore
        store = PostgresScanStore(dsn, pool_min_size=1, pool_max_size=3)
        peer = PostgresScanStore(dsn, pool_min_size=1, pool_max_size=2)
    else:
        database = tmp_path / 'automatic.db'
        store, peer = SqliteScanStore(database), SqliteScanStore(database)
    scan_id = 'auto-resume-' + uuid.uuid4().hex
    store.save_scan(
        ScanStatus(scan_id=scan_id, status='complete', progress=1,
                   total_candidates=0, processed_candidates=0, vulnerabilities=[]),
        ScanMeta(scan_items=[], created_at='2026-11-16', scan_name=scan_id, auto_resume_enabled=True),
    )
    store.schedule_scan_auto_resume(scan_id, 'http://server')
    try:
        yield store, peer, scan_id
    finally:
        with store._lock:
            store._conn.execute('DELETE FROM scans WHERE scan_id = ?', (scan_id,))
            store._conn.commit()
        peer.close()
        store.close()


def reserve(store, scan_id, **kwargs):
    return store.reserve_scan_resume(scan_id, expected_revision=0, automatic=True, **kwargs)


def expire(store, scan_id):
    with store._lock:
        store._conn.execute('UPDATE scan_auto_resume SET lease_until = 1 WHERE scan_id = ?', (scan_id,))
        store._conn.commit()


def test_only_one_concurrent_reservation_and_lifetime_budget(execution):
    store, peer, scan_id = execution
    barrier = threading.Barrier(2)
    def claim(connection):
        barrier.wait(timeout=5)
        return reserve(connection, scan_id)
    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(claim, (store, peer)))
    token = next(value for value in claims if value is not None)
    assert claims.count(None) == 1
    assert peer.get_scan_auto_resume(scan_id)['auto_resume_count'] == 1
    assert store.finish_scan_resume_reservation(scan_id, token)
    for count in (2, 3):
        token = reserve(peer, scan_id)
        assert token
        assert store.get_scan_auto_resume(scan_id)['auto_resume_count'] == count
        assert store.finish_scan_resume_reservation(scan_id, token)
    assert reserve(store, scan_id) is None
    assert store.load_scan(scan_id)[0].auto_resume_state == 'exhausted'
    manual = peer.reserve_scan_resume(scan_id, expected_revision=0, automatic=False)
    assert manual
    assert store.get_scan_meta(scan_id).auto_resume_count == 3
    assert store.finish_scan_resume_reservation(scan_id, manual)
    assert reserve(store, scan_id) is None


def test_untouched_expired_reservation_recovers_same_round(execution):
    store, peer, scan_id = execution
    token = reserve(store, scan_id)
    expire(store, scan_id)
    assert not peer.recover_scan_resume_reservation(scan_id)
    recovered = reserve(peer, scan_id)
    assert recovered and recovered != token
    assert not store.check_scan_resume_reservation(scan_id, token)
    token = recovered
    assert store.get_scan_auto_resume(scan_id)['auto_resume_count'] == 1
    assert peer.mark_scan_resume_dispatch_started(scan_id, token)
    expire(store, scan_id)
    assert store.recover_scan_resume_reservation(scan_id)
    replacement = reserve(peer, scan_id)
    assert replacement and replacement != token
    assert store.get_scan_auto_resume(scan_id)['auto_resume_count'] == 2


def test_global_stop_fences_reserved_dispatch_and_manual_rearms(execution):
    store, peer, scan_id = execution
    token = reserve(store, scan_id)
    assert peer.pause_scan_auto_resume(scan_id)
    assert not store.check_scan_resume_reservation(scan_id, token)
    assert not store.mark_scan_resume_dispatch_started(scan_id, token)
    assert not store.finish_scan_resume_reservation(scan_id, token)
    assert not store.schedule_scan_auto_resume(scan_id, 'http://server')
    assert not store.set_scan_auto_resume_state(scan_id, 'pending', round_id=token)
    assert store.claim_scan_for_resume(scan_id, processed_candidates=0, progress=0, resume_round=token) is None
    assert reserve(store, scan_id) is None
    manual = store.reserve_scan_resume(scan_id, expected_revision=0, automatic=False)
    assert manual
    assert peer.get_scan_auto_resume(scan_id)['auto_resume_count'] == 1
    assert store.finish_scan_resume_reservation(scan_id, manual, state='pending')
    assert reserve(peer, scan_id)


def test_fp_snapshot_and_core_activity_prevent_stale_claim(execution):
    store, peer, scan_id = execution
    review_id = 'review-' + uuid.uuid4().hex
    store.create_fp_review_job(review_id, scan_id, 1, '2026-11-16')
    assert reserve(store, scan_id) is None
    store.update_fp_review_job(review_id, status='error')
    revision = store.begin_fp_review_execution(review_id, agent_session_id='session')
    assert reserve(peer, scan_id, expected_fp_revisions={}) is None
    assert reserve(peer, scan_id, expected_fp_revisions={review_id: revision - 1}) is None
    token = reserve(peer, scan_id, expected_fp_revisions={review_id: (revision, 'error')})
    assert token
    assert store.finish_scan_resume_reservation(scan_id, token)
    store.update_scan_progress(scan_id, status=ScanItemStatus.PENDING)
    assert reserve(peer, scan_id) is None
    assert store.get_scan_meta(scan_id).auto_resume_count == 1


def test_late_terminal_callbacks_cannot_overwrite_new_execution(execution):
    store, peer, scan_id = execution
    old_revision = store.begin_scan_execution(scan_id, agent_id='agent', agent_session_id='old')
    new_revision = store.claim_scan_for_resume(scan_id, processed_candidates=0, progress=0,
                                             expected_revision=old_revision, agent_session_id='new')
    assert new_revision
    assert not peer.update_scan_progress(scan_id, status=ScanItemStatus.COMPLETE,
                                         expected_revision=old_revision, expected_agent_session_id='old')
    assert store.load_scan(scan_id)[0].status == ScanItemStatus.PENDING
    review_id = 'review-' + uuid.uuid4().hex
    store.create_fp_review_job(review_id, scan_id, 1, '2026-11-16')
    old = store.begin_fp_review_execution(review_id, agent_session_id='old')
    store.begin_fp_review_execution(review_id, agent_session_id='new')
    assert not peer.update_fp_review_job(review_id, status='complete', expected_revision=old,
                                        expected_agent_session_id='old')
    assert store.get_fp_review_job_state(review_id).status != 'complete'


def test_creation_default_and_historical_default_are_distinct(tmp_path):
    assert CreateScanRequest().auto_resume_enabled is True
    store = SqliteScanStore(tmp_path / 'legacy.db')
    try:
        store.save_scan(
            ScanStatus(scan_id='old', status='complete', progress=1, total_candidates=0,
                       processed_candidates=0, vulnerabilities=[]),
            ScanMeta(scan_items=[], created_at='2026-01-01'),
        )
        assert not store.load_scan('old')[0].auto_resume_enabled
        assert not store.get_scan_meta('old').auto_resume_enabled
        assert not store.list_scans()[0].auto_resume_enabled
        assert not store.schedule_scan_auto_resume('old', 'http://server')
        assert store.list_scan_auto_resume_pending() == []
    finally:
        store.close()


def test_same_revision_user_stop_blocks_late_completion_and_review_start(execution):
    store, peer, scan_id = execution
    token = reserve(store, scan_id)
    revision = store.begin_scan_execution(scan_id, agent_id='agent', agent_session_id='session')
    store.update_scan_progress(scan_id, status=ScanItemStatus.CANCELLED, error_message='用户手动停止')
    assert not peer.update_scan_progress(scan_id, status=ScanItemStatus.COMPLETE,
                                         expected_revision=revision, expected_agent_session_id='session')
    review_id = 'review-' + uuid.uuid4().hex
    store.create_fp_review_job(review_id, scan_id, 1, '2026-11-16')
    old = store.begin_fp_review_execution(review_id, agent_session_id='session')
    store.update_fp_review_job(review_id, status='cancelled')
    assert not peer.update_fp_review_job(review_id, status='complete', expected_revision=old,
                                        expected_agent_session_id='session')
    assert peer.acquire_fp_review_execution(review_id, agent_session_id='session', resume_round=token,
                                            expected_revision=old) is None


def test_delete_invalidates_waiting_reservation(execution):
    store, peer, scan_id = execution
    token = reserve(store, scan_id)
    assert store.request_scan_deletion(scan_id)
    assert peer.get_scan_auto_resume(scan_id) is None
    assert not peer.mark_scan_resume_dispatch_started(scan_id, token)
    assert not peer.check_scan_resume_reservation(scan_id, token)
    assert reserve(peer, scan_id) is None
    assert not peer.schedule_scan_auto_resume(scan_id, 'http://server')


def test_core_claimed_before_crash_keeps_count_and_uses_execution_recovery(execution):
    store, peer, scan_id = execution
    token = reserve(store, scan_id)
    revision = store.claim_scan_for_resume(scan_id, processed_candidates=0, progress=0,
                                          expected_revision=0, resume_round=token, agent_session_id='session')
    assert revision
    expire(store, scan_id)
    assert peer.recover_scan_resume_reservation(scan_id)
    row = store.get_scan_auto_resume(scan_id)
    assert row['lease_until'] == 0
    assert row['auto_resume_count'] == 1
    assert row['auto_resume_state'] == 'running'
    assert not peer.check_scan_resume_reservation(scan_id, token)


def test_legacy_schema_migrates_to_disabled(tmp_path):
    database = tmp_path / 'old-schema.db'
    store = SqliteScanStore(database)
    store.save_scan(ScanStatus(scan_id='old', status='complete', progress=1, total_candidates=0,
                              processed_candidates=0, vulnerabilities=[]),
                    ScanMeta(scan_items=[], created_at='2026-01-01'))
    with store._lock:
        for column in ('auto_resume_enabled', 'auto_resume_count', 'auto_resume_state', 'auto_resume_reason'):
            store._conn.execute(f'ALTER TABLE scans DROP COLUMN {column}')
        store._conn.commit()
    store.close()
    store = SqliteScanStore(database)
    try:
        assert not store.get_scan_meta('old').auto_resume_enabled
        assert store.load_scan('old')[0].auto_resume_count == 0
        assert store.list_scan_auto_resume_pending() == []
    finally:
        store.close()


def test_finish_lease_serializes_callbacks_and_all_resume_claims(execution):
    store, peer, scan_id = execution
    token = store.acquire_scan_finish(scan_id, agent_session_id='', execution_revision=0)
    assert token
    assert peer.acquire_scan_finish(scan_id, agent_session_id='', execution_revision=0) is None
    assert reserve(peer, scan_id) is None
    assert peer.reserve_scan_resume(scan_id, expected_revision=0, automatic=False) is None
    assert peer.claim_scan_for_resume(scan_id, processed_candidates=0, progress=0) is None
    assert store.renew_scan_finish(scan_id, token)
    assert peer.release_scan_finish(scan_id, token)
    resumed = reserve(peer, scan_id)
    assert resumed
    assert store.acquire_scan_finish(scan_id, agent_session_id='', execution_revision=0) is None
    assert peer.finish_scan_resume_reservation(scan_id, resumed)
    revision = store.begin_scan_execution(scan_id, agent_id='agent', agent_session_id='new')
    assert store.acquire_scan_finish(scan_id, agent_session_id='', execution_revision=0) is None
    current = peer.acquire_scan_finish(scan_id, agent_session_id='new', execution_revision=revision)
    assert current
    assert not store.release_scan_finish(scan_id, token)
    assert peer.release_scan_finish(scan_id, current)


def test_manual_resume_takes_over_expired_unsent_round_without_budget_reset(execution):
    store, peer, scan_id = execution
    old = reserve(store, scan_id)
    expire(store, scan_id)
    manual = peer.reserve_scan_resume(scan_id, expected_revision=0, automatic=False)
    assert manual and manual != old
    assert peer.get_scan_auto_resume(scan_id)['auto_resume_count'] == 1
    assert not store.mark_scan_resume_dispatch_started(scan_id, old)


def test_dispatched_new_main_can_finish_during_its_own_resume_handoff(execution):
    store, peer, scan_id = execution
    token = reserve(store, scan_id)
    assert store.acquire_scan_finish(scan_id, agent_session_id='', execution_revision=0) is None
    revision = store.claim_scan_for_resume(scan_id, processed_candidates=0, progress=0,
                                          expected_revision=0, resume_round=token, agent_session_id='session')
    assert revision
    assert peer.acquire_scan_finish(scan_id, agent_session_id='session', execution_revision=revision) is None
    assert store.mark_scan_resume_dispatch_started(scan_id, token)
    assert peer.acquire_scan_finish(scan_id, agent_session_id='', execution_revision=0) is None
    finished = peer.acquire_scan_finish(scan_id, agent_session_id='session', execution_revision=revision)
    assert finished
    assert store.check_scan_resume_reservation(scan_id, token)
    assert peer.release_scan_finish(scan_id, finished)
