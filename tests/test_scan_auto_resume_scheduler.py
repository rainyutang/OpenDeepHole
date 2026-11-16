"""Automatic continuation owns a bounded scan-wide budget, including review-only work."""
import asyncio
from unittest.mock import AsyncMock

import pytest

from backend.application import ApplicationError, get_runtime
from backend.models import ScanItemStatus, ScanMeta, ScanStatus, Vulnerability
from backend.scans import auto_resume, continuation
from backend.store.sqlite import SqliteScanStore


async def direct_store(store, operation, *args, **kwargs):
    return (getattr(store, operation) if isinstance(operation, str) else operation)(*args, **kwargs)


@pytest.fixture
def automatic_scan(tmp_path, monkeypatch):
    store = SqliteScanStore(tmp_path / "auto.db")
    runtime = get_runtime()
    runtime.store = store
    runtime.store_runner = direct_store
    runtime.publisher = lambda *args, **kwargs: None
    scan = ScanStatus(scan_id="scan", status=ScanItemStatus.ERROR, created_at="2026-11-16",
                      static_analysis_done=True, auto_resume_enabled=True,
                      progress=0, total_candidates=0, processed_candidates=0, vulnerabilities=[])
    meta = ScanMeta(scan_items=[], created_at=scan.created_at, user_id="owner",
                    agent_id="agent", project_path="/repo", auto_resume_enabled=True)
    store.save_scan(scan, meta)
    store.schedule_scan_auto_resume("scan", "http://server")
    yield store
    store.close()


def run(coro):
    return asyncio.run(coro)


def test_three_rounds_are_lifetime_budget_and_manual_does_not_reset(automatic_scan, monkeypatch):
    store = automatic_scan
    rounds = []

    async def dispatch(scan_id, server_url, user, **kwargs):
        assert user.user_id == "owner"
        token = await auto_resume.acquire_resume_dispatch(
            scan_id, automatic=True, expected_revision=0, server_url=server_url,
        )
        rounds.append(token)
        await auto_resume.finish_resume_dispatch(scan_id, token, failed=True, reason="模拟派发失败")

    monkeypatch.setattr(continuation, "_continue_scan", dispatch)
    for _ in range(5):
        run(auto_resume.process_auto_resume("scan"))
    assert len(set(rounds)) == 3
    record = store.get_scan_auto_resume("scan")
    assert record["auto_resume_count"] == 3
    assert record["auto_resume_state"] == "exhausted"

    async def manual():
        token = await auto_resume.acquire_resume_dispatch(
            "scan", automatic=False, expected_revision=0, server_url="http://server",
        )
        await auto_resume.finish_resume_dispatch("scan", token)
    run(manual())
    run(auto_resume.process_auto_resume("scan"))
    assert store.get_scan_auto_resume("scan")["auto_resume_count"] == 3
    assert len(rounds) == 3


@pytest.mark.parametrize("status", [ScanItemStatus.PENDING, ScanItemStatus.ANALYZING, ScanItemStatus.AUDITING])
def test_never_resume_while_main_execution_active(automatic_scan, monkeypatch, status):
    automatic_scan.update_scan_progress("scan", status=status)
    dispatch = AsyncMock()
    monkeypatch.setattr(continuation, "_continue_scan", dispatch)
    run(auto_resume.process_auto_resume("scan"))
    dispatch.assert_not_awaited()


def test_wait_for_reviews_even_after_main_finishes(automatic_scan, monkeypatch):
    store = automatic_scan
    store.create_fp_review_job("review", "scan", 1, "2026-11-16")
    dispatch = AsyncMock()
    monkeypatch.setattr(continuation, "_continue_scan", dispatch)
    run(auto_resume.process_auto_resume("scan"))
    dispatch.assert_not_awaited()
    assert store.get_scan_auto_resume("scan")["auto_resume_count"] == 0


def test_no_work_finishes_without_using_budget(automatic_scan, monkeypatch):
    automatic_scan.update_scan_progress("scan", status=ScanItemStatus.COMPLETE)
    dispatch = AsyncMock()
    monkeypatch.setattr(continuation, "_continue_scan", dispatch)
    run(auto_resume.process_auto_resume("scan"))
    dispatch.assert_not_awaited()
    record = automatic_scan.get_scan_auto_resume("scan")
    assert record["auto_resume_state"] == "idle"
    assert record["auto_resume_count"] == 0


def test_preflight_failure_waits_without_consuming_round(automatic_scan, monkeypatch):
    dispatch = AsyncMock(side_effect=ApplicationError(400, "Agent 不在线"))
    monkeypatch.setattr(continuation, "_continue_scan", dispatch)
    run(auto_resume.process_auto_resume("scan"))
    record = automatic_scan.get_scan_auto_resume("scan")
    assert record["auto_resume_state"] == "waiting"
    assert record["auto_resume_reason"] == "Agent 不在线"
    assert record["auto_resume_count"] == 0


def test_stop_invalidates_reserved_dispatch_and_late_notification(automatic_scan):
    async def scenario():
        token = await auto_resume.acquire_resume_dispatch(
            "scan", automatic=True, expected_revision=0, server_url="http://server",
        )
        await auto_resume.pause_auto_resume("scan")
        with pytest.raises(ApplicationError):
            await auto_resume.verify_resume_dispatch("scan", token)
        await auto_resume.finish_resume_dispatch("scan", token)
        await auto_resume.notify_auto_resume("scan", "http://server")
    run(scenario())
    assert automatic_scan.get_scan_auto_resume("scan")["auto_resume_state"] == "paused"


def test_stop_endpoint_cancels_waiting_round_even_when_scan_is_terminal(automatic_scan, monkeypatch):
    from backend.models import User
    from backend.scans import lifecycle
    monkeypatch.setattr(lifecycle, "_check_scan_owner", AsyncMock())
    monkeypatch.setattr(lifecycle, "_resolve_scan_agent_id", AsyncMock(return_value=None))
    result = run(lifecycle.stop_scan("scan", User(user_id="owner", username="owner", role="user")))
    assert result["main_scan_stopped"] is False
    assert automatic_scan.get_scan_auto_resume("scan")["auto_resume_state"] == "paused"
    run(auto_resume.notify_auto_resume("scan", "http://server"))
    assert automatic_scan.list_scan_auto_resume_pending() == []


def test_inflight_third_dispatch_is_not_marked_exhausted(automatic_scan, monkeypatch):
    store = automatic_scan
    for _ in range(2):
        token = store.reserve_scan_resume("scan", expected_revision=0, automatic=True)
        store.finish_scan_resume_reservation("scan", token)
    token = store.reserve_scan_resume("scan", expected_revision=0, automatic=True)
    dispatch = AsyncMock()
    monkeypatch.setattr(continuation, "_continue_scan", dispatch)
    run(auto_resume.process_auto_resume("scan"))
    dispatch.assert_not_awaited()
    assert store.get_scan_auto_resume("scan")["auto_resume_state"] == "running"
    assert store.check_scan_resume_reservation("scan", token)


@pytest.mark.parametrize("enabled,existing,cancelled,expected", [
    (False, False, False, False), (True, False, False, True),
    (False, True, False, True), (True, True, True, False),
])
def test_review_only_obeys_setting_and_user_cancellation(automatic_scan, monkeypatch, enabled, existing, cancelled, expected):
    from backend.scans import fp_review
    store = automatic_scan
    scan, meta = store.load_scan("scan")
    scan.status = ScanItemStatus.COMPLETE
    scan.auto_fp_review = meta.auto_fp_review = enabled
    scan.vulnerabilities = [Vulnerability(
        file="test.c", line=1, function="f", vuln_type="npd", severity="high",
        description="issue", ai_analysis="issue", ai_verdict="confirmed", confirmed=True,
    )]
    store.save_scan(scan, meta)
    store.add_vulnerability("scan", scan.vulnerabilities[0])
    if existing:
        store.create_fp_review_job("review", "scan", 1, "2026-11-16")
        store.update_fp_review_job("review", status="cancelled" if cancelled else "error")
    dispatch = AsyncMock()
    first_review = AsyncMock()
    monkeypatch.setattr(continuation, "_continue_scan", dispatch)
    monkeypatch.setattr(fp_review, "_start_fp_review", first_review)
    run(auto_resume.process_auto_resume("scan"))
    assert dispatch.await_count + first_review.await_count == int(expected)
    assert first_review.await_count == int(enabled and not existing)
    assert store.get_scan_auto_resume("scan")["auto_resume_count"] == 0


def test_paused_or_disabled_scan_cannot_be_scheduled(automatic_scan, monkeypatch):
    store = automatic_scan
    store.pause_scan_auto_resume("scan")
    dispatch = AsyncMock()
    monkeypatch.setattr(continuation, "_continue_scan", dispatch)
    run(auto_resume.notify_auto_resume("scan", "http://server"))
    run(auto_resume.process_auto_resume("scan"))
    dispatch.assert_not_awaited()
    assert store.list_scan_auto_resume_pending() == []


def test_third_reserved_but_unsent_round_is_recovered_without_extra_count(automatic_scan, monkeypatch):
    store = automatic_scan
    for _ in range(2):
        token = store.reserve_scan_resume("scan", expected_revision=0, automatic=True)
        store.finish_scan_resume_reservation("scan", token)
    old_token = store.reserve_scan_resume("scan", expected_revision=0, automatic=True)
    with store._lock:
        store._conn.execute("UPDATE scan_auto_resume SET lease_until = 1 WHERE scan_id = 'scan'")
        store._conn.commit()
    recovered = []

    async def dispatch(scan_id, server_url, user, **kwargs):
        token = await auto_resume.acquire_resume_dispatch(
            scan_id, automatic=True, expected_revision=0, server_url=server_url,
        )
        recovered.append(token)
        store.update_scan_progress(scan_id, status=ScanItemStatus.COMPLETE)
        await auto_resume.finish_resume_dispatch(scan_id, token)

    monkeypatch.setattr(continuation, "_continue_scan", dispatch)
    run(auto_resume.process_auto_resume("scan"))
    assert len(recovered) == 1 and recovered[0] != old_token
    assert store.get_scan_auto_resume("scan")["auto_resume_count"] == 3
    run(auto_resume.process_auto_resume("scan"))
    assert len(recovered) == 1
    assert store.get_scan_auto_resume("scan")["auto_resume_state"] == "idle"
