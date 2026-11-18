"""Automatic continuation uses ordinary work selection without reviving stops."""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from backend.application import ApplicationError, BackendRuntime, use_runtime
from backend.models import (
    AgentFpReviewFinish, AgentScanFinish, FpReviewJob, FpReviewStatus, ScanItemStatus, ScanMeta,
    ScanStatus, User, Vulnerability,
)
from backend.scans import auto_resume, continuation, fp_review, fp_review_callbacks, resume_execution
from backend.scans.fp_review_policy import _automatic_fp_review_resume_state, _ensure_fp_review_job_for_scan
from backend.scans.ingestion.completion import _start_completion_review
from backend.scans.ingestion import completion
from backend.scans.ingestion.results import agent_report_vulnerability
from backend.store.sqlite import SqliteScanStore


async def direct_store(store, operation, *args, **kwargs):
    return (getattr(store, operation) if isinstance(operation, str) else operation)(*args, **kwargs)


def scan_with_finding(*, auto_fp_review=True):
    return ScanStatus(
        scan_id="scan", status="complete", auto_fp_review=auto_fp_review,
        progress=1.0, total_candidates=1, processed_candidates=1,
        static_analysis_done=True, vulnerabilities=[Vulnerability(
            file="a.c", line=1, function="f", vuln_type="npd", severity="high",
            description="finding", confirmed=True, ai_verdict="confirmed",
        )],
    )


@pytest.mark.parametrize(("enabled", "states", "expected"), [
    (True, [], (False, 1)),
    (False, [], (False, 0)),
    (False, [("review", "error")], (False, 1)),
    (True, [("review", "cancelled")], (False, 0)),
    (True, [("old", "cancelled"), ("new", "error")], (False, 1)),
    (True, [("old", "running"), ("new", "error")], (True, 0)),
])
def test_automatic_fp_policy_respects_settings_stops_and_active_jobs(enabled, states, expected):
    assert _automatic_fp_review_resume_state(scan_with_finding(auto_fp_review=enabled), {}, states) == expected


@pytest.mark.parametrize(("enabled", "existing", "starts"), [
    (True, True, False), (True, False, True), (False, True, True),
])
def test_completion_does_not_retry_existing_fp_outside_budget(monkeypatch, enabled, existing, starts):
    store = SimpleNamespace(
        get_scan_meta=lambda _: SimpleNamespace(auto_resume_enabled=enabled),
        get_fp_review_by_scan=lambda _: object() if existing else None,
    )
    start = AsyncMock(return_value={"ok": True})
    monkeypatch.setattr(fp_review, "_start_fp_review", start)
    monkeypatch.setattr("backend.scans.fp_review_policy._scan_fp_review_settings", lambda *_: (True, "adversarial"))
    with use_runtime(BackendRuntime(store=store, store_runner=direct_store)):
        asyncio.run(_start_completion_review(
            "scan", scan=None, final_status="complete", confirmed=1, server_url="http://server",
        ))
    assert bool(start.await_count) == starts


def test_global_stop_suppresses_initial_and_streamed_automatic_fp_start(monkeypatch):
    store = SimpleNamespace(
        get_scan_meta=lambda _: SimpleNamespace(auto_resume_enabled=True, auto_resume_state="paused"),
        get_scan_auto_resume=lambda _: {"auto_resume_state": "paused"},
    )
    start = AsyncMock()
    monkeypatch.setattr(fp_review, "_start_fp_review", start)
    monkeypatch.setattr("backend.scans.fp_review_policy._scan_fp_review_settings", lambda *_: (True, "adversarial"))
    with use_runtime(BackendRuntime(store=store, store_runner=direct_store)):
        assert _ensure_fp_review_job_for_scan("scan") == {"cancelled": True}
        asyncio.run(_start_completion_review(
            "scan", scan=None, final_status="complete", confirmed=1, server_url="http://server",
        ))
    start.assert_not_awaited()


def test_fast_core_finish_does_not_compete_with_mixed_round_fp_start(monkeypatch):
    store = SimpleNamespace(get_scan_auto_resume=lambda _: {"lease_until": time.time() + 120})
    start = AsyncMock()
    monkeypatch.setattr(fp_review, "_start_fp_review", start)
    monkeypatch.setattr("backend.scans.fp_review_policy._scan_fp_review_settings", lambda *_: (True, "adversarial"))
    with use_runtime(BackendRuntime(store=store, store_runner=direct_store)):
        asyncio.run(_start_completion_review(
            "scan", scan=None, final_status="complete", confirmed=1, server_url="http://server",
        ))
    start.assert_not_awaited()


@pytest.mark.parametrize("automatic", [False, True])
def test_fp_only_resume_shares_round_reservation_and_preserves_stop_policy(monkeypatch, automatic):
    scan = scan_with_finding()
    meta = ScanMeta(created_at="now", execution_revision=7, scan_items=[])
    job = FpReviewJob(review_id="review", scan_id="scan", created_at="now", status="error", execution_revision=4)
    store = SimpleNamespace(
        load_scan=lambda _: (scan, meta), get_processed_keys=lambda _: set(),
        list_fp_review_verdicts_by_scans=lambda _: {},
        list_fp_review_states_by_scans=lambda _: {"scan": [("review", "error")]},
        get_fp_review_job_state=lambda _: job,
    )
    preflight = AsyncMock()
    acquire = AsyncMock(return_value="round-token")
    finish = AsyncMock()
    start = AsyncMock(return_value={"items_dispatched": True})
    monkeypatch.setattr(fp_review, "preflight_fp_review", preflight)
    monkeypatch.setattr(continuation, "_start_fp_review", start)
    monkeypatch.setattr(auto_resume, "acquire_resume_dispatch", acquire)
    monkeypatch.setattr(auto_resume, "finish_resume_dispatch", finish)
    with use_runtime(BackendRuntime(store=store, store_runner=direct_store)):
        response = asyncio.run(continuation._continue_scan(
            "scan", "http://server", User(user_id="owner", username="owner", role="user"),
            skip_owner_check=True, auto_resume_round="auto" if automatic else None,
            auto_resume_expected_revision=7 if automatic else None,
        ))
    assert response.scan_id == "scan"
    preflight.assert_awaited_once_with(meta)
    acquire.assert_awaited_once_with(
        "scan", automatic=automatic, expected_revision=7, server_url="http://server",
        expected_fp_revisions={"review": (4, "error")},
    )
    assert start.await_args.kwargs["allow_cancelled"] is not automatic
    assert start.await_args.kwargs["resume_round"] == "round-token"
    finish.assert_awaited_once_with("scan", "round-token")


def test_automatic_resume_rejects_changed_core_revision_before_reservation(monkeypatch):
    store = SimpleNamespace(load_scan=lambda _: (
        scan_with_finding(), ScanMeta(created_at="now", execution_revision=8, scan_items=[]),
    ))
    acquire = AsyncMock()
    monkeypatch.setattr(auto_resume, "acquire_resume_dispatch", acquire)
    with use_runtime(BackendRuntime(store=store, store_runner=direct_store)):
        with pytest.raises(ApplicationError, match="执行轮次已变化"):
            asyncio.run(continuation._continue_scan(
                "scan", "http://server", User(user_id="owner", username="owner", role="user"),
                skip_owner_check=True, auto_resume_round="auto", auto_resume_expected_revision=7,
            ))
    acquire.assert_not_awaited()


def test_fp_only_without_model_is_rejected_before_round_budget(monkeypatch):
    scan = scan_with_finding()
    meta = ScanMeta(created_at="now", scan_items=[], execution_revision=7, agent_id="agent")
    store = SimpleNamespace(
        load_scan=lambda _: (scan, meta), get_processed_keys=lambda _: set(),
        list_fp_review_verdicts_by_scans=lambda _: {},
        list_fp_review_states_by_scans=lambda _: {},
    )
    acquire = AsyncMock()
    monkeypatch.setattr(auto_resume, "acquire_resume_dispatch", acquire)
    monkeypatch.setattr(fp_review, "_resolve_scan_agent_id", AsyncMock(return_value="agent"))
    monkeypatch.setattr("backend.agents.runtime_updates.ensure_agent_accepting_tasks_async", AsyncMock())
    monkeypatch.setattr("backend.agents.directory.resolve_agent_id_connection_async", AsyncMock(
        return_value=("agent", object()),
    ))
    monkeypatch.setattr("backend.agents.configuration.get_scan_agent_config_async", AsyncMock(return_value=object()))
    monkeypatch.setattr("backend.agents.configuration.agent_config_has_explicit_model", lambda _: False)
    with use_runtime(BackendRuntime(store=store, store_runner=direct_store)):
        with pytest.raises(ApplicationError, match="显式模型"):
            asyncio.run(continuation._continue_scan(
                "scan", "http://server", User(user_id="owner", username="owner", role="user"),
                skip_owner_check=True, auto_resume_round="auto", auto_resume_expected_revision=7,
            ))
    acquire.assert_not_awaited()


@pytest.mark.parametrize("changed", [False, True])
def test_fp_finish_only_wakes_scheduler_after_guarded_terminal_write(monkeypatch, changed):
    job = FpReviewJob(review_id="review", scan_id="scan", created_at="now", status="running")
    update = Mock(return_value=changed)
    store = SimpleNamespace(
        get_fp_review_job_state=lambda _: job, execution_matches=lambda *_args, **_kwargs: True,
        update_fp_review_job=update,
    )
    notify = AsyncMock()
    publisher = Mock()
    monkeypatch.setattr(auto_resume, "notify_auto_resume", notify)
    with use_runtime(BackendRuntime(store=store, store_runner=direct_store, publisher=publisher)):
        asyncio.run(fp_review_callbacks.agent_fp_review_finish(
            "scan", AgentFpReviewFinish(
                review_id="review", status="error", execution_revision=9, agent_session_id="session",
            ), server_url="http://server",
        ))
    assert update.call_args.kwargs["expected_revision"] == 9
    assert update.call_args.kwargs["expected_agent_session_id"] == "session"
    assert bool(notify.await_count) == changed
    assert bool(publisher.call_count) == changed


@pytest.mark.parametrize("stop_phase", ["acquire", "payload", "late_send"])
def test_fp_resume_cannot_dispatch_after_stop_during_preparation(monkeypatch, stop_phase):
    scan = scan_with_finding()
    meta = ScanMeta(created_at="now", scan_items=[], agent_id="agent", agent_name="agent")
    job = FpReviewJob(
        review_id="review", scan_id="scan", created_at="now", status="running", execution_revision=2,
    )
    acquire = Mock(return_value=None if stop_phase == "acquire" else 2)
    mark = Mock(return_value=True)
    store = SimpleNamespace(
        load_scan=lambda _: (scan, meta), get_scan_meta=lambda _: meta,
        acquire_fp_review_execution=acquire, get_fp_review_job_state=lambda _: job,
        mark_scan_resume_dispatch_started=mark, update_fp_review_job=Mock(return_value=False),
    )
    async def sending(_agent, command):
        if stop_phase == "late_send" and command["type"] == "fp_review":
            job.status = FpReviewStatus.CANCELLED
        return True

    send = AsyncMock(side_effect=sending)

    async def prepare_payload(*_args):
        if stop_phase == "payload":
            job.status = FpReviewStatus.CANCELLED
        return None

    monkeypatch.setattr(fp_review, "_resolve_scan_agent_id", AsyncMock(return_value="agent"))
    monkeypatch.setattr(fp_review, "_selected_feedback_entries", lambda *_: [])
    monkeypatch.setattr(fp_review, "_ensure_fp_review_job_for_scan", lambda *_args, **_kwargs: {
        "review_id": "review", "method": "adversarial", "confirmed": [{"index": 0}],
        "previous_status": "error", "execution_revision": 1,
    })
    monkeypatch.setattr("backend.agents.runtime_updates.ensure_agent_accepting_tasks_async", AsyncMock())
    monkeypatch.setattr("backend.agents.directory.resolve_agent_id_connection_async", AsyncMock(
        return_value=("agent", SimpleNamespace(agent_session_id="session")),
    ))
    monkeypatch.setattr("backend.agents.artifacts.create_agent_task_runtime_update_payload_async", prepare_payload)
    monkeypatch.setattr("backend.review_notes.scan_review_notes_payload", AsyncMock(return_value=[]))
    monkeypatch.setattr("backend.agents.gateway.send_agent_command", send)
    monkeypatch.setattr(auto_resume, "verify_resume_dispatch", AsyncMock(
        side_effect=[None, None, ApplicationError(409, "去误报任务已被停止")]
        if stop_phase == "late_send" else None,
    ))
    with use_runtime(BackendRuntime(store=store, store_runner=direct_store, publisher=Mock())):
        with pytest.raises(ApplicationError, match="已被停止"):
            asyncio.run(fp_review._start_fp_review(
                "scan", "http://server", require_unresolved=True, resume_round="round",
            ))
    assert acquire.call_args.kwargs["resume_round"] == "round"
    assert acquire.call_args.kwargs["expected_revision"] == 1
    if stop_phase == "late_send":
        assert [call.args[1]["type"] for call in send.await_args_list] == ["fp_review", "fp_review_stop"]
        mark.assert_called_once()
    else:
        send.assert_not_awaited()
        mark.assert_not_called()


@pytest.mark.parametrize("failure", ["connection", "payload"])
def test_fp_preparation_failure_does_not_mark_an_undispatched_job_running(monkeypatch, failure):
    scan = scan_with_finding()
    meta = ScanMeta(created_at="now", scan_items=[], agent_id="agent", agent_name="agent")
    store = SimpleNamespace(load_scan=lambda _: (scan, meta), get_scan_meta=lambda _: meta)
    ensure_job = Mock()
    monkeypatch.setattr(fp_review, "_ensure_fp_review_job_for_scan", ensure_job)
    monkeypatch.setattr(fp_review, "_resolve_scan_agent_id", AsyncMock(return_value="agent"))
    monkeypatch.setattr(fp_review, "_selected_feedback_entries", lambda *_: [])
    monkeypatch.setattr("backend.agents.runtime_updates.ensure_agent_accepting_tasks_async", AsyncMock())
    monkeypatch.setattr("backend.agents.directory.resolve_agent_id_connection_async", AsyncMock(
        return_value=None if failure == "connection" else ("agent", SimpleNamespace(agent_session_id="session")),
    ))
    monkeypatch.setattr("backend.review_notes.scan_review_notes_payload", AsyncMock(return_value=[]))
    monkeypatch.setattr("backend.agents.artifacts.create_agent_task_runtime_update_payload_async", AsyncMock(
        side_effect=RuntimeError("unavailable"),
    ))
    with use_runtime(BackendRuntime(store=store, store_runner=direct_store, publisher=Mock())):
        assert asyncio.run(fp_review._start_fp_review(
            "scan", "http://server", require_unresolved=True, raise_on_error=False,
        )) is None
    ensure_job.assert_not_called()


@pytest.mark.parametrize("automatic", [False, True])
def test_replayed_finding_cannot_retry_failed_fp_outside_round_budget(tmp_path, monkeypatch, automatic):
    store = SqliteScanStore(tmp_path / "replay.db")
    scan = scan_with_finding()
    scan.vulnerabilities[0].output_source.agent_session_id = "session"
    meta = ScanMeta(created_at="now", scan_items=[], auto_resume_enabled=automatic)
    store.save_scan(scan, meta)
    store.add_vulnerability("scan", scan.vulnerabilities[0])
    store.begin_scan_execution("scan", agent_id="agent", agent_session_id="session")
    store.create_fp_review_job("review", "scan", 1, "now")
    store.update_fp_review_job("review", status="error")
    ensured = Mock(return_value={"cancelled": True})
    monkeypatch.setattr("backend.scans.fp_review_policy._ensure_fp_review_job_for_scan", ensured)
    monkeypatch.setattr("backend.scans.report_records._fp_review_stage_titles", lambda *_: {})
    monkeypatch.setattr("backend.scans.report_records._scan_fp_result_map", lambda *_: {})
    monkeypatch.setattr("backend.scans.reporting._vuln_report_markdown", lambda *_args, **_kwargs: "rendered")
    try:
        with use_runtime(BackendRuntime(store=store, store_runner=direct_store, publisher=Mock())):
            response = asyncio.run(agent_report_vulnerability(
                "scan", scan.vulnerabilities[0], supports_fp_review_execution_revision=True,
            ))
        assert response["report_markdown"] == "rendered"
        assert "fp_review" not in response
        assert bool(ensured.call_count) is not automatic
        assert store.get_fp_review_by_scan("scan").status == FpReviewStatus.ERROR
    finally:
        store.close()


def test_finish_lease_fences_whole_report_and_initial_fp_handoff(tmp_path, monkeypatch):
    store = SqliteScanStore(tmp_path / "finish.db")
    scan = scan_with_finding()
    store.save_scan(scan, ScanMeta(created_at="now", scan_items=[], auto_resume_enabled=True))
    store.begin_scan_execution("scan", agent_id="agent", agent_session_id="session")
    body = AgentScanFinish(
        status="complete", vulnerabilities=[], total_candidates=1, processed_candidates=1,
        agent_session_id="session", execution_revision=1,
    )
    original = completion._persist_scan_finish
    notify = AsyncMock()
    monkeypatch.setattr(auto_resume, "notify_auto_resume", notify)

    async def scenario():
        entered, proceed = asyncio.Event(), asyncio.Event()

        async def paused(*args):
            entered.set()
            await proceed.wait()
            return await original(*args)

        async def start_review(*_args, **_kwargs):
            assert store.get_scan_auto_resume("scan")["finish_until"] > 0
            assert store.reserve_scan_resume("scan", expected_revision=1, automatic=True) is None

        monkeypatch.setattr(completion, "_persist_scan_finish", paused)
        monkeypatch.setattr(completion, "_start_completion_review", start_review)
        finishing = asyncio.create_task(completion.agent_finish_scan("scan", body, "http://server"))
        await entered.wait()
        assert store.reserve_scan_resume("scan", expected_revision=1, automatic=True) is None
        assert store.claim_scan_for_resume(
            "scan", expected_revision=1, processed_candidates=0, progress=0,
        ) is None
        with pytest.raises(ApplicationError, match="already finishing"):
            await completion.agent_finish_scan("scan", body, "http://server")
        proceed.set()
        assert await finishing == {"ok": True}
        assert store.get_scan_auto_resume("scan")["finish_until"] == 0
        token = store.reserve_scan_resume("scan", expected_revision=1, automatic=True)
        assert token
        assert store.claim_scan_for_resume(
            "scan", expected_revision=1, processed_candidates=0, progress=0, resume_round=token,
            agent_session_id="session",
        ) == 2
        with pytest.raises(ApplicationError, match="stale"):
            await completion.agent_finish_scan("scan", body, "http://server")
        assert store.load_scan("scan")[0].status == "pending"

    try:
        with use_runtime(BackendRuntime(store=store, store_runner=direct_store, publisher=Mock())):
            asyncio.run(scenario())
        notify.assert_awaited_once_with("scan", "http://server")
    finally:
        store.close()


def test_core_start_delivered_after_stop_is_stopped_again_without_rollback(monkeypatch):
    store = SimpleNamespace(
        mark_scan_resume_dispatch_started=lambda *_: True,
        get_scan_meta=lambda _: SimpleNamespace(execution_revision=9),
    )
    stop = AsyncMock(return_value={"still_active": False})
    monkeypatch.setattr("backend.agents.gateway.request_agent_scan_stop", stop)
    scan = scan_with_finding()
    plan = SimpleNamespace(resume_threat_analysis=False, retry_mining_engine_ids=[])
    checkpoint = SimpleNamespace(
        removed_processed_keys=[], previous_candidate_audits=[],
        previous_threat_analysis_run=None, previous_mining_engine_runs=[],
    )

    async def scenario():
        entered, deliver = asyncio.Event(), asyncio.Event()
        stopped = False

        async def send(*_args):
            entered.set()
            await deliver.wait()
            return True

        async def verify(*_args):
            if stopped:
                raise ApplicationError(409, "续扫已被停止")

        monkeypatch.setattr("backend.agents.gateway.send_agent_command", send)
        monkeypatch.setattr(auto_resume, "verify_resume_dispatch", verify)
        dispatch = asyncio.create_task(resume_execution.dispatch_resume(
            "scan", scan, User(user_id="owner", username="owner", role="user"),
            SimpleNamespace(agent_id="agent"), plan, checkpoint,
            {"type": "resume", "execution_revision": 9}, resume_round="round",
        ))
        await entered.wait()
        stopped = True
        deliver.set()
        with pytest.raises(ApplicationError, match="已被停止"):
            await dispatch

    with use_runtime(BackendRuntime(store=store, store_runner=direct_store, publisher=Mock())):
        asyncio.run(scenario())
    stop.assert_awaited_once_with("agent", "scan", execution_revision=9)


def test_fast_core_finish_is_not_published_as_pending_after_dispatch():
    completed = scan_with_finding()
    store = SimpleNamespace(load_scan_runtime=lambda _: (
        completed, ScanMeta(created_at="now", scan_items=[], execution_revision=9),
    ))
    publisher = Mock()
    plan = SimpleNamespace(
        incomplete_threat_tasks=[], candidate_payload=[], resume_threat_analysis=False,
        retry_mining_engine_ids=[],
    )
    checkpoint = SimpleNamespace(total_candidates=1, processed_offset=0, progress=0)
    with use_runtime(BackendRuntime(store=store, store_runner=direct_store, publisher=publisher)):
        asyncio.run(continuation._finish_resume(
            "scan", completed.model_copy(update={"status": "pending"}),
            SimpleNamespace(agent_id="agent"), plan, checkpoint, 9, 0, None, "http://server",
        ))
    payload = publisher.call_args.args[2]
    assert payload["status"] == "complete"
    assert payload["progress"] == 1
    assert payload["processed_candidates"] == 1
    assert payload["auto_resume_count"] == 0


@pytest.mark.parametrize("fp_only", [False, True])
def test_manual_resume_after_exhausted_resets_count_and_allows_three_more_auto_rounds(tmp_path, monkeypatch, fp_only):
    store = SqliteScanStore(tmp_path / "manual-reset.db")
    scan = (
        scan_with_finding().model_copy(update={"auto_resume_enabled": True})
        if fp_only else ScanStatus(
            scan_id="scan", status="error", auto_fp_review=False, auto_resume_enabled=True,
            progress=0.0, total_candidates=1, processed_candidates=0,
            static_analysis_done=True, vulnerabilities=[],
        )
    )
    meta = ScanMeta(
        created_at="now", scan_items=[], user_id="owner", agent_id="agent", agent_name="agent",
        project_path="/repo", auto_resume_enabled=True, auto_fp_review=fp_only,
    )
    store.save_scan(scan, meta)
    if fp_only:
        store.add_vulnerability("scan", scan.vulnerabilities[0])
        store.create_fp_review_job("review", "scan", 1, "now")
        store.update_fp_review_job("review", status="error")
    store.schedule_scan_auto_resume("scan", "http://server")
    for _ in range(3):
        token = store.reserve_scan_resume("scan", expected_revision=0, automatic=True, server_url="http://server")
        assert token
        assert store.finish_scan_resume_reservation("scan", token)
    assert store.reserve_scan_resume("scan", expected_revision=0, automatic=True, server_url="http://server") is None
    assert store.set_scan_auto_resume_state("scan", "exhausted", "已达自动续扫上限，可手动续扫")
    assert store.get_scan_auto_resume("scan")["auto_resume_count"] == 3
    assert store.get_scan_auto_resume("scan")["auto_resume_state"] == "exhausted"

    published = []
    runtime = BackendRuntime(
        store=store, store_runner=direct_store,
        publisher=lambda _sid, event, data: published.append((event, data)),
    )
    if fp_only:
        monkeypatch.setattr(fp_review, "preflight_fp_review", AsyncMock(side_effect=ApplicationError(400, "Agent 不在线")))
    else:
        monkeypatch.setattr(continuation, "_prepare_resume_agent", AsyncMock(side_effect=ApplicationError(400, "Agent 不在线")))
    with use_runtime(runtime):
        with pytest.raises(ApplicationError, match="Agent 不在线"):
            asyncio.run(continuation.resume_scan(
                "scan", "http://server", User(user_id="owner", username="owner", role="user"),
            ))
    assert store.get_scan_auto_resume("scan")["auto_resume_count"] == 3
    assert store.get_scan_auto_resume("scan")["auto_resume_state"] == "exhausted"

    if fp_only:
        monkeypatch.setattr(fp_review, "preflight_fp_review", AsyncMock())

        async def start_fp(*_args, **_kwargs):
            store.update_fp_review_job("review", status="running")
            return {"items_dispatched": True}

        monkeypatch.setattr(continuation, "_start_fp_review", start_fp)
    else:
        monkeypatch.setattr(continuation, "_prepare_resume_agent", AsyncMock(return_value=SimpleNamespace(
            agent_id="agent",
            agent=SimpleNamespace(
                name="agent", agent_session_id="session", protocol_version=1,
                supports_resume_manifest_pull=False,
            ),
        )))
        monkeypatch.setattr(continuation, "_resume_payload", AsyncMock(return_value={
            "type": "resume", "agent_runtime_update": None,
        }))
        monkeypatch.setattr("backend.agents.gateway.send_agent_command", AsyncMock(return_value=True))

    try:
        with use_runtime(runtime):
            response = asyncio.run(continuation.resume_scan(
                "scan", "http://server", User(user_id="owner", username="owner", role="user"),
            ))
        assert response.scan_id == "scan"
        record = store.get_scan_auto_resume("scan")
        assert record["auto_resume_count"] == 0
        assert record["auto_resume_state"] == "running"
        assert record["auto_resume_reason"] == ""
        if not fp_only:
            assert runtime.scans.running_scans["scan"].auto_resume_count == 0
            assert runtime.scans.running_scans["scan"].auto_resume_state == "running"
            assert runtime.scans.running_scans["scan"].auto_resume_reason == ""
        status_events = [data for event, data in published if event == "scan_status" and "auto_resume_count" in data]
        assert status_events
        assert all(data["auto_resume_count"] == 0 for data in status_events)
        assert status_events[-1]["auto_resume_state"] == "running"
        assert status_events[-1]["auto_resume_reason"] == ""

        if fp_only:
            store.update_fp_review_job("review", status="error")
            expected_rev = 0
        else:
            expected_rev = store.get_scan_meta("scan").execution_revision
            store.update_scan_progress("scan", status=ScanItemStatus.ERROR)
        for count in (1, 2, 3):
            token = store.reserve_scan_resume(
                "scan", expected_revision=expected_rev, automatic=True, server_url="http://server",
            )
            assert token
            assert store.get_scan_auto_resume("scan")["auto_resume_count"] == count
            assert store.finish_scan_resume_reservation("scan", token)
        assert store.reserve_scan_resume(
            "scan", expected_revision=expected_rev, automatic=True, server_url="http://server",
        ) is None
        assert store.get_scan_auto_resume("scan")["auto_resume_state"] == "exhausted"
    finally:
        store.close()
