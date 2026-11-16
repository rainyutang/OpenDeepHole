"""Incremental audit reports and server-owned stop/resume settlement."""

import asyncio
import os
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from backend.application import ApplicationError, BackendRuntime, use_runtime
from backend.models import MiningEngineRunStatus, ScanMeta, ScanStatus, User
from backend.scans import lifecycle
from backend.scans.ingestion import artifacts, progress
from backend.sse import storage_notification
from backend.store.sqlite import SqliteScanStore


async def direct_store(store, operation, *args, **kwargs):
    return getattr(store, operation)(*args, **kwargs)


@pytest.fixture(params=["sqlite", "postgres"])
def env(request, tmp_path):
    if request.param == "postgres":
        dsn = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN")
        if not dsn:
            pytest.skip("PostgreSQL test DSN not configured")
        from backend.store.postgres import PostgresScanStore
        store = PostgresScanStore(dsn)
    else:
        store = SqliteScanStore(tmp_path / "reports.db")
    scan_id = uuid.uuid4().hex
    store.save_scan(
        ScanStatus(scan_id=scan_id, status="auditing", execution_revision=1,
                   progress=0, total_candidates=0, processed_candidates=0, vulnerabilities=[]),
        ScanMeta(scan_items=[], created_at="2026-11-16", user_id="owner",
                 execution_revision=1, execution_agent_session_id="session-a"),
    )
    with store._lock:
        store._conn.execute(
            "UPDATE scans SET execution_revision = 1, execution_agent_session_id = 'session-a' WHERE scan_id = ?",
            (scan_id,),
        )
        store._conn.commit()
    events = []
    runtime = BackendRuntime(store=store, store_runner=direct_store, publisher=lambda *args: events.append(args))
    with use_runtime(runtime):
        yield SimpleNamespace(store=store, scan_id=scan_id, events=events, runtime=runtime)
    with store._lock:
        store._conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        store._conn.commit()
    store.close()


def report(env, key="task", *, sequence=1, revision=1, **values):
    body = {
        "task_id": env.scan_id + "-" + key, "status": "pending",
        "execution_revision": revision, "report_agent_session_id": "session-a",
        "report_sequence": sequence, **values,
    }
    return asyncio.run(artifacts.agent_upsert_threat_pattern_audit_task(env.scan_id, body))


def stop(env, monkeypatch):
    monkeypatch.setattr(lifecycle, "_resolve_scan_agent_id", AsyncMock(return_value=None))
    return asyncio.run(lifecycle.stop_scan(env.scan_id, User(user_id="owner", username="owner", role="user")))


def test_stop_uses_persisted_tasks_and_no_full_scan_hydration(env, monkeypatch):
    for key, status in (("pending", "pending"), ("queued", "queued"), ("running", "running"), ("done", "completed")):
        report(env, key, status=status)
    env.events.clear()
    monkeypatch.setattr(env.store, "load_scan", lambda *_: pytest.fail("stop must not load all scan artifacts"))
    assert stop(env, monkeypatch)["main_scan_stopped"]
    tasks = {task.task_id.rsplit("-", 1)[-1]: task.status for task in env.store.list_threat_pattern_audit_tasks(env.scan_id)}
    assert tasks == {"pending": "cancelled", "queued": "cancelled", "running": "cancelled", "done": "completed"}
    notices = [data for _, event, data in env.events if event == "resource_changed"]
    assert notices == [{"resource": "threat-pattern-audit-tasks", "change": "task_status",
                        "engine_ids": ["threat_pattern_audit"], "execution_revision": 1}]
    assert env.store.get_scan_auto_resume(env.scan_id)["auto_resume_state"] == "paused"
    env.events.clear()
    stop(env, monkeypatch)
    assert not any(event == "resource_changed" for _, event, _ in env.events)


def test_late_reports_preserve_results_and_cannot_cancel_resumed_execution(env, monkeypatch):
    report(env, status="running")
    stop(env, monkeypatch)
    assert report(env, "late-registration")["task"]["status"] == "cancelled"
    assert report(env, sequence=2, status="running")["task"]["status"] == "cancelled"
    assert report(env, sequence=3, status="completed", result_vuln_indexes=[7])["task"]["status"] == "completed"
    assert report(env, sequence=4, status="cancelled")["task"]["status"] == "completed"
    revision = env.store.claim_scan_for_resume(env.scan_id, processed_candidates=0, progress=0,
                                               expected_revision=1, agent_session_id="session-a")
    assert revision == 2
    assert report(env, "late-registration", revision=2)["task"]["status"] == "pending"
    with pytest.raises(ApplicationError) as error:
        report(env, "late-registration", sequence=5, status="cancelled")
    assert error.value.status_code == 409
    assert env.store.get_threat_pattern_audit_task_detail(env.scan_id, env.scan_id + "-late-registration")["status"] == "pending"


def test_state_only_notifications_preserve_identity_and_skip_duplicate_events(env):
    report(env)
    env.events.clear()
    response = report(env, sequence=2, status="running")
    assert len(env.events) == 1
    event, notice = storage_notification(env.events[0][1], env.events[0][2])
    assert event == "resource_changed"
    assert notice["change"] == "task_status" and notice["execution_revision"] == 1
    assert notice["engine_ids"] == ["threat_pattern_audit"]
    assert storage_notification(event, notice) == (event, notice)
    assert report(env, sequence=2, status="running") == response
    assert len(env.events) == 1


def test_engine_failure_settles_only_its_tasks_and_rejects_old_execution(env, monkeypatch):
    report(env, "normal", status="running")
    report(env, "iterative", status="queued", engine_id="threat_pattern_iterative_audit")
    body = MiningEngineRunStatus(engine_id="threat_pattern_audit", engine_label="pattern",
                                 status="error", execution_revision=1, report_agent_session_id="session-a")
    monkeypatch.setattr(env.store, "load_scan", lambda *_: pytest.fail("engine reports must not hydrate all scan artifacts"))
    asyncio.run(progress.agent_report_mining_engine_run(env.scan_id, body))
    assert [data["execution_revision"] for _, event, data in env.events if event == "mining_engine_run"] == [1]
    statuses = {task.engine_id: task.status for task in env.store.list_threat_pattern_audit_tasks(env.scan_id)}
    assert statuses == {"threat_pattern_audit": "cancelled", "threat_pattern_iterative_audit": "queued"}
    with pytest.raises(ApplicationError) as error:
        asyncio.run(progress.agent_report_mining_engine_run(env.scan_id, body.model_copy(update={"report_agent_session_id": "old"})))
    assert error.value.status_code == 409
    assert env.store.get_threat_pattern_audit_task_detail(env.scan_id, env.scan_id + "-iterative")["status"] == "queued"


@pytest.mark.parametrize("identity", [
    {"execution_revision": 1},
    {"execution_revision": 1, "report_agent_session_id": " ", "report_sequence": 1},
    {"execution_revision": 1, "report_agent_session_id": "a", "report_sequence": True},
])
def test_partial_or_invalid_report_identity_is_rejected(env, identity):
    with pytest.raises(ApplicationError) as error:
        asyncio.run(artifacts.agent_upsert_threat_pattern_audit_task(env.scan_id, {"task_id": "bad", **identity}))
    assert error.value.status_code == 400
    assert not env.store.list_threat_pattern_audit_tasks(env.scan_id)
