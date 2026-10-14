"""Lifetime model accounting across resumes and Agent process restarts."""

import asyncio
import concurrent.futures
import os
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import pytest

from backend.models import AgentScanFinish, OpenCodePoolStatus, ScanItemStatus, ScanMeta, ScanStatus
from backend.store.sqlite import SqliteScanStore


@pytest.fixture(params=["sqlite", "postgres"])
def env(tmp_path, request):
    if request.param == "postgres":
        from backend.store.postgres import PostgresScanStore
        dsn = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN")
        if not dsn:
            pytest.skip("isolated PostgreSQL DSN not configured")
        def open_store():
            return PostgresScanStore(dsn, pool_min_size=1, pool_max_size=6)
    else:
        def open_store():
            return SqliteScanStore(tmp_path / "models.db")
    store = open_store()
    scan_id = "models-" + uuid4().hex
    now = "2026-10-14T00:00:00Z"
    store.save_scan(
        ScanStatus(scan_id=scan_id, project_id=scan_id, created_at=now, status="auditing",
                   scan_items=[], progress=0, total_candidates=0, processed_candidates=0, vulnerabilities=[]),
        ScanMeta(created_at=now, scan_items=[], scan_name=scan_id, auto_fp_review=False),
    )
    store._conn.execute(
        "INSERT INTO agents (agent_key, ip, machine_name, created_at, updated_at) VALUES (?, '127.0.0.1', 'test', ?, ?)",
        (scan_id, now, now),
    )
    store._conn.commit()
    value = SimpleNamespace(store=store, scan_id=scan_id, open_store=open_store)
    try:
        yield value
    finally:
        with value.store._lock:
            value.store._conn.execute("DELETE FROM scan_deletions WHERE scan_id = ?", (scan_id,))
            value.store._conn.execute("DELETE FROM fp_review_jobs WHERE scan_id = ?", (scan_id,))
            value.store._conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            value.store._conn.execute("DELETE FROM agents WHERE agent_key = ?", (scan_id,))
            value.store._conn.commit()
        value.store.close()


def snapshot(env, session="first", *, total=5, success=4, failure=1, timeout=0, cancelled=0,
             average=12, stamp="2026-10-14T00:00:01Z", model_id="m", model_fields=None, **fields):
    return OpenCodePoolStatus(
        scope_id=env.scan_id, agent_session_id=session,
        execution_revision=env.store.get_scan_identity(env.scan_id)["execution_revision"],
        updated_at=stamp,
        models=[] if total is None else [{
            "id": model_id, "model": "provider/" + model_id, "total": total,
            "success": success, "failure": failure, "timeout": timeout, "cancelled": cancelled,
            "avg_duration_seconds": average, "last_status": "success",
            "last_started_at": stamp, "last_finished_at": stamp, **(model_fields or {}),
        }], **fields,
    )


def write(env, *args, **kwargs):
    return env.store.persist_opencode_pool(env.scan_id, snapshot(env, *args, **kwargs))


def resume(env, session):
    env.store.update_scan_progress(env.scan_id, status=ScanItemStatus.CANCELLED)
    revision = env.store.get_scan_identity(env.scan_id)["execution_revision"]
    assert env.store.claim_scan_for_resume(
        env.scan_id, processed_candidates=0, progress=0, expected_revision=revision,
        agent_session_id=session,
    ) == revision + 1


def test_resume_restart_refresh_and_weighted_duration(env):
    first = write(env)
    assert first.models[0].total == 5
    assert write(env).updated_at == first.updated_at  # heartbeat is idempotent
    resume(env, "first")
    assert write(env).models[0].total == 5  # same process, new execution
    resume(env, "second")
    empty = write(env, "second", total=None, stamp="")
    assert empty.models[0].total == 5
    assert empty.global_running == empty.global_queued == 0
    assert not empty.models[0].enabled
    combined = write(env, "second", total=2, success=1, failure=0, timeout=1, average=20)
    model = combined.models[0]
    assert (model.total, model.success, model.failure, model.timeout) == (7, 5, 1, 1)
    assert model.avg_duration_seconds == pytest.approx(100 / 7)
    assert combined.updated_at > empty.updated_at
    env.store.close()
    env.store = env.open_store()
    assert env.store.load_scan_overview(env.scan_id)[0].opencode_pool.models[0].total == 7
    assert env.store.load_scan(env.scan_id)[0].opencode_pool.models[0].total == 7
    assert write(env, "second", total=2, success=1, failure=0, timeout=1, average=20).models[0].total == 7


def test_retries_count_attempts_without_duplicating_logical_history(env):
    write(env, total=1, success=0, failure=1, average=3)
    final = write(env, total=2, success=1, failure=1, average=5, stamp="2026-10-14T00:00:02Z",
                  completed_tasks=[{"task_id": "one-task", "outcome": "success"}])
    assert final.completed_task_count == 1
    assert (final.models[0].total, final.models[0].success, final.models[0].failure) == (2, 1, 1)


def test_late_snapshots_and_task_receipts_cannot_recount_aggregate(env):
    write(env)
    resume(env, "second")
    raw = snapshot(env, "second", total=2, success=2, failure=0)
    combined = env.store.persist_opencode_pool(env.scan_id, raw)
    assert combined.models[0].total == 7
    late = raw.model_copy(update={"updated_at": "2026-10-13T00:00:00Z", "models": []})
    assert env.store.persist_opencode_pool(env.scan_id, late).model_dump() == combined.model_dump()
    regressed = snapshot(env, "second", total=1, success=1, failure=0, stamp="2026-10-14T00:00:03Z")
    assert env.store.persist_opencode_pool(env.scan_id, regressed).models[0].total == 7
    old_execution = snapshot(env, "first", total=100, success=99)
    old_execution.execution_revision = 0
    assert env.store.persist_opencode_pool(env.scan_id, old_execution).models[0].total == 7
    task = {"task_id": "receipt", "revision": 1, "scope_id": env.scan_id, "outcome": "success"}
    assert env.store.persist_opencode_task_report(
        agent_key=env.scan_id, scan_id=env.scan_id, agent_session_id="second",
        task_id="receipt", revision=1, task=task,
    )
    assert env.store.get_opencode_pool_status(env.scan_id).models[0].total == 7
    assert env.store.persist_opencode_pool(env.scan_id, None, reported=False, terminal_scan=True).models[0].total == 7
    assert env.store.persist_opencode_pool(env.scan_id, None).models[0].total == 7
    assert env.store.persist_opencode_pool(env.scan_id, raw).models[0].total == 7


@pytest.mark.parametrize("session", ["first", "second"])
def test_legacy_baseline_is_saved_once_before_resume_identity_changes(env, session):
    legacy = snapshot(env)
    # Simulate a database created before the accounting tables existed.
    env.store._conn.execute("UPDATE scans SET opencode_pool = ? WHERE scan_id = ?", (legacy.model_dump_json(), env.scan_id))
    env.store._conn.commit()
    resume(env, session)
    count = 6 if session == "first" else 1
    current = write(env, session, total=count, success=count - (session == "first"),
                    failure=int(session == "first"), stamp="2026-10-14T00:00:02Z")
    assert current.models[0].total == 6
    resume(env, session)
    assert write(env, session, total=count, success=count - (session == "first"),
                 failure=int(session == "first"), stamp="2026-10-14T00:00:02Z").models[0].total == 6


def test_existing_database_creates_ledger_and_retains_old_snapshot(env):
    legacy = snapshot(env)
    env.store._conn.execute("UPDATE scans SET opencode_pool = ? WHERE scan_id = ?", (legacy.model_dump_json(), env.scan_id))
    # These tables did not exist in the previous backend version. All writes
    # in this test are confined to the fixture's disposable database.
    env.store._conn.execute("DROP TABLE scan_opencode_model_usage")
    env.store._conn.execute("DROP TABLE scan_opencode_pool_sources")
    env.store._conn.commit()
    env.store.close()
    env.store = env.open_store()
    assert env.store.get_opencode_pool_status(env.scan_id).models[0].total == 5
    resume(env, "second")
    assert write(env, "second", total=1, success=1, failure=0).models[0].total == 6


def test_historical_models_keep_usage_without_reviving_tasks_or_health(env):
    write(env, model_id="removed", global_running=1, global_queued=1,
          model_fields={"running": 1, "queued": 1, "active_tasks": [{"task_id": "old"}],
                        "health_penalty_level": 2, "effective_weight": 0.1,
                        "last_health_failure_at": "2026-10-14T00:00:01Z"},
          queued_tasks=[{"request_id": "old-queue"}], planned_tasks=[{"planned_task_id": "old-plan"}])
    resume(env, "second")
    current = write(env, "second", total=1, success=1, failure=0, global_running=1,
                    model_fields={"running": 1, "active_tasks": [{"task_id": "new"}]})
    models = {model.id: model for model in current.models}
    assert models["removed"].total == 5
    assert not models["removed"].enabled and not models["removed"].available
    assert models["removed"].running == models["removed"].queued == models["removed"].health_penalty_level == 0
    assert models["removed"].active_tasks == []
    assert models["removed"].last_health_failure_at == ""
    assert current.global_running == 1 and models["m"].active_tasks == [{"task_id": "new"}]
    assert current.queued_tasks == current.planned_tasks == []


def test_concurrent_snapshots_are_atomic_and_monotonic(env):
    write(env)
    resume(env, "second")
    values = [snapshot(env, "second", total=count, success=count, failure=0,
                       stamp=f"2026-10-14T00:00:{count:02}Z") for count in [3, 1, 2, 3, 2, 1]]
    other = env.open_store()
    try:
        def send(item):
            index, value = item
            return (env.store if index % 2 else other).persist_opencode_pool(env.scan_id, value)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(send, enumerate(values)))
        current = env.store.get_opencode_pool_status(env.scan_id)
        assert current.models[0].total == 8
        assert current.models[0].success == 7
    finally:
        other.close()


def test_pool_and_finish_events_use_lifetime_projection(env):
    from backend.api import agent as agent_api
    write(env)
    resume(env, "second")
    raw = snapshot(env, "second", total=2, success=2, failure=0)
    events = []
    with (
        patch("backend.api.agent.get_scan_store", return_value=env.store),
        patch("backend.api.scan.get_scan_store", return_value=env.store),
        patch("backend.sse.publish", side_effect=lambda scan, kind, data: events.append((kind, data))),
    ):
        asyncio.run(agent_api.agent_push_opencode_pool(env.scan_id, raw))
        assert events[-1][1]["opencode_pool"]["models"][0]["total"] == 7
        for final_snapshot in (raw, raw, None):
            asyncio.run(agent_api.agent_finish_scan(env.scan_id, AgentScanFinish(
                status="error", error_message="test end", vulnerabilities=[], total_candidates=0,
                processed_candidates=0, agent_session_id="second", execution_revision=raw.execution_revision,
                opencode_pool=final_snapshot,
            ), SimpleNamespace(base_url="http://testserver/")))
            status_events = [data for kind, data in events if kind == "scan_status"]
            assert status_events[-1]["opencode_pool"]["models"][0]["total"] == 7
            assert env.store.get_opencode_pool_status(env.scan_id).models[0].total == 7


def test_independent_review_resume_uses_the_same_scan_ledger(env):
    from backend.api import agent as agent_api
    from fastapi import HTTPException

    write(env)
    env.store.update_scan_progress(env.scan_id, status=ScanItemStatus.COMPLETE)
    review_id = "review-" + env.scan_id
    env.store.create_fp_review_job(review_id, env.scan_id, 2, "2026-10-14T00:00:00Z")
    revision = env.store.acquire_fp_review_execution(review_id, agent_session_id="second")
    env.store.update_fp_review_job(review_id, status="running")
    owner = {"kind": "fp_review", "id": review_id, "revision": revision}
    task = {"task_id": "review-running", "task_type": "fp_review", "execution_kind": "fp_review",
            "execution_id": review_id, "execution_revision": revision, "agent_session_id": "second"}
    raw = snapshot(env, "second", total=2, success=0, failure=0, cancelled=1,
                   global_running=1, execution_owner=owner,
                   model_fields={"running": 1, "active_tasks": [task]})
    with patch("backend.api.agent.get_scan_store", return_value=env.store), patch("backend.sse.publish"):
        asyncio.run(agent_api.agent_push_opencode_pool(env.scan_id, raw))
        current = env.store.get_opencode_pool_status(env.scan_id)
        assert current.models[0].total == 7
        assert current.models[0].cancelled == 1
        assert current.models[0].active_tasks == [task]
        assert current.global_running == 1
        # An independently restarted review contributes only its new process use.
        env.store.update_fp_review_job(review_id, status="error")
        next_revision = env.store.acquire_fp_review_execution(review_id, agent_session_id="third")
        env.store.update_fp_review_job(review_id, status="running")
        next_pool = snapshot(env, "third", total=1, success=1, failure=0,
                             execution_owner={**owner, "revision": next_revision})
        asyncio.run(agent_api.agent_push_opencode_pool(env.scan_id, next_pool))
        assert env.store.get_opencode_pool_status(env.scan_id).models[0].total == 8
        with pytest.raises(HTTPException) as rejected:
            asyncio.run(agent_api.agent_push_opencode_pool(env.scan_id, raw))
        assert rejected.value.status_code == 409
        assert env.store.get_opencode_pool_status(env.scan_id).models[0].total == 8


def test_new_scan_and_deletion_are_isolated(env):
    write(env)
    other_id = "other-" + env.scan_id
    original, meta = env.store.load_scan(env.scan_id)
    meta.scan_name = other_id
    env.store.save_scan(original.model_copy(update={"scan_id": other_id, "opencode_pool": None}), meta)
    try:
        assert env.store.get_opencode_pool_status(other_id).models == []
        env.store.update_scan_progress(env.scan_id, status=ScanItemStatus.COMPLETE)
        env.store.request_scan_deletion(env.scan_id)
        for _ in range(10):
            env.store.process_scan_deletions(scan_id=env.scan_id)
            if env.store.get_scan_identity(env.scan_id) is None:
                break
        assert env.store.get_scan_identity(env.scan_id) is None
        for table in ("scan_opencode_pool_sources", "scan_opencode_model_usage"):
            assert env.store._conn.execute(f"SELECT COUNT(*) AS n FROM {table} WHERE scan_id = ?", (env.scan_id,)).fetchone()["n"] == 0
    finally:
        env.store._conn.execute("DELETE FROM scans WHERE scan_id = ?", (other_id,))
        env.store._conn.commit()
