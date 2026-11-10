"""ETA samples use complete, lightweight, scan-scoped logical task history."""

import json
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from backend.models import OpenCodePoolStatus, ScanItemStatus, ScanMeta, ScanStatus, VulnerabilityValidation
from backend.scan_estimate import estimate_scan_progress_from_store
from backend.store.sqlite import SqliteScanStore


@pytest.fixture(params=["sqlite", "postgres"])
def sample_store(request, tmp_path):
    if request.param == "postgres":
        from backend.store.postgres import PostgresScanStore
        dsn = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN")
        if not dsn:
            pytest.skip("isolated PostgreSQL DSN not configured")
        store = PostgresScanStore(dsn, pool_min_size=1, pool_max_size=2)
    else:
        store = SqliteScanStore(tmp_path / "estimation.db")
    prefix = uuid4().hex
    owner, other_owner = prefix + "-owner", prefix + "-other-owner"
    agent, other_agent = prefix + "-agent", prefix + "-other-agent"
    now = datetime.now(timezone.utc)
    scans = []
    for key in (agent, other_agent):
        store._conn.execute(
            "INSERT INTO agents (agent_key, ip, machine_name, created_at, updated_at) VALUES (?, '127.0.0.1', ?, ?, ?)",
            (key, key, now.isoformat(), now.isoformat()),
        )
    store._conn.commit()

    def scan(label, *, user=owner, key=agent):
        scan_id = prefix + "-" + label
        store.save_scan(
            ScanStatus(scan_id=scan_id, project_id=prefix, scan_items=[], created_at=now.isoformat(),
                       status="auditing", progress=0, total_candidates=0, processed_candidates=0, vulnerabilities=[]),
            ScanMeta(scan_items=[], created_at=now.isoformat(), scan_name=scan_id, user_id=user, agent_key=key),
        )
        scans.append(scan_id)
        return scan_id

    def report(scan_id, name, *, key=agent, **fields):
        task = {"task_id": name, "scope_id": scan_id, "revision": 1, "outcome": "success",
                "task_type": "threat_analysis", "duration_seconds": 10,
                "finished_at": (now - timedelta(days=1)).isoformat(),
                "prompt": "large private prompt" * 1000, "session_events": [{"content": "private trace"}],
                **fields}
        store.upsert_opencode_task_report(agent_key=key, scan_id=scan_id, agent_session_id="session",
                                         task_id=name, revision=task["revision"], task=task)
        return task

    current = scan("current")
    try:
        yield store, current, scan, report, now, agent, other_agent, other_owner
    finally:
        for scan_id in scans:
            store._conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        for key in (agent, other_agent):
            store._conn.execute("DELETE FROM agents WHERE agent_key = ?", (key,))
        store._conn.commit()
        store.close()


@pytest.mark.parametrize("legacy", [False, True])
def test_full_current_history_is_metadata_only_and_latest_revision(sample_store, legacy):
    store, current, _, report, *_ = sample_store
    tasks = [{"task_id": f"task-{i}", "revision": 1, "outcome": "success", "duration_seconds": i + 1,
              "logical_duration_seconds": i + 2, "task_type": "fp_review", "prompt": "secret" * 1000,
              "session_events": [{"content": "secret"}]} for i in range(105)]
    if legacy:
        store._conn.execute("UPDATE scans SET history_version = 0, opencode_pool = ? WHERE scan_id = ?",
                            (json.dumps({"completed_tasks": tasks}), current))
        store._conn.commit()
    else:
        store.update_opencode_pool_status(current, OpenCodePoolStatus(scope_id=current, completed_tasks=tasks))
        report(current, "task-0", revision=2, logical_duration_seconds=123)
        report(current, "task-0", revision=1, duration_seconds=1)
        # Large bodies must not be loaded, even indirectly by a compatibility helper.
        store._conn.execute("UPDATE scan_task_versions SET task_json = 'not JSON' WHERE scan_id = ?", (current,))
        store._conn.commit()
    result = store.get_scan_estimation_tasks(current)
    assert len(result) == 105
    assert all("prompt" not in task and "session_events" not in task for task in result)
    first = next(task for task in result if task["task_id"] == "task-0")
    assert first["logical_duration_seconds"] == (2 if legacy else 123)
    assert first["revision"] == (1 if legacy else 2)
    assert store.get_scan_estimation_tasks("missing") == []


def _queued_scan(store, scan_id, task_type="threat_analysis"):
    return store.load_scan_runtime(scan_id)[0].model_copy(update={
        "agent_online": True,
        "opencode_pool": OpenCodePoolStatus(
            queued_tasks=[{"task_id": "waiting", "task_type": task_type}],
            models=[{"id": "model", "enabled": True, "available": True,
                     "capability": "high", "max_concurrency": 1}],
        ),
    })


@pytest.mark.parametrize("local_duration", [None, 10])
def test_estimate_uses_only_current_scan_even_with_same_agent_history(sample_store, local_duration):
    store, current, scan, report, now, *_ = sample_store
    if local_duration is not None:
        report(current, "local", duration_seconds=local_duration)
    current_scan = _queued_scan(store, current)
    before = estimate_scan_progress_from_store(store, current_scan, {})
    past = scan("same-agent-history")
    store.update_opencode_pool_status(past, OpenCodePoolStatus(completed_tasks=[
        {"task_id": f"foreign-{i}", "task_type": "threat_analysis", "outcome": "success",
         "duration_seconds": 10000, "finished_at": now.isoformat()}
        for i in range(1000)
    ]))
    after = estimate_scan_progress_from_store(store, current_scan, {})
    assert after.model_dump(exclude={"calculated_at"}) == before.model_dump(exclude={"calculated_at"})
    assert after.state == ("estimating" if local_duration is None else "ready")
    assert after.progress == (0 if local_duration is None else 0.5)
    assert after.remaining_seconds == local_duration


def test_legacy_tasks_without_ids_are_distinct_without_loading_bodies(sample_store):
    store, current, *_ = sample_store
    tasks = [{"outcome": "success", "duration_seconds": 12, "prompt": body} for body in ("first", "second")]
    store._conn.execute("UPDATE scans SET history_version = 0, opencode_pool = ? WHERE scan_id = ?",
                        (json.dumps({"completed_tasks": tasks}), current))
    store._conn.commit()
    result = store.get_scan_estimation_tasks(current)
    assert len(result) == 2
    assert len({task["task_id"] for task in result}) == 2
    assert all("prompt" not in task for task in result)


@pytest.mark.parametrize("legacy", [False, True])
def test_current_snapshot_durations_are_used_without_other_scan_snapshots(sample_store, legacy):
    store, current, scan, _, now, *_ = sample_store
    past = scan("same-agent-snapshot")
    for scan_id, duration in ((current, 12), (past, 12000)):
        task = {"task_id": "snapshot-task", "task_type": "candidate_audit", "outcome": "success",
                "duration_seconds": duration, "finished_at": (now - timedelta(days=2)).isoformat(),
                "prompt": "private body" * 1000}
        if legacy:
            store._conn.execute("UPDATE scans SET history_version = 0, opencode_pool = ? WHERE scan_id = ?",
                                (json.dumps({"completed_tasks": [task]}), scan_id))
            store._conn.commit()
        else:
            store.update_opencode_pool_status(scan_id, OpenCodePoolStatus(completed_tasks=[task]))
    result = estimate_scan_progress_from_store(store, _queued_scan(store, current, "candidate_audit"), {})
    assert result.state == "ready"
    assert result.progress == 0.5
    assert result.remaining_seconds == 12


def test_terminal_scan_keeps_only_current_independent_validation_tasks(sample_store):
    store, current, *_ = sample_store
    store.upsert_vulnerability_validation(current, VulnerabilityValidation(vuln_index=4, status="pending"))
    revision = store.begin_validation_execution(current, 4, agent_session_id="validation-session")
    owner = {"execution_kind": "vulnerability_validation", "execution_id": f"{current}:4",
             "execution_revision": revision, "agent_session_id": "validation-session"}
    pool = OpenCodePoolStatus(scope_id=current, global_running=2, models=[{"id": "m", "running": 2,
        "active_tasks": [{**owner, "task_id": "validation"}, {"task_id": "scan", "execution_kind": "scan"}]}],
        queued_tasks=[{**owner, "task_id": "queued"}], planned_tasks=[{**owner, "planned_task_id": "planned"}])
    store.persist_opencode_pool(current, pool, reported=False)
    store.update_scan_progress(current, status=ScanItemStatus.COMPLETE)
    actual = store.get_opencode_pool_status(current)
    assert actual.global_running == actual.global_queued == 1
    assert [task["task_id"] for task in actual.models[0].active_tasks] == ["validation"]
    assert len(actual.planned_tasks) == 1
    store.begin_validation_execution(current, 4, agent_session_id="replacement-session")
    assert store.get_opencode_pool_status(current).global_running == 0
    assert store.get_opencode_pool_status(current).planned_tasks == []
