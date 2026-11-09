"""ETA samples use complete, lightweight, owner-scoped logical task history."""

import json
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from backend.models import OpenCodePoolStatus, ScanItemStatus, ScanMeta, ScanStatus, VulnerabilityValidation
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


def test_history_samples_use_actual_agent_owner_valid_duration_and_completion_window(sample_store):
    store, current, scan, report, now, _, other_agent, other_owner = sample_store
    past = scan("past")
    moved = scan("moved", key=other_agent)
    foreign = scan("foreign", user=other_owner)
    report(current, "self")
    report(past, "valid", logical_duration_seconds=30)
    report(moved, "actual-agent", finished_at=(now - timedelta(hours=1)).isoformat())
    report(foreign, "other-owner")
    report(past, "other-agent", key=other_agent)
    report(past, "revised", revision=1)
    report(past, "revised", revision=2, outcome="failure")
    report(past, "late-old-report", finished_at=(now - timedelta(days=31)).isoformat())
    report(past, "future", finished_at=(now + timedelta(days=1)).isoformat())
    report(past, "missing-date", finished_at="")
    for i, invalid in enumerate((None, 0, -1, "NaN", "Infinity", True, "bad")):
        report(past, f"invalid-{i}", duration_seconds=invalid)
    report(past, "invalid-logical", logical_duration_seconds=0)
    since = (now - timedelta(days=30)).isoformat()
    tasks = store.get_agent_estimation_samples(current, since=since)
    assert [task["task_id"] for task in tasks] == ["actual-agent", "valid"]
    assert all("prompt" not in task and "session_events" not in task for task in tasks)
    assert tasks[1]["logical_duration_seconds"] == 30
    assert store.get_agent_estimation_samples("missing", since=since) == []
    assert store.get_agent_estimation_samples(current, since="invalid") == []


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
def test_snapshot_only_history_uses_stable_agent_key_and_keeps_legacy_durations(sample_store, legacy):
    store, current, scan, _, now, _, other_agent, _ = sample_store
    past = scan("snapshot")
    foreign = scan("wrong-agent", key=other_agent)
    task = {"task_id": "legacy", "task_type": "candidate_audit", "outcome": "success", "duration_seconds": 12,
            "finished_at": (now - timedelta(days=2)).isoformat(), "prompt": "private body" * 1000}
    for scan_id in (past, foreign):
        if legacy:
            store._conn.execute("UPDATE scans SET history_version = 0, opencode_pool = ? WHERE scan_id = ?",
                                (json.dumps({"completed_tasks": [task]}), scan_id))
            store._conn.commit()
        else:
            store.update_opencode_pool_status(scan_id, OpenCodePoolStatus(completed_tasks=[task]))
    tasks = store.get_agent_estimation_samples(current, since=(now - timedelta(days=30)).isoformat())
    assert len(tasks) == 1 and tasks[0]["scope_id"] == past
    assert tasks[0]["duration_seconds"] == 12
    assert "prompt" not in tasks[0]


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
