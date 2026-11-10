"""Estimation SQL work depends on the current scan, not unrelated history."""
import json
from datetime import datetime, timezone

import pytest

from backend.models import OpenCodePoolStatus, ScanMeta, ScanStatus
from backend.scan_estimate import estimate_scan_progress_from_store
from backend.store.sqlite import SqliteScanStore


@pytest.fixture
def history_store(tmp_path):
    store = SqliteScanStore(tmp_path / "history.db")
    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    store._conn.execute(
        "INSERT INTO agents (agent_key, ip, machine_name, created_at, updated_at) "
        "VALUES ('agent', 'test', 'test', ?, ?)", (stamp, stamp),
    )
    store._conn.commit()
    for scan_id in ("current", "past"):
        store.save_scan(
            ScanStatus(scan_id=scan_id, status="auditing", total_candidates=0,
                       processed_candidates=0, progress=0, vulnerabilities=[]),
            ScanMeta(scan_items=[], created_at=stamp, scan_name=scan_id,
                     user_id="owner", agent_key="agent"),
        )
    store._conn.execute("UPDATE scans SET history_version = 1")
    store._conn.commit()
    try:
        yield store, now
    finally:
        store.close()


def _append_history(store, scan_id, stamp, start, end):
    rows = [
        (f"{scan_id}-record-{i}", scan_id, f"task-{i}", 1, json.dumps({
            "task_id": f"task-{i}", "revision": 1, "task_type": "threat_analysis",
            "outcome": "success", "duration_seconds": 10, "finished_at": stamp,
        }), "not JSON: task bodies must never be loaded", stamp)
        for i in range(start, end)
    ]
    store._conn.executemany(
        "INSERT INTO scan_task_versions (record_id, scan_id, task_id, revision, "
        "metadata_json, task_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", rows,
    )
    store._conn.executemany(
        "INSERT INTO scan_task_current (scan_id, task_id, revision, record_id) VALUES (?, ?, ?, ?)",
        [(scan_id, row[2], 1, row[0]) for row in rows],
    )
    store._conn.executemany(
        "INSERT INTO opencode_task_reports (agent_key, scan_id, agent_session_id, task_id, "
        "revision, task_json, created_at, record_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [("agent", scan_id, "session", row[2], 1, "not JSON", stamp, row[0]) for row in rows],
    )
    store._conn.commit()


def _measured_sql(store, operation):
    instructions = 0
    queries = []

    def progress():
        nonlocal instructions
        instructions += 1
        # Deterministically stop a regression that scans every unrelated task.
        return int(instructions > 2000000)

    store._conn.set_trace_callback(queries.append)
    store._conn.set_progress_handler(progress, 1)
    try:
        result = operation()
    finally:
        store._conn.set_progress_handler(None, 0)
        store._conn.set_trace_callback(None)
    return result, instructions, queries


def test_other_scan_history_growth_does_not_increase_estimation_reads(history_store):
    store, now = history_store
    _append_history(store, "current", now.isoformat(), 0, 1)
    scan = store.load_scan_runtime("current")[0].model_copy(update={
        "agent_online": True,
        "opencode_pool": OpenCodePoolStatus(
            queued_tasks=[{"task_id": "waiting", "task_type": "threat_analysis"}],
            models=[{"id": "model", "capability": "high", "max_concurrency": 1}],
        ),
    })
    previous = 0
    steps = []
    estimates = []
    for size in (1000, 10000):
        _append_history(store, "past", now.isoformat(), previous, size)
        result, instructions, queries = _measured_sql(
            store, lambda: estimate_scan_progress_from_store(store, scan, {}),
        )
        estimates.append(result.model_dump(exclude={"calculated_at"}))
        steps.append(instructions)
        assert not any("opencode_task_reports" in query for query in queries)
        assert all("'past'" not in query for query in queries)
        previous = size
    assert estimates[0] == estimates[1]
    assert estimates[0]["remaining_seconds"] == 10
    assert steps[1] <= steps[0] + 20


def test_ten_thousand_current_tasks_use_scan_index_with_linear_sql_work(history_store):
    store, now = history_store
    previous = 0
    steps = []
    for size in (1000, 10000):
        _append_history(store, "current", now.isoformat(), previous, size)
        tasks, instructions, queries = _measured_sql(
            store, lambda: store.get_scan_estimation_tasks("current"),
        )
        assert len(tasks) == size
        assert all("prompt" not in task for task in tasks)
        steps.append(instructions)
        previous = size
    assert steps[1] <= steps[0] * 12
    metadata_query = next(query for query in queries if "SELECT v.metadata_json" in query)
    plan = [row[3] for row in store._conn.execute("EXPLAIN QUERY PLAN " + metadata_query).fetchall()]
    assert any("SEARCH c USING INDEX sqlite_autoindex_scan_task_current_1 (scan_id=?)" in step for step in plan)
