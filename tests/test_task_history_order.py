import json
from datetime import datetime, timedelta, timezone

import pytest

from backend.models import OpenCodePoolStatus
from test_storage_history import make_store, task_page_cursor
from test_storage_postgres import DSN, pg_store  # noqa: F401 - shared isolated fixture


@pytest.fixture(params=["sqlite", "sqlite_legacy", "postgres", "postgres_legacy"])
def history_store(request, tmp_path):
    postgres = request.param.startswith("postgres")
    if postgres:
        if not DSN:
            pytest.skip("isolated PostgreSQL DSN not configured")
        store, scan_id = request.getfixturevalue("pg_store")
    else:
        store, scan_id = make_store(tmp_path), "s"

    def save(tasks):
        if request.param.endswith("legacy"):
            with store._lock:
                store._conn.execute("UPDATE scans SET history_version = 0, opencode_pool = ? WHERE scan_id = ?",
                                    (json.dumps({"completed_tasks": tasks}), scan_id))
                store._conn.commit()
        else:
            store.update_opencode_pool_status(scan_id, OpenCodePoolStatus(scope_id=scan_id, completed_tasks=tasks))

    yield store, scan_id, save
    if not postgres:
        store.close()


def all_pages(store, scan_id, **filters):
    cursor = {}
    items = []
    while page := store.list_task_page(scan_id, limit=50, **filters, **cursor):
        assert not {item["task_id"] for item in items} & {item["task_id"] for item in page}
        items.extend(page)
        cursor = task_page_cursor(page[-1])
    return items


def test_newest_execution_loaded_before_limit_independent_of_id_outcome_and_arrival(history_store):
    store, scan_id, save = history_store
    now = datetime(2026, 9, 8, tzinfo=timezone.utc)
    values = [{"task_id": f"task-{(index * 37) % 107:03}", "revision": 1,
               "outcome": ("success", "failure", "timeout", "cancelled")[index % 4],
               "finished_at": (now + timedelta(seconds=index)).isoformat(),
               "task_name": "match" if index % 3 else "other", "prompt": "large body" * 1000}
              for index in range(107)]
    save(list(reversed(values)))  # Old executions can arrive last after reconnect.
    expected = [value["task_id"] for value in reversed(values)]
    assert [item["task_id"] for item in store.list_task_page(scan_id)] == expected[:50]
    pages = all_pages(store, scan_id)
    assert [item["task_id"] for item in pages] == expected
    assert all("prompt" not in item for item in pages)
    assert [item["task_id"] for item in all_pages(store, scan_id, task_name="match")] == [
        value["task_id"] for value in reversed(values) if value["task_name"] == "match"]


def test_time_ties_cross_page_boundary_with_missing_and_invalid_dates_at_end(history_store):
    store, scan_id, save = history_store
    values = [{"task_id": f"tie-{i:03}", "finished_at": "2026-09-08T08:00:00+08:00"} for i in range(60)]
    values += [
        {"task_id": "a-microsecond-newer", "finished_at": "2026-09-08T00:00:00.000002Z"},
        {"task_id": "z-microsecond-older", "finished_at": "2026-09-08T00:00:00.000001+00:00"},
        {"task_id": "start-fallback", "finished_at": "invalid", "started_at": "2026-09-08T00:00:01"},
        {"task_id": "missing-end", "started_at": "2026-09-08T00:00:02Z"},
        {"task_id": "old", "finished_at": "2026-09-07T23:59:59.999999Z"},
        {"task_id": "no-date"},
        {"task_id": "bad-date", "finished_at": "2026-02-30T00:00:00Z", "started_at": "invalid"},
        {"task_id": "relative-date", "finished_at": "now"},
    ]
    save(values)
    pages = all_pages(store, scan_id)
    assert [item["task_id"] for item in pages] == [
        "missing-end", "start-fallback", "a-microsecond-newer", "z-microsecond-older",
        *[f"tie-{i:03}" for i in reversed(range(60))], "old", "relative-date", "no-date", "bad-date"]
    assert all(item["sort_time"] == "2026-09-08T00:00:00.000000Z" for item in pages[4:64])


def test_cursor_retains_boundary_when_its_task_gets_a_new_revision(history_store):
    store, scan_id, save = history_store
    values = [{"task_id": str(i), "revision": 1, "finished_at": f"2026-09-08T00:00:0{i}Z"} for i in range(4)]
    save(values)
    first = store.list_task_page(scan_id, limit=2)
    cursor = task_page_cursor(first[-1])
    values[2] = {**values[2], "revision": 2, "finished_at": "2026-09-08T00:00:05Z"}
    save(values)
    assert [item["task_id"] for item in store.list_task_page(scan_id, **cursor)] == ["1", "0"]
    refreshed = store.list_task_page(scan_id)
    assert refreshed[0]["task_id"] == "2"
    assert refreshed[0]["revision"] == 2
