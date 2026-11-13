import json
from pathlib import Path

import pytest

from backend.models import OpenCodePoolStatus, ScanMeta, ScanStatus
from backend.store.sqlite import SqliteScanStore


def make_store(tmp_path: Path):
    store = SqliteScanStore(tmp_path / "history.db")
    now = "2026-09-07T00:00:00+00:00"
    store.save_scan(
        ScanStatus(scan_id="s", project_id="p", scan_items=[], created_at=now,
                   status="auditing", progress=0, total_candidates=0,
                   processed_candidates=0, vulnerabilities=[]),
        ScanMeta(scan_items=[], created_at=now),
    )
    store._conn.execute(
        "INSERT INTO agents (agent_key, ip, machine_name, created_at, updated_at) VALUES ('a', '127.0.0.1', 'test', ?, ?)",
        (now, now),
    )
    store._conn.commit()
    return store


def task(index=1, revision=1):
    return {"task_id": f"t{index:06}", "scope_id": "s", "revision": revision,
            "outcome": "success", "prompt": "完整正文" * 1000,
            "session_events": [{"session_id": "session", "content": "原始轨迹"}]}


def receipt(store, value):
    return store.upsert_opencode_task_report(
        agent_key="a", scan_id="s", agent_session_id="a-session",
        task_id=value["task_id"], revision=value["revision"], task=value,
    )


def task_page_cursor(item):
    return {"before_sort_time": item["sort_time"], "before_task_id": item["task_id"]}


def test_live_detail_supports_legacy_request_ids_without_exposing_planned_tasks(tmp_path):
    store = make_store(tmp_path)
    legacy = {"scope_id": "s", "queued_tasks": [{"request_id": "queued", "prompt": "排队正文"}],
              "planned_tasks": [{"planned_task_id": "planned"}], "completed_tasks": [task()]}
    store._conn.execute("UPDATE scans SET history_version = 0, opencode_pool = ?", (json.dumps(legacy),))
    store._conn.commit()
    try:
        assert store.get_task_detail("s", "queued", revision=1) == {
            "request_id": "queued", "task_id": "queued", "prompt": "排队正文",
        }
        assert store.get_task_detail("s", "queued", revision=2) is None
        assert store.get_task_detail("s", "planned") is None
        assert store.get_task_detail("missing-scan", "queued") is None
        assert store.get_task_detail("s", task()["task_id"]) == task()
        assert store.get_task_detail("s", task()["task_id"], record_id="missing-record") is None
        store._conn.execute("UPDATE scans SET status = 'complete'")
        store._conn.commit()
        assert store.get_task_detail("s", "queued") is None
    finally:
        store.close()


def test_receipt_body_once_and_old_revision_does_not_replace_current(tmp_path):
    store = make_store(tmp_path)
    try:
        newer = task(revision=2)
        assert receipt(store, newer)
        assert not receipt(store, newer)
        assert receipt(store, task(revision=1))
        assert store.get_task_detail("s", newer["task_id"]) == newer
        assert store.get_task_detail("s", newer["task_id"], revision=1) == task()
        pool = store.get_opencode_pool_status("s")
        assert pool.completed_task_count == 1
        assert pool.completed_tasks == []
        assert len(store._conn.execute("SELECT opencode_pool FROM scans").fetchone()[0]) < 2000
        assert store._conn.execute("SELECT task_json FROM opencode_task_reports LIMIT 1").fetchone()[0] == "{}"
        assert store.load_scan("s")[0].opencode_pool.completed_tasks == [newer]
        with pytest.raises(ValueError, match="idempotency conflict"):
            receipt(store, {**newer, "prompt": "different"})
        assert store.get_task_detail("s", newer["task_id"]) == newer
    finally:
        store.close()


def test_legacy_snapshot_is_archived_and_heartbeat_cannot_erase_history(tmp_path):
    store = make_store(tmp_path)
    legacy = {"completed_tasks": [task()], "total_tasks": 4, "completed_task_count": 1,
              "token_usage": {"input_tokens": 500, "total_tokens": 500}}
    raw = json.dumps(legacy, ensure_ascii=False)
    store._conn.execute("UPDATE scans SET opencode_pool = ?, history_version = 0", (raw,))
    store._conn.commit()
    try:
        assert store.list_task_page("s")[0]["task_id"] == task()["task_id"]
        assert "prompt" not in store.list_task_page("s")[0]
        store.update_opencode_pool_status("s", OpenCodePoolStatus(scope_id="s"))
        assert store.load_scan("s")[0].opencode_pool.completed_tasks == [task()]
        archive = store._conn.execute("SELECT payload_json, verified_at FROM scan_legacy_payloads").fetchone()
        assert archive["payload_json"] == raw
        assert archive["verified_at"] == ""
        assert store.get_opencode_pool_status("s").total_tasks == 4
    finally:
        store.close()


def test_transaction_rolls_back_receipt_projection_and_counter_together(tmp_path):
    store = make_store(tmp_path)
    store._conn.execute("CREATE TRIGGER fail_receipt BEFORE INSERT ON opencode_task_reports BEGIN SELECT RAISE(ABORT, 'injected'); END")
    try:
        with pytest.raises(Exception, match="injected"):
            receipt(store, task())
        assert store._conn.execute("SELECT COUNT(*) FROM scan_task_versions").fetchone()[0] == 0
        assert store._conn.execute("SELECT COUNT(*) FROM scan_task_current").fetchone()[0] == 0
        assert store._conn.execute("SELECT stored_task_count FROM scans").fetchone()[0] == 0
    finally:
        store.close()


def test_duplicate_receipts_are_atomic_across_sqlite_connections(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    first = make_store(tmp_path)
    second = SqliteScanStore(tmp_path / "history.db")
    barrier = threading.Barrier(2)
    def write(store):
        barrier.wait()
        return receipt(store, task())
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            assert sorted(executor.map(write, (first, second))) == [False, True]
        assert first.get_opencode_pool_status("s").completed_task_count == 1
        assert first._conn.execute("SELECT COUNT(*) FROM opencode_task_reports").fetchone()[0] == 1
        assert not first._conn.in_transaction
        assert not second._conn.in_transaction
    finally:
        first.close()
        second.close()


def test_same_revision_legacy_conflict_keeps_both_bodies(tmp_path):
    store = make_store(tmp_path)
    try:
        original = task()
        partial = {**original, "session_events": []}
        store.update_opencode_pool_status("s", OpenCodePoolStatus(completed_tasks=[original]))
        store.update_opencode_pool_status("s", OpenCodePoolStatus(completed_tasks=[partial]))
        assert store.get_task_detail("s", original["task_id"]) == original
        assert store._conn.execute("SELECT COUNT(*) FROM scan_task_versions").fetchone()[0] == 2
        assert store.get_opencode_pool_status("s").completed_task_count == 1
    finally:
        store.close()


def test_task_page_has_no_bodies_and_stable_cursor(tmp_path):
    store = make_store(tmp_path)
    try:
        for i in range(107):
            receipt(store, task(i))
        first = store.list_task_page("s", limit=50)
        second = store.list_task_page("s", limit=50, **task_page_cursor(first[-1]))
        assert len(first) == len(second) == 50
        assert {x["task_id"] for x in first}.isdisjoint({x["task_id"] for x in second})
        assert len(json.dumps(first)) < 20000
        assert all("prompt" not in x and "session_events" not in x for x in first)
    finally:
        store.close()


@pytest.mark.parametrize("legacy", [False, True])
def test_task_name_filter_matches_exact_history_without_report_bodies(tmp_path, legacy):
    store = make_store(tmp_path)
    name = "candidate-audit-s-0"
    values = [
        {**task(1), "task_name": name},
        {**task(2), "task_name": name + "1"},
        {**task(3), "task_name": name},
    ]
    try:
        if legacy:
            store._conn.execute("UPDATE scans SET opencode_pool = ?, history_version = 0 WHERE scan_id = 's'",
                                (json.dumps({"completed_tasks": values}),))
            store._conn.commit()
        else:
            for value in values:
                receipt(store, value)
        first = store.list_task_page("s", task_name=name, limit=1)
        second = store.list_task_page("s", task_name=name, **task_page_cursor(first[0]))
        assert [item["task_id"] for item in first + second] == [values[2]["task_id"], values[0]["task_id"]]
        assert all("prompt" not in item and "session_events" not in item for item in first + second)
        assert store.get_task_detail("s", second[0]["task_id"])["prompt"] == values[0]["prompt"]
        assert store.list_task_page("s", task_name="candidate-audit-other-0") == []
    finally:
        store.close()


@pytest.mark.parametrize("fields, expected", [
    ({}, "vulnerability_mining"),
    ({"task_name": "candidate-audit-only-name"}, "vulnerability_mining"),
    ({"task_type": " AUDIT "}, "candidate_audit"),
    ({"task_type": "candidate_audit"}, "candidate_audit"),
    ({"task_type": "project_audit"}, "project_audit"),
    ({"task_type": "sensitive_clear"}, "sensitive_clear"),
    ({"task_type": "report_audit"}, "report_audit"),
    ({"task_type": "threat_analysis"}, "threat_analysis"),
    ({"task_type": "threat_audit"}, "threat_audit"),
    ({"task_type": "threat_pattern_audit"}, "threat_pattern_audit"),
    ({"task_type": "threat_pattern_iterative_audit"}, "threat_pattern_iterative_audit"),
    ({"task_type": "fp_review"}, "fp_review"),
    ({"task_type": "validation"}, "vulnerability_validation"),
    ({"task_type": "vulnerability_validation"}, "vulnerability_validation"),
    ({"task_type": "vulnerability_dedup"}, "vulnerability_dedup"),
    ({"task_type": "vulnerability_mining", "task_name": "candidate-audit-s-0"}, "candidate_audit"),
    ({"task_type": "vulnerability_mining", "task_name": "project-audit-s-0"}, "project_audit"),
    ({"task_type": "vulnerability_mining", "task_name": "threat-audit-s-0"}, "threat_audit"),
    ({"task_type": "vulnerability_mining", "task_name": "threat-pattern-audit-s-0"}, "threat_pattern_audit"),
    ({"task_type": "vulnerability_mining", "task_name": "threat-pattern-iterative-audit-s-0"}, "threat_pattern_iterative_audit"),
    ({"task_type": "vulnerability_mining", "task_name": "vulnerability-dedup-s-0"}, "vulnerability_dedup"),
    ({"task_type": "vulnerability_mining", "task_name": "other"}, "vulnerability_mining"),
    ({"task_type": "unrecognized"}, "other"),
    ({"task_type": "  ", "context": {"task_type": "audit"}}, "candidate_audit"),
    ({"context": {"task_type": "VULNERABILITY_MINING", "task_name": " CANDIDATE-AUDIT-S-0 "}}, "candidate_audit"),
    ({"task_type": "fp_review", "context": {"task_type": "audit"}}, "fp_review"),
])
def test_task_kind_legacy_sql_matches_classification(tmp_path, fields, expected):
    from backend.task_kinds import TASK_KINDS, task_kind
    store = make_store(tmp_path)
    value = {**task(), **fields}
    try:
        assert task_kind(value) == expected
        store._store_task_version_locked("s", value)
        # Simulate pre-projection immutable history, with context only in body.
        metadata = {key: item for key, item in value.items() if key not in {"prompt", "session_events", "context"}}
        store._conn.execute("UPDATE scan_task_versions SET metadata_json = ?", (json.dumps(metadata),))
        for kind in TASK_KINDS:
            rows = store.list_task_page("s", task_kind=kind)
            assert len(rows) == int(kind == expected)
            if rows:
                assert task_kind(rows[0]) == expected
                assert not {"context", "prompt", "session_events"} & rows[0].keys()
    finally:
        store.close()


def test_projected_task_pages_do_not_parse_report_bodies_or_read_other_scans(tmp_path):
    store = make_store(tmp_path)
    try:
        for value in [task(1), {**task(2), "task_type": "audit"}]:
            store._store_task_version_locked("s", value)
        # A malformed body would make json_extract fail if the lazy fallback ran.
        store._conn.execute("UPDATE scan_task_versions SET task_json = 'not JSON'")
        statements = []
        store._conn.set_trace_callback(statements.append)
        assert [row["task_id"] for row in store.list_task_page("s", task_kind="candidate_audit")] == [task(2)["task_id"]]
        assert [row["task_id"] for row in store.list_task_page("s", task_kind="vulnerability_mining")] == [task(1)["task_id"]]
        assert len(store.list_task_page("s", task_name="")) == 2
        assert store.list_task_page("s", task_name="  ") == []
        store._conn.set_trace_callback(None)
        query = next(statement for statement in statements if "FROM scan_task_current c" in statement)
        plan = [row["detail"] for row in store._conn.execute("EXPLAIN QUERY PLAN " + query)]
        assert any("SEARCH c USING INDEX" in step and "scan_id=?" in step for step in plan), plan
        assert any("SEARCH v USING INDEX" in step and "record_id=?" in step for step in plan), plan
        assert "COUNT(" not in query
        assert "LIMIT 50" in query
    finally:
        store.close()


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("direct_name", [None, "", "  "])
def test_old_context_task_name_and_kind_filters_agree(tmp_path, legacy, direct_name):
    store = make_store(tmp_path)
    name = " Candidate-Audit-Exact "
    value = {**task(), "task_type": "vulnerability_mining", "context": {"task_name": name}}
    if direct_name is not None:
        value["task_name"] = direct_name
    try:
        if legacy:
            store._conn.execute("UPDATE scans SET history_version = 0, opencode_pool = ?",
                                (json.dumps({"completed_tasks": [value]}),))
        else:
            store._store_task_version_locked("s", value)
            metadata = {k: v for k, v in value.items() if k not in {"prompt", "context", "session_events"}}
            store._conn.execute("UPDATE scan_task_versions SET metadata_json = ?", (json.dumps(metadata),))
        rows = store.list_task_page("s", task_kind="candidate_audit", task_name=name)
        assert len(rows) == 1
        assert rows[0]["task_name"] == name
        assert store.list_task_page("s", task_kind="candidate_audit", task_name=name.strip()) == []
        assert store.list_task_page("s", task_kind="candidate_audit", task_name="") == []
        assert store.list_task_page("s", task_kind="candidate_audit", task_name="  ") == []
    finally:
        store.close()
