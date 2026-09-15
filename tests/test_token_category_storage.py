import asyncio
import json
import os
import uuid
from unittest.mock import patch

import pytest

from backend.models import OpenCodePoolStatus, ScanMeta, ScanStatus
from backend.store.sqlite import SqliteScanStore
from task_agent.token_usage import TokenCounters, attribute_token_usage, merge_token_usages, token_usage_from_models


@pytest.fixture(params=["sqlite", "postgres"])
def storage(request, tmp_path):
    if request.param == "postgres":
        dsn = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN")
        if not dsn:
            pytest.skip("isolated PostgreSQL DSN not configured")
        from backend.store.postgres import PostgresScanStore
        store = PostgresScanStore(dsn, pool_min_size=1, pool_max_size=2)
    else:
        store = SqliteScanStore(tmp_path / "tokens.db")
    scan_id = "category-test-" + uuid.uuid4().hex
    store.save_scan(ScanStatus(scan_id=scan_id, project_id=scan_id, status="complete", progress=1,
                              total_candidates=0, processed_candidates=0, vulnerabilities=[]),
                    ScanMeta(scan_items=[], created_at="2026-09-15T00:00:00+00:00"))
    with store._lock:
        store._conn.execute("INSERT INTO agents (agent_key, ip, machine_name, created_at, updated_at) VALUES (?, '', '', '', '')", (scan_id,))
        store._conn.commit()
    try:
        yield store, scan_id
    finally:
        with store._lock:
            store._conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            store._conn.execute("DELETE FROM agents WHERE agent_key = ?", (scan_id,))
            store._conn.commit()
        store.close()


def usage(category=None, inputs=10, outputs=2, *, model="model-a", complete=True):
    value = token_usage_from_models({model: TokenCounters(inputs, outputs, 1, 3, 1)}, complete=complete)
    return attribute_token_usage(value, category) if category else value


def report(storage, value, *, session="old", stamp="2026-09-15T01:00:00+00:00", revision=0):
    store, scan_id = storage
    status = OpenCodePoolStatus(scope_id=scan_id, agent_session_id=session, updated_at=stamp,
                               execution_revision=revision, token_usage=value.as_dict())
    store.upsert_scan_opencode_token_usage(scan_id=scan_id, agent_session_id=session, status=status)
    status.token_usage = store.get_scan_opencode_token_usage(scan_id)
    store.persist_opencode_pool(scan_id, status)
    return status


def categories(storage):
    store, scan_id = storage
    return {item.category: item.total_tokens for item in store.get_scan_opencode_token_usage(scan_id).by_category}


def task(key, value, *, kind="vulnerability_mining", name="candidate-audit-s-0", revision=1, session=None):
    return {"task_id": key, "revision": revision, "task_type": kind, "task_name": name,
            "outcome": "success", "token_usage": value.as_dict(), "serve_session_id": session or "ses-" + key}


def receipt(storage, value, session="old"):
    store, scan_id = storage
    store.upsert_opencode_task_report(agent_key=scan_id, scan_id=scan_id, agent_session_id=session,
                                     task_id=value["task_id"], revision=value["revision"], task=value)


def backfill(storage, *, restart=False, batch_rows=2, batch_bytes=32 * 1024 * 1024):
    store, scan_id = storage
    for index in range(100):
        result = store.backfill_token_categories_batch(scan_id=scan_id, restart=restart and index == 0,
                                                       batch_rows=batch_rows, batch_bytes=batch_bytes)
        if result["complete"]:
            return result
    raise AssertionError("Backfill did not finish")


def test_snapshots_are_atomic_idempotent_monotonic_and_sum_across_processes(storage):
    initial = usage("threat_analysis")
    report(storage, initial)
    report(storage, initial)
    enlarged = merge_token_usages([initial, usage("fp_review", 20, complete=False)])
    report(storage, enlarged, stamp="2026-09-15T02:00:00+00:00")
    report(storage, initial, stamp="2026-09-15T03:00:00+00:00")  # Cannot reset the same process.
    report(storage, merge_token_usages([enlarged, initial]), stamp="2026-09-15T01:00:00+00:00")  # Late snapshot.
    report(storage, usage("static_candidate", 3, model="model-b"), session="new")
    assert categories(storage) == {"threat_analysis": 17, "fp_review": 27, "static_candidate": 10}
    store, scan_id = storage
    total = store.get_scan_opencode_token_usage(scan_id)
    assert total.total_tokens == 54 and not total.complete
    assert sum(item.total_tokens for item in total.by_model) == 54
    assert store.verify_token_categories(scan_id)["ok"]
    original = total.model_dump()
    with patch.object(store, "_persist_reported_token_categories_locked", side_effect=RuntimeError("injected")):
        with pytest.raises(RuntimeError, match="injected"):
            report(storage, merge_token_usages([enlarged, initial]), stamp="2026-09-15T04:00:00+00:00")
    assert store.get_scan_opencode_token_usage(scan_id).model_dump() == original


def test_history_deduplicates_receipts_and_versions_retaining_real_revisions(storage):
    one, two, missing = usage(), usage(inputs=4), usage(inputs=1)
    report(storage, merge_token_usages([one, two, missing]))
    first = task("a", one)
    receipt(storage, first)
    receipt(storage, first)
    receipt(storage, task("a", two, kind="fp_review", revision=2))
    store, scan_id = storage
    with store._lock:
        store._store_task_version_locked(scan_id, {**first, "prompt": "another historical copy"})
        store._archive_legacy_locked(scan_id, "opencode_pool", json.dumps({"agent_session_id": "old", "completed_tasks": [first]}))
        store._conn.commit()
    backfill(storage, batch_rows=1)
    assert categories(storage) == {"static_candidate": 17, "fp_review": 11, "uncategorized": 8}
    assert store.verify_token_categories(scan_id)["ok"]
    backfill(storage, restart=True)
    assert categories(storage) == {"static_candidate": 17, "fp_review": 11, "uncategorized": 8}


def test_native_usage_supersedes_history_without_cross_session_double_count(storage):
    report(storage, usage())
    receipt(storage, task("a", usage()))
    backfill(storage)
    assert categories(storage) == {"static_candidate": 17}
    report(storage, usage("threat_analysis"), stamp="2026-09-15T02:00:00+00:00")
    report(storage, usage("fp_review"), session="new")
    receipt(storage, task("b", usage(), kind="fp_review"), session="new")
    backfill(storage, restart=True)
    assert categories(storage) == {"threat_analysis": 17, "fp_review": 17}
    # Legacy heartbeat adds only an unknown balance; it cannot erase ownership.
    report(storage, usage(inputs=13), stamp="2026-09-15T03:00:00+00:00")
    assert categories(storage) == {"threat_analysis": 17, "fp_review": 17, "uncategorized": 3}


def test_delayed_pool_update_preserves_recovered_and_newer_usage_after_reopen(storage):
    store, scan_id = storage
    delayed = report(storage, usage())
    receipt(storage, task("a", usage()))
    backfill(storage)
    pool = store.persist_opencode_pool(scan_id, delayed)
    assert pool.token_usage.by_category[0].category == "static_candidate"
    report(storage, usage("fp_review", inputs=20), stamp="2026-09-15T02:00:00+00:00")
    pool = store.persist_opencode_pool(scan_id, delayed)
    assert pool.token_usage.total_tokens == 27
    assert pool.token_usage.by_category[0].category == "fp_review"
    if getattr(store, "distributed", False):
        peer = type(store)(store.dsn, pool_min_size=1, pool_max_size=2, initialize=False)
    else:
        from pathlib import Path
        peer = SqliteScanStore(Path(store._conn.execute("PRAGMA database_list").fetchone()["file"]), initialize=False)
    try:
        assert peer.get_opencode_pool_status(scan_id).token_usage == pool.token_usage
        assert peer.get_scan_opencode_token_usage(scan_id) == pool.token_usage
        assert peer.verify_token_categories(scan_id)["ok"]
    finally:
        peer.close()


def test_oversized_or_unattributable_history_keeps_original_total(storage):
    report(storage, usage(inputs=2))
    receipt(storage, task("too-large", usage(inputs=20)))
    receipt(storage, task("unknown-owner", usage(), kind="fp_review"), session="untracked-session")
    backfill(storage)
    assert categories(storage) == {"uncategorized": 9}


def test_legacy_snapshots_recover_only_dominating_nonoverlapping_session_usage(storage):
    store, scan_id = storage
    original = task("a", usage(inputs=5))
    partial = task("a", usage(inputs=2))
    overlaps = [task(key, usage(inputs=1), session="shared-session") for key in ("b", "c")]
    # Non-dominating snapshots cannot be stitched into a fictitious total.
    conflicts = [task("d", usage(inputs=3, outputs=1)), task("d", usage(inputs=1, outputs=3))]
    report(storage, usage(inputs=50))
    with store._lock:
        for value in (partial, original, *overlaps, *conflicts):
            store._store_task_version_locked(scan_id, value)
        store._archive_legacy_locked(scan_id, "opencode_pool", json.dumps({"agent_session_id": "old", "completed_tasks": [original, *overlaps, *conflicts]}))
        store._conn.commit()
    backfill(storage, batch_rows=1)
    assert categories(storage) == {"static_candidate": 12, "uncategorized": 45}


def test_reference_archives_recover_process_identity_and_resume_after_byte_limit(storage):
    store, scan_id = storage
    value = {**task("a", usage()), "prompt": "historical body" * 100}
    report(storage, usage())
    with store._lock:
        record_id, _ = store._store_task_version_locked(scan_id, value)
        manifest = {"base": {"agent_session_id": "old", "completed_tasks": [None]},
                    "refs": [{"kind": "task", "id": record_id, "path": ["completed_tasks", 0]}]}
        store._archive_legacy_locked(scan_id, "opencode_pool", json.dumps(manifest))
        store._conn.execute("UPDATE scan_legacy_payloads SET payload_format = 1 WHERE scan_id = ?", (scan_id,))
        store._conn.commit()
    with pytest.raises(ValueError, match="byte limit"):
        backfill(storage, batch_bytes=200)
    assert categories(storage) == {"uncategorized": 17}
    for _ in range(20):
        if store.backfill_token_categories_batch(scan_id=scan_id, batch_rows=1)["phase"] == "archives":
            break
    else:
        raise AssertionError("Recovery did not reach archived references")
    # A small manifest must not allow its referenced body to bypass the limit.
    with pytest.raises(ValueError, match="task reference exceeds batch byte limit"):
        store.backfill_token_categories_batch(scan_id=scan_id, batch_bytes=1000)
    backfill(storage)
    assert categories(storage) == {"static_candidate": 17}


def test_scan_deletion_removes_categories_and_recovery_projections(storage):
    report(storage, usage())
    receipt(storage, task("a", usage()))
    backfill(storage)
    store, scan_id = storage
    assert store.delete_scan(scan_id)
    for table in ("scan_opencode_category_token_usage", "scan_token_category_recovery"):
        assert store._conn.execute(f"SELECT COUNT(*) FROM {table} WHERE scan_id = ?", (scan_id,)).fetchone()[0] == 0


def test_agent_api_sse_and_persisted_snapshot_include_categories_and_reject_stale_execution(storage):
    from backend.api import agent as api
    store, scan_id = storage

    async def direct(store, operation, *args, **kwargs):
        return getattr(store, operation)(*args, **kwargs)

    async def run():
        with (patch.object(api, "get_scan_store", return_value=store), patch.object(api, "run_store_call", side_effect=direct),
              patch.object(store, "execution_matches", return_value=True), patch("backend.sse.publish") as publish):
            payload = OpenCodePoolStatus(scope_id=scan_id, agent_session_id="old", token_usage=usage("threat_analysis").as_dict())
            assert await api.agent_push_opencode_pool(scan_id, payload) == {"ok": True}
            event = publish.call_args.args[2]["opencode_pool"]
            assert event["token_usage"]["by_category"][0]["category"] == "threat_analysis"
            assert store.get_opencode_pool_status(scan_id).token_usage.by_category[0].total_tokens == 17
        with (patch.object(api, "get_scan_store", return_value=store), patch.object(api, "run_store_call", side_effect=direct),
              patch.object(store, "execution_matches", return_value=False)):
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as error:
                await api.agent_push_opencode_pool(scan_id, payload)
            assert error.value.status_code == 409

    asyncio.run(run())
