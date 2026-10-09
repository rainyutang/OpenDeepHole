"""Partial static results survive auditing, resume, API reporting and reload."""

import asyncio
import json
import os
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest

from backend.api import agent as agent_api
from backend.models import MiningEngineRunStatus, MiningEngineSelection, ScanMeta, ScanStatus
from backend.store.sqlite import SqliteScanStore
from deephole_client.config import AgentConfig
from deephole_client.scanner import _update_static_analysis_errors
from deephole_client.vulnerability_mining.engines.static_candidate import engine
from deephole_client.vulnerability_mining.engines.static_candidate.static_analysis.results import (
    load_summary, store_candidates,
)
from deephole_client.vulnerability_mining.sdk import MiningEngineRun


ERROR = {
    "checker_name": "loop_var_misuse", "checker_label": "循环变量误用",
    "error": "static analysis worker stopped without a result (exit code 3221225477, 0xC0000005 ACCESS_VIOLATION)",
    "exit_code": 3221225477,
}


def test_resume_replays_failure_without_rerunning_rules_or_renumbering_candidates(tmp_path, monkeypatch):
    candidates = [
        {"file": f"{name}.c", "line": 1, "function": "f", "description": "candidate", "vuln_type": rule}
        for name, rule in [("a", "npd"), ("b", "memleak"), ("c", "npd")]
    ]
    static = AsyncMock(return_value={
        "status": "partial", "candidates": candidates,
        "stats": {"checkers": {"npd": 2, "memleak": 1}}, "checker_errors": [ERROR],
    })
    audit = AsyncMock(side_effect=[
        {"status": "cancelled", "completed_candidates": 1},
        {"status": "success", "completed_candidates": 3},
        {"status": "success", "completed_candidates": 3},
    ])
    monkeypatch.setattr(engine, "run_static_analysis", static)
    monkeypatch.setattr(engine, "run_candidate_audit", audit)
    reporter = SimpleNamespace(
        report_candidates=AsyncMock(), send_static_progress=AsyncMock(),
        get_processed_candidate_indexes=AsyncMock(return_value={0}),
    )
    events = []

    async def output(event):
        events.append(event)

    kwargs = dict(
        project_path=tmp_path, code_scan_path=tmp_path, scan_dir=tmp_path,
        work_dir=tmp_path / "work", index_db_path=tmp_path / "index.db", scan_id="scan",
        config=AgentConfig(), reporter=reporter, checker_names=["npd", "memleak", "loop_var_misuse"],
        checker_packages=[], product="", feedback_entries=[], is_resume=False,
        retry_candidates=None, retry_total_candidates=None, retry_processed_offset=0,
        output=output, cancel_event=threading.Event(), report_vulnerabilities=AsyncMock(),
    )
    assert asyncio.run(engine.run(**kwargs))["status"] == "cancelled"
    before = audit.await_args.kwargs["candidates"]
    assert [(c["idx"], c["file"]) for c in before] == [(0, "b.c"), (1, "a.c"), (2, "c.c")]
    assert asyncio.run(engine.run(**{**kwargs, "is_resume": True}))["status"] == "success"
    after = audit.await_args.kwargs["candidates"]
    assert after == before[1:]
    static.assert_awaited_once()
    summaries = [e for e in events if e["kind"] == "checker_summary"]
    assert summaries[-1]["data"]["checker_errors"] == [ERROR]
    assert summaries[-1]["data"]["reused"] is True

    # A targeted retry uses platform-owned indexes and keeps the full cache.
    events.clear()
    assert asyncio.run(engine.run(**{
        **kwargs, "retry_candidates": [before[2]], "retry_total_candidates": 3,
        "retry_processed_offset": 2,
    }))["status"] == "success"
    assert audit.await_args.kwargs["candidates"] == [before[2]]
    assert reporter.report_candidates.await_count == 2
    assert json.loads((tmp_path / "candidates.json").read_text()) == candidates
    assert events[0]["data"]["checker_errors"] == [ERROR]


def test_legacy_candidate_cache_and_interrupted_replacement(tmp_path):
    path = tmp_path / "candidates.json"
    path.write_text("[]")
    assert load_summary(path) is None
    store_candidates(path, [], {"status": "partial", "checker_errors": [ERROR]})
    assert load_summary(path)["checker_errors"] == [ERROR]
    path.write_text('[{"file": "different.c"}]')
    with pytest.raises(ValueError, match="does not match"):
        load_summary(path)


def test_version_summaries_do_not_erase_other_versions_or_duplicate_errors():
    run = MiningEngineRun(engine_id="multi_version", engine_label="multi")

    def apply(kind, version, **data):
        return _update_static_analysis_errors(run, {
            "process": "static_analysis", "kind": kind, "data": {"version_name": version, **data},
        })

    assert apply("checker_error", "v1", **ERROR)
    assert apply("checker_error", "v2", **ERROR)
    assert not apply("checker_error", "v2", **ERROR)
    apply("checker_summary", "v1", checker_errors=[ERROR])
    assert {e["version_name"] for e in run.static_analysis_errors} == {"v1", "v2"}
    apply("checker_summary", "v1", checker_errors=[])
    assert [e["version_name"] for e in run.static_analysis_errors] == ["v2"]
    apply("checker_start", "v2", checker_name=ERROR["checker_name"])
    assert run.static_analysis_errors == []


@pytest.fixture(params=["sqlite", "postgres"])
def persisted_scan(request, tmp_path):
    if request.param == "postgres":
        dsn = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN")
        if not dsn:
            pytest.skip("isolated PostgreSQL DSN not configured")
        from backend.store.postgres import PostgresScanStore
        store = PostgresScanStore(dsn, pool_min_size=1, pool_max_size=4)
    else:
        store = SqliteScanStore(tmp_path / "scans.db")
    sid = "static-errors-" + uuid4().hex
    engines = [MiningEngineSelection(engine_id="static_candidate", engine_label="Static")]
    store.save_scan(
        ScanStatus(scan_id=sid, status="complete", progress=0, total_candidates=0,
                   processed_candidates=0, vulnerabilities=[], mining_engines=engines),
        ScanMeta(scan_items=[], created_at="2026-10-09T00:00:00+00:00", mining_engines=engines),
    )
    try:
        yield store, sid
    finally:
        store.delete_scan(sid)
        store.close()


def test_partial_failures_survive_api_sse_and_storage_reload(persisted_scan, monkeypatch):
    store, sid = persisted_scan

    async def direct_store(store, method, *args, **kwargs):
        return getattr(store, method)(*args, **kwargs)

    monkeypatch.setattr(agent_api, "get_scan_store", lambda: store)
    monkeypatch.setattr(agent_api, "run_store_call", direct_store)
    monkeypatch.setattr(agent_api, "_ensure_running_scan", AsyncMock(return_value=None))
    monkeypatch.setattr(agent_api, "_reconcile_candidate_progress", AsyncMock())
    publish = Mock()
    monkeypatch.setattr("backend.sse.publish", publish)
    run = MiningEngineRunStatus(
        engine_id="static_candidate", engine_label="Static", status="success",
        total_candidates=2, processed_candidates=2, static_analysis_errors=[ERROR],
    )
    response = asyncio.run(agent_api.agent_report_mining_engine_run(sid, run))
    expected = run.model_dump(mode="json")["static_analysis_errors"]
    assert response["run"]["static_analysis_errors"] == expected
    assert publish.call_args.args[1] == "mining_engine_run"
    assert publish.call_args.args[2]["runs"][0]["static_analysis_errors"] == expected
    for load in (store.load_scan, store.load_scan_runtime, store.load_scan_overview):
        loaded = load(sid)[0].mining_engine_runs[0]
        assert loaded.status == "success"
        assert loaded.model_dump(mode="json")["static_analysis_errors"] == expected
    # Older Agent snapshots remain valid and have no warning.
    assert MiningEngineRunStatus(engine_id="static_candidate", engine_label="Static").static_analysis_errors == []
