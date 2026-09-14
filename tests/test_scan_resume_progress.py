"""Candidate progress across completed-scan retries and worker-local caches."""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI

from backend import report_routes, sse
from backend.api import agent as agent_api, scan as scan_api
from backend.models import (
    AgentInfo, Candidate, MiningEngineRunStatus, MiningEngineSelection,
    OpenCodePoolStatus, ScanEvent, ScanItemStatus, ScanMeta, ScanStatus, User, Vulnerability,
)
from backend.store.sqlite import SqliteScanStore


async def direct_store(store, operation, *args, **kwargs):
    return (getattr(store, operation) if isinstance(operation, str) else operation)(*args, **kwargs)


def result(index, failed=False):
    return Vulnerability(
        file=f"{index}.c", line=1, function="f", vuln_type="npd", severity="low",
        description="result", ai_verdict="failed" if failed else "false_positive",
        confirmed=False, audit_index=index,
    )


@pytest.fixture(params=["sqlite", "postgres"])
def progress_env(request, tmp_path, monkeypatch):
    if request.param == "postgres":
        dsn = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN")
        if not dsn:
            pytest.skip("isolated PostgreSQL DSN not configured")
        from backend.store.postgres import PostgresScanStore
        store = PostgresScanStore(dsn, pool_min_size=1, pool_max_size=4)
    else:
        store = SqliteScanStore(tmp_path / "scans.db")
    sid = "progress-" + uuid4().hex
    engines = [MiningEngineSelection(engine_id="static_candidate", engine_label="static")]
    now = datetime.now(timezone.utc).isoformat()
    store.save_scan(
        ScanStatus(scan_id=sid, status="complete", progress=1, total_candidates=3,
                   processed_candidates=3, vulnerabilities=[], static_analysis_done=True,
                   mining_engines=engines, mining_engine_runs=[MiningEngineRunStatus(
                       engine_id="static_candidate", engine_label="static", status="success",
                   )]),
        ScanMeta(scan_items=[], created_at=now, project_path="/repo", scan_name=sid,
                 agent_id="agent", agent_name="agent", user_id="user", mining_engines=engines),
    )
    store.replace_scan_candidates(sid, [Candidate(
        file=f"{i}.c", line=1, function="f", vuln_type="npd", description="candidate",
    ) for i in range(3)])
    for i in range(3):
        store.update_scan_candidate_audit(
            sid, i, state="success" if i == 0 else "failed", result=result(i, i > 0),
            vulnerability_idx=None, dedup_decision={},
        )
    store.begin_scan_execution(sid, agent_id="agent", agent_session_id="session")
    stale = store.load_scan(sid)[0]
    stale.status = "auditing"
    cache = {}
    for module in (agent_api, scan_api, report_routes):
        monkeypatch.setattr(module, "get_scan_store", lambda: store)
        monkeypatch.setattr(module, "run_store_call", direct_store)
    for module in (agent_api, scan_api):
        monkeypatch.setattr(module, "_running_scans", cache)
        monkeypatch.setattr(module, "_scan_owners", {})
    agent = AgentInfo(agent_id="agent", name="agent", ip="127.0.0.1", user_id="user",
                      last_seen=now, agent_session_id="session", protocol_version=1)
    monkeypatch.setattr(agent_api, "_registered_agents", {"agent": agent})
    monkeypatch.setattr(agent_api, "ensure_agent_accepting_tasks_async", AsyncMock())
    monkeypatch.setattr(agent_api, "get_scan_agent_config_async", AsyncMock(return_value=object()))
    monkeypatch.setattr(agent_api, "agent_config_has_explicit_model", lambda _: True)
    monkeypatch.setattr(agent_api, "agent_explicit_model_ids", lambda _: ["provider/model"])
    monkeypatch.setattr(agent_api, "create_agent_task_runtime_update_payload_async", AsyncMock(return_value=None))
    monkeypatch.setattr(agent_api, "request_agent_scan_stop", AsyncMock(return_value={"still_active": False}))
    monkeypatch.setattr(agent_api, "send_agent_command", AsyncMock(return_value=True))
    monkeypatch.setattr(scan_api, "_checker_packages_for", lambda _: [])
    monkeypatch.setattr(scan_api, "_start_fp_review", AsyncMock())
    monkeypatch.setattr(sse, "publish", Mock())
    app = FastAPI()
    app.include_router(agent_api.router)
    user = User(user_id="user", username="user", role="admin")

    async def resume():
        return await scan_api.resume_scan(sid, SimpleNamespace(base_url="http://server/"), user)

    try:
        yield SimpleNamespace(store=store, sid=sid, stale=stale, cache=cache,
                              resume=resume, app=app, user=user)
    finally:
        with store._lock:
            store._conn.execute("DELETE FROM scans WHERE scan_id = ?", (sid,))
            store._conn.commit()
        store.close()


def test_completed_scan_retry_counts_results_and_ignores_pool_cache(progress_env):
    env = progress_env

    async def run():
        await env.resume()
        resumed = env.store.load_scan(env.sid)[0]
        assert (resumed.processed_candidates, resumed.total_candidates) == (1, 3)
        assert resumed.execution_revision == 2
        assert [c.audit_state for c in env.store.list_scan_candidates(env.sid)] == ["success", "pending", "pending"]
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=env.app), base_url="http://server") as client:
            for index, failed in [(1, False), (2, True), (2, True)]:
                response = await client.post(f"/api/agent/scan/{env.sid}/candidate-audit", json={
                    "candidate_idx": index, "state": "failed" if failed else "success",
                    "result": result(index, failed).model_dump(mode="json"),
                    "completed_candidates": index + 1, "total_candidates": 3,
                    "agent_session_id": "session", "execution_revision": 2,
                })
                assert response.status_code == 200, response.text
                assert response.json()["processed"] == index + 1
                # Simulate a second worker that last saw the old complete run.
                env.cache[env.sid] = env.stale.model_copy(deep=True)
                sse.publish.reset_mock()
                await agent_api.agent_push_opencode_pool(env.sid, OpenCodePoolStatus(
                    execution_revision=2, agent_session_id="session", global_running=1,
                ))
                event = sse.publish.call_args.args[2]
                assert "processed_candidates" not in event
                assert "total_candidates" not in event
                assert "progress" not in event
                assert "status" not in event
                assert event["execution_revision"] == 2
                persisted = env.store.load_scan(env.sid)[0]
                assert (persisted.processed_candidates, persisted.total_candidates) == (index + 1, 3)
            response = await client.post(f"/api/agent/scan/{env.sid}/finish", json={
                "status": "complete", "vulnerabilities": [], "total_candidates": 3,
                "processed_candidates": 3, "agent_session_id": "session", "execution_revision": 2,
            })
            assert response.status_code == 200, response.text
        env.cache.clear()
        overview = await scan_api.get_scan_overview_v2(env.sid, current_user=env.user)
        assert overview.processed_candidates == overview.total_candidates == 3
        assert overview.execution_revision == 2
        assert overview.detail_counts.candidate_audit_failed == 1
        await env.resume()
        resumed = env.store.load_scan(env.sid)[0]
        assert (resumed.processed_candidates, resumed.total_candidates) == (2, 3)
        assert resumed.execution_revision == 3

    asyncio.run(run())


@pytest.mark.parametrize("source", ["pool", "log", "index", "static"])
def test_auxiliary_events_never_republish_candidate_progress(progress_env, source):
    env = progress_env

    async def run():
        await env.resume()
        env.cache[env.sid] = env.stale.model_copy(deep=True)
        sse.publish.reset_mock()
        if source == "pool":
            await agent_api.agent_push_opencode_pool(env.sid, OpenCodePoolStatus(
                execution_revision=2, agent_session_id="session",
            ))
        elif source == "log":
            await agent_api.agent_scan_event(env.sid, ScanEvent.create("candidate_audit", "candidate finished"))
        elif source == "index":
            await agent_api.agent_push_index_status(env.sid, agent_api._IndexStatusBody(
                status="done", parsed_files=5, total_files=5,
            ))
        else:
            await agent_api.agent_push_static_progress(env.sid, agent_api._StaticProgressBody(done=True))
        for call in sse.publish.call_args_list:
            if call.args[1] == "scan_status":
                assert not {"processed_candidates", "total_candidates", "progress"} & call.args[2].keys()

    asyncio.run(run())


def test_distributed_cache_refresh_and_reconciliation_use_current_execution(progress_env, monkeypatch):
    env = progress_env

    async def run():
        await env.resume()
        env.cache[env.sid] = env.stale.model_copy(deep=True)
        # Exercise the worker-cache path even with the lightweight SQLite fixture.
        monkeypatch.setattr(env.store, "distributed", True, raising=False)
        current = await agent_api._ensure_running_scan(env.sid)
        assert current.execution_revision == 2
        assert current.processed_candidates == 1
        assert current.status == "pending"
        current.candidates = env.store.list_scan_candidates(env.sid)
        refreshed = await agent_api._ensure_running_scan(env.sid)
        assert refreshed.candidates == current.candidates
        env.cache[env.sid] = env.stale.model_copy(deep=True)
        await agent_api._reconcile_candidate_progress(env.sid)
        event = sse.publish.call_args.args[2]
        assert (event["processed_candidates"], event["total_candidates"]) == (1, 3)
        assert event["status"] == "pending"
        assert event["execution_revision"] == 2
        env.store.update_scan_progress(env.sid, status=ScanItemStatus.COMPLETE)
        assert await agent_api._ensure_running_scan(env.sid) is None
        assert env.sid not in env.cache

    asyncio.run(run())
