"""Resume through the real candidate engine, audit runner, pool and HTTP reports."""
from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from backend.api import agent as agent_api, scan as scan_api
from backend.models import Candidate, MiningEngineRunStatus
from deephole_client.config import AgentConfig
from deephole_client.reporter import Reporter
from deephole_client.vulnerability_mining.engines.static_candidate import engine
from deephole_client.vulnerability_mining.engines.static_candidate.candidate_audit import runner
from task_agent import OpenCodeResult
from task_agent.model_pool import acquire_model_lease, model_pool_snapshot, release_model_lease
from task_agent.task_service import bind_opencode_execution_context, get_opencode_execution_context

from test_opencode_model_pool import _reset_model_pool  # noqa: F401 - shared isolated pool fixture
from test_scan_resume_progress import progress_env, result  # noqa: F401 - shared SQLite/PostgreSQL fixture


@pytest.mark.parametrize("unfinished_state", ["failed", "queued"])
def test_resume_executes_only_unfinished_candidates_through_real_pool(
    progress_env, tmp_path, monkeypatch, unfinished_state,
):
    env = progress_env
    project = tmp_path / "project"
    project.mkdir()
    index_path = project / "code_index.db"
    index_path.touch()
    for index in (123, 124):
        (project / f"{index}.c").write_text("void f(void) {}\n")
    scan, meta = env.store.load_scan(env.sid)
    scan.project_path = meta.project_path = str(project)
    scan.code_scan_path = meta.code_scan_path = str(project)
    scan.code_scan_paths = meta.code_scan_paths = [str(project)]
    scan.scan_items = meta.scan_items = ["npd"]
    scan.total_candidates = 125
    env.store.save_scan(scan, meta)
    env.store.replace_scan_candidates(env.sid, [Candidate(
        file=f"{index}.c", line=1, function="f", vuln_type="npd", description="candidate",
    ) for index in range(125)])
    for index in range(125):
        state = "success" if index < 123 else unfinished_state
        env.store.update_scan_candidate_audit(
            env.sid, index, state=state,
            result=None if state == "queued" else result(index, state == "failed"),
            vulnerability_idx=None, dedup_decision={},
        )
    previous_successes = env.store.list_scan_candidates(env.sid)[:123]
    config = AgentConfig()
    config.pattern_filter.enabled = False
    pool_config = SimpleNamespace(models=[{
        "id": "test", "model": "test/model", "capability": "high", "max_concurrency": 1,
    }])
    config.opencode.models = pool_config.models
    model_calls = []

    async def run():
        await env.resume()
        payload = agent_api.send_agent_command.await_args.args[1]
        assert payload["retry_mining_engine_ids"] == ["static_candidate"]
        assert [item["idx"] for item in payload["retry_candidates"]] == [123, 124]
        assert payload["retry_total_candidates"] == 125
        assert payload["retry_processed_offset"] == 123
        reporter = Reporter("http://server")
        reporter.agent_session_id = "session"
        reporter.set_scan_execution(env.sid, payload["execution_revision"])
        await reporter._client.aclose()
        reporter._client = httpx.AsyncClient(transport=httpx.ASGITransport(app=env.app))
        monkeypatch.setattr(reporter, "report_candidates", AsyncMock(
            side_effect=AssertionError("targeted resume must preserve the full candidate set"),
        ))

        async def model_task(**kwargs):
            index = int(kwargs["task_name"].rsplit("-", 1)[1])
            model_calls.append(index)
            context = get_opencode_execution_context()
            assert context.task_metadata["planned_task_id"]
            assert context.skill_paths
            assert context.execution_kind == "scan" and context.execution_id == env.sid
            snapshot = model_pool_snapshot(env.sid)
            assert len(snapshot["planned_tasks"]) == 125 - index
            lease = await acquire_model_lease(
                pool_config, stats_scope_id=env.sid, required_capability="high",
                task_context={**context.task_metadata, "task_name": kwargs["task_name"],
                              "task_type": kwargs["task_type"],
                              "execution_kind": context.execution_kind,
                              "execution_id": context.execution_id},
            )
            try:
                await kwargs["lease_state_callback"]("running")
                snapshot = model_pool_snapshot(env.sid)
                assert len(snapshot["planned_tasks"]) == 124 - index
                assert snapshot["global_running"] == 1
                assert not snapshot["queued_tasks"]
                assert await reporter.push_opencode_pool_status(env.sid, snapshot)
                persisted = env.store.load_scan(env.sid)[0]
                assert len(persisted.opencode_pool.planned_tasks) == 124 - index
                assert persisted.opencode_pool.global_running == 1
                assert persisted.processed_candidates == index
                return OpenCodeResult(
                    session_id=f"test-{index}", status="success", text="guarded", model="test/model",
                    structured=result(index).model_dump(mode="json"),
                )
            finally:
                await release_model_lease(lease, outcome="success")

        monkeypatch.setattr(runner, "run_opencode_task", model_task)
        try:
            with bind_opencode_execution_context(
                scan_id=env.sid, execution_kind="scan", execution_id=env.sid,
                task_metadata={"mining_engine_id": "static_candidate",
                               "execution_revision": payload["execution_revision"],
                               "agent_session_id": "session"},
            ):
                outcome = await engine.run(
                    project_path=project, code_scan_path=project,
                    scan_dir=tmp_path / "scan", work_dir=tmp_path / "scan",
                    index_db_path=index_path, scan_id=env.sid, config=config, reporter=reporter,
                    checker_names=["npd"], checker_packages=[], product="", feedback_entries=[],
                    is_resume=True, retry_candidates=payload["retry_candidates"],
                    retry_total_candidates=payload["retry_total_candidates"],
                    retry_processed_offset=payload["retry_processed_offset"],
                    output=AsyncMock(), cancel_event=threading.Event(),
                    report_vulnerabilities=AsyncMock(return_value=[]),
                )
            assert outcome["status"] == "success"
            assert outcome["processed_candidates"] == outcome["total_candidates"] == 125
            assert model_calls == [123, 124]
            snapshot = model_pool_snapshot(env.sid)
            assert snapshot["planned_tasks"] == snapshot["queued_tasks"] == []
            assert snapshot["global_running"] == 0
            await reporter.report_mining_engine_run(env.sid, MiningEngineRunStatus(
                engine_id="static_candidate", engine_label="static", **outcome,
            ))
            await reporter.finish_scan(env.sid, [], "complete", 125, 125)
            env.cache.clear()
            overview = await scan_api.get_scan_overview_v2(env.sid, current_user=env.user)
            assert overview.processed_candidates == overview.total_candidates == 125
            assert overview.detail_counts.candidate_audit_success == 125
            assert not overview.can_continue
            assert env.store.list_scan_candidates(env.sid)[:123] == previous_successes
        finally:
            await reporter.close()

    asyncio.run(run())
