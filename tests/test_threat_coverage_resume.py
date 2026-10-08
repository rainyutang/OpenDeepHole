"""Historical scans collect coverage independently of the resumed pipeline."""
from __future__ import annotations

import asyncio
import copy
import json
import threading
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest

from backend import sse
from backend.models import ScanItemStatus
from deephole_client import file_inventory as collector, scanner
from deephole_client.codex_runtime import ScanCodexConfigResult
from deephole_client.config import AgentConfig
from test_agent_scan_paths import _reporter
from test_threat_coverage import analysis, coverage_env, inventory


@pytest.fixture
def resume_scan(tmp_path, monkeypatch):
    project = tmp_path / "project"
    root = project / "src"
    (root / "auth").mkdir(parents=True)
    (root / "auth/a.c").write_text("code", encoding="utf-8")
    (root / "authentication.c").write_text("code", encoding="utf-8")
    (root / "README").write_text("text", encoding="utf-8")
    reporter = _reporter()
    reporter.scan_execution_revision = lambda _id: 1
    reporter.get_file_inventory = AsyncMock(return_value=None)
    reporter.push_file_inventory = AsyncMock()
    old_analysis = analysis()
    reporter.get_threat_analysis.return_value = old_analysis
    monkeypatch.setattr(scanner.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(scanner, "configure_platform_runtime", lambda *_args: None)
    monkeypatch.setattr(scanner, "opencode_task_context", lambda **_kwargs: nullcontext())
    for method in ("prepare_scan_codex_access_async", "sync_scan_codex_mcp_async"):
        monkeypatch.setattr(scanner, method, AsyncMock(return_value=ScanCodexConfigResult()))
    monkeypatch.setattr(scanner, "run_threat_analysis", AsyncMock())
    monkeypatch.setattr(scanner, "run_code_graph_build", AsyncMock(return_value={
        "status": "success", "index_db_path": str(tmp_path / "index.db"), "stats": {},
    }))
    monkeypatch.setattr(scanner, "run_mining_engine", AsyncMock(return_value={
        "status": "success", "error_message": "", "total_candidates": 0, "processed_candidates": 0,
    }))
    kwargs = dict(
        config=AgentConfig(), project_path=project, code_scan_path=root, reporter=reporter,
        scan_name="historical", product="", validation_environment="", checker_names=[],
        scan_id="historical", cancel_event=threading.Event(), is_resume=True,
        threat_analysis_enabled=True, threat_analysis_method="custom_threat_analysis",
        resume_threat_analysis=False, retry_mining_engine_ids=["static_candidate"],
        mining_engines=[{"engine_id": "static_candidate", "engine_label": "static", "enabled": True}],
    )
    return SimpleNamespace(project=project, root=root, reporter=reporter, kwargs=kwargs, analysis=old_analysis)


@pytest.mark.parametrize("restore_analysis", [False, True])
def test_stopped_historical_scan_uploads_tree_and_uses_old_artifacts(
    coverage_env, resume_scan, restore_analysis, monkeypatch,
):
    env, run = coverage_env, resume_scan
    env.store.replace_threat_analysis(env.scan_id, run.analysis)
    original = copy.deepcopy(env.store.get_threat_analysis(env.scan_id))
    assert env.store.get_file_inventory(env.scan_id) is None
    env.store.update_scan_progress(env.scan_id, status=ScanItemStatus.CANCELLED)
    revision = env.store.claim_scan_for_resume(
        env.scan_id, expected_revision=env.revision, agent_id="agent-1",
        agent_session_id="session-1", processed_candidates=0, progress=0,
    )
    assert revision == env.revision + 1
    run.reporter.scan_execution_revision = lambda _id: revision
    run.kwargs.update(scan_id=env.scan_id, resume_threat_analysis=restore_analysis)

    async def check():
        uploaded, release_engine = asyncio.Event(), asyncio.Event()
        notices = sse.subscribe(env.scan_id)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=env.app), base_url="http://test") as client:
            async def upload(scan_id, snapshot, **ownership):
                response = await client.post(f"/api/agent/scan/{scan_id}/file-inventory", json={
                    "inventory": snapshot, **ownership,
                })
                assert response.status_code == 200, response.text
                if snapshot["status"] == "complete":
                    uploaded.set()
            run.reporter.push_file_inventory.side_effect = upload
            async def engine(*_args, **_kwargs):
                await release_engine.wait()
                return {"status": "success", "error_message": "", "total_candidates": 0, "processed_candidates": 0}
            monkeypatch.setattr(scanner, "run_mining_engine", AsyncMock(side_effect=engine))
            task = asyncio.create_task(scanner.run_scan(**run.kwargs))
            try:
                await asyncio.wait_for(uploaded.wait(), 5)
                run.reporter.finish_scan.assert_not_awaited()
                response = await client.get(f"/api/scan/{env.scan_id}/threat-coverage", headers=env.headers)
                data = response.json()
                assert response.status_code == 200 and data["analysis_ready"]
                assert data["inventory"]["status"] == "complete"
                assert data["modules"][0]["mapped_paths"] == ["auth", "auth/a.c"]
                assert data["targets"][0]["pattern_id"] == "AUTH-1"
                assert data["targets"][0]["mapped_paths"] == ["auth", "auth/a.c"]
                assert notices.get_nowait()["data"]["resource"] == "file-inventory"
                token = (await client.post(f"/api/scan/{env.scan_id}/share", headers=env.headers)).json()["token"]
                shared = await client.get(f"/api/shared/scans/{env.scan_id}/threat-coverage", params={"token": token})
                assert shared.json() == data
                release_engine.set()
                await asyncio.wait_for(task, 5)
                scanner.run_threat_analysis.assert_not_awaited()
                run.reporter.push_threat_analysis.assert_not_awaited()
                run.reporter.report_threat_analysis_run.assert_not_awaited()
                assert run.reporter.finish_scan.await_args.args[2] == "complete"
                assert env.store.get_threat_analysis(env.scan_id) == original
                assert env.store.list_threat_audit_tasks(env.scan_id) == []
                if restore_analysis:
                    run.reporter.get_threat_analysis.assert_awaited_once()
                else:
                    run.reporter.get_threat_analysis.assert_not_awaited()
            finally:
                release_engine.set()
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                sse.unsubscribe(env.scan_id, notices)
    asyncio.run(check())


@pytest.mark.parametrize("stage", ["index_running", "index_error", "setup_error"])
def test_resume_inventory_does_not_wait_for_index_or_disappear_on_early_exit(resume_scan, monkeypatch, stage):
    run = resume_scan
    async def check():
        posted, release_index = asyncio.Event(), asyncio.Event()
        collecting = threading.Event()
        release_inventory = threading.Event()
        real_collect = collector.collect_file_inventory
        def collect(*args, **kwargs):
            collecting.set()
            assert release_inventory.wait(5)
            return real_collect(*args, **kwargs)
        monkeypatch.setattr(collector, "collect_file_inventory", collect)
        async def upload(_id, value, **_kwargs):
            if value["status"] == "complete":
                posted.set()
        run.reporter.push_file_inventory.side_effect = upload
        if stage == "setup_error":
            monkeypatch.setattr(scanner, "configure_platform_runtime", Mock(side_effect=RuntimeError("setup failed")))
        else:
            async def index(**_kwargs):
                if stage == "index_running":
                    await release_index.wait()
                return {"status": "error", "error": "index failed"}
            monkeypatch.setattr(scanner, "run_code_graph_build", AsyncMock(side_effect=index))
        task = asyncio.create_task(scanner.run_scan(**run.kwargs))
        try:
            assert await asyncio.to_thread(collecting.wait, 5)
            assert not task.done()
            release_inventory.set()
            await asyncio.wait_for(posted.wait(), 5)
            if stage == "index_running":
                assert not task.done()
                run.reporter.finish_scan.assert_not_awaited()
            release_index.set()
            if stage == "setup_error":
                with pytest.raises(RuntimeError, match="setup failed"):
                    await asyncio.wait_for(task, 5)
            else:
                await asyncio.wait_for(task, 5)
                assert run.reporter.finish_scan.await_args.args[2] == "error"
            scanner.run_threat_analysis.assert_not_awaited()
            scanner.run_mining_engine.assert_not_awaited()
        finally:
            release_inventory.set()
            release_index.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    asyncio.run(check())


@pytest.mark.parametrize("stage", ["setup", "inventory_cleanup"])
def test_stop_during_resume_setup_or_inventory_cleanup_stops_collection(resume_scan, monkeypatch, stage):
    run = resume_scan
    async def check():
        started, stopped = threading.Event(), threading.Event()
        real_collect = collector.collect_file_inventory
        def collect(*args, **kwargs):
            started.set()
            assert kwargs["stop_event"].wait(5)
            stopped.set()
            return real_collect(*args, **kwargs)
        monkeypatch.setattr(collector, "collect_file_inventory", collect)
        if stage == "setup":
            async def setup(**_kwargs):
                await asyncio.Event().wait()
            monkeypatch.setattr(scanner, "prepare_scan_codex_access_async", setup)
        task = asyncio.create_task(scanner.run_scan(**run.kwargs))
        try:
            assert await asyncio.to_thread(started.wait, 5)
            if stage == "inventory_cleanup":
                run.reporter.finish_scan.assert_awaited_once()
            run.kwargs["cancel_event"].set()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 5)
            assert await asyncio.to_thread(stopped.wait, 5)
            assert run.reporter.push_file_inventory.await_args.args[1]["status"] == "cancelled"
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    asyncio.run(check())


@pytest.mark.parametrize("previous", ["complete", "partial", "failed", "cancelled"])
def test_resume_uses_remote_complete_inventory_or_recollects_unfinished_inventory(resume_scan, tmp_path, monkeypatch, previous):
    run = resume_scan
    scan_dir = tmp_path / "work"
    saved = inventory(project_path=str(run.project), scan_root=str(run.root), status=previous)
    run.reporter.get_file_inventory.return_value = saved
    collect = Mock(wraps=collector.collect_file_inventory)
    monkeypatch.setattr(collector, "collect_file_inventory", collect)
    if previous != "complete":
        collector._save(scan_dir / "coverage/file-inventory.json", saved)
    asyncio.run(collector.collect_and_report_file_inventory(
        project=run.project, scan_root=run.root, scan_dir=scan_dir, scan_id="historical",
        reporter=run.reporter, cancel_event=threading.Event(), is_resume=True,
    ))
    local = json.loads((scan_dir / "coverage/file-inventory.json").read_text(encoding="utf-8"))
    if previous == "complete":
        collect.assert_not_called()
        run.reporter.push_file_inventory.assert_not_awaited()
        assert local == saved
    else:
        collect.assert_called_once()
        assert local["status"] == "complete" and local["snapshot_id"] != saved["snapshot_id"]
        assert run.reporter.push_file_inventory.await_args.args[1] == local
