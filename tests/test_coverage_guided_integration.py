from __future__ import annotations

import asyncio
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from deephole_client import file_inventory as collector, scanner
from test_threat_coverage_resume import resume_scan


COVERAGE_METHOD = "opencode_coverage_guided_lightweight_threat_analysis"


def _snapshot(root: Path, *, status: str = "complete") -> dict:
    return {
        "schema_version": 1, "snapshot_id": "shared-snapshot", "status": status,
        "project_path": str(root), "scan_root": str(root),
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "entries": [{"path": ".", "kind": "directory"}, {"path": "a.c", "kind": "file"}],
        "issues": [], "issue_count": 0, "excluded_paths": [], "error_message": "",
    }


def test_method_waits_for_the_same_collection_and_receives_its_snapshot(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (project / "a.c").write_text("code", encoding="utf-8")
    scan_dir = project / ".scan"
    scan_dir.mkdir()
    (scan_dir / "must-not-count").write_text("artifact", encoding="utf-8")
    reporter = SimpleNamespace(
        scan_execution_revision=lambda _: 7, agent_session_id="session",
        push_file_inventory=AsyncMock(),
    )
    real_collect = collector.collect_file_inventory
    calls = []

    def collect(*args, **kwargs):
        calls.append(args)
        return real_collect(*args, **kwargs)

    monkeypatch.setattr(collector, "collect_file_inventory", collect)

    async def check():
        cancelled = threading.Event()
        async with collector.file_inventory_lifecycle(
            project=project, scan_root=project, scan_dir=scan_dir,
            scan_id="scan", reporter=reporter, cancel_event=cancelled, is_resume=False,
        ) as start:
            task = start()
            assert task is start()
            snapshot = await collector.prepare_coverage_inventory(
                project=project, scan_root=project, output_path=scan_dir / "threat_analysis",
                start=start, cancel_event=cancelled,
            )
            assert snapshot == task.result()
            saved = json.loads((scan_dir / "threat_analysis/coverage-input/file-inventory.json").read_text())
            assert saved == snapshot
            assert snapshot["entries"] == [
                {"path": ".", "kind": "directory"}, {"path": "a.c", "kind": "file"},
            ]
            assert reporter.push_file_inventory.await_args.args[1] == snapshot

    asyncio.run(check())
    assert len(calls) == 1


@pytest.mark.parametrize("status", ["partial", "failed"])
def test_incomplete_snapshot_is_passed_to_method_without_a_second_collection(tmp_path, status):
    expected = _snapshot(tmp_path, status=status)

    async def check():
        async def collected():
            return expected

        task = asyncio.create_task(collected())
        actual = await collector.prepare_coverage_inventory(
            project=tmp_path, scan_root=tmp_path, output_path=tmp_path / "analysis",
            start=lambda: task, cancel_event=threading.Event(),
        )
        assert actual == expected

    asyncio.run(check())


def test_scope_mismatch_creates_failed_input_instead_of_using_wrong_denominator(tmp_path):
    snapshot = _snapshot(tmp_path / "other")

    async def check():
        async def collected():
            return snapshot

        task = asyncio.create_task(collected())
        actual = await collector.prepare_coverage_inventory(
            project=tmp_path, scan_root=tmp_path, output_path=tmp_path / "analysis",
            start=lambda: task, cancel_event=threading.Event(),
        )
        assert actual["status"] == "failed"
        assert actual["entries"] == []
        assert "范围" in actual["error_message"]

    asyncio.run(check())


def test_missing_uploader_does_not_prevent_initial_analysis(tmp_path):
    async def check():
        actual = await collector.prepare_coverage_inventory(
            project=tmp_path, scan_root=tmp_path, output_path=tmp_path / "analysis",
            start=lambda: None, cancel_event=threading.Event(),
        )
        assert actual["status"] == "failed"
        assert "跳过补查" in actual["error_message"]

    asyncio.run(check())


def test_cancelled_method_wait_leaves_collector_for_its_lifecycle_cleanup(tmp_path):
    async def check():
        collecting = asyncio.Event()

        async def collect():
            collecting.set()
            await asyncio.Event().wait()

        task = asyncio.create_task(collect())
        waiting = asyncio.create_task(collector.prepare_coverage_inventory(
            project=tmp_path, scan_root=tmp_path, output_path=tmp_path / "analysis",
            start=lambda: task, cancel_event=threading.Event(),
        ))
        await collecting.wait()
        waiting.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiting
        assert not task.cancelled()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        assert not (tmp_path / "analysis/coverage-input/file-inventory.json").exists()

    asyncio.run(check())


@pytest.mark.parametrize(("method_id", "has_inventory"), [
    (COVERAGE_METHOD, True), ("opencode_lightweight_threat_analysis", False),
])
def test_scanner_only_prepares_input_for_coverage_method(resume_scan, monkeypatch, method_id, has_inventory):
    run = resume_scan
    observed = []

    async def analyze(**kwargs):
        output = kwargs["output_path"]
        input_path = output / "coverage-input/file-inventory.json"
        observed.append(input_path.exists())
        if has_inventory:
            snapshot = json.loads(input_path.read_text())
            assert snapshot["scan_root"] == str(run.root)
            assert snapshot["status"] == "complete"
            assert snapshot["snapshot_id"] == run.reporter.push_file_inventory.await_args.args[1]["snapshot_id"]
        output.mkdir(parents=True, exist_ok=True)
        result = {"result": True}
        for key, name, value in (
            ("value_asset_path", "assets.json", []),
            ("high_risk_modules_path", "modules.json", []),
            ("attack_tree_path", "trees.json", {"attack_trees": []}),
        ):
            path = output / name
            path.write_text(json.dumps(value), encoding="utf-8")
            result[key] = str(path)
        return result

    monkeypatch.setattr(scanner, "run_threat_analysis", AsyncMock(side_effect=analyze))
    run.kwargs.update(
        is_resume=False, resume_threat_analysis=True, retry_mining_engine_ids=[],
        mining_engines=[], threat_analysis_method=method_id,
    )
    asyncio.run(scanner.run_scan(**run.kwargs))
    assert observed == [has_inventory]
    assert run.reporter.finish_scan.await_args.args[2] == "complete"


def test_completed_coverage_resume_reuses_results_without_creating_task(resume_scan, monkeypatch):
    run = resume_scan
    register = AsyncMock()
    monkeypatch.setattr(scanner, "register_planned_task", register)
    run.kwargs.update(
        resume_threat_analysis=True, mining_engines=[], retry_mining_engine_ids=[],
        threat_analysis_method=COVERAGE_METHOD,
    )
    asyncio.run(scanner.run_scan(**run.kwargs))
    scanner.run_threat_analysis.assert_not_awaited()
    register.assert_not_awaited()
    assert run.reporter.finish_scan.await_args.args[2] == "complete"
