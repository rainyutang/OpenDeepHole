from __future__ import annotations

import asyncio
import errno
import threading
from pathlib import Path

import pytest

from deephole_client.code_graph_build import run_code_graph_build
from deephole_client.code_graph_build.code_database import CodeDatabase
from deephole_client.code_graph_build.cpp_analyzer import CppAnalyzer, CodeIndexToolError
from deephole_client.code_graph_build import source_filter
from deephole_client.code_graph_build import runner as graph_runner
from mcp_server.index_reader import CodeIndexReader


def _fake_ctags(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    calls: list[list[str]] = []
    monkeypatch.setattr(CppAnalyzer, "_ensure_tools_available", staticmethod(lambda: None))

    def run(_self, root, files, _work_dir):
        paths = [path.relative_to(root).as_posix() for path in files]
        calls.append(paths)
        return [
            {
                "_type": "tag",
                "name": path.stem,
                "path": relative,
                "line": 1,
                "end": 1,
                "kind": "function",
                "signature": "(void)",
            }
            for path, relative in zip(files, paths)
        ]

    monkeypatch.setattr(CppAnalyzer, "_run_ctags_json", run)
    return calls


def _existing_index(project: Path) -> tuple[Path, bytes]:
    index = project / "code_index.db"
    database = CodeDatabase(index)
    try:
        database.get_or_create_file("previous.c")
        database.set_metadata("preserve", "previous successful index")
        database.mark_index_complete()
        database.checkpoint()
    finally:
        database.close()
    return index, index.read_bytes()


def _assert_old_index_preserved(project: Path, index: Path, before: bytes) -> None:
    assert index.read_bytes() == before
    assert not list(project.glob(".code_index.db.*.building*"))
    assert not list(project.glob(".opendeephole-index-*"))


def test_partial_index_is_usable_but_rebuilt_until_missing_source_is_restored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    good = project / "good.c"
    good.write_text("int good(void) { return 1; }\n", encoding="utf-8")
    missing = project / "restored.h"
    # The file was present during discovery and disappeared before reading.
    monkeypatch.setattr(CppAnalyzer, "_collect_source_files", lambda _self, _root: [good, missing])
    ctags_calls = _fake_ctags(monkeypatch)
    events: list[dict] = []

    async def scenario():
        partial = await run_code_graph_build(
            project_path=project, work_dir=tmp_path / "work", output=events.append,
        )
        assert partial["status"] == "success"
        assert partial["cache_hit"] is False
        assert partial["skipped_files"] == 1
        assert partial["coverage_complete"] is False
        assert partial["stats"]["files"] == 1
        assert ctags_calls == [["good.c"]]
        warnings = [event for event in events if event["kind"] == "warning"]
        assert any("restored.h" in event["message"] for event in warnings)
        assert any("FileNotFoundError" in event["message"] for event in warnings)

        database = CodeDatabase(project / "code_index.db")
        try:
            assert database.is_index_complete()
            assert database.get_metadata("coverage_complete") == "false"
            assert database.get_metadata("skipped_files") == "1"
            assert [row["name"] for row in database.get_all_functions()] == ["good"]
        finally:
            database.close()
        reader = CodeIndexReader(project / "code_index.db")
        try:
            assert reader.is_index_complete()
            assert len(reader.get_functions_by_name("good")) == 1
        finally:
            reader.close()

        # Even without a repair, partial coverage must not become a cache hit.
        still_partial = await run_code_graph_build(
            project_path=project, work_dir=tmp_path / "work",
        )
        assert still_partial["cache_hit"] is False
        assert still_partial["skipped_files"] == 1
        assert still_partial["coverage_complete"] is False

        missing.write_text("int restored(void) { return 2; }\n", encoding="utf-8")
        repaired = await run_code_graph_build(
            project_path=project, work_dir=tmp_path / "work",
        )
        assert repaired["status"] == "success"
        assert repaired["cache_hit"] is False
        assert repaired["coverage_complete"] is True
        assert repaired["skipped_files"] == 0
        assert repaired["stats"]["files"] == 2
        database = CodeDatabase(project / "code_index.db")
        try:
            assert database.get_metadata("coverage_complete") == "true"
            assert database.get_metadata("skipped_files") == "0"
            assert {row["name"] for row in database.get_all_functions()} == {"good", "restored"}
        finally:
            database.close()

        cached = await run_code_graph_build(
            project_path=project, work_dir=tmp_path / "work",
        )
        assert cached["status"] == "success"
        assert cached["cache_hit"] is True
        assert cached["skipped_files"] == 0
        assert cached["coverage_complete"] is True
        assert cached["stats"] == repaired["stats"]
        assert ctags_calls == [["good.c"], ["good.c"], ["good.c", "restored.h"]]
        assert not list(project.glob(".code_index.db.*.building*"))
        assert not list(project.glob(".opendeephole-index-*"))

    asyncio.run(scenario())


def test_all_discovered_sources_unreadable_preserves_existing_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    index, before = _existing_index(project)
    missing = project / "missing.h"
    monkeypatch.setattr(CppAnalyzer, "_collect_source_files", lambda _self, _root: [missing])
    ctags_calls = _fake_ctags(monkeypatch)
    events: list[dict] = []

    result = asyncio.run(run_code_graph_build(
        project_path=project, work_dir=tmp_path / "work", reuse_cache=False,
        output=events.append,
    ))

    assert result["status"] == "error"
    assert result["index_db_path"] == ""
    assert result["skipped_files"] == 1
    assert result["coverage_complete"] is False
    assert ctags_calls == []
    assert any(event["kind"] == "warning" and "missing.h" in event["message"] for event in events)
    _assert_old_index_preserved(project, index, before)


@pytest.mark.parametrize("failure", ["cancel_before", "cancel_during", "tool_failure"])
def test_unsuccessful_rebuild_does_not_replace_old_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "good.c").write_text("int good(void) { return 1; }\n", encoding="utf-8")
    index, before = _existing_index(project)
    cancel = threading.Event()
    monkeypatch.setattr(CppAnalyzer, "_ensure_tools_available", staticmethod(lambda: None))

    def run(_self, _root, _files, _work_dir):
        if failure == "tool_failure":
            raise CodeIndexToolError("ctags process failed")
        cancel.set()
        return []

    monkeypatch.setattr(CppAnalyzer, "_run_ctags_json", run)
    if failure == "cancel_before":
        cancel.set()
    result = asyncio.run(run_code_graph_build(
        project_path=project, work_dir=tmp_path / "work", reuse_cache=False,
        cancel_event=cancel,
    ))

    assert result["status"] == ("error" if failure == "tool_failure" else "cancelled")
    assert result["skipped_files"] == 0
    assert result["coverage_complete"] is False
    assert result["index_db_path"] == ""
    if failure == "tool_failure":
        assert "ctags process failed" in result["error"]
    _assert_old_index_preserved(project, index, before)


def test_empty_source_tree_has_complete_coverage(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    result = asyncio.run(run_code_graph_build(
        project_path=project, work_dir=tmp_path / "work",
    ))
    assert result["status"] == "success"
    assert result["stats"]["files"] == 0
    assert result["skipped_files"] == 0
    assert result["coverage_complete"] is True


def test_existing_complete_index_without_coverage_metadata_remains_reusable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _existing_index(project)

    def unexpected_build(*_args, **_kwargs):
        raise AssertionError("A compatible complete index should be reused")

    monkeypatch.setattr(CppAnalyzer, "analyze_directory", unexpected_build)
    result = asyncio.run(run_code_graph_build(
        project_path=project, work_dir=tmp_path / "work",
    ))
    assert result["status"] == "success"
    assert result["cache_hit"] is True
    assert result["skipped_files"] == 0
    assert result["coverage_complete"] is True


def test_directory_read_error_prevents_cache_reuse_without_known_skipped_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "good.c").write_text("int good(void) { return 1; }\n", encoding="utf-8")
    ctags_calls = _fake_ctags(monkeypatch)

    def walk(root, *, onerror):
        yield str(root), [], ["good.c"]
        onerror(PermissionError(errno.EACCES, "Access denied", str(project / "unreadable")))

    monkeypatch.setattr(source_filter.os, "walk", walk)
    events: list[dict] = []

    async def scenario():
        for _ in range(2):
            result = await run_code_graph_build(
                project_path=project, work_dir=tmp_path / "work", output=events.append,
            )
            assert result["status"] == "success"
            assert result["cache_hit"] is False
            assert result["coverage_complete"] is False
            assert result["skipped_files"] == 0
            assert result["stats"]["files"] == 1

    asyncio.run(scenario())
    assert ctags_calls == [["good.c"], ["good.c"]]
    assert any(event["kind"] == "warning" and "unreadable" in event["message"] for event in events)


def test_async_source_warning_is_delivered_before_failed_build_returns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setattr(
        CppAnalyzer, "_collect_source_files", lambda _self, _root: [project / "missing.h"],
    )
    _fake_ctags(monkeypatch)
    events: list[dict] = []

    async def scenario():
        async def output(event):
            if event["kind"] == "warning":
                # A network reporter can finish after indexing itself fails.
                await asyncio.sleep(0.05)
            events.append(event)

        result = await run_code_graph_build(
            project_path=project, work_dir=tmp_path / "work", output=output,
        )
        assert result["status"] == "error"
        assert any(
            event["kind"] == "warning" and "missing.h" in event["message"]
            for event in events
        )

    asyncio.run(scenario())


def test_task_cancellation_signals_worker_before_waiting_for_slow_events(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    index, before = _existing_index(project)
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    run_in_thread = graph_runner._run_in_daemon_thread

    async def observe_worker(function):
        def observed():
            try:
                return function()
            finally:
                finished.set()

        return await run_in_thread(observed)

    def analyze(self, directory, *, on_progress, **kwargs):
        on_progress(1, 1)
        entered.set()
        assert release.wait(2)
        self.db.get_or_create_file("new.c")

    monkeypatch.setattr(graph_runner, "_run_in_daemon_thread", observe_worker)
    monkeypatch.setattr(CppAnalyzer, "analyze_directory", analyze)

    async def scenario():
        async def wait_for_thread_event(event):
            # Keep this test independent of asyncio's shared executor lifecycle.
            deadline = asyncio.get_running_loop().time() + 2
            while not event.is_set() and asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(0.005)
            assert event.is_set()

        async def output(event):
            if event["message"] == "Indexing source files":
                await asyncio.sleep(0.15)

        task = asyncio.create_task(run_code_graph_build(
            project_path=project, work_dir=tmp_path / "work", reuse_cache=False,
            output=output,
        ))
        await wait_for_thread_event(entered)
        task.cancel()
        # Let cancellation reach the task while the worker is still blocked.
        await asyncio.sleep(0.01)
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        await wait_for_thread_event(finished)
        _assert_old_index_preserved(project, index, before)

    try:
        asyncio.run(scenario())
    finally:
        release.set()
