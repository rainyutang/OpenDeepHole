import asyncio
import json
from contextlib import ExitStack, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from deephole_client import review_notes
from deephole_client.fp_review import run_fp_review


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(review_notes, "_FAILED_SYNCS", {})
    return tmp_path


def payload(revision=1, *, enabled=True, entries=None):
    entries = entries if entries is not None else [
        {"id": "one", "title": "边界检查", "content": "检查上游长度约束"},
    ]
    return {
        "scan_id": "scan-1", "revision": revision, "enabled": enabled,
        "note_ids": [entry["id"] for entry in entries], "entries": entries,
    }


def test_changes_only_leave_current_files_and_metadata(home):
    review_notes.sync_review_notes(payload())
    directory = review_notes.get_review_notes_dir("scan-1")
    assert directory == home / ".opendeephole/scans/scan-1/review-notes"
    assert (directory / "边界检查.md").read_text() == "# 边界检查\n\n检查上游长度约束\n"
    review_notes.sync_review_notes(payload(2, entries=[
        {"id": "one", "title": "权限约束", "content": "检查调用者权限"},
    ]))
    assert [path.name for path in directory.iterdir()] == ["权限约束.md"]
    assert review_notes.sync_review_notes(payload(1)) == 2
    assert [path.name for path in directory.iterdir()] == ["权限约束.md"]
    assert review_notes.review_notes_revisions() == {"scan-1": 2}
    review_notes.sync_review_notes(payload(3, entries=[]))
    assert list(directory.iterdir()) == []
    assert review_notes.get_review_notes_dir("scan-1") is None
    review_notes.sync_review_notes(payload(4))
    review_notes.sync_review_notes(payload(5, enabled=False))
    assert list(directory.iterdir()) == []
    assert review_notes.get_review_notes_dir("scan-1") is None
    state = json.loads((directory.parent / "review-notes-state.json").read_text())
    assert state["revision"] == 5
    assert "检查上游长度约束" not in json.dumps(state, ensure_ascii=False)
    assert sorted(path.name for path in directory.parent.iterdir()) == [
        "review-notes", "review-notes-state.json",
    ]
    directory.rmdir()
    assert review_notes.review_notes_revisions() == {}


def test_titles_are_safe_unique_and_preserve_chinese_content(home):
    titles = ["../逃逸", "CON", "CON.txt", "a/b", "a\\b", "SAME", "same", "界" * 200]
    review_notes.sync_review_notes(payload(entries=[
        {"id": str(index), "title": title, "content": f"内容 {index}"}
        for index, title in enumerate(titles)
    ]))
    directory = review_notes.get_review_notes_dir("scan-1")
    paths = list(directory.iterdir())
    assert len(paths) == len(titles)
    assert len({path.name.casefold() for path in paths}) == len(titles)
    assert all(path.suffix == ".md" and len(path.name.encode()) <= 255 for path in paths)
    assert not any(path.name in {"CON.md", "CON.txt.md"} for path in paths)
    assert any("# ../逃逸" in path.read_text() for path in paths)
    with pytest.raises(ValueError, match="scan_id"):
        review_notes.sync_review_notes({**payload(), "scan_id": "../../outside"})


def test_symlink_directory_is_rejected(home):
    outside = home / "outside"
    outside.mkdir()
    scan = home / ".opendeephole/scans/scan-1"
    scan.mkdir(parents=True)
    (scan / "review-notes").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic"):
        review_notes.sync_review_notes(payload())
    assert not list(outside.iterdir())


def test_reconnect_restores_missing_files_and_corrupt_metadata(home):
    review_notes.sync_review_notes(payload())
    directory = review_notes.get_review_notes_dir("scan-1")
    (directory / "边界检查.md").unlink()
    assert review_notes.review_notes_revisions() == {}
    review_notes.sync_review_notes(payload())
    assert (directory / "边界检查.md").is_file()
    (directory / "边界检查.md").unlink()
    directory.rmdir()
    assert review_notes.review_notes_revisions() == {}
    review_notes.sync_review_notes(payload())
    assert (directory / "边界检查.md").is_file()
    (directory.parent / "review-notes-state.json").write_text("not JSON")
    assert review_notes.review_notes_revisions() == {}
    review_notes.sync_review_notes(payload())
    assert review_notes.review_notes_revisions() == {"scan-1": 1}
    with pytest.raises(ValueError, match="missing"):
        review_notes.sync_review_notes({**payload(2), "note_ids": ["missing"]})
    assert review_notes.review_notes_revisions() == {}
    review_notes.sync_review_notes(payload(2))
    assert review_notes.review_notes_revisions() == {"scan-1": 2}


def test_failed_write_is_reported_and_same_revision_can_retry(home):
    from deephole_client.main import _handle_command

    review_notes.sync_review_notes(payload())
    actual_write = review_notes._write_atomic

    def fail_markdown(path, text):
        if path.suffix == ".md":
            raise OSError("disk full")
        actual_write(path, text)

    command = {"type": "review_notes_update", "request_id": "request", **payload(2)}
    with patch.object(review_notes, "_write_atomic", side_effect=fail_markdown):
        result = asyncio.run(_handle_command(command, None, None, None))
    assert result["type"] == "review_notes_result"
    assert result["request_id"] == "request"
    assert result["ok"] is False and "disk full" in result["error"]
    with pytest.raises(RuntimeError, match="尚未同步"):
        review_notes.get_review_notes_dir("scan-1")
    assert review_notes.review_notes_revisions() == {}
    result = asyncio.run(_handle_command(command, None, None, None))
    assert result["ok"] is True and result["revision"] == 2
    assert review_notes.get_review_notes_dir("scan-1") is not None
    stale = asyncio.run(_handle_command({**command, "revision": 1}, None, None, None))
    assert stale["ok"] is True and stale["revision"] == 2


@pytest.mark.parametrize("kind", ["task", "resume", "fp_review"])
def test_work_commands_apply_notes_before_starting_work(home, kind):
    from deephole_client import main, server

    command = {
        "type": kind, "scan_id": "scan-1", "review_id": "review-1",
        "project_path": str(home), "review_notes": payload(),
    }

    async def assert_notes(**kwargs):
        directory = review_notes.get_review_notes_dir(kwargs["scan_id"])
        assert (directory / "边界检查.md").is_file()

    with patch.object(main, "_ensure_runtime_updated_safely", new=AsyncMock()), patch.object(
        server, "scan_command_is_obsolete", return_value=False,
    ), patch.object(server, "prepare_scan_resume", new=AsyncMock()), patch.object(
        server, f"handle_{kind}", new=AsyncMock(side_effect=assert_notes),
    ) as handler:
        asyncio.run(main._handle_command(command, None, None, None))
    handler.assert_awaited_once()


@pytest.mark.parametrize("kind", ["task", "resume", "fp_review"])
def test_work_command_sync_failure_reports_error_without_starting(home, kind):
    from deephole_client import main, server

    command = {
        "type": kind, "scan_id": "scan-1", "review_id": "review-1", "execution_revision": 4,
        "project_path": str(home), "review_notes": payload(),
    }
    reporter = Mock(report_scan_start_failure=AsyncMock(), finish_fp_review=AsyncMock())
    with patch.object(main, "_ensure_runtime_updated_safely", new=AsyncMock()), patch.object(
        main, "apply_command_review_notes", side_effect=OSError("disk full"),
    ), patch.object(server, "scan_command_is_obsolete", return_value=False), patch.object(
        server, "prepare_scan_resume", new=AsyncMock(),
    ), patch.object(server, f"handle_{kind}", new=AsyncMock()) as handler:
        with pytest.raises(OSError, match="disk full"):
            asyncio.run(main._handle_command(command, None, None, reporter))
    handler.assert_not_awaited()
    reported = reporter.finish_fp_review if kind == "fp_review" else reporter.report_scan_start_failure
    reported.assert_awaited_once()
    assert "disk full" in reported.await_args.args[-1]


@pytest.mark.parametrize("bad_scan", [False, True])
def test_reconnect_applies_welcome_before_replaying_pending_work(home, bad_scan, capsys):
    from deephole_client import main

    review_notes.sync_review_notes(payload())
    updated = payload(2, entries=[{"id": "one", "title": "更新依据", "content": "新内容"}])
    bad_update = {**payload(2), "scan_id": "scan-bad"}
    if bad_scan:
        review_notes.sync_review_notes({**payload(), "scan_id": "scan-bad"})
    messages = []

    class Socket:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def send(self, text):
            messages.append(json.loads(text))

        async def recv(self):
            return json.dumps({
                "type": "welcome", "agent_id": "agent",
                "review_notes": ([bad_update] if bad_scan else []) + [updated],
            })

    def pending_commands(**kwargs):
        assert kwargs == {"clear": True}
        directory = review_notes.get_review_notes_dir("scan-1")
        assert (directory / "更新依据.md").is_file()
        assert not (directory / "边界检查.md").exists()
        if bad_scan:
            with pytest.raises(RuntimeError, match="尚未同步"):
                review_notes.get_review_notes_dir("scan-bad")
            assert "scan-bad" not in review_notes.review_notes_revisions()
        raise asyncio.CancelledError

    config = SimpleNamespace(agent_name="Agent", server_url="http://example.test", owner_token="")
    reporter = Mock(agent_session_id="session", pending_terminal_work=Mock(return_value=[]))

    async def direct_thread_call(function, *args, **kwargs):
        return function(*args, **kwargs)

    with ExitStack() as stack:
        if bad_scan:
            actual_write = review_notes._write_atomic

            def fail_bad_scan(path, text):
                if "scan-bad" in path.parts:
                    raise PermissionError("scan directory is read-only")
                actual_write(path, text)

            stack.enter_context(patch.object(review_notes, "_write_atomic", side_effect=fail_bad_scan))
        stack.enter_context(patch.object(main.asyncio, "to_thread", side_effect=direct_thread_call))
        stack.enter_context(patch("websockets.connect", return_value=Socket()))
        stack.enter_context(patch("deephole_client.config.remote_config_dict", return_value={}))
        stack.enter_context(patch("deephole_client.vulnerability_validation.run_vulnerability_validation", new=AsyncMock(return_value={"catalog": {}})))
        stack.enter_context(patch("deephole_client.updater.compute_runtime_hash", return_value="hash"))
        for name in ("pending_scan_snapshots", "pending_fp_review_snapshots", "pending_validation_snapshots"):
            stack.enter_context(patch(f"deephole_client.updater.{name}", return_value=[]))
        stack.enter_context(patch("deephole_client.updater.load_pending_commands", side_effect=pending_commands))
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(main._ws_loop(config, Mock(active_snapshots=Mock(return_value=[])), reporter))
    assert messages[0]["review_notes_revisions"] == (
        {"scan-1": 1, "scan-bad": 1} if bad_scan else {"scan-1": 1}
    )
    if bad_scan:
        assert "scan directory is read-only" in capsys.readouterr().out
        review_notes.sync_review_notes(bad_update)
        assert review_notes.get_review_notes_dir("scan-bad") is not None


def test_independent_review_item_uses_current_local_notes_without_fetching(home):
    from deephole_client import server

    review_notes.sync_review_notes(payload())
    item = SimpleNamespace(
        reporter=Mock(), config=Mock(), project_path=str(home), code_scan_path=str(home),
        vulnerability={"index": 0}, review_id="review", scan_id="scan-1", method="adversarial",
        feedback_entries=[], code_graph_mcp=None, knowledge_base_mcp=None, cancel_event=None,
        scan_mode="custom", planned_task_id="planned", execution_revision=1,
    )
    invoke = AsyncMock(return_value={"status": "cancelled"})
    loaded = SimpleNamespace(manifest=SimpleNamespace(skill_paths=[]))
    with patch.object(server, "_agent_id", None), patch(
        "task_agent.opencode_task_context", return_value=nullcontext(),
    ), patch("deephole_client.fp_review.load_fp_review_methods", return_value=Mock(get=Mock(return_value=loaded))), patch(
        "deephole_client.fp_review.run_fp_review", new=invoke,
    ):
        asyncio.run(server._run_single_fp_review_item(item))
    assert invoke.await_args.kwargs["review_notes_dir"] == review_notes.get_review_notes_dir("scan-1")
    assert item.reporter.method_calls == []


@pytest.mark.parametrize("method,expected_calls", [("adversarial", 3), ("fp_check", 2)])
def test_all_review_stages_only_reference_current_notes_directory(home, method, expected_calls):
    review_notes.sync_review_notes(payload())
    directory = review_notes.get_review_notes_dir("scan-1")

    async def invoke(**kwargs):
        structured = {
            "route": "standard", "decision": "verdict", "verdict": "true_positive",
            "reason": "已核验", "stage_markdown": "# 已核验证据", "evidence": [],
            "revised_severity": "high", "vulnerability_report": "# 已核验问题",
            "gates": {name: True for name in (
                "process", "reachability", "real_impact", "poc_validation", "math_bounds", "environment",
            )},
            "completeness": {name: True for name in (
                "claim_restatement", "data_flow", "escalation_checkpoint_one", "exploitability",
                "impact", "escalation_checkpoint_two", "poc", "devil_advocate", "gate_review",
            )},
        }
        return SimpleNamespace(status="success", structured=structured, output_source={}, text="")

    mocked = AsyncMock(side_effect=invoke)
    with patch("task_agent.run_opencode_task", new=mocked):
        result = asyncio.run(run_fp_review(
            method_id=method, project_path=home, code_scan_path=home, work_dir=home / "review",
            scan_id="scan-1", review_id="review-1", vuln_index=0,
            vulnerability={"index": 0, "vulnerability_report": "# 原始问题"},
            review_notes_dir=directory,
        ))
    assert result["status"] == "success"
    assert mocked.await_count == expected_calls
    for call in mocked.await_args_list:
        assert call.kwargs["readable_paths"] == directory
        assert f"复核时请参考并关注 `{directory}` 下的问题判定依据文件，按当前问题需要查看相关内容。" in call.kwargs["prompt"]
        assert "检查上游长度约束" not in call.kwargs["prompt"]
        assert "review_notes" not in call.kwargs["output_schema"]["properties"]
