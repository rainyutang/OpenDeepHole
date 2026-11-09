"""Compact high-risk map and merge tasks consume checked files and resume safely."""

from __future__ import annotations

import asyncio
import copy
import importlib
import json
import shlex
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from test_deephole_compact_threat_analysis import _module, compact_native  # noqa: F401


def _task(native, tmp_path, phase):
    layout = native.ThreatAnalysisLayout(tmp_path / "artifacts with spaces")
    layout.ensure()
    stages = importlib.import_module(native.__name__ + ".stages.high_risk_modules")
    stage = stages.HighRiskModuleStage(submit_tasks=lambda *a, **kw: [], layout=layout)
    maps = stage.build_map_tasks(input_batches=[[tmp_path / "source"]])
    task = maps[1] if phase == "map" else stage.build_merge_task(
        candidate_files=[item["output_path"] for item in maps],
    )
    return task, layout


def _write(task, output):
    path = Path(task["output_path"])
    path.write_text(json.dumps(output, ensure_ascii=False) + "\n\n", encoding="utf-8")
    return path.read_bytes()


def _result(*, status="success", text="[]", structured=None):
    return SimpleNamespace(status=status, text=text, structured=structured,
                           session_id="module-session", model="test/model")


@pytest.mark.parametrize("phase", ["map", "merge"])
@pytest.mark.parametrize("empty", [False, True])
@pytest.mark.parametrize("repair", [False, True])
def test_high_risk_file_is_authoritative_and_command_is_bound(tmp_path, compact_native, phase, empty, repair):
    task, _ = _task(compact_native, tmp_path, phase)
    expected = [] if empty else [_module()]
    _write(task, [_module()])
    if repair:
        task.update(invoke_skill=False, session_id="module-session", runtime_prompt="请修正高风险模块文件。")
    file_bytes = None

    async def runner(**kwargs):
        nonlocal file_bytes
        assert kwargs["output_schema"] is None
        assert kwargs["json_repair_output_prompt"] is None
        assert kwargs["post_session_validation_retry_count"] == 1
        assert kwargs["bash_command_match_mode"] == "bound_python_script"
        command, = kwargs["allowed_bash_commands"]
        argv = shlex.split(command)
        assert Path(argv[1]).name == "validate_high_risk_modules.py"
        assert argv[2:] == ["--output", str(Path(task["output_path"]).resolve())]
        assert command in kwargs["prompt"]
        assert str(task["output_path"]) in kwargs["prompt"]
        assert not any(text in kwargs["prompt"] for text in ("[]", "空数组", "聊天回复", "宿主"))
        assert Path(compact_native.__file__).parent.resolve() in kwargs["readable_paths"]
        assert Path(task["output_path"]).exists() is repair
        assert not Path(task["output_path"]).with_suffix(".json.schema.json").exists()
        if repair:
            assert kwargs["session_id"] == "module-session"
            assert not kwargs["prompt"].startswith("/")
        file_bytes = _write(task, expected)
        assert await kwargs["post_session_validator"]() is None
        return _result(text="{}", structured={"not": "the file"})

    result, = asyncio.run(compact_native.TaskAgentSubmitter(run_opencode_task=runner).submit_tasks_async([task]))
    assert result["status"] == "succeeded"
    assert result["output"] == expected
    assert Path(task["output_path"]).read_bytes() == file_bytes


@pytest.mark.parametrize("phase", ["map", "merge"])
@pytest.mark.parametrize("failure", ["missing", "malformed", "wrong_field_type"])
def test_invalid_high_risk_files_cannot_be_replaced_by_json_replies(tmp_path, compact_native, phase, failure):
    task, _ = _task(compact_native, tmp_path, phase)
    file_path = Path(task["output_path"])
    original_bytes = None

    async def runner(**kwargs):
        nonlocal original_bytes
        if failure == "malformed":
            file_path.write_text('[\n {"模块名称": ', encoding="utf-8")
        elif failure == "wrong_field_type":
            invalid = _module()
            invalid["是否外部暴露面"] = True
            _write(task, [invalid])
        if file_path.exists():
            original_bytes = file_path.read_bytes()
        feedback = await kwargs["post_session_validator"]()
        assert feedback and str(file_path) in feedback
        if failure == "wrong_field_type":
            assert "是否外部暴露面" in feedback
        # Simulate a transport success that must still never bypass the file contract.
        return _result(text="[]", structured=[])

    result, = asyncio.run(compact_native.TaskAgentSubmitter(run_opencode_task=runner).submit_tasks_async([task]))
    assert result["status"] == "failed"
    assert str(file_path) in result["error"]
    if failure == "missing":
        assert not file_path.exists()
    else:
        assert file_path.read_bytes() == original_bytes


@pytest.mark.parametrize("phase", ["map", "merge"])
@pytest.mark.parametrize("recover", [True, False])
def test_high_risk_validator_uses_real_task_service_correction_and_retry(tmp_path, compact_native, phase, recover):
    from task_agent.serve_client import OpenCodeFileWrite, OpenCodePromptResult
    from task_agent.task_service import OpenCodeTaskService, bind_opencode_execution_context
    from test_opencode_task_service import _runtime, _service_patches, _source

    task, layout = _task(compact_native, tmp_path, phase)
    calls = []

    async def run():
        service = OpenCodeTaskService()

        async def run_prompt(**kwargs):
            calls.append(kwargs)
            session_id = kwargs["session_id"] or f"module-session-{len(calls)}"
            if kwargs["session_id"] is None:
                await kwargs["on_session_id"](session_id)
            _write(task, [] if recover and len(calls) > 1 else [{"模块名称": "missing other required fields"}])
            kwargs["on_file_write"](OpenCodeFileWrite(
                call_id=f"write-{len(calls)}", path=str(task["output_path"]), created=True,
            ))
            return OpenCodePromptResult(session_id=session_id, message_id=f"message-{len(calls)}",
                                        lines=["[]"], text="[]", model="provider/model-low")

        manager = SimpleNamespace(run_prompt=run_prompt)
        service._runtime_for_task = AsyncMock(return_value=(_runtime(tmp_path), "provider/model-low", _source()))
        with ExitStack() as stack:
            mocks = [stack.enter_context(item) for item in _service_patches(manager, max_retries=1)]
            stack.enter_context(patch("task_agent.task_service._get_opencode_task_service", return_value=service))
            with bind_opencode_execution_context(project_dir=tmp_path, work_dir=layout.root):
                result, = await compact_native.TaskAgentSubmitter().submit_tasks_async([task])
                await asyncio.gather(*(record.worker for record in service._records.values()))
        assert str(task["output_path"]) in calls[1]["prompt"]
        assert [call["session_id"] for call in calls] == (
            [None, "module-session-1"] if recover else [None, "module-session-1", None, "module-session-3"]
        )
        assert result["status"] == ("succeeded" if recover else "failed"), result.get("error")
        if recover:
            assert result["output"] == []
            assert json.loads(Path(task["output_path"]).read_text(encoding="utf-8")) == []
        terminal = [call.kwargs for call in mocks[2].await_args_list if call.kwargs["record_completion"]]
        assert len(terminal) == 1
        assert terminal[0]["outcome"] == ("success" if recover else "failure")
        assert all(event["failure_kind"] == "post_session_validation_failed"
                   for event in terminal[0]["context_updates"]["session_events"]
                   if event["outcome"] == "failure")

    asyncio.run(run())


@pytest.mark.parametrize("phase", ["map", "merge"])
def test_high_risk_resume_rejects_bad_schema_and_accepts_empty_array(tmp_path, compact_native, phase):
    task, _ = _task(compact_native, tmp_path, phase)
    base = importlib.import_module(compact_native.__name__ + ".stages.base")
    _write(task, [{"模块名称": "incomplete"}])
    assert base.existing_success_result(task) is None
    _write(task, [])
    resumed = base.existing_success_result(task)
    assert resumed["status"] == "succeeded"
    assert resumed["output"] == []


@pytest.mark.parametrize("invalid_cache", ["malformed", "schema", "missing"])
def test_regenerated_map_invalidates_previously_successful_merge(tmp_path, compact_native, invalid_cache):
    source = tmp_path / "source"
    source.mkdir()
    (source / "parser.c").write_text("int parse(void) { return 0; }", encoding="utf-8")
    module = {**_module(), "代码目录": ".", "是否外部暴露面": "否", "是否涉及web相关处理": "否"}
    layout = compact_native.ThreatAnalysisLayout(tmp_path / "analysis")
    state = {"candidate": [module], "tasks": []}

    def submit(tasks, *, timeout=None):
        results = []
        for task in tasks:
            state["tasks"].append(task)
            if task["task_type"] == "value_asset_map":
                output = []
            elif task["task_type"] == "high_risk_module_map":
                field = task["metadata"]["high_risk_field"]
                output = copy.deepcopy(state["candidate"]) if module[field] == "是" else []
            else:
                assert task["task_type"] == "high_risk_module_merge"
                output = []
                for path in task["input_files"]:
                    output.extend(json.loads(Path(path).read_text(encoding="utf-8")))
            _write(task, output)
            results.append({"task_id": task["task_id"], "task_type": task["task_type"], "status": "succeeded",
                            "output": output, "output_path": task["output_path"], "metadata": task["metadata"]})
        return results

    pipeline = compact_native.ThreatAnalysisPipeline(submit_tasks=submit, layout=layout)
    first = pipeline.run(input_files=[source], code_root=source)
    assert first.high_risk_modules == [module]
    changed_task = next(task for task in state["tasks"] if task["task_type"] == "high_risk_module_map"
                        and task["metadata"]["high_risk_field"] == "是否涉及对不可信来源数据进行解析或处理的代码")
    state["tasks"].clear()
    pipeline.run(input_files=[source], code_root=source, resume=True)
    assert state["tasks"] == []

    changed_path = Path(changed_task["output_path"])
    if invalid_cache == "malformed":
        changed_path.write_text("[", encoding="utf-8")
    elif invalid_cache == "schema":
        _write(changed_task, [{"模块名称": "incomplete"}])
    else:
        changed_path.unlink()
    state["candidate"] = []
    resumed = pipeline.run(input_files=[source], code_root=source, resume=True)
    assert [task["task_id"] for task in state["tasks"]] == [changed_task["task_id"], "high-risk-module-merge"]
    assert resumed.high_risk_modules == []
    assert json.loads((layout.high_risk_final_dir / "high-risk-module-merge.json").read_text(encoding="utf-8")) == []
