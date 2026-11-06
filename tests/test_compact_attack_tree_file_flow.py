"""Compact tree tasks consume validated files, including repairs and resume."""

from __future__ import annotations

import asyncio
import copy
import importlib
import json
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from test_deephole_compact_threat_analysis import (
    COMPACT_CATALOG,
    _assets,
    _attack_tree,
    _module,
    compact_native,  # noqa: F401
)


def _tasks(native, tmp_path, *, count=1):
    trees = importlib.import_module(native.__name__ + ".stages.attack_trees")
    layout = native.ThreatAnalysisLayout(tmp_path / "artifacts with spaces")
    layout.ensure()
    module = _module()
    modules_path = tmp_path / "modules.json"
    modules_path.write_text(json.dumps([module], ensure_ascii=False), encoding="utf-8")
    stage = trees.AttackTreeStage(submit_tasks=lambda *a, **kw: [], layout=layout)
    tasks = stage.build_tasks(
        value_assets=_assets()[:count], high_risk_modules=[module],
        high_risk_modules_file=modules_path,
    )
    mode = json.loads(COMPACT_CATALOG.read_text(encoding="utf-8"))[0]
    pattern = {"pattern_id": "、".join(mode["攻击模式编号"]),
               "pattern_name": mode["攻击模式名称"], "association_description": "解析请求影响资产。"}
    outputs = [_attack_tree(task["task_id"], asset, module,
                            trees._stable_high_risk_module_id(module), [copy.deepcopy(pattern)])
               for task, asset in zip(tasks, _assets())]
    return tasks, outputs


def _write(task, output):
    path = Path(task["output_path"])
    path.write_text(json.dumps(output, ensure_ascii=False), encoding="utf-8")
    return path.read_bytes()


def _success(**overrides):
    return SimpleNamespace(status="success", text="已经写入文件。", structured=None,
                           session_id="tree-session", model="test/model", **overrides)


@pytest.mark.parametrize("repair", [False, True])
def test_tree_task_reads_file_without_overwriting_it_from_reply(tmp_path, compact_native, repair):
    tasks, outputs = _tasks(compact_native, tmp_path)
    task, expected = tasks[0], outputs[0]
    if repair:
        task.update(invoke_skill=False, session_id="tree-session", runtime_prompt="请修正叶子节点。")
    expected_bytes = None

    async def runner(**kwargs):
        nonlocal expected_bytes
        assert kwargs["output_schema"] is None
        assert kwargs["post_session_validation_retry_count"] == 1
        assert kwargs["bash_command_match_mode"] == "bound_python_script"
        assert str(task["output_path"]) in kwargs["prompt"]
        command, = kwargs["allowed_bash_commands"]
        assert command in kwargs["prompt"]
        if repair:
            assert kwargs["session_id"] == "tree-session"
            assert not kwargs["prompt"].startswith("/")
        expected_bytes = _write(task, expected)
        assert await kwargs["post_session_validator"]() is None
        # A plausible JSON response must never replace the actual model-written file.
        return SimpleNamespace(status="success", text='{"attack_trees": []}',
                               structured={"attack_trees": []}, session_id="tree-session", model="test/model")

    submitter = compact_native.TaskAgentSubmitter(run_opencode_task=runner)
    result, = asyncio.run(submitter.submit_tasks_async([task]))
    assert result["status"] == "succeeded"
    assert result["output"] == expected
    assert Path(task["output_path"]).read_bytes() == expected_bytes


@pytest.mark.parametrize("failure", ["missing", "malformed", "unknown_pattern", "mismatched_name"])
def test_tree_file_validation_feedback_rejects_invalid_artifacts(tmp_path, compact_native, failure):
    tasks, outputs = _tasks(compact_native, tmp_path)
    task, output = tasks[0], outputs[0]
    file_path = Path(task["output_path"])
    feedback = ""

    async def runner(**kwargs):
        nonlocal feedback
        if failure == "malformed":
            file_path.write_text('{"attack_trees": [\n', encoding="utf-8")
        elif failure != "missing":
            pattern = output["attack_trees"][0]["attack_paths"][0]["attack_patterns"][0]
            if failure == "unknown_pattern":
                pattern["pattern_id"] = "OUTSIDE-51"
            else:
                pattern["pattern_name"] = "不是该编号的规范名称"
            _write(task, output)
        feedback = await kwargs["post_session_validator"]()
        assert feedback and str(file_path) in feedback
        # The task service reports failure after its configured retry budget is exhausted.
        return SimpleNamespace(status="failure", text=feedback, structured=outputs[0],
                               session_id="tree-session", model="test/model")

    result, = asyncio.run(compact_native.TaskAgentSubmitter(run_opencode_task=runner).submit_tasks_async([task]))
    assert result["status"] == "failed"
    assert feedback in result["error"]
    if failure == "missing":
        assert not file_path.exists()
    elif failure == "malformed":
        assert file_path.read_text(encoding="utf-8") == '{"attack_trees": [\n'
    else:
        assert json.loads(file_path.read_text(encoding="utf-8")) == output


def test_tree_file_can_be_corrected_using_the_same_validator(tmp_path, compact_native):
    tasks, outputs = _tasks(compact_native, tmp_path)
    task, expected = tasks[0], outputs[0]

    async def runner(**kwargs):
        invalid = copy.deepcopy(expected)
        invalid["attack_trees"][0]["attack_paths"][0]["attack_patterns"][0]["pattern_id"] = "OUTSIDE-51"
        _write(task, invalid)
        feedback = await kwargs["post_session_validator"]()
        assert "OUTSIDE-51" in feedback
        _write(task, expected)
        assert await kwargs["post_session_validator"]() is None
        return _success()

    result, = asyncio.run(compact_native.TaskAgentSubmitter(run_opencode_task=runner).submit_tasks_async([task]))
    assert result["status"] == "succeeded"
    assert result["output"] == expected


def test_fresh_tree_task_cannot_accept_a_leftover_file_without_new_output(tmp_path, compact_native):
    tasks, outputs = _tasks(compact_native, tmp_path)
    task = tasks[0]
    _write(task, outputs[0])

    async def runner(**kwargs):
        assert not Path(task["output_path"]).exists()
        feedback = await kwargs["post_session_validator"]()
        assert feedback and str(task["output_path"]) in feedback
        return SimpleNamespace(status="failure", text=feedback, structured=outputs[0],
                               session_id="new-session", model="test/model")

    result, = asyncio.run(compact_native.TaskAgentSubmitter(run_opencode_task=runner).submit_tasks_async([task]))
    assert result["status"] == "failed"
    assert not Path(task["output_path"]).exists()


@pytest.mark.parametrize("recover", [True, False])
def test_compact_file_validator_participates_in_real_task_service_retries(tmp_path, compact_native, recover):
    from task_agent.serve_client import OpenCodeFileWrite, OpenCodePromptResult
    from task_agent.task_service import OpenCodeTaskService, bind_opencode_execution_context
    from test_opencode_task_service import _runtime, _service_patches, _source

    tasks, outputs = _tasks(compact_native, tmp_path)
    task, expected = tasks[0], outputs[0]
    calls = []

    async def run():
        service = OpenCodeTaskService()

        async def run_prompt(**kwargs):
            calls.append(kwargs)
            session_id = kwargs["session_id"] or f"compact-session-{len(calls)}"
            if kwargs["session_id"] is None:
                await kwargs["on_session_id"](session_id)
            output = copy.deepcopy(expected)
            if not recover or len(calls) == 1:
                output["attack_trees"][0]["attack_paths"][0]["attack_patterns"][0]["pattern_id"] = "OUTSIDE-51"
            _write(task, output)
            kwargs["on_file_write"](OpenCodeFileWrite(
                call_id=f"write-{len(calls)}", path=str(task["output_path"]), created=True,
            ))
            return OpenCodePromptResult(session_id=session_id, message_id=f"message-{len(calls)}",
                                        lines=["文件已写入。"], text="文件已写入。", model="provider/model-low")

        manager = SimpleNamespace(run_prompt=run_prompt)
        service._runtime_for_task = AsyncMock(return_value=(_runtime(tmp_path), "provider/model-low", _source()))
        with ExitStack() as stack:
            mocks = [stack.enter_context(item) for item in _service_patches(
                manager, max_retries=1, writable_roots=(tmp_path,),
            )]
            stack.enter_context(patch("task_agent.task_service._get_opencode_task_service", return_value=service))
            with bind_opencode_execution_context(project_dir=tmp_path, work_dir=tmp_path / "artifacts with spaces"):
                result, = await compact_native.TaskAgentSubmitter().submit_tasks_async([task])
                await asyncio.gather(*(record.worker for record in service._records.values()))
        assert "OUTSIDE-51" in calls[1]["prompt"]
        assert str(task["output_path"]) in calls[1]["prompt"]
        assert [call["session_id"] for call in calls] == (
            [None, "compact-session-1"] if recover else [None, "compact-session-1", None, "compact-session-3"]
        )
        assert result["status"] == ("succeeded" if recover else "failed"), result.get("error")
        if recover:
            assert result["output"] == expected
        else:
            assert "OUTSIDE-51" in result["error"]
        terminal = [call.kwargs for call in mocks[2].await_args_list if call.kwargs["record_completion"]]
        assert len(terminal) == 1
        assert terminal[0]["outcome"] == ("success" if recover else "failure")
        events = terminal[0]["context_updates"]["session_events"]
        assert all(event["failure_kind"] == "post_session_validation_failed"
                   for event in events if event["outcome"] == "failure")

    asyncio.run(run())


def test_asset_task_keeps_structured_output_contract(tmp_path, compact_native):
    assets = importlib.import_module(compact_native.__name__ + ".stages.value_assets")
    layout = compact_native.ThreatAnalysisLayout(tmp_path / "analysis")
    layout.ensure()
    stage = assets.ValueAssetStage(submit_tasks=lambda *a, **kw: [], layout=layout)
    task = stage.build_task(input_files=[tmp_path / "source"])
    expected = _assets()

    async def runner(**kwargs):
        assert kwargs["output_schema"] == task["output_schema"]
        assert kwargs.get("post_session_validator") is None
        return SimpleNamespace(status="success", text="[]", structured=expected,
                               session_id="asset-session", model="test/model")

    result, = asyncio.run(compact_native.TaskAgentSubmitter(run_opencode_task=runner).submit_tasks_async([task]))
    assert result["status"] == "succeeded"
    assert result["output"] == expected
    assert json.loads(Path(task["output_path"]).read_text(encoding="utf-8")) == expected


@pytest.mark.parametrize("correct_leaf", [True, False])
def test_stage_repairs_non_external_leaf_in_same_file_or_prunes_it(tmp_path, compact_native, correct_leaf):
    trees = importlib.import_module(compact_native.__name__ + ".stages.attack_trees")
    baselines = importlib.import_module(compact_native.__name__ + ".baselines")
    layout = compact_native.ThreatAnalysisLayout(tmp_path / "analysis")
    layout.ensure()
    asset = _assets()[0]
    external = _module()
    internal = {**external, "模块名称": "内部处理模块", "代码目录": "src/internal", "是否外部暴露面": "否"}
    modules = [external, internal]
    modules_path = tmp_path / "modules.json"
    modules_path.write_text(json.dumps(modules, ensure_ascii=False), encoding="utf-8")
    output_path = layout.attack_trees_raw_dir / "attack-tree-by-asset-001.json"
    calls = []

    async def runner(**kwargs):
        calls.append(kwargs)
        if len(calls) == 2:
            assert kwargs["session_id"] == "tree-session"
            assert not kwargs["prompt"].startswith("/")
            assert str(output_path) in kwargs["prompt"]
            assert "内部处理模块" in kwargs["prompt"]
            # A semantic repair edits the previous artifact instead of starting with a blank file.
            previous = json.loads(output_path.read_text(encoding="utf-8"))
            assert previous["attack_trees"][0]["nodes"][1]["module_name"] == "内部处理模块"
        module = external if len(calls) == 2 and correct_leaf else internal
        output = _attack_tree(kwargs["task_name"], asset, module,
                              trees._stable_high_risk_module_id(module), [])
        _write({"output_path": output_path}, output)
        # Catalog/schema validation must allow the existing later semantic repair to run.
        assert await kwargs["post_session_validator"]() is None
        return _success()

    submitter = compact_native.TaskAgentSubmitter(run_opencode_task=runner)
    stage = trees.AttackTreeStage(submit_tasks=submitter.submit_tasks, layout=layout)
    result = stage.run(value_assets=[asset], high_risk_modules=modules,
                       high_risk_modules_file=modules_path)
    assert [call["session_id"] for call in calls] == [None, "tree-session"]
    assert json.loads((layout.attack_trees_final_dir / "attack_trees.json").read_text(encoding="utf-8")) == result
    if correct_leaf:
        tree, = result["attack_trees"]
        leaf = next(node for node in tree["nodes"] if node["node_type"] == "叶子节点")
        assert leaf["module_name"] == external["模块名称"]
        assert leaf["external_exposure"] is True
    else:
        assert result["attack_trees"] == []
        assert json.loads(output_path.read_text(encoding="utf-8")) == {"attack_trees": []}
    records = [record for tree in result["attack_trees"] for record in tree.get("module_pattern_baselines", [])]
    records.extend(result.get("unassigned_module_pattern_baselines", []))
    assert {record["module_name"] for record in records} == {module["模块名称"] for module in modules}
    assert all({pattern["pattern_id"] for pattern in record["attack_patterns"]}
               == set(baselines.BASELINE_PATTERN_IDS) for record in records)


@pytest.mark.parametrize("invalid_kind", ["unknown_pattern", "mismatched_name", "duplicate"])
def test_resume_rebuilds_only_the_tree_with_invalid_patterns(tmp_path, compact_native, invalid_kind):
    tasks, outputs = _tasks(compact_native, tmp_path, count=2)
    for task, output in zip(tasks, outputs):
        _write(task, output)
    bad = copy.deepcopy(outputs[1])
    patterns = bad["attack_trees"][0]["attack_paths"][0]["attack_patterns"]
    if invalid_kind == "unknown_pattern":
        patterns[0]["pattern_id"] = "OUTSIDE-51"
    elif invalid_kind == "mismatched_name":
        patterns[0]["pattern_name"] = "不匹配的名称"
    else:
        patterns.append(copy.deepcopy(patterns[0]))
    _write(tasks[1], bad)
    base = importlib.import_module(compact_native.__name__ + ".stages.base")
    submitted = []

    def submit_tasks(pending, *, timeout=None):
        submitted.extend(task["task_id"] for task in pending)
        _write(tasks[1], outputs[1])
        return [{"task_id": tasks[1]["task_id"], "status": "succeeded", "output": outputs[1]}]

    results = base.run_or_resume_tasks(submit_tasks=submit_tasks, tasks=tasks, resume=True,
                                       validate_existing_output_schema=True)
    assert submitted == [tasks[1]["task_id"]]
    assert [result["output"] for result in results] == outputs

    def no_tasks(*args, **kwargs):
        pytest.fail("Valid cached trees should be reused without another model task")

    results = base.run_or_resume_tasks(submit_tasks=no_tasks, tasks=tasks, resume=True,
                                       validate_existing_output_schema=True)
    assert [result["output"] for result in results] == outputs
