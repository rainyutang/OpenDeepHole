from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from types import SimpleNamespace

import pytest

from backend.models import ThreatPatternAuditTask
from task_agent import OpenCodeResult
from deephole_client.vulnerability_mining.engines.threat_pattern_audit import engine as original
from deephole_client.vulnerability_mining.engines.threat_pattern_audit.prompt import build_threat_pattern_prompt
from deephole_client.vulnerability_mining.engines.threat_pattern_audit.task_tracking import PatternTaskTracker
from deephole_client.vulnerability_mining.engines.threat_pattern_iterative_audit import engine
from deephole_client.vulnerability_mining.engines.threat_pattern_iterative_audit.prompt import (
    ITERATIVE_VULNERABILITY_LIST_SCHEMA, build_iterative_prompt,
)
from test_threat_pattern_audit import TaskReporter, _artifacts, _finding


def finding(round_number=1, *, more=True, clues=None):
    return {**_finding(), "line": 88 + round_number,
            "description": f"独立问题 {round_number}", "has_more_findings": more,
            "followup_clues": f"src/auth/session.c 的线索 {round_number}" if clues is None else clues}


@pytest.fixture
def harness(tmp_path, monkeypatch):
    tree, modules = _artifacts(tmp_path)
    work = tmp_path / "work"
    reporter = TaskReporter()
    cancel = threading.Event()
    calls, reports, events = [], [], []
    state = SimpleNamespace(outcomes={}, cancel_after=0, report_failure=False)

    async def invoke(**values):
        calls.append(values)
        round_number = int(values["task_name"].rsplit("-", 1)[1])
        await values["lease_state_callback"]("queued")
        await values["lease_state_callback"]("running")
        payload = state.outcomes.get(round_number, [finding(round_number)])
        if isinstance(payload, str):
            return OpenCodeResult(status=payload, text="round failed", structured=None, model="test/model", session_id=f"session-{round_number}",
                                  output_source={"model": "test/model"})
        path = work / "task-results" / f"{values['task_name']}.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        assert await values["post_session_validator"]() is None
        if state.cancel_after == round_number:
            cancel.set()
        return OpenCodeResult(status="success", text="done", structured=None, model="test/model", session_id=f"session-{round_number}",
                              output_source={"model": "test/model"})

    async def report(values):
        if state.report_failure:
            raise RuntimeError("transport unavailable")
        reports.extend(values)
        # The platform rejecting a duplicate must not discard the model's other clues.
        return [(values[0], {"deduplicated": True})]

    async def output(event):
        events.append(event)

    monkeypatch.setattr(engine, "run_opencode_task", invoke)
    kwargs = dict(engine_id=engine.ENGINE_ID, scan_id="iterative", project_path=tmp_path,
                  code_scan_path=tmp_path, work_dir=work, reporter=reporter, cancel_event=cancel,
                  config=SimpleNamespace(opencode_concurrency=1), report_vulnerabilities=report,
                  output=output, threat_analysis_result={"result": True, "attack_tree_path": str(tree),
                                                        "high_risk_modules_path": str(modules)})
    return SimpleNamespace(kwargs=kwargs, state=state, calls=calls, reports=reports, events=events,
                           reporter=reporter, cancel=cancel, work=work, tree=tree, modules=modules)


def test_three_rounds_are_distinct_clue_guided_and_resume_without_model_calls(harness):
    h = harness
    outcome = asyncio.run(engine.run(**h.kwargs))
    assert outcome == {"status": "success", "error_message": "", "total_candidates": 3, "processed_candidates": 3}
    assert len(h.calls) == len(h.reports) == len(h.reporter.tasks) == 3
    assert len({call["task_name"] for call in h.calls}) == 3
    for index, call in enumerate(h.calls, 1):
        assert call["task_name"].endswith(f"-round-{index}")
        assert "session_id" not in call
        assert call["required_bash_commands"] == call["allowed_bash_commands"]
        assert call["required_bash_success_markers"] == {call["allowed_bash_commands"][0]: "ok"}
        assert call["required_bash_retry_count"] == 1
        assert call["output_schema"] is None
        assert call["prompt"].rstrip().endswith(call["allowed_bash_commands"][0])
        assert "已发现问题列表：" in call["prompt"]
        if index > 1:
            assert call["prompt"].splitlines()[1] == f"审计时参考线索：{finding(index - 1)['followup_clues']}"
        else:
            assert "审计时参考线索" not in call["prompt"]
        task = h.reporter.tasks[call["task_name"]]
        assert task.iteration == index and task.engine_id == engine.ENGINE_ID
        assert task.parent_task_id == (h.calls[index - 2]["task_name"] if index > 1 else "")
        assert task.has_more_findings is True
        assert task.output_source.serve_session_id == f"session-{index}"
        report = h.reports[index - 1]
        assert report["source_task_id"] == task.task_id
        assert report["analysis_source"] == engine.ENGINE_ID
        assert "has_more_findings" not in report and "followup_clues" not in report
        assert report["vulnerability_report"]
    assert len(json.loads((h.work / "previous-findings.json").read_text())) == 3
    assert len(list((h.work / ".completed-task-results").glob("*.json"))) == 3
    assert [(item["data"]["current"], item["data"]["total"]) for item in h.events if "current" in item["data"]] == [
        (0, 1), (1, 1), (1, 2), (2, 2), (2, 3), (3, 3)]
    snapshots = {key: task.model_dump() for key, task in h.reporter.tasks.items()}
    previous_updates = len(h.reporter.updates)
    resumed = asyncio.run(engine.run(is_resume=True, **h.kwargs))
    assert resumed == outcome
    assert len(h.calls) == 3
    assert len(json.loads((h.work / "previous-findings.json").read_text())) == 3
    assert len(h.reporter.updates) == previous_updates
    assert {key: task.model_dump() for key, task in h.reporter.tasks.items()} == snapshots


@pytest.mark.parametrize("outcomes,count", [
    ({1: []}, 1), ({1: [finding(more=False, clues="")]}, 1),
    ({1: [finding(clues="  \n")]}, 1), ({2: []}, 2),
    ({2: [finding(2, more=False, clues="")]}, 2),
])
def test_empty_or_missing_followup_stops_without_forcing_clues(harness, outcomes, count):
    harness.state.outcomes = outcomes
    result = asyncio.run(engine.run(**harness.kwargs))
    assert result["status"] == "success"
    assert result["total_candidates"] == result["processed_candidates"] == count
    assert len(harness.calls) == count


@pytest.mark.parametrize("round_number", [1, 2])
def test_cancel_after_success_marker_reuses_round_and_retains_total_budget(harness, round_number):
    h = harness
    h.state.cancel_after = round_number
    result = asyncio.run(engine.run(**h.kwargs))
    assert result["status"] == "cancelled"
    assert len(h.calls) == round_number
    assert len(list((h.work / ".completed-task-results").glob("*.json"))) == round_number
    assert h.reporter.tasks[h.calls[-1]["task_name"]].output_source.serve_session_id == f"session-{round_number}"
    h.cancel.clear()
    h.state.cancel_after = 0
    result = asyncio.run(engine.run(is_resume=True, **h.kwargs))
    assert result["status"] == "success" and result["total_candidates"] == 3
    assert len(h.calls) == 3


def test_reporting_failure_keeps_successful_artifact_for_replay(harness):
    h = harness
    h.state.report_failure = True
    result = asyncio.run(engine.run(**h.kwargs))
    assert result["status"] == "error" and "transport unavailable" in result["error_message"]
    assert len(h.calls) == 1
    h.state.report_failure = False
    result = asyncio.run(engine.run(is_resume=True, **h.kwargs))
    assert result["status"] == "success" and len(h.calls) == 3


def test_failed_second_round_restarts_only_remaining_rounds(harness):
    h = harness
    h.state.outcomes[2] = "timeout"
    result = asyncio.run(engine.run(**h.kwargs))
    assert result["status"] == "error" and len(h.calls) == 2
    failed = h.reporter.tasks[h.calls[-1]["task_name"]]
    assert failed.status == "timeout" and failed.output_source.serve_session_id == "session-2"
    h.state.outcomes.clear()
    result = asyncio.run(engine.run(is_resume=True, **h.kwargs))
    assert result["status"] == "success"
    assert [call["task_name"].rsplit("-", 1)[1] for call in h.calls] == ["1", "2", "2", "3"]


def test_changed_parent_invalidates_child_input_and_unreachable_rounds(harness):
    h = harness
    asyncio.run(engine.run(**h.kwargs))
    first = h.calls[0]["task_name"]
    result_path = h.work / "task-results" / f"{first}.json"
    result_path.write_text(json.dumps([finding(clues="changed clues")]))
    marker_path = h.work / ".completed-task-results" / f"{first}.json"
    marker = json.loads(marker_path.read_text())
    marker["result_sha256"] = hashlib.sha256(result_path.read_bytes()).hexdigest()
    marker_path.write_text(json.dumps(marker))
    h.state.outcomes[2] = []
    result = asyncio.run(engine.run(is_resume=True, **h.kwargs))
    assert result["status"] == "success" and result["total_candidates"] == 2
    assert len(h.calls) == 4
    assert h.calls[-1]["task_name"].endswith("-round-2")
    assert "审计时参考线索：changed clues" in h.calls[-1]["prompt"]
    assert h.reporter.tasks[h.calls[2]["task_name"]].status == "superseded"


def test_engine_trackers_do_not_supersede_other_engine_tasks(harness):
    h = harness
    h.reporter.tasks["old-task"] = ThreatPatternAuditTask(task_id="old-task", status="completed")
    asyncio.run(engine.run(is_resume=True, **h.kwargs))
    assert h.reporter.tasks["old-task"].status == "completed"
    new_ids = [call["task_name"] for call in h.calls]
    tracker = PatternTaskTracker("iterative", h.reporter)
    asyncio.run(tracker.prepare([], original._task_id, resume=True))
    assert all(h.reporter.tasks[key].status == "completed" for key in new_ids)


def test_history_is_visible_before_followup(harness, monkeypatch):
    h = harness
    invoke = engine.run_opencode_task

    async def check(**values):
        round_number = int(values["task_name"].rsplit("-", 1)[1])
        history = json.loads((h.work / "previous-findings.json").read_text())
        assert len(history) == round_number - 1
        return await invoke(**values)

    monkeypatch.setattr(engine, "run_opencode_task", check)
    assert asyncio.run(engine.run(**h.kwargs))["status"] == "success"


def test_history_is_shared_across_targets(harness, monkeypatch):
    h = harness
    tree = json.loads(h.tree.read_text())
    tree["attack_trees"][0]["attack_paths"][0]["attack_patterns"].append({
        "pattern_id": "SECOND-PATTERN", "pattern_name": "另一个攻击模式"})
    h.tree.write_text(json.dumps(tree))
    h.state.outcomes[1] = [finding(more=False, clues="")]
    invoke = engine.run_opencode_task

    async def check(**values):
        history = json.loads((h.work / "previous-findings.json").read_text())
        assert len(history) == len(h.calls)
        return await invoke(**values)

    monkeypatch.setattr(engine, "run_opencode_task", check)
    result = asyncio.run(engine.run(**h.kwargs))
    assert result["status"] == "success" and len(h.calls) == 2


def test_changed_pattern_description_invalidates_all_round_inputs(harness, monkeypatch):
    h = harness
    assert asyncio.run(engine.run(**h.kwargs))["status"] == "success"
    monkeypatch.setattr(original, "_load_pattern_descriptions", lambda: {
        ("SYS-AUTH-02", "会话伪造"): "updated pattern context"})
    result = asyncio.run(engine.run(is_resume=True, **h.kwargs))
    assert result["status"] == "success" and len(h.calls) == 6
    assert all("updated pattern context" in call["prompt"] for call in h.calls[3:])


def test_resume_rejects_changed_scan_scope_before_reusing_results(harness):
    h = harness
    assert asyncio.run(engine.run(**h.kwargs))["status"] == "success"
    values = {**h.kwargs, "is_resume": True, "code_scan_path": h.kwargs["project_path"] / "src/auth"}
    result = asyncio.run(engine.run(**values))
    assert result["status"] == "error" and "scan scope mismatch" in result["error_message"]
    assert len(h.calls) == 3


def test_cached_path_error_keeps_result_for_same_session_repair(harness, monkeypatch):
    h = harness
    h.state.outcomes[1] = [finding(more=False, clues="")]
    assert asyncio.run(engine.run(**h.kwargs))["status"] == "success"
    task_id = h.calls[0]["task_name"]
    result_path = h.work / "task-results" / f"{task_id}.json"
    payload = [{**finding(more=False, clues=""), "file": "src/auth/missing.c"}]
    result_path.write_text(json.dumps(payload))
    marker_path = h.work / ".completed-task-results" / f"{task_id}.json"
    marker = json.loads(marker_path.read_text())
    marker["result_sha256"] = hashlib.sha256(result_path.read_bytes()).hexdigest()
    marker_path.write_text(json.dumps(marker))
    invoke = engine.run_opencode_task

    async def repair(**values):
        assert values["session_id"] == "session-1"
        assert json.loads(result_path.read_text()) == payload
        assert "此前的结果文件未通过路径校验" in values["prompt"]
        assert "src/auth/missing.c" in values["prompt"]
        return await invoke(**values)

    monkeypatch.setattr(engine, "run_opencode_task", repair)
    result = asyncio.run(engine.run(is_resume=True, **h.kwargs))
    assert result["status"] == "success" and len(h.calls) == 2
    assert json.loads(result_path.read_text()) == h.state.outcomes[1]


def test_cancellation_closes_saved_unvisited_rounds_without_new_session(harness, monkeypatch):
    h = harness
    assert asyncio.run(engine.run(**h.kwargs))["status"] == "success"
    last = h.calls[-1]["task_name"]
    h.reporter.tasks[last].status = "queued"
    report = h.kwargs["report_vulnerabilities"]

    async def cancel_on_cached_report(values):
        result = await report(values)
        h.cancel.set()
        return result

    h.kwargs["report_vulnerabilities"] = cancel_on_cached_report
    assert asyncio.run(engine.run(is_resume=True, **h.kwargs))["status"] == "cancelled"
    assert len(h.calls) == 3
    assert h.reporter.tasks[last].status == "cancelled"


def test_parallel_targets_do_not_lose_history_updates(harness, monkeypatch):
    h = harness
    tree = json.loads(h.tree.read_text())
    tree["attack_trees"][0]["attack_paths"][0]["attack_patterns"].append({
        "pattern_id": "SECOND-PATTERN", "pattern_name": "另一个攻击模式"})
    h.tree.write_text(json.dumps(tree))
    h.kwargs["config"].opencode_concurrency = 2
    ready = asyncio.Event()

    async def invoke(**values):
        h.calls.append(values)
        number = len(h.calls)
        if number == 2:
            ready.set()
        await asyncio.wait_for(ready.wait(), timeout=2)
        payload = [finding(number, more=False, clues="")]
        path = h.work / "task-results" / f"{values['task_name']}.json"
        path.write_text(json.dumps(payload))
        assert await values["post_session_validator"]() is None
        return OpenCodeResult(status="success", text="done", structured=None, model="test/model",
                              session_id=f"parallel-{number}", output_source={"model": "test/model"})

    monkeypatch.setattr(engine, "run_opencode_task", invoke)
    assert asyncio.run(engine.run(**h.kwargs))["status"] == "success"
    history = json.loads((h.work / "previous-findings.json").read_text())
    assert len(history) == 2 and {item["line"] for item in history} == {89, 90}


@pytest.mark.parametrize("field,value", [("has_more_findings", "true"), ("has_more_findings", 1),
                                         ("followup_clues", None), ("followup_clues", [])])
def test_control_fields_have_strict_types(field, value):
    payload = finding()
    payload[field] = value
    with pytest.raises(ValueError):
        original.validate_schema([payload], ITERATIVE_VULNERABILITY_LIST_SCHEMA)


@pytest.mark.parametrize("field", ["has_more_findings", "followup_clues"])
def test_control_fields_are_required(field):
    payload = finding()
    payload.pop(field)
    with pytest.raises(ValueError, match="missing required"):
        original.validate_schema([payload], ITERATIVE_VULNERABILITY_LIST_SCHEMA)


def test_prompt_only_changes_approved_business_text_and_has_exact_end():
    values = dict(module_name="模块", code_paths="src/a.c", pattern_name="威胁", pattern_description="描述",
                  project_path="/project", scan_paths="/project/src", previous_findings_path="history.json",
                  schema_path="schema.json", result_path="result.json", validation_command="python validate.py")
    plain = build_threat_pattern_prompt(**values)
    expected = plain.replace("所有字段必须填写且不得为空", "所有报告字段必须填写且不得为空")
    extra = "- `has_more_findings` 表示是否发现当前模块中同一攻击模式下其他不同问题的线索；有线索时可在 `followup_clues` 中简述相关位置和疑似问题，没有线索时填写 false 和空字符串。\n"
    expected = expected.replace("- 完整审计后仍无法确认", extra + "- 完整审计后仍无法确认")
    expected = expected.replace("找到 1 个合格问题后即可停止；", "")
    assert build_iterative_prompt(**values) == expected
    clues = "src/a.c: {candidate}\nnext clue"
    followup = build_iterative_prompt(**values, followup_clues=clues)
    assert followup == expected.replace("在该模块尝试", f"审计时参考线索：{clues}\n在该模块尝试", 1)
    assert followup.rstrip().endswith("python validate.py")
    assert "上一轮" not in followup and "不要求额外寻找" not in followup
    assert "宿主会重新读取" not in followup
    assert "写入后运行以下命令自检，必须返回 `ok` 才认为任务完成：" in followup


def test_repeated_state_does_not_publish_duplicate_snapshots(harness):
    h = harness

    async def run():
        tracker = PatternTaskTracker("iterative", h.reporter, engine_id=engine.ENGINE_ID)
        targets = original._build_targets(json.loads(h.tree.read_text()), json.loads(h.modules.read_text()),
                                          fallback_code_path=h.kwargs["project_path"])
        await tracker.prepare(targets, engine._task_id, resume=False)
        key = next(iter(tracker.tasks))
        await tracker.state(key, "queued")
        await tracker.state(key, "queued")
        await tracker.state(key, "running")
        await tracker.state(key, "running")
        await tracker.state(key, "completed", has_more_findings=False, followup_clues="")
        await tracker.state(key, "completed", has_more_findings=False, followup_clues="")

    asyncio.run(run())
    assert [task.status for task in h.reporter.updates] == ["pending", "queued", "running", "completed"]
