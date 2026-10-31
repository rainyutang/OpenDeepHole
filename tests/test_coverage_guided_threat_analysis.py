from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from task_agent import opencode_task_context
from task_agent.task_service import get_opencode_execution_context
from test_codex_goal_threat_analysis import _valid_artifacts
from test_opencode_lightweight_threat_analysis import _implementation


METHOD_ID = "opencode_coverage_guided_lightweight_threat_analysis"


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _initial_artifacts(paths: dict[str, Path]) -> None:
    assets, modules, tree_data = _valid_artifacts()
    _write(paths["value_asset_path"], assets)
    _write(paths["high_risk_modules_path"], modules)
    tree_root = paths["attack_tree_path"]
    tree_root.mkdir(parents=True, exist_ok=True)
    tree = tree_data["attack_trees"][0]
    _write(tree_root / "index.json", {
        "attack_trees": [{"tree_id": tree["tree_id"], "file": "attack-tree-001.json"}],
    })
    _write(tree_root / "attack-tree-001.json", tree)


def _negative_delta(code_root: Path, round_root: Path, targets: list[str]) -> None:
    results = []
    for target in targets:
        path = code_root / target
        evidence = path if path.is_file() else next(path.rglob("*.c"))
        results.append({
            "input_path": target,
            "path": target,
            "status": "complete",
            "classification": "non_high_risk",
            "reason": "Only local formatting helpers; no untrusted input or security decision",
            "evidence": [{
                "file": evidence.relative_to(code_root).as_posix(),
                "line_start": 1,
                "line_end": 1,
            }],
        })
    _write(round_root / "delta.json", {
        "path_results": results,
        "module_updates": [],
        "new_modules": [],
        "new_value_assets": [],
    })
    _write(round_root / "attack-trees" / "index.json", {"attack_trees": []})


@pytest.fixture
def setup_scan(tmp_path: Path):
    implementation = _implementation(METHOD_ID)
    code_root = tmp_path / "source"
    output = tmp_path / "output"

    def prepare(uncovered: int = 0) -> tuple[Path, dict]:
        source_file = code_root / "src" / "auth" / "input.c"
        source_file.parent.mkdir(parents=True, exist_ok=True)
        source_file.write_text("int authenticate(void) { return 1; }\n", encoding="utf-8")
        for number in range(uncovered):
            path = code_root / f"uncovered-{number:02}" / "helper.c"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("int format(void) { return 0; }\n", encoding="utf-8")
        entries = [{"path": ".", "kind": "directory"}]
        entries.extend({
            "path": path.relative_to(code_root).as_posix(),
            "kind": "directory" if path.is_dir() else "file",
        } for path in sorted(code_root.rglob("*")))
        inventory = {
            "schema_version": 1,
            "snapshot_id": "coverage-workflow-test",
            "status": "complete",
            "project_path": str(code_root),
            "scan_root": str(code_root),
            "captured_at": "2026-10-30T00:00:00+00:00",
            "entries": entries,
            "issues": [],
            "issue_count": 0,
            "excluded_paths": [],
            "error_message": "",
        }
        inventory_path = output / "coverage-input" / "file-inventory.json"
        _write(inventory_path, inventory)
        return inventory_path, inventory

    return implementation, code_root, output, prepare


def _mock_initial(implementation, monkeypatch):
    calls = []

    async def initial(**kwargs):
        calls.append(kwargs)
        _initial_artifacts(kwargs["paths"])
        return SimpleNamespace(status="success", session_id="initial-session", text="done")

    monkeypatch.setattr(implementation, "_run_task", initial)
    return calls


def test_two_batches_recompute_candidates_and_preserve_original_artifacts(setup_scan, monkeypatch):
    implementation, code_root, output, prepare = setup_scan
    prepare(12)
    initial_calls = _mock_initial(implementation, monkeypatch)
    supplemental_calls = []
    initial_tree = {}

    async def supplement(**kwargs):
        supplemental_calls.append(kwargs)
        tree_path = output / "final" / "attack-trees" / "attack-tree-001.json"
        initial_tree.setdefault("bytes", tree_path.read_bytes())
        assert tree_path.read_bytes() == initial_tree["bytes"]
        _negative_delta(code_root, kwargs["round_root"], kwargs["targets"])
        return SimpleNamespace(status="success", session_id=f"supplement-{kwargs['round_number']}", text="done")

    monkeypatch.setattr(implementation, "_run_supplement_task", supplement)
    result = implementation.run_threat_analysis(code_root, output)

    assert result["result"] is True
    assert len(initial_calls) == 1
    assert len(supplemental_calls) == 2
    first, second = supplemental_calls
    assert len(first["targets"]) == len(second["targets"]) == 5
    assert set(first["targets"]).isdisjoint(second["targets"])
    assert [item["round_number"] for item in supplemental_calls] == [1, 2]
    assert first["baseline"] != second["baseline"]
    assert (output / "final" / "attack-trees" / "attack-tree-001.json").read_bytes() == initial_tree["bytes"]
    report = json.loads(Path(result["coverage_report_path"]).read_text(encoding="utf-8"))
    assert report["stop_reason"] == "round_limit"
    assert len(report["rounds"]) == 2
    assert len(report["non_high_risk_paths"]) == 10
    assert report["remaining_uncovered_files"] == 12
    assert report["pending_files"] == 2
    assert json.loads(Path(result["high_risk_modules_path"]).read_text(encoding="utf-8")) == _valid_artifacts()[1]


def test_no_candidates_skips_supplement_tasks(setup_scan, monkeypatch):
    implementation, code_root, output, prepare = setup_scan
    prepare()
    _mock_initial(implementation, monkeypatch)
    supplement = AsyncMock(side_effect=AssertionError("fully covered scan must not supplement"))
    monkeypatch.setattr(implementation, "_run_supplement_task", supplement)

    result = implementation.run_threat_analysis(code_root, output)

    assert result["result"] is True
    supplement.assert_not_awaited()
    report = json.loads(Path(result["coverage_report_path"]).read_text(encoding="utf-8"))
    assert report["stop_reason"] == "no_candidates"
    assert report["remaining_uncovered_files"] == 0


@pytest.mark.parametrize("invalid", ["partial", "wrong_scope"])
def test_unusable_inventory_keeps_initial_result(setup_scan, monkeypatch, invalid):
    implementation, code_root, output, prepare = setup_scan
    inventory_path, inventory = prepare(1)
    if invalid == "partial":
        inventory["status"] = "partial"
    else:
        inventory["scan_root"] = str(code_root / "elsewhere")
    _write(inventory_path, inventory)
    _mock_initial(implementation, monkeypatch)
    supplement = AsyncMock(side_effect=AssertionError("unusable inventory must not guide selection"))
    monkeypatch.setattr(implementation, "_run_supplement_task", supplement)

    result = implementation.run_threat_analysis(code_root, output)

    assert result["result"] is True
    supplement.assert_not_awaited()
    assert Path(result["attack_tree_path"]).is_dir()
    report = json.loads(Path(result["coverage_report_path"]).read_text(encoding="utf-8"))
    assert report["stop_reason"] == "inventory_unavailable"


def test_failed_supplement_preserves_last_valid_result_and_reports_gap(setup_scan, monkeypatch):
    implementation, code_root, output, prepare = setup_scan
    prepare(6)
    _mock_initial(implementation, monkeypatch)
    calls = []

    async def supplement(**kwargs):
        calls.append(kwargs)
        if kwargs["round_number"] == 1:
            _negative_delta(code_root, kwargs["round_root"], kwargs["targets"])
            return SimpleNamespace(status="success", session_id="supplement-1", text="done")
        (kwargs["round_root"] / "delta.json").write_text("{", encoding="utf-8")
        return SimpleNamespace(status="failure", session_id="supplement-2", text="validation retries exhausted")

    monkeypatch.setattr(implementation, "_run_supplement_task", supplement)
    result = implementation.run_threat_analysis(code_root, output)

    assert result["result"] is True
    assert len(calls) == 2
    assert Path(result["high_risk_modules_path"]).parent == calls[1]["baseline"]
    report = json.loads(Path(result["coverage_report_path"]).read_text(encoding="utf-8"))
    assert report["stop_reason"] == "supplement_failed"
    assert report["remaining_uncovered_files"] == 6
    assert report["pending_files"] == 1
    assert len(report["non_high_risk_paths"]) == 5
    assert "validation retries exhausted" in json.dumps(report)


def test_module_path_extension_and_independent_tree_are_used_by_next_batch(setup_scan, monkeypatch):
    implementation, code_root, output, prepare = setup_scan
    prepare(6)
    _mock_initial(implementation, monkeypatch)
    calls = []

    async def supplement(**kwargs):
        calls.append(kwargs)
        round_root = kwargs["round_root"]
        _negative_delta(code_root, round_root, kwargs["targets"])
        if kwargs["round_number"] == 1:
            delta = json.loads((round_root / "delta.json").read_text(encoding="utf-8"))
            for result in delta["path_results"]:
                result["classification"] = "existing_module"
                result["module_name"] = "认证入口"
                result["reason"] = "The helper is part of the authentication input handling module"
            delta["module_updates"] = [{
                "module_name": "认证入口",
                "add_code_paths": list(kwargs["targets"]),
                "set_fields": {"面临威胁": "认证请求处理和辅助缓冲区中的输入风险"},
            }]
            _write(round_root / "delta.json", delta)
            tree = _valid_artifacts()[2]["attack_trees"][0]
            tree["nodes"][1]["description"] = "补查识别的认证输入辅助路径"
            _write(round_root / "attack-trees" / "index.json", {"attack_trees": [
                {"tree_id": tree["tree_id"], "file": "attack-tree-001.json"},
            ]})
            _write(round_root / "attack-trees" / "attack-tree-001.json", tree)
        return SimpleNamespace(status="success", session_id=f"supplement-{kwargs['round_number']}", text="done")

    monkeypatch.setattr(implementation, "_run_supplement_task", supplement)
    result = implementation.run_threat_analysis(code_root, output)

    assert result["result"] is True
    assert len(calls) == 2
    assert len(calls[0]["targets"]) == 5
    assert len(calls[1]["targets"]) == 1
    modules = json.loads(Path(result["high_risk_modules_path"]).read_text(encoding="utf-8"))
    assert set(modules[0]["代码目录"]) == {"src/auth", *calls[0]["targets"]}
    assert modules[0]["面临威胁"] == "认证请求处理和辅助缓冲区中的输入风险"
    merged_index = json.loads((Path(result["attack_tree_path"]) / "index.json").read_text(encoding="utf-8"))
    assert len(merged_index["attack_trees"]) == 2
    assert len({tree["tree_id"] for tree in merged_index["attack_trees"]}) == 2
    assert len(json.loads((output / "final" / "attack-trees" / "index.json").read_text())["attack_trees"]) == 1


@pytest.mark.parametrize("invalid", ["malformed_delta", "old_tree_conflict"])
def test_success_reply_cannot_publish_invalid_delta(setup_scan, monkeypatch, invalid):
    implementation, code_root, output, prepare = setup_scan
    prepare(1)
    _mock_initial(implementation, monkeypatch)

    async def supplement(**kwargs):
        round_root = kwargs["round_root"]
        _negative_delta(code_root, round_root, kwargs["targets"])
        if invalid == "malformed_delta":
            (round_root / "delta.json").write_text("{", encoding="utf-8")
        else:
            delta = json.loads((round_root / "delta.json").read_text(encoding="utf-8"))
            delta["module_updates"] = [{
                "module_name": "认证入口",
                "add_code_paths": [],
                "set_fields": {"是否外部暴露面": "否"},
            }]
            _write(round_root / "delta.json", delta)
        return SimpleNamespace(status="success", session_id="invalid-supplement", text="done")

    monkeypatch.setattr(implementation, "_run_supplement_task", supplement)
    result = implementation.run_threat_analysis(code_root, output)

    assert result["result"] is True
    modules = json.loads(Path(result["high_risk_modules_path"]).read_text(encoding="utf-8"))
    assert modules == _valid_artifacts()[1]
    report = json.loads(Path(result["coverage_report_path"]).read_text(encoding="utf-8"))
    assert report["stop_reason"] == "supplement_failed"
    assert report["non_high_risk_paths"] == []
    assert report["remaining_uncovered_files"] == 1


def test_cancelled_second_batch_resumes_checkpoint_without_repeating_initial(setup_scan, monkeypatch):
    implementation, code_root, output, prepare = setup_scan
    prepare(6)
    initial_calls = _mock_initial(implementation, monkeypatch)
    calls = []
    cancelled = False

    async def supplement(**kwargs):
        nonlocal cancelled
        calls.append(kwargs)
        if kwargs["round_number"] == 2 and not cancelled:
            cancelled = True
            raise asyncio.CancelledError()
        _negative_delta(code_root, kwargs["round_root"], kwargs["targets"])
        return SimpleNamespace(status="success", session_id=f"supplement-{kwargs['round_number']}", text="done")

    monkeypatch.setattr(implementation, "_run_supplement_task", supplement)
    with pytest.raises(asyncio.CancelledError):
        implementation.run_threat_analysis(code_root, output)
    result = implementation.run_threat_analysis(code_root, output, is_resume=True)

    assert result["result"] is True
    assert len(initial_calls) == 1
    assert [call["round_number"] for call in calls] == [1, 2, 2]
    assert calls[1]["targets"] == calls[2]["targets"]
    report = json.loads(Path(result["coverage_report_path"]).read_text(encoding="utf-8"))
    assert len(report["rounds"]) == 2
    assert report["stop_reason"] == "no_candidates"


def test_supplement_prompt_gives_task_inputs_without_scheduler_instructions(setup_scan):
    implementation, code_root, output, prepare = setup_scan
    prepare(1)
    baseline = output / "final"
    round_root = output / "round-1"
    prompt = implementation.build_supplement_prompt(
        code_root=code_root,
        targets=["uncovered-00"],
        baseline=baseline,
        round_root=round_root,
    )

    for value in (str(code_root), "uncovered-00", str(baseline), str(round_root)):
        assert value in prompt
    for name in ("delta.schema.json", "attack-tree.schema.json", "attack-tree-index.schema.json", "supplement-guidance.json"):
        assert name in prompt
    for scheduler_text in ("最多五", "最多5", "最多两", "最多2", "第一步", "第二步", "第三步", "检查点", "试合并"):
        assert scheduler_text not in prompt
    assert "只读" in prompt
    assert "相对于" in prompt
    assert len(prompt) < 1800


def test_supplement_is_planned_under_distinct_identity_and_validates_in_same_task(setup_scan, monkeypatch):
    implementation, code_root, output, prepare = setup_scan
    inventory_path, _ = prepare(1)
    baseline = output / "final"
    paths = implementation._artifact_paths(output)
    _initial_artifacts(paths)
    round_root = output / "round-1"
    round_root.mkdir(parents=True, exist_ok=True)
    register = AsyncMock(return_value="planned-supplement-1")
    clear = AsyncMock()
    monkeypatch.setattr("task_agent.model_pool.register_planned_task", register)
    monkeypatch.setattr("task_agent.model_pool.clear_planned_task", clear)
    calls = []
    validation_outputs = []

    async def invoke(**kwargs):
        context = get_opencode_execution_context()
        calls.append((kwargs, context))
        (round_root / "delta.json").write_text("{", encoding="utf-8")
        validation_outputs.append(await kwargs["post_session_validator"]())
        _negative_delta(code_root, round_root, ["uncovered-00"])
        validation_outputs.append(await kwargs["post_session_validator"]())
        return SimpleNamespace(status="success", session_id="supplement-session", text="done")

    monkeypatch.setattr("task_agent.run_opencode_task", invoke)
    with opencode_task_context(
        scan_id="scan-1",
        execution_kind="scan",
        execution_id="scan-1",
        project_dir=code_root,
        work_dir=output,
        cancel_event=threading.Event(),
        task_metadata={"planned_task_id": "initial-planned-task"},
    ):
        result = asyncio.run(implementation._run_supplement_task(
            prompt="supplement task",
            round_root=round_root,
            baseline=baseline,
            code_root=code_root,
            targets=["uncovered-00"],
            inventory_path=inventory_path,
            round_number=1,
        ))
        assert get_opencode_execution_context().task_metadata["planned_task_id"] == "initial-planned-task"

    assert result.status == "success"
    register.assert_awaited_once()
    assert register.await_args.args[0] == "scan-1"
    assert register.await_args.kwargs["task_key"] == "threat-analysis:coverage-supplement:1"
    clear.assert_awaited_once_with("planned-supplement-1")
    assert len(calls) == 1
    kwargs, context = calls[0]
    assert kwargs["task_name"] == "opencode-coverage-guided-supplement-1"
    assert kwargs["task_type"] == "threat_analysis"
    assert kwargs["post_session_validation_retry_count"] == 1
    assert context.work_dir == round_root
    assert context.task_metadata["planned_task_id"] == "planned-supplement-1"
    assert validation_outputs[0]
    assert "delta.json" in validation_outputs[0]
    assert validation_outputs[1] is None


def test_sync_component_registers_and_clears_supplement_on_owner_loop(setup_scan, monkeypatch):
    from task_agent import run_sync_component

    implementation, code_root, output, prepare = setup_scan
    inventory_path, _ = prepare(1)
    round_root = output / "round-bridge"
    round_root.mkdir(parents=True)
    observations = []

    async def run():
        owner = asyncio.get_running_loop()

        async def register(*args, **kwargs):
            assert asyncio.get_running_loop() is owner
            observations.append("planned")
            return "bridge-planned"

        async def clear(identity):
            assert asyncio.get_running_loop() is owner
            assert identity == "bridge-planned"
            observations.append("cleared")

        async def invoke(**kwargs):
            assert asyncio.get_running_loop() is owner
            context = get_opencode_execution_context()
            assert context.task_metadata["planned_task_id"] == "bridge-planned"
            assert context.work_dir == round_root
            observations.append("invoked")
            return SimpleNamespace(status="success", session_id="bridge-session", text="done")

        monkeypatch.setattr("task_agent.model_pool.register_planned_task", register)
        monkeypatch.setattr("task_agent.model_pool.clear_planned_task", clear)
        monkeypatch.setattr("task_agent.run_opencode_task", invoke)

        def native():
            return asyncio.run(implementation._run_supplement_task(
                prompt="supplement", round_root=round_root, baseline=output / "final",
                code_root=code_root, targets=["uncovered-00"],
                inventory_path=inventory_path, round_number=1))

        with opencode_task_context(scan_id="scan-bridge", project_dir=code_root, work_dir=output):
            result = await run_sync_component(native)
        assert result.session_id == "bridge-session"

    asyncio.run(run())
    assert observations == ["planned", "invoked", "cleared"]


def test_validator_returns_chinese_diagnostics_with_non_utf8_parent_environment(
    setup_scan, monkeypatch,
):
    from deephole_client.threat_analysis.methods.opencode_coverage_guided_lightweight_threat_analysis import workflow

    implementation, code_root, output, prepare = setup_scan
    inventory_path, _ = prepare(1)
    _initial_artifacts(implementation._artifact_paths(output))
    round_root = output / "rounds" / "round-1"
    _negative_delta(code_root, round_root, ["uncovered-00"])
    delta_path = round_root / "delta.json"
    delta = json.loads(delta_path.read_text(encoding="utf-8"))
    delta["path_results"][0]["evidence"][0]["line_end"] = 999
    _write(delta_path, delta)
    context_path = inventory_path.parent / "round-1.json"
    _write(context_path, {
        "baseline": str(output / "final"), "round_root": str(round_root),
        "code_root": str(code_root), "targets": ["uncovered-00"],
        "inventory_path": str(inventory_path),
    })
    monkeypatch.setenv("PYTHONIOENCODING", "gbk")
    monkeypatch.setenv("PYTHONUTF8", "0")

    feedback = asyncio.run(workflow._supplement_validation_feedback(context_path))

    assert feedback is not None
    assert "delta.json $.path_results[0].evidence[0]" in feedback
    assert "行" in feedback
    assert "\ufffd" not in feedback
    _negative_delta(code_root, round_root, ["uncovered-00"])
    assert asyncio.run(workflow._supplement_validation_feedback(context_path)) is None


@pytest.mark.parametrize("corruption", ["json", "missing_status", "invalid_rounds"])
def test_corrupt_supplement_checkpoint_keeps_initial_result_without_new_tasks(setup_scan, monkeypatch, corruption):
    implementation, code_root, output, prepare = setup_scan
    prepare(1)
    _mock_initial(implementation, monkeypatch)
    monkeypatch.setattr(implementation, "_run_supplement_task", AsyncMock(
        return_value=SimpleNamespace(status="failure", session_id="failed", text="failed")))
    implementation.run_threat_analysis(code_root, output)
    state_path = output / "coverage-workflow-state.json"
    state = json.loads(state_path.read_text())
    if corruption == "json":
        state_path.write_text("{", encoding="utf-8")
    elif corruption == "missing_status":
        state.pop("status")
        _write(state_path, state)
    else:
        state["rounds"] = ["invalid"]
        _write(state_path, state)
    supplement = AsyncMock(side_effect=AssertionError("corrupt state must not reset the budget"))
    monkeypatch.setattr(implementation, "_run_supplement_task", supplement)
    result = implementation.run_threat_analysis(code_root, output, is_resume=True)
    assert result["result"] is True
    supplement.assert_not_awaited()
    assert Path(result["high_risk_modules_path"]).parent == output / "final"
    report = json.loads(Path(result["coverage_report_path"]).read_text())
    assert report["status"] == "incomplete"
    assert report["stop_reason"] == "checkpoint_unavailable"


def test_damaged_merged_checkpoint_keeps_initial_result(setup_scan, monkeypatch):
    implementation, code_root, output, prepare = setup_scan
    prepare(1)
    _mock_initial(implementation, monkeypatch)

    async def supplement(**kwargs):
        _negative_delta(code_root, kwargs["round_root"], kwargs["targets"])
        return SimpleNamespace(status="success", session_id="round-1", text="done")

    monkeypatch.setattr(implementation, "_run_supplement_task", supplement)
    result = implementation.run_threat_analysis(code_root, output)
    Path(result["high_risk_modules_path"]).write_text("{", encoding="utf-8")
    runner = AsyncMock(side_effect=AssertionError("must not reset supplement budget"))
    monkeypatch.setattr(implementation, "_run_supplement_task", runner)
    restored = implementation.run_threat_analysis(code_root, output, is_resume=True)
    assert restored["result"] is True
    runner.assert_not_awaited()
    assert Path(restored["high_risk_modules_path"]).parent == output / "final"
    report = json.loads(Path(restored["coverage_report_path"]).read_text())
    assert report["stop_reason"] == "checkpoint_unavailable"


def test_malformed_complete_inventory_is_not_reported_as_full_coverage(setup_scan, monkeypatch):
    implementation, code_root, output, prepare = setup_scan
    inventory_path, inventory = prepare(1)
    inventory["entries"] = []
    _write(inventory_path, inventory)
    _mock_initial(implementation, monkeypatch)
    runner = AsyncMock()
    monkeypatch.setattr(implementation, "_run_supplement_task", runner)
    result = implementation.run_threat_analysis(code_root, output)
    assert result["result"] is True
    runner.assert_not_awaited()
    report = json.loads(Path(result["coverage_report_path"]).read_text())
    assert report["status"] == "incomplete"
    assert report["stop_reason"] == "inventory_unavailable"
