"""Compact module projection constrains trees, fixed baselines, and resume."""

from __future__ import annotations

import copy
import importlib
import json
from pathlib import Path

import pytest

from deephole_client.scan_paths import resolve_scan_scope
from deephole_client.threat_analysis_runner import _adapt_high_risk_modules_for_project
from deephole_client.vulnerability_mining.engines.threat_pattern_audit.engine import _build_targets
from task_agent import opencode_task_context
from test_deephole_compact_threat_analysis import _assets, _attack_tree, _module, compact_native  # noqa: F401


def _read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write(path, data):
    Path(path).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "project" / "source"
    for name in ["src/a.c", "src/b.c", "lib/ok.c", "outside/other.c"]:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("int value;", encoding="utf-8")
    return root


@pytest.mark.parametrize("raw, expected", [
    ("outside", None),
    ("src/b.c", None),
    ("src", "src/a.c"),
    (".", ["src/a.c", "lib/ok.c"]),
    (["src", "src/a.c", "outside", "lib/ok.c"], ["src/a.c", "lib/ok.c"]),
    ("src\\a.c", "src/a.c"),
    ("../source/src/a.c", None),
    (" ", None),
    ("src/missing.c", None),
    ([], None),
])
def test_projection_uses_selected_union_and_never_falls_back(source, compact_native, raw, expected):
    module_scope = importlib.import_module(compact_native.__name__ + ".module_scope")
    scope = resolve_scan_scope(source, code_scan_paths=[source / "src/a.c", source / "lib/ok.c"])
    module = {**_module(), "代码目录": raw}
    original = copy.deepcopy(module)
    projected = module_scope.scope_modules([module], code_root=source, scope=scope)
    assert module == original
    assert projected == ([] if expected is None else [{**module, "代码目录": expected}])


def test_projection_preserves_directory_descendants_and_rejects_symlink_escape(source, compact_native):
    module_scope = importlib.import_module(compact_native.__name__ + ".module_scope")
    scope = resolve_scan_scope(source, code_scan_paths=[source / "src"])
    (source / "parent-link").symlink_to(source.parent, target_is_directory=True)
    (source / "loop").symlink_to("loop")
    modules = [{**_module(), "代码目录": path} for path in [str(source / "src/a.c"), "parent-link", "loop"]]
    assert module_scope.scope_modules(modules, code_root=source, scope=scope) == [
        {**_module(), "代码目录": "src/a.c"},
    ]


def test_projection_reports_module_and_path_diagnostics(source, compact_native):
    module_scope = importlib.import_module(compact_native.__name__ + ".module_scope")
    scope = resolve_scan_scope(source, code_scan_paths=[source / "src/a.c"])
    paths = ["src", "outside", "src/missing.c"]
    changes = []
    module_scope.scope_modules([{**_module(), "代码目录": paths}], code_root=source, scope=scope, changes=changes)
    assert changes == [{
        "module_name": _module()["模块名称"], "original_paths": paths, "effective_paths": ["src/a.c"],
        "reason": "scope_intersection", "excluded_paths": [
            {"path": "outside", "reason": "outside_scan_scope"},
            {"path": "src/missing.c", "reason": "missing_source_path"},
        ],
    }]


def _install_submitter(monkeypatch, native, modules):
    trees = importlib.import_module(native.__name__ + ".stages.attack_trees")
    state = {"tasks": [], "fail_trees": False}

    def submit_tasks(_submitter, tasks, *, timeout=None):
        state["tasks"].extend(tasks)
        results = []
        for task in tasks:
            kind = task["task_type"]
            if kind == "value_asset_map":
                output = [asset for asset in _assets()[:1]
                          if asset["资产类别"] == task["metadata"]["asset_category"]]
            elif kind == "high_risk_module_map":
                output = [module for module in modules if module[task["metadata"]["high_risk_field"]] == "是"]
            elif kind == "high_risk_module_merge":
                output = modules
            else:
                assert kind == "attack_tree_by_asset"
                if state["fail_trees"]:
                    results.append({"task_id": task["task_id"], "status": "failed", "error": "test tree failure"})
                    continue
                scoped = _read(task["input_files"][0])
                module = next(module for module in scoped if module["是否外部暴露面"] == "是")
                output = _attack_tree(task["task_id"], _assets()[0], module,
                                      trees._stable_high_risk_module_id(module), [])
            _write(task["output_path"], output)
            results.append({"task_id": task["task_id"], "task_type": kind, "status": "succeeded",
                            "output_path": task["output_path"], "output": output, "metadata": task["metadata"]})
        return results

    monkeypatch.setattr(native.TaskAgentSubmitter, "submit_tasks", submit_tasks)
    return state


def test_pipeline_publishes_only_intersections_and_preserves_raw_merge(source, tmp_path, compact_native, monkeypatch):
    modules = [
        {**_module(), "代码目录": ["src/a.c", "outside/other.c"]},
        {**_module(), "模块名称": "内部模块", "代码目录": "src", "是否外部暴露面": "否"},
        {**_module(), "模块名称": "范围外模块", "代码目录": "outside"},
    ]
    state = _install_submitter(monkeypatch, compact_native, modules)
    selected = [source / "src/a.c", source / "lib/ok.c"]
    output = tmp_path / "analysis"
    logs = []
    with opencode_task_context(project_dir=source, work_dir=output, output=logs.append):
        result = compact_native.run_threat_analysis(source, output, code_paths=selected)
    assert result["result"] is True, result
    scoped = [{**module, "代码目录": "src/a.c"} for module in modules[:2]]
    assert _read(result["high_risk_modules_path"]) == scoped
    assert _read(output / "high_risk_modules/final/high-risk-module-merge.json") == modules
    scope_changes = _read(output / "high_risk_modules/final/scope-changes.json")
    assert scope_changes[-1]["module_name"] == "范围外模块"
    assert scope_changes[-1]["effective_paths"] == []
    assert any("范围外模块" in line and "outside_scan_scope" in line for line in logs)
    tree_task = next(task for task in state["tasks"] if task["task_type"] == "attack_tree_by_asset")
    assert tree_task["input_files"][0] == result["high_risk_modules_path"]
    assert "范围外模块" not in tree_task["runtime_prompt"]
    for task in state["tasks"]:
        if task["task_type"] in {"high_risk_module_map", "high_risk_module_merge"}:
            assert str(source) in task["runtime_prompt"]
            assert str(selected[0]) in task["runtime_prompt"]
            assert str(selected[1]) in task["runtime_prompt"]
    artifact = _read(result["attack_tree_path"])
    baselines = artifact["attack_trees"][0]["module_pattern_baselines"] + artifact["unassigned_module_pattern_baselines"]
    assert {record["module_name"] for record in baselines} == {module["模块名称"] for module in scoped}
    adapted = _adapt_high_risk_modules_for_project(
        result, project_path=source.parent, code_path=source, output_path=output,
    )
    assert {module["代码目录"] for module in _read(adapted["high_risk_modules_path"])} == {"source/src/a.c"}
    targets = _build_targets(artifact, _read(adapted["high_risk_modules_path"]), fallback_code_path=source,
                            scan_scope=resolve_scan_scope(source.parent, code_scan_paths=selected))
    assert len(targets) == 30
    assert {tuple(target["code_paths"]) for target in targets} == {(str(selected[0]),)}


@pytest.mark.parametrize("internal", [False, True])
def test_no_external_entry_produces_empty_trees_without_reviving_excluded_modules(
    source, tmp_path, compact_native, monkeypatch, internal,
):
    modules = [{**_module(), "模块名称": "范围外模块", "代码目录": "outside"}]
    if internal:
        modules.append({**_module(), "模块名称": "内部模块", "代码目录": "src", "是否外部暴露面": "否"})
    state = _install_submitter(monkeypatch, compact_native, modules)
    result = compact_native.run_threat_analysis(source, tmp_path / "analysis", code_paths=[source / "src/a.c"])
    assert result["result"] is True, result
    assert not any(task["task_type"] == "attack_tree_by_asset" for task in state["tasks"])
    artifact = _read(result["attack_tree_path"])
    assert artifact["attack_trees"] == []
    if internal:
        record, = artifact["unassigned_module_pattern_baselines"]
        assert record["module_name"] == "内部模块"
        assert len(record["attack_patterns"]) == 15
    else:
        assert artifact == {"attack_trees": []}
        assert _read(result["high_risk_modules_path"]) == []


def test_resume_rebuilds_only_trees_for_missing_marker_and_changed_module_paths(
    source, tmp_path, compact_native, monkeypatch,
):
    modules = [{**_module(), "代码目录": "src/a.c"}]
    state = _install_submitter(monkeypatch, compact_native, modules)
    selected = [source / "src/a.c", source / "lib/ok.c"]
    output = tmp_path / "analysis"
    result = compact_native.run_threat_analysis(source, output, code_paths=selected)
    assert result["result"] is True
    marker = output / "attack_trees/final/scoped-inputs.json"
    initial_marker = _read(marker)
    state["tasks"].clear()
    assert compact_native.run_threat_analysis(source, output, code_paths=selected, is_resume=True) == result
    assert state["tasks"] == []

    marker.unlink()
    assert compact_native.run_threat_analysis(source, output, code_paths=selected, is_resume=True) == result
    assert [task["task_type"] for task in state["tasks"]] == ["attack_tree_by_asset"]
    old_tree = _read(state["tasks"][0]["output_path"])
    state["tasks"].clear()
    changed = [{**modules[0], "代码目录": "lib/ok.c"}]
    _write(output / "high_risk_modules/final/high-risk-module-merge.json", changed)
    assert compact_native.run_threat_analysis(source, output, code_paths=selected, is_resume=True) == result
    assert [task["task_type"] for task in state["tasks"]] == ["attack_tree_by_asset"]
    assert _read(result["high_risk_modules_path"]) == changed
    assert _read(marker) != initial_marker
    assert _read(state["tasks"][0]["output_path"])["attack_trees"][0]["nodes"][1]["module_id"] != old_tree["attack_trees"][0]["nodes"][1]["module_id"]


def test_failed_rebuild_does_not_reuse_old_trees_or_commit_fingerprint(source, tmp_path, compact_native, monkeypatch):
    modules = [{**_module(), "代码目录": "src/a.c"}]
    state = _install_submitter(monkeypatch, compact_native, modules)
    selected = [source / "src/a.c", source / "lib/ok.c"]
    output = tmp_path / "analysis"
    result = compact_native.run_threat_analysis(source, output, code_paths=selected)
    assert result["result"] is True
    raw_merge = output / "high_risk_modules/final/high-risk-module-merge.json"
    _write(raw_merge, [{**modules[0], "代码目录": "lib/ok.c"}])
    state.update(fail_trees=True, tasks=[])
    failed = compact_native.run_threat_analysis(source, output, code_paths=selected, is_resume=True)
    assert failed["result"] is False
    assert "test tree failure" in failed["reason"]
    assert not (output / "attack_trees/final/scoped-inputs.json").exists()
    assert [task["task_type"] for task in state["tasks"]] == ["attack_tree_by_asset"]

    # Even if inputs return to the previously successful version, the old
    # marker must not certify files partially overwritten during the failure.
    _write(raw_merge, modules)
    state.update(fail_trees=False, tasks=[])
    assert compact_native.run_threat_analysis(source, output, code_paths=selected, is_resume=True) == result
    assert [task["task_type"] for task in state["tasks"]] == ["attack_tree_by_asset"]


def test_resume_drops_previous_tree_and_baseline_when_module_becomes_outside_scope(
    source, tmp_path, compact_native, monkeypatch,
):
    modules = [{**_module(), "代码目录": "src/a.c"}]
    state = _install_submitter(monkeypatch, compact_native, modules)
    selected = [source / "src/a.c"]
    output = tmp_path / "analysis"
    result = compact_native.run_threat_analysis(source, output, code_paths=selected)
    assert result["result"] is True
    _write(output / "high_risk_modules/final/high-risk-module-merge.json", [{**modules[0], "代码目录": "outside"}])
    state["tasks"].clear()
    assert compact_native.run_threat_analysis(source, output, code_paths=selected, is_resume=True) == result
    assert state["tasks"] == []
    assert _read(result["high_risk_modules_path"]) == []
    assert _read(result["attack_tree_path"]) == {"attack_trees": []}
