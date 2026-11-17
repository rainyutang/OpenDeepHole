from __future__ import annotations

import copy
import importlib
import json
from collections import Counter
from pathlib import Path

import pytest

from backend.threat_data import parse_threat_analysis_data
from backend.threat_coverage import analysis_targets
from deephole_client.process_artifacts import collect_json_artifacts
from deephole_client.threat_analysis import THREAT_ANALYSIS_METHODS_DIR
from deephole_client.threat_analysis_runner import _load_implementation
from deephole_client.vulnerability_mining.engines.threat_pattern_audit.engine import (
    _build_targets,
)


ORIGINAL_ROOT = THREAT_ANALYSIS_METHODS_DIR / "deephole_threat_analysis"
COMPACT_ROOT = THREAT_ANALYSIS_METHODS_DIR / "deephole_compact_threat_analysis"
SKILL_PREFIX = "deephole-compact-"
ATTACK_SKILL = (
    COMPACT_ROOT / "skills/attack-trees/deephole-compact-attack-tree-by-asset"
)
COMPACT_CATALOG = ATTACK_SKILL / "references/attack_mode.json"


def _method_files(root: Path) -> dict[str, Path]:
    return {
        path.relative_to(root).as_posix(): path
        for path in root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }


def test_compact_method_preserves_original_implementation_and_prompts():
    original_files = _method_files(ORIGINAL_ROOT)
    compact_files = {
        relative.replace(SKILL_PREFIX, ""): path
        for relative, path in _method_files(COMPACT_ROOT).items()
    }
    assert compact_files.keys() - original_files.keys() == {
        "baselines.py",
        "coverage_supplement.py",
        "module_scope.py",
        "validate_attack_tree.py",
        "validate_module_threats.py",
        "artifact_validation.py",
        "validate_high_risk_modules.py",
        "stages/module_threats.py",
        "skills/module-threats/module-attack-threats/SKILL.md",
        "skills/module-threats/module-attack-threats/references/attack_mode.json",
    }
    assert original_files.keys() - compact_files.keys() == set()
    attack_skill = "skills/attack-trees/attack-tree-by-asset/"
    for relative, original in original_files.items():
        if relative in {
            "method.yaml",
            "pipeline.py",
            "threat_analysis.py",
            # Compact module/tree tasks validate model-written files.
            "task_agent_submitter.py",
            "stages/base.py",
            "stages/attack_trees.py",
            "stages/high_risk_modules.py",
            "skills/high-risk-modules/high-risk-module-map/SKILL.md",
            "skills/high-risk-modules/high-risk-module-merge/SKILL.md",
            attack_skill + "SKILL.md",
            attack_skill + "references/attack_mode.json",
        }:
            continue
        compact_content = compact_files[relative].read_bytes().replace(SKILL_PREFIX.encode(), b"")
        if relative == "schemas.py":
            compact_content = compact_content.split(b"\n\n# Final artifacts extend")[0].rstrip(b"\n") + b"\n"
        # Other business stages retain the original implementation.
        assert compact_content == original.read_bytes(), relative


def test_compact_catalog_is_an_exact_copy_of_the_51_mode_library():
    lightweight = (
        THREAT_ANALYSIS_METHODS_DIR
        / "codex_goal_threat_analysis/references/attack_mode.json"
    )
    original = (
        ORIGINAL_ROOT
        / "skills/attack-trees/attack-tree-by-asset/references/attack_mode.json"
    )
    assert COMPACT_CATALOG.read_bytes() == lightweight.read_bytes()
    modes = json.loads(COMPACT_CATALOG.read_text(encoding="utf-8"))
    assert len(modes) == 51
    assert len({tuple(mode["攻击模式编号"]) for mode in modes}) == 51
    assert Counter(mode["攻击模式编号"][0].rsplit("-", 1)[0] for mode in modes) == {
        "ODH-NATIVE": 11,
        "ODH-PROTO": 14,
        "ODH-CRYPTO": 11,
        "ODH-SYS": 15,
    }
    assert len(json.loads(original.read_text(encoding="utf-8"))) == 1355


def test_attack_prompt_uses_private_catalog_with_lightweight_pattern_count():
    prompt = (ATTACK_SKILL / "SKILL.md").read_text(encoding="utf-8")
    assert "51 项" in prompt
    assert "唯一攻击模式来源" in prompt
    assert "针对每条攻击路径分析全部实际适用的攻击模式" in prompt
    assert "有足够适用模式时至少输出 10 个" in prompt
    assert "确实不足 10 个时输出全部实际适用模式" in prompt
    assert "不为凑数关联缺乏依据的模式" in prompt
    assert "无法合理匹配时，攻击模式列表输出空数组" in prompt
    assert "不设数量下限" not in prompt


@pytest.fixture
def compact_native():
    native = _load_implementation("deephole_compact_threat_analysis")
    yield native
    # The runtime deliberately loads every method under the same native alias.
    _load_implementation()


def _assets():
    return [
        {
            "资产名": name,
            "资产类别": category,
            "资产描述": f"请求处理链路使用的{name}。",
            "攻击损失": f"{name}被泄露、篡改或中断。",
            "判断为价值资产的原因": "请求解析代码读取或更新该资产。",
        }
        for category, name in [
            ("数据资产", "请求数据"),
            ("软件资产", "解析器配置"),
            ("硬件资产", "设备状态"),
            ("服务资产", "请求解析服务"),
        ]
    ]


def _module():
    return {
        "模块名称": "请求解析模块",
        "代码目录": "src/parser",
        "面临威胁": "外部请求可能影响解析状态和服务可用性。",
        "是否涉及设备或系统对外提供管理和控制接口相关的代码": "否",
        "是否涉及对不可信来源数据进行解析或处理的代码": "是",
        "是否涉及安全相关类代码(如，认证、授权、接入控制、加解密、密钥管理、日志审计、软件完整性保护等模块)": "否",
        "是否涉及个人数据或者敏感数据的代码": "否",
        "是否涉及web相关处理": "是",
        "是否外部暴露面": "是",
        "判断为高风险模块的原因": "解析模块直接接收外部 Web 请求。",
    }


def _attack_tree(task_id, asset, module, module_id, patterns):
    root_id, leaf_id, edge_id = (f"{task_id}-{part}" for part in ("root", "leaf", "edge"))
    return {
        "attack_trees": [{
            "tree_id": task_id,
            "value_asset": {
                "asset_name": asset["资产名"],
                "asset_category": asset["资产类别"],
                "asset_description": asset["资产描述"],
                "attack_loss": asset["攻击损失"],
            },
            "nodes": [
                {
                    "node_id": root_id,
                    "node_type": "根节点",
                    "node_name": "攻击价值资产：" + asset["资产名"],
                    "description": asset["攻击损失"],
                    "module_name": None,
                    "module_id": None,
                    "is_high_risk_module": False,
                    "external_exposure": False,
                    "external_interface_description": None,
                },
                {
                    "node_id": leaf_id,
                    "node_type": "叶子节点",
                    "node_name": module["模块名称"],
                    "description": "接收外部请求并解析输入。",
                    "module_name": module["模块名称"],
                    "module_id": module_id,
                    "is_high_risk_module": True,
                    "external_exposure": True,
                    "external_interface_description": "Web 请求入口。",
                },
            ],
            "edges": [{
                "edge_id": edge_id,
                "source_node_id": leaf_id,
                "target_node_id": root_id,
                "influence_type": "直接影响",
                "description": "解析外部请求时访问或影响该资产。",
            }],
            "attack_paths": [{
                "path_id": task_id + "-path",
                "path_name": "外部请求影响" + asset["资产名"],
                "node_ids": [leaf_id, root_id],
                "edge_ids": [edge_id],
                "path_description": "请求解析模块影响资产。",
                "related_high_risk_modules": [{
                    "module_name": module["模块名称"],
                    "module_id": module_id,
                    "node_id": leaf_id,
                    "external_exposure": True,
                    "path_role": "外部攻击入口",
                    "association_description": "该模块接收路径中的外部输入。",
                }],
                "attack_patterns": patterns,
            }],
        }],
    }


@pytest.mark.parametrize("pattern_count", [0, 1, 3, 16, 51])
def test_native_pipeline_artifacts_and_resume_preserve_actual_pattern_count(
    tmp_path, compact_native, monkeypatch, pattern_count,
):
    native = compact_native
    trees_module = importlib.import_module(native.__name__ + ".stages.attack_trees")
    validator = importlib.import_module(native.__name__ + ".output_validation")
    assets, module = _assets(), _module()
    modes = json.loads(COMPACT_CATALOG.read_text(encoding="utf-8"))[:pattern_count]
    patterns = [{
        "pattern_id": "、".join(mode["攻击模式编号"]),
        "pattern_name": mode["攻击模式名称"],
        "association_description": "外部请求解析影响该路径上的资产。",
    } for mode in modes]
    batches = []

    def submit_tasks(_submitter, tasks, *, timeout=None):
        batches.append(tasks)
        results = []
        for task in tasks:
            metadata = task["metadata"]
            kind = task["task_type"]
            if kind == "value_asset_map":
                output = [asset for asset in assets if asset["资产类别"] == metadata["asset_category"]]
            elif kind == "high_risk_module_map":
                output = [module] if module[metadata["high_risk_field"]] == "是" else []
            elif kind == "high_risk_module_merge":
                output = [module]
            elif kind == "attack_tree_by_asset":
                assert json.loads(Path(task["input_files"][0]).read_text(encoding="utf-8")) == [module]
                asset = next(asset for asset in assets if asset["资产名"] == metadata["asset_name"])
                output = _attack_tree(
                    task["task_id"], asset, module,
                    trees_module._stable_high_risk_module_id(module), patterns,
                )
            else:
                pytest.fail(f"Unexpected task type: {kind}")
            validator.validate_json_schema(output, task["output_schema"])
            output_path = Path(task["output_path"])
            output_path.write_text(json.dumps(output, ensure_ascii=False), encoding="utf-8")
            results.append({
                "task_id": task["task_id"],
                "task_type": kind,
                "status": "succeeded",
                "output_path": str(output_path),
                "output": output,
                "metadata": metadata,
            })
        return results

    monkeypatch.setattr(native.TaskAgentSubmitter, "submit_tasks", submit_tasks)
    code_root = tmp_path / "source"
    (code_root / "src/parser").mkdir(parents=True)
    output_root = tmp_path / "analysis"
    result = native.run_threat_analysis(code_root, output_root)

    assert result["result"] is True, result
    assert [len(batch) for batch in batches] == [9, 1, 4]
    assert Counter(task["task_type"] for task in batches[0]) == {
        "value_asset_map": 4, "high_risk_module_map": 5,
    }
    assert {task["metadata"]["asset_category"] for task in batches[0][:4]} == {
        "数据资产", "软件资产", "硬件资产", "服务资产",
    }
    assert {task["metadata"]["high_risk_category"] for task in batches[0][4:]} == {
        "管理和控制接口相关代码", "不可信来源数据解析或处理代码", "安全相关类代码",
        "个人数据或者敏感数据代码", "Web 相关处理",
    }
    skill_names = {
        "value_asset_map": "deephole-compact-value-asset-map",
        "high_risk_module_map": "deephole-compact-high-risk-module-map",
        "high_risk_module_merge": "deephole-compact-high-risk-module-merge",
        "attack_tree_by_asset": "deephole-compact-attack-tree-by-asset",
    }
    for batch in batches:
        for task in batch:
            assert task["skill_name"] == skill_names[task["task_type"]]

    bundle = parse_threat_analysis_data(collect_json_artifacts(result, output_root=output_root))
    artifacts = bundle["artifacts"]
    assert artifacts["value_asset_path"]["path"] == "value_assets/final/value-assets.json"
    assert artifacts["high_risk_modules_path"]["path"] == "high_risk_modules/final/high-risk-modules-scoped.json"
    assert artifacts["attack_tree_path"]["path"] == "attack_trees/final/attack_trees.json"
    assert artifacts["value_asset_path"]["content"] == assets
    assert artifacts["high_risk_modules_path"]["content"] == [module]
    tree_output = artifacts["attack_tree_path"]["content"]
    assert len(tree_output["attack_trees"]) == len(assets)
    for tree in tree_output["attack_trees"]:
        assert tree["attack_paths"][0]["attack_patterns"] == patterns
        assert all("module_id" not in node for node in tree["nodes"])
        assert all("module_id" not in item for item in tree["attack_paths"][0]["related_high_risk_modules"])
    targets = _build_targets(tree_output, [module], fallback_code_path=code_root)
    baselines = importlib.import_module(native.__name__ + ".baselines")
    expected_ids = set(baselines.BASELINE_PATTERN_IDS) | {pattern["pattern_id"] for pattern in patterns}
    assert len(targets) == len(expected_ids)
    assert {target["pattern_id"] for target in targets} == expected_ids
    catalog = {"、".join(mode["攻击模式编号"]): mode for mode in json.loads(COMPACT_CATALOG.read_text(encoding="utf-8"))}
    assert all(target["pattern_description"] == catalog[target["pattern_id"]]["攻击模式描述"] for target in targets)
    missing_ids = set(baselines.BASELINE_PATTERN_IDS) - {pattern["pattern_id"] for pattern in patterns}
    records = tree_output["attack_trees"][0].get("module_pattern_baselines", [])
    assert {pattern["pattern_id"] for record in records for pattern in record["attack_patterns"]} == missing_ids
    assert len(records) == (1 if missing_ids else 0)
    assert all("module_pattern_baselines" not in tree for tree in tree_output["attack_trees"][1:])
    coverage_targets = analysis_targets(tree_output, [module], str(code_root))
    assert {(target["module_name"], target["pattern_id"], tuple(target["paths"])) for target in coverage_targets} == {
        (target["module_name"], target["pattern_id"],
         tuple(Path(path).relative_to(code_root).as_posix() for path in target["code_paths"])) for target in targets
    }

    def fail_if_called(*args, **kwargs):
        pytest.fail("Completed native artifacts should be reused without model tasks")

    monkeypatch.setattr(native.TaskAgentSubmitter, "submit_tasks", fail_if_called)
    assert native.run_threat_analysis(code_root, output_root, is_resume=True) == result
    assert collect_json_artifacts(result, output_root=output_root) == bundle


def _completed_tree(native, *, task_id="tree", module=None, patterns=None):
    module = module or _module()
    trees = importlib.import_module(native.__name__ + ".stages.attack_trees")
    return trees.normalize_attack_tree_output(
        _attack_tree(task_id, _assets()[0], module, trees._stable_high_risk_module_id(module), patterns or []),
        value_asset=_assets()[0], high_risk_modules=[module],
    )


def test_baselines_preserve_graph_and_select_first_module_host_globally(compact_native):
    baseline = importlib.import_module(compact_native.__name__ + ".baselines")
    first = _completed_tree(compact_native)
    second = _completed_tree(compact_native, task_id="second", patterns=[{
        "pattern_id": "ODH-NATIVE-01", "pattern_name": "越界写入破坏内存状态",
        "association_description": "AI 原始关系说明。",
    }])
    # Separate asset tasks are allowed to reuse tree IDs.
    second["attack_trees"][0]["tree_id"] = first["attack_trees"][0]["tree_id"]
    original = {"attack_trees": first["attack_trees"] + second["attack_trees"]}
    before = copy.deepcopy(original)
    result = baseline.add_module_pattern_baselines(original, [_module()])
    assert original == before
    record = result["attack_trees"][0].pop("module_pattern_baselines")[0]
    assert record["module_name"] == _module()["模块名称"]
    assert record["node_id"] == "tree-leaf"
    assert record["source"] == "compact_baseline"
    assert {pattern["pattern_id"] for pattern in record["attack_patterns"]} == set(baseline.BASELINE_PATTERN_IDS) - {"ODH-NATIVE-01"}
    assert result == original


def test_baselines_cover_internal_and_unassigned_modules_without_creating_paths(compact_native):
    baseline = importlib.import_module(compact_native.__name__ + ".baselines")
    output = _completed_tree(compact_native)
    internal = {**_module(), "模块名称": "内部缓存模块", "是否外部暴露面": "否"}
    unassigned = {**_module(), "模块名称": "未关联资产模块", "是否外部暴露面": "否"}
    tree = output["attack_trees"][0]
    node = {**tree["nodes"][1], "node_id": "internal", "node_type": "内部节点",
            "module_name": internal["模块名称"], "node_name": internal["模块名称"],
            "external_exposure": False, "external_interface_description": None}
    tree["nodes"].append(node)
    tree["edges"][0]["target_node_id"] = "internal"
    tree["edges"].append({**tree["edges"][0], "edge_id": "internal-edge", "source_node_id": "internal", "target_node_id": "tree-root"})
    path = tree["attack_paths"][0]
    path["node_ids"].insert(1, "internal")
    path["edge_ids"].append("internal-edge")
    path["related_high_risk_modules"].append({
        "module_name": internal["模块名称"], "node_id": "internal", "external_exposure": False,
        "path_role": "内部影响模块", "association_description": "处理入口数据。",
    })
    result = baseline.add_module_pattern_baselines(output, [_module(), internal, unassigned])
    records = result["attack_trees"][0].pop("module_pattern_baselines")
    assert [(item["module_name"], item["node_id"]) for item in records] == [(_module()["模块名称"], "tree-leaf"), (internal["模块名称"], "internal")]
    unassigned_record = result.pop("unassigned_module_pattern_baselines")[0]
    assert unassigned_record["module_name"] == unassigned["模块名称"]
    assert unassigned_record["node_id"] is None
    assert all(len(item["attack_patterns"]) == 15 for item in records + [unassigned_record])
    assert result == output


def test_baselines_handle_empty_trees_and_are_idempotent(compact_native):
    baseline = importlib.import_module(compact_native.__name__ + ".baselines")
    empty = {"attack_trees": []}
    assert baseline.add_module_pattern_baselines(empty, []) == empty
    result = baseline.add_module_pattern_baselines(empty, [_module()])
    assert result["attack_trees"] == []
    record = result["unassigned_module_pattern_baselines"][0]
    assert record["node_id"] is None
    assert len(record["attack_patterns"]) == 15
    assert baseline.add_module_pattern_baselines(result, [_module()]) == result
    assigned = baseline.add_module_pattern_baselines(_completed_tree(compact_native), [_module()])
    assert baseline.add_module_pattern_baselines(assigned, [_module()]) == assigned


def test_baselines_use_private_catalog_and_leave_fully_covered_module_unchanged(compact_native):
    baseline = importlib.import_module(compact_native.__name__ + ".baselines")
    catalog = {"、".join(mode["攻击模式编号"]): mode for mode in json.loads(COMPACT_CATALOG.read_text(encoding="utf-8"))}
    result = baseline.add_module_pattern_baselines({"attack_trees": []}, [_module()])
    patterns = result["unassigned_module_pattern_baselines"][0]["attack_patterns"]
    assert [item["pattern_id"] for item in patterns] == [*(f"ODH-NATIVE-{i:02d}" for i in range(1, 12)), "ODH-SYS-08", "ODH-SYS-09", "ODH-SYS-12", "ODH-SYS-13"]
    for pattern in patterns:
        mode = catalog[pattern["pattern_id"]]
        assert pattern["pattern_name"] == mode["攻击模式名称"]
        assert mode["攻击模式描述"] in pattern["association_description"]
        assert "不表示已确认" in pattern["association_description"]
    output = _completed_tree(compact_native, patterns=patterns)
    assert baseline.add_module_pattern_baselines(output, [_module()]) == output


def test_baselines_reject_unconsumable_ai_pattern_with_blank_name(compact_native):
    baseline = importlib.import_module(compact_native.__name__ + ".baselines")
    output = _completed_tree(compact_native)
    output["attack_trees"][0]["attack_paths"][0]["attack_patterns"] = [{
        "pattern_id": "ODH-NATIVE-01", "pattern_name": "   ",
        "association_description": "AI 返回了空白名称。",
    }]
    with pytest.raises(ValueError, match="pattern"):
        baseline.add_module_pattern_baselines(output, [_module()])


def test_baselines_only_reference_known_high_risk_nodes(compact_native):
    baseline = importlib.import_module(compact_native.__name__ + ".baselines")
    output = _completed_tree(compact_native)
    output["attack_trees"][0]["nodes"][1]["is_high_risk_module"] = False
    result = baseline.add_module_pattern_baselines(output, [_module()])
    assert "module_pattern_baselines" not in result["attack_trees"][0]
    assert result["unassigned_module_pattern_baselines"][0]["node_id"] is None
    assert baseline.add_module_pattern_baselines(output, []) == output


def test_final_baseline_schema_is_separate_from_ai_task_schema(compact_native):
    baseline = importlib.import_module(compact_native.__name__ + ".baselines")
    schemas = importlib.import_module(compact_native.__name__ + ".schemas")
    validator = importlib.import_module(compact_native.__name__ + ".output_validation")
    errors = importlib.import_module(compact_native.__name__ + ".errors")
    result = baseline.add_module_pattern_baselines(_completed_tree(compact_native), [_module()])
    validator.validate_json_schema(result, schemas.FINAL_ATTACK_TREE_SCHEMA)
    with pytest.raises(errors.OutputSchemaValidationError, match="additional properties"):
        validator.validate_json_schema(result, schemas.ATTACK_TREE_SCHEMA)
    result["attack_trees"][0]["module_pattern_baselines"][0]["node_id"] = None
    with pytest.raises(errors.OutputSchemaValidationError):
        validator.validate_json_schema(result, schemas.FINAL_ATTACK_TREE_SCHEMA)


def test_pipeline_without_assets_still_produces_unassigned_baselines(tmp_path, compact_native, monkeypatch):
    def submit_tasks(_submitter, tasks, *, timeout=None):
        results = []
        for task in tasks:
            output = [] if task["task_type"] == "value_asset_map" else [_module()]
            Path(task["output_path"]).write_text(json.dumps(output, ensure_ascii=False), encoding="utf-8")
            results.append({"task_id": task["task_id"], "task_type": task["task_type"], "status": "succeeded",
                            "output_path": task["output_path"], "output": output, "metadata": task["metadata"]})
        return results

    monkeypatch.setattr(compact_native.TaskAgentSubmitter, "submit_tasks", submit_tasks)
    code_root = tmp_path / "source"
    (code_root / "src/parser").mkdir(parents=True)
    result = compact_native.run_threat_analysis(code_root, tmp_path / "analysis")
    assert result["result"] is True, result
    artifact = json.loads(Path(result["attack_tree_path"]).read_text(encoding="utf-8"))
    assert artifact["attack_trees"] == []
    assert len(artifact["unassigned_module_pattern_baselines"][0]["attack_patterns"]) == 15


def test_module_threat_skill_and_catalog_match_private_51_modes():
    skill_dir = COMPACT_ROOT / "skills/module-threats/deephole-compact-module-attack-threats"
    catalog = skill_dir / "references/attack_mode.json"
    prompt = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
    assert catalog.read_bytes() == COMPACT_CATALOG.read_bytes()
    assert "禁止探索其它源码" in prompt
    assert "禁止过度探索与问题挖掘" in prompt
    assert "51 项" in prompt
    assert "pattern_id" in prompt and "pattern_name" in prompt and "description" in prompt


def test_select_uncovered_targets_excludes_only_hidden_and_code_index_without_splitting_umbrella_dirs(compact_native):
    supplement = importlib.import_module(compact_native.__name__ + ".coverage_supplement")
    entries = [
        {"path": ".", "kind": "directory"},
        {"path": ".git", "kind": "directory"},
        {"path": ".git/config", "kind": "file"},
        {"path": ".env", "kind": "file"},
        {"path": "code_index.db", "kind": "file"},
        {"path": "code_index.db-wal", "kind": "file"},
        {"path": "code_index.db-shm", "kind": "file"},
        {"path": "sub", "kind": "directory"},
        {"path": "sub/code_index.db-journal", "kind": "file"},
        {"path": "src", "kind": "directory"},
        {"path": "src/parser", "kind": "directory"},
        {"path": "src/parser/a.c", "kind": "file"},
        {"path": "src/auth", "kind": "directory"},
        {"path": "src/auth/login.c", "kind": "file"},
        {"path": "umbrella", "kind": "directory"},
        *[{"path": f"umbrella/f{i}.c", "kind": "file"} for i in range(10)],
        {"path": "tests", "kind": "directory"},
        {"path": "tests/test_main.py", "kind": "file"},
        {"path": "docs", "kind": "directory"},
        {"path": "docs/README.md", "kind": "file"},
        {"path": "third_party", "kind": "directory"},
        {"path": "third_party/zlib.c", "kind": "file"},
        {"path": "build", "kind": "directory"},
        {"path": "build/out.txt", "kind": "file"},
    ]
    inventory = {
        "schema_version": 1,
        "snapshot_id": "snap-1",
        "status": "complete",
        "project_path": "/project",
        "scan_root": "/project",
        "captured_at": "2026-11-17T00:00:00+00:00",
        "entries": entries,
        "issues": [],
        "issue_count": 0,
        "excluded_paths": [],
    }
    first_round = supplement.select_uncovered_targets(inventory, [_module()])
    # Umbrella dir stays intact (not auto-split), non-code/test/docs/build/third_party are kept,
    # while .git/.env and code_index.db* (including sub/ which only holds code_index.db-journal) are excluded.
    assert first_round == ["umbrella", "build", "docs", "tests", "third_party"]
    second_round = supplement.select_uncovered_targets(inventory, [_module()], inspected_paths=first_round)
    assert second_round == ["src/auth"]
    assert supplement.select_uncovered_targets(inventory, [_module()], inspected_paths=first_round + second_round) == []


def test_pipeline_supplements_up_to_three_rounds_of_five_paths_then_merges_once(
    tmp_path, compact_native, monkeypatch,
):
    code_root = tmp_path / "source"
    (code_root / "src/parser").mkdir(parents=True)
    (code_root / "src/parser/main.c").write_text("int main_parser(void) { return 0; }", encoding="utf-8")
    (code_root / ".hidden_dir").mkdir(parents=True)
    (code_root / ".hidden_dir/secret.c").write_text("int s;", encoding="utf-8")
    (code_root / "code_index.db").write_text("sqlite", encoding="utf-8")
    (code_root / "code_index.db-wal").write_text("wal", encoding="utf-8")
    for idx in range(17):
        mod_dir = code_root / f"pkg_{idx:02d}" / "inner"
        mod_dir.mkdir(parents=True)
        (mod_dir / "handler.c").write_text("int h;", encoding="utf-8")

    supplement_targets: list[list[str]] = []
    merge_inputs: list[list[str]] = []
    supplement_ext = {
        **_module(),
        "代码目录": "pkg_00",
        "判断为高风险模块的原因": "补充解析扩展入口。",
    }
    supplement_new = {
        **_module(),
        "模块名称": "补充管理模块",
        "代码目录": "pkg_05",
        "是否涉及设备或系统对外提供管理和控制接口相关的代码": "是",
        "判断为高风险模块的原因": "未覆盖目录中的管理接口。",
    }
    merged_modules = [
        {**_module(), "代码目录": ["src/parser", "pkg_00"]},
        supplement_new,
    ]

    def submit_tasks(_submitter, tasks, *, timeout=None):
        results = []
        for task in tasks:
            kind = task["task_type"]
            if kind == "value_asset_map":
                output = []
            elif kind == "high_risk_module_map":
                output = [_module()] if task["metadata"]["high_risk_field"] == "是否涉及web相关处理" else []
            elif kind == "high_risk_module_supplement":
                targets = task["metadata"]["target_paths"]
                supplement_targets.append(targets)
                assert "高风险模块候选摘要" in task["runtime_prompt"]
                if task["metadata"]["round"] == 1:
                    output = [supplement_ext]
                elif task["metadata"]["round"] == 2:
                    output = [supplement_new]
                else:
                    output = []
            elif kind == "high_risk_module_merge":
                merge_inputs.append(list(task["input_files"]))
                assert "补充识别路径归属于已有高风险模块" in task["runtime_prompt"]
                output = merged_modules
            else:
                pytest.fail(f"Unexpected task type: {kind}")
            Path(task["output_path"]).write_text(json.dumps(output, ensure_ascii=False), encoding="utf-8")
            results.append({
                "task_id": task["task_id"],
                "task_type": kind,
                "status": "succeeded",
                "output_path": task["output_path"],
                "output": output,
                "metadata": task["metadata"],
            })
        return results

    monkeypatch.setattr(compact_native.TaskAgentSubmitter, "submit_tasks", submit_tasks)
    output_root = tmp_path / "analysis"
    result = compact_native.run_threat_analysis(code_root, output_root)
    assert result["result"] is True, result
    assert supplement_targets == [
        [f"pkg_{i:02d}" for i in range(0, 5)],
        [f"pkg_{i:02d}" for i in range(5, 10)],
        [f"pkg_{i:02d}" for i in range(10, 15)],
    ]
    # Round 1 only returned pkg_00, yet pkg_01..pkg_04 were NOT re-drilled into pkg_01/inner in round 2!
    assert len(merge_inputs) == 1
    assert len(merge_inputs[0]) == 5 + 3
    assert json.loads(Path(result["high_risk_modules_path"]).read_text(encoding="utf-8")) == merged_modules

    # Resume reuses completed supplement + merge + trees without calling submit_tasks.
    monkeypatch.setattr(
        compact_native.TaskAgentSubmitter,
        "submit_tasks",
        lambda *_a, **_k: pytest.fail("Should not re-run on resume"),
    )
    assert compact_native.run_threat_analysis(code_root, output_root, is_resume=True) == result


def test_pipeline_without_attack_tree_analyzes_one_module_per_task_and_supports_resume(
    tmp_path, compact_native, monkeypatch,
):
    from backend.threat_coverage import build_threat_coverage

    code_root = tmp_path / "source"
    (code_root / "src/parser").mkdir(parents=True)
    (code_root / "src/parser/a.c").write_text("int a;", encoding="utf-8")
    (code_root / "src/internal").mkdir(parents=True)
    (code_root / "src/internal/b.c").write_text("int b;", encoding="utf-8")

    mod_a = _module()
    mod_b = {
        **_module(),
        "模块名称": "内部处理模块",
        "代码目录": "src/internal",
        "是否外部暴露面": "否",
    }
    modes = json.loads(COMPACT_CATALOG.read_text(encoding="utf-8"))
    ai_pattern = {
        "pattern_id": "ODH-NATIVE-01",
        "pattern_name": next(m["攻击模式名称"] for m in modes if m["攻击模式编号"] == ["ODH-NATIVE-01"]),
        "description": "解析外部输入长度时可能发生越界写入。",
    }
    proto_pattern = {
        "pattern_id": "ODH-PROTO-01",
        "pattern_name": next(m["攻击模式名称"] for m in modes if m["攻击模式编号"] == ["ODH-PROTO-01"]),
        "description": "协议消息边界校验不一致导致解析歧义。",
    }

    seen_batches: list[list[dict]] = []

    def submit_tasks(_submitter, tasks, *, timeout=None):
        seen_batches.append(tasks)
        results = []
        for task in tasks:
            kind = task["task_type"]
            assert kind != "value_asset_map", "Value assets must be skipped when generate_attack_tree=False"
            assert kind != "attack_tree_by_asset", "Attack trees must be skipped when generate_attack_tree=False"
            if kind == "high_risk_module_map":
                output = [mod_a, mod_b] if task["metadata"]["high_risk_field"] == "是否涉及web相关处理" else []
            elif kind == "high_risk_module_merge":
                output = [mod_a, mod_b]
            elif kind == "module_attack_threats":
                assert task["skill_name"] == "deephole-compact-module-attack-threats"
                assert "不要探索其它源码" in task["runtime_prompt"]
                assert "不要做过度的代码探索" in task["runtime_prompt"]
                assert len(task["input_files"]) == 1
                assert task["input_files"][0] in {str((code_root / "src/parser").resolve()), str((code_root / "src/internal").resolve())}
                output = [ai_pattern, proto_pattern] if task["metadata"]["module_name"] == mod_a["模块名称"] else []
            else:
                pytest.fail(f"Unexpected task type: {kind}")
            Path(task["output_path"]).write_text(json.dumps(output, ensure_ascii=False), encoding="utf-8")
            results.append({
                "task_id": task["task_id"],
                "task_type": kind,
                "status": "succeeded",
                "output_path": task["output_path"],
                "output": output,
                "metadata": task["metadata"],
            })
        return results

    monkeypatch.setattr(compact_native.TaskAgentSubmitter, "submit_tasks", submit_tasks)
    output_root = tmp_path / "analysis"
    result = compact_native.run_threat_analysis(
        code_root,
        output_root,
        generate_attack_tree=False,
    )
    assert result["result"] is True, result
    assert [len(batch) for batch in seen_batches] == [5, 1, 2]
    assert [t["task_type"] for t in seen_batches[-1]] == ["module_attack_threats", "module_attack_threats"]

    bundle = parse_threat_analysis_data(collect_json_artifacts(result, output_root=output_root))
    assert bundle["artifacts"]["value_asset_path"]["content"] == []
    assert bundle["artifacts"]["high_risk_modules_path"]["content"] == [mod_a, mod_b]
    envelope = bundle["artifacts"]["attack_tree_path"]["content"]
    assert envelope["analysis_mode"] == "module_threats_only"
    assert envelope["attack_trees"] == []
    assert envelope["module_threats"] == [
        {"module_name": mod_a["模块名称"], "attack_patterns": [ai_pattern, proto_pattern]},
        {"module_name": mod_b["模块名称"], "attack_patterns": []},
    ]
    baselines = {item["module_name"]: item["attack_patterns"] for item in envelope["unassigned_module_pattern_baselines"]}
    # mod_a already had ODH-NATIVE-01 from AI, so only 14 fixed baselines are supplemented; mod_b gets all 15.
    assert len(baselines[mod_a["模块名称"]]) == 14
    assert "ODH-NATIVE-01" not in {p["pattern_id"] for p in baselines[mod_a["模块名称"]]}
    assert len(baselines[mod_b["模块名称"]]) == 15

    # Downstream audit engines and threat coverage consume both module_threats and baselines.
    audit_targets = _build_targets(envelope, [mod_a, mod_b], fallback_code_path=code_root)
    assert len(audit_targets) == 16 + 15
    inv = {
        "schema_version": 1,
        "snapshot_id": "s1",
        "status": "complete",
        "project_path": str(code_root),
        "scan_root": str(code_root),
        "captured_at": "2026-11-17T00:00:00+00:00",
        "entries": [
            {"path": ".", "kind": "directory"},
            {"path": "src", "kind": "directory"},
            {"path": "src/parser", "kind": "directory"},
            {"path": "src/parser/a.c", "kind": "file"},
            {"path": "src/internal", "kind": "directory"},
            {"path": "src/internal/b.c", "kind": "file"},
        ],
        "issues": [],
        "issue_count": 0,
        "excluded_paths": [],
    }
    coverage = build_threat_coverage(inv, bundle)
    assert coverage["analysis_ready"] is True
    assert [m["name"] for m in coverage["modules"]] == [mod_a["模块名称"], mod_b["模块名称"]]
    assert len(coverage["targets"]) == 16 + 15
    proto_target = next(t for t in coverage["targets"] if t["pattern_id"] == "ODH-PROTO-01")
    assert proto_target["sources"] == [{
        "source_kind": "module_threat",
        "tree_id": "",
        "path_id": "",
        "path_name": "模块攻击威胁",
        "description": proto_pattern["description"],
    }]

    # Resume with same generate_attack_tree=False reuses all artifacts.
    monkeypatch.setattr(
        compact_native.TaskAgentSubmitter,
        "submit_tasks",
        lambda *_a, **_k: pytest.fail("Should reuse module_threats_only artifacts on resume"),
    )
    assert compact_native.run_threat_analysis(
        code_root, output_root, is_resume=True, generate_attack_tree=False,
    ) == result


def test_validate_module_threats_enforces_schema_and_51_pattern_catalog(tmp_path, compact_native):
    validator = importlib.import_module(compact_native.__name__ + ".validate_module_threats")
    tree_validator = importlib.import_module(compact_native.__name__ + ".validate_attack_tree")
    modes = json.loads(COMPACT_CATALOG.read_text(encoding="utf-8"))
    first = modes[0]
    valid = [{
        "pattern_id": "、".join(first["攻击模式编号"]),
        "pattern_name": first["攻击模式名称"],
        "description": "模块直接处理外部缓冲区长度。",
    }]
    output_file = tmp_path / "module-threat.json"
    output_file.write_text(json.dumps(valid, ensure_ascii=False), encoding="utf-8")
    assert validator.validate_file(output_file) == valid
    assert validator.main(["--output", str(output_file)]) == 0

    for invalid in [
        [{"pattern_id": "UNKNOWN-01", "pattern_name": "未知模式", "description": "不在51项中"}],
        [{**valid[0], "pattern_name": "被篡改的名称"}],
        [{**valid[0], "description": "   "}],
        [valid[0], valid[0]],
        [{**valid[0], "extra": True}],
    ]:
        output_file.write_text(json.dumps(invalid, ensure_ascii=False), encoding="utf-8")
        with pytest.raises(ValueError):
            validator.validate_file(output_file)
        assert validator.main(["--output", str(output_file)]) == 1

    schemas = importlib.import_module(compact_native.__name__ + ".schemas")
    envelope_file = tmp_path / "attack_trees.json"
    envelope = {
        "analysis_mode": "module_threats_only",
        "attack_trees": [],
        "module_threats": [{"module_name": "请求解析模块", "attack_patterns": valid}],
    }
    envelope_file.write_text(json.dumps(envelope, ensure_ascii=False), encoding="utf-8")
    assert tree_validator.validate_file(envelope_file, schemas.FINAL_ATTACK_TREE_SCHEMA) == envelope
