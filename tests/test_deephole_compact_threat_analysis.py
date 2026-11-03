from __future__ import annotations

import importlib
import json
import re
from collections import Counter
from pathlib import Path

import pytest

from backend.threat_data import parse_threat_analysis_data
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
    assert compact_files.keys() == original_files.keys()
    attack_skill = "skills/attack-trees/attack-tree-by-asset/"
    for relative, original in original_files.items():
        if relative in {
            "method.yaml",
            attack_skill + "SKILL.md",
            attack_skill + "references/attack_mode.json",
        }:
            continue
        # The clone may change Skill identities, but not business behavior.
        assert compact_files[relative].read_bytes().replace(
            SKILL_PREFIX.encode(), b""
        ) == original.read_bytes(), relative


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


def test_attack_prompt_uses_private_catalog_without_a_pattern_quota():
    prompt = (ATTACK_SKILL / "SKILL.md").read_text(encoding="utf-8")
    assert "51 项" in prompt
    assert "唯一攻击模式来源" in prompt
    assert "不设数量下限" in prompt
    assert "无法合理匹配时，攻击模式列表输出空数组" in prompt
    assert not re.search(r"至少\s*10", prompt)


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


@pytest.mark.parametrize("pattern_count", [0, 1, 3])
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
    assert artifacts["high_risk_modules_path"]["path"] == "high_risk_modules/final/high-risk-module-merge.json"
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
    assert len(targets) == pattern_count
    assert {target["pattern_id"] for target in targets} == {pattern["pattern_id"] for pattern in patterns}
    assert [target["pattern_description"] for target in targets] == [mode["攻击模式描述"] for mode in modes]

    def fail_if_called(*args, **kwargs):
        pytest.fail("Completed native artifacts should be reused without model tasks")

    monkeypatch.setattr(native.TaskAgentSubmitter, "submit_tasks", fail_if_called)
    assert native.run_threat_analysis(code_root, output_root, is_resume=True) == result
    assert collect_json_artifacts(result, output_root=output_root) == bundle
