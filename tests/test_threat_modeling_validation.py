from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from deephole_client.threat_analysis.methods.codex_goal_threat_analysis import schema_validation as validator
from test_codex_goal_threat_analysis import _valid_artifacts


def _artifacts():
    assets, modules, trees = _valid_artifacts()
    modules.append({**modules[0], "模块名称": "内部认证", "是否外部暴露面": "否"})
    tree = trees["attack_trees"][0]
    tree["nodes"].append({
        **tree["nodes"][1], "node_id": "internal", "node_type": "内部节点",
        "node_name": "内部认证", "module_name": "内部认证",
        "external_exposure": False, "external_interface_description": None,
    })
    tree["edges"][0]["target_node_id"] = "internal"
    tree["edges"].append({
        **tree["edges"][0], "edge_id": "edge-2",
        "source_node_id": "internal", "target_node_id": "root",
    })
    path = tree["attack_paths"][0]
    path["node_ids"] = ["leaf", "internal", "root"]
    path["edge_ids"] = ["edge-1", "edge-2"]
    path["related_high_risk_modules"].append({
        **path["related_high_risk_modules"][0], "module_name": "内部认证",
        "node_id": "internal", "external_exposure": False, "path_role": "内部影响模块",
    })
    return assets, modules, trees


def _write(tmp_path, artifacts, directory):
    assets, modules, trees = artifacts
    paths = {
        "value_asset_path": tmp_path / "value-assets.json",
        "high_risk_modules_path": tmp_path / "high-risk-modules.json",
        "attack_tree_path": tmp_path / ("attack-trees" if directory else "attack-trees.json"),
    }
    payloads = {paths["value_asset_path"]: assets, paths["high_risk_modules_path"]: modules}
    if directory:
        tree_root = paths["attack_tree_path"]
        payloads[tree_root / "index.json"] = {"attack_trees": [
            {"tree_id": tree["tree_id"], "file": f"attack-tree-{index}.json"}
            for index, tree in enumerate(trees["attack_trees"])
        ]}
        for index, tree in enumerate(trees["attack_trees"]):
            payloads[tree_root / f"attack-tree-{index}.json"] = tree
    else:
        payloads[paths["attack_tree_path"]] = trees
    for path, value in payloads.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    references = Path(validator.__file__).parent / "references"
    return {
        **paths,
        "value_asset_schema_path": references / "value-assets.schema.json",
        "high_risk_modules_schema_path": references / "high-risk-modules.schema.json",
        "attack_tree_schema_path": references / "attack-trees.schema.json",
        "attack_mode_path": references / "attack_mode.json",
    }


@pytest.mark.parametrize("directory", [False, True])
@pytest.mark.parametrize("case", [
    "leaf_module_exposure", "leaf_name", "leaf_exposure", "leaf_interface",
    "internal_name", "internal_exposure", "internal_interface", "internal_module_exposure",
    "related_exposure", "related_role", "root_name", "uncovered_asset",
])
def test_modeling_issues_warn_without_changing_artifacts_and_remain_strict_by_default(tmp_path, directory, case):
    artifacts = assets, modules, trees = _artifacts()
    tree = trees["attack_trees"][0]
    root, leaf, internal = tree["nodes"]
    related = tree["attack_paths"][0]["related_high_risk_modules"][0]
    if case == "leaf_module_exposure":
        modules[0]["是否外部暴露面"] = "否"
    elif case == "leaf_name":
        leaf["node_name"] = "认证调用入口"
    elif case == "leaf_exposure":
        leaf["external_exposure"] = False
    elif case == "leaf_interface":
        leaf["external_interface_description"] = None
    elif case == "internal_name":
        internal["node_name"] = "内部认证处理"
    elif case == "internal_exposure":
        internal["external_exposure"] = True
    elif case == "internal_interface":
        internal["external_interface_description"] = "内部调用接口"
    elif case == "internal_module_exposure":
        modules[1]["是否外部暴露面"] = "是"
    elif case == "related_exposure":
        related["external_exposure"] = False
    elif case == "related_role":
        related["path_role"] = "内部影响模块"
    elif case == "root_name":
        root["node_name"] = "用户身份认证服务"
    elif case == "uncovered_asset":
        assets.append({**assets[0], "资产名": "另一项资产"})
    paths = _write(tmp_path, artifacts, directory)
    before = {file: file.read_bytes() for file in tmp_path.rglob("*.json")}
    warnings = []
    validator.validate_artifacts(**paths, strict_modeling=False, warnings=warnings)
    assert warnings
    assert before == {file: file.read_bytes() for file in before}
    validator.validate_artifacts(**paths, strict_modeling=False)
    with pytest.raises(validator.ArtifactValidationError):
        validator.validate_artifacts(**paths)


@pytest.mark.parametrize("directory", [False, True])
@pytest.mark.parametrize("case", [
    "unknown_module", "leaf_risk_flag", "internal_risk_flag", "unknown_node", "unknown_edge",
    "disconnected_edge", "duplicate_node", "related_module", "missing_related", "unknown_pattern",
    "unknown_asset", "schema_type",
])
def test_relaxed_modeling_still_rejects_unusable_artifacts(tmp_path, directory, case):
    artifacts = _artifacts()
    tree = artifacts[2]["attack_trees"][0]
    leaf = tree["nodes"][1]
    path = tree["attack_paths"][0]
    if case == "unknown_module":
        leaf["module_name"] = "不存在的模块"
    elif case == "leaf_risk_flag":
        leaf["is_high_risk_module"] = False
    elif case == "internal_risk_flag":
        tree["nodes"][2]["is_high_risk_module"] = False
    elif case == "unknown_node":
        path["node_ids"][1] = "unknown"
    elif case == "unknown_edge":
        path["edge_ids"][1] = "unknown"
    elif case == "disconnected_edge":
        tree["edges"][0]["target_node_id"] = "root"
    elif case == "duplicate_node":
        tree["nodes"].append(deepcopy(leaf))
    elif case == "related_module":
        path["related_high_risk_modules"][0]["module_name"] = "内部认证"
    elif case == "missing_related":
        path["related_high_risk_modules"].pop()
    elif case == "unknown_pattern":
        path["attack_patterns"][0]["pattern_id"] = "unknown"
    elif case == "unknown_asset":
        tree["value_asset"]["asset_name"] = "不存在的资产"
    elif case == "schema_type":
        leaf["external_exposure"] = "false"
    with pytest.raises(validator.ArtifactValidationError):
        validator.validate_artifacts(**_write(tmp_path, artifacts, directory), strict_modeling=False)
