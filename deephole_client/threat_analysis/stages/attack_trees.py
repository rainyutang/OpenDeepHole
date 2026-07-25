"""Attack tree analysis stage."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from threat_analysis_harness.artifacts import ThreatAnalysisLayout
from threat_analysis_harness.errors import ArtifactConsistencyError
from threat_analysis_harness.output_validation import validate_json_schema
from threat_analysis_harness.schemas import ATTACK_TREE_SCHEMA
from threat_analysis_harness.stages.base import (
    ProgressReporter,
    SubmitTasks,
    TaskJson,
    require_all_success,
    run_or_resume_tasks,
)


class AttackTreeStage:
    task_type = "attack_tree_by_asset"
    skill_name = "attack-tree-by-asset"

    def __init__(
        self,
        *,
        submit_tasks: SubmitTasks,
        layout: ThreatAnalysisLayout,
    ) -> None:
        self.submit_tasks = submit_tasks
        self.layout = layout

    def build_tasks(
        self,
        *,
        value_assets: Sequence[dict[str, Any]],
        high_risk_modules: Sequence[dict[str, Any]],
        high_risk_modules_file: str | Path,
        context_files: Sequence[str | Path] = (),
        runtime_prompt: str | None = None,
    ) -> list[TaskJson]:
        tasks: list[TaskJson] = []
        module_references = _high_risk_module_references(high_risk_modules)
        task_output_schema = _attack_tree_task_schema(module_references)
        for index, asset in enumerate(value_assets, start=1):
            task_id = f"attack-tree-by-asset-{index:03d}"
            tasks.append(
                {
                    "task_id": task_id,
                    "task_type": self.task_type,
                    "skill_name": self.skill_name,
                    "runtime_prompt": _asset_prompt(
                        asset,
                        high_risk_modules_file=high_risk_modules_file,
                        module_references=module_references,
                        context_files=context_files,
                        runtime_prompt=runtime_prompt,
                    ),
                    "input_files": [str(high_risk_modules_file)]
                    + [str(path) for path in context_files],
                    "output_path": str(self.layout.attack_trees_raw_dir / f"{task_id}.json"),
                    "output_schema": task_output_schema,
                    "metadata": {
                        "stage": "attack_trees",
                        "asset_name": asset.get("资产名") or asset.get("asset_name"),
                    },
                    "priority": 40,
                }
            )
        return tasks

    def run(
        self,
        *,
        value_assets: Sequence[dict[str, Any]],
        high_risk_modules: Sequence[dict[str, Any]],
        high_risk_modules_file: str | Path | None = None,
        context_files: Sequence[str | Path] = (),
        runtime_prompt: str | None = None,
        timeout: float | None = None,
        resume: bool = False,
        progress_reporter: ProgressReporter | None = None,
    ) -> dict[str, Any]:
        self.layout.ensure()
        final_high_risk_modules_file = high_risk_modules_file or (
            self.layout.high_risk_final_dir / "high-risk-module-merge.json"
        )
        tasks = self.build_tasks(
            value_assets=value_assets,
            high_risk_modules=high_risk_modules,
            high_risk_modules_file=final_high_risk_modules_file,
            context_files=context_files,
            runtime_prompt=runtime_prompt,
        )
        results = require_all_success(
            run_or_resume_tasks(
                submit_tasks=self.submit_tasks,
                tasks=tasks,
                resume=resume,
                timeout=timeout,
                progress_reporter=progress_reporter,
                validate_existing_output_schema=True,
            )
        )
        normalized_outputs = [
            normalize_attack_tree_output(
                result["output"],
                value_asset=asset,
                high_risk_modules=high_risk_modules,
            )
            for asset, result in zip(value_assets, results)
        ]
        combined = combine_attack_tree_outputs(normalized_outputs)
        self.layout.write_final_json("attack_trees/final/attack_trees.json", combined)
        return combined


def normalize_attack_tree_output(
    output: dict[str, Any],
    *,
    value_asset: dict[str, Any],
    high_risk_modules: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    normalized = copy.deepcopy(output)
    attack_trees = normalized.get("attack_trees", [])
    if not attack_trees:
        asset_name = _asset_name(value_asset)
        raise ArtifactConsistencyError(
            f"Attack tree output is missing tree for asset: {asset_name}"
        )

    canonical_asset = _canonical_attack_tree_asset(value_asset)
    module_index = _high_risk_module_index(high_risk_modules)

    for tree in attack_trees:
        tree["value_asset"] = dict(canonical_asset)
        _normalize_tree_nodes(tree, canonical_asset, module_index)
        _normalize_attack_paths(tree, module_index)
        _strip_internal_module_ids(tree)

    validate_json_schema(normalized, ATTACK_TREE_SCHEMA)
    return normalized


def combine_attack_tree_outputs(outputs: Sequence[dict[str, Any]]) -> dict[str, Any]:
    attack_trees: list[dict[str, Any]] = []
    for output in outputs:
        attack_trees.extend(output.get("attack_trees", []))
    return {
        "attack_trees": attack_trees,
    }


def _asset_prompt(
    asset: dict[str, Any],
    *,
    high_risk_modules_file: str | Path,
    module_references: Sequence["_HighRiskModuleReference"],
    context_files: Sequence[str | Path] = (),
    runtime_prompt: str | None = None,
) -> str:
    asset_name = asset.get("资产名") or asset.get("asset_name") or "当前价值资产"
    task_instruction = runtime_prompt or (
        f"请根据 skill 要求，仅针对价值资产“{asset_name}”进行攻击树分析。"
    )
    asset_json = json.dumps(asset, ensure_ascii=False, indent=2)
    context_text = (
        "额外代码上下文文件：" + "、".join(str(path) for path in context_files) + "。"
        if context_files
        else "未提供额外代码上下文文件。"
    )
    module_reference_json = json.dumps(
        [
            {
                "module_id": reference.module_id,
                "module_name": _module_name(reference.module),
                "code_paths": _module_code_paths(reference.module),
                "external_exposure": _is_external_module(reference.module),
            }
            for reference in module_references
        ],
        ensure_ascii=False,
        indent=2,
    )
    return (
        f"{task_instruction}\n"
        f"当前任务的价值资产如下：\n{asset_json}\n"
        f"全部最终高风险模块文件：{high_risk_modules_file}；"
        "必须读取该文件中的高风险模块后再分析攻击路径。"
        f"\n本次任务的内部高风险模块引用目录如下：\n{module_reference_json}\n"
        "必须按以下内部引用规则输出："
        "每个 nodes 项都必须包含 module_id；根节点和普通内部节点填写 null，"
        "叶子节点及属于高风险模块的内部节点填写引用目录中的对应 module_id；"
        "每个 related_high_risk_modules 项也必须填写对应 module_id。"
        "module_id 必须原样使用引用目录中的值，不得自行生成；"
        "module_name 和 node_name 仍使用引用目录中的规范 module_name。"
        "module_id 仅用于任务过程中的程序对齐，最终公开攻击树产物会自动移除该字段。"
        f"{context_text}"
        "最终只输出符合 JSON schema 的对象。"
    )


def _normalize_tree_nodes(
    tree: dict[str, Any],
    canonical_asset: dict[str, str],
    module_index: "_HighRiskModuleIndex",
) -> None:
    root_name = f"攻击价值资产：{canonical_asset['asset_name']}"
    for node in tree.get("nodes", []):
        if node.get("node_type") == "根节点":
            if node.get("module_id") is not None:
                raise ArtifactConsistencyError(
                    f"Root node must use module_id=null: {node.get('node_id')}"
                )
            node["node_name"] = root_name
            node["module_name"] = None
            node["is_high_risk_module"] = False
            node["external_exposure"] = False
            node["external_interface_description"] = None
            continue

        if node.get("node_type") == "叶子节点" and not str(
            node.get("module_id") or ""
        ).strip():
            raise ArtifactConsistencyError(
                f"Leaf node is missing internal module_id: {node.get('node_name')}"
            )

        match = _find_high_risk_module(
            module_index,
            node.get("module_id"),
            node.get("module_name"),
            node.get("node_name"),
        )
        if node.get("node_type") == "叶子节点":
            reference = _require_high_risk_module(
                match,
                "Leaf node",
                node.get("module_id") or node.get("node_name"),
            )
            _apply_high_risk_module_to_node(node, reference)
            if not _is_external_module(reference.module):
                raise ArtifactConsistencyError(
                    "Leaf node references non-external high-risk module: "
                    f"{_module_name(reference.module)}"
                )
            continue

        if match is None:
            if node.get("node_type") == "内部节点":
                _normalize_unmatched_internal_node(node)
            continue

        if node.get("is_high_risk_module") is True:
            _apply_high_risk_module_to_node(node, match)
            continue

        _apply_high_risk_module_to_node(node, match)


def _normalize_attack_paths(
    tree: dict[str, Any],
    module_index: "_HighRiskModuleIndex",
) -> None:
    nodes_by_id = {
        str(node.get("node_id")): node
        for node in tree.get("nodes", [])
        if node.get("node_id") is not None
    }

    for path in tree.get("attack_paths", []):
        node_ids = {str(node_id) for node_id in path.get("node_ids", [])}
        related_modules: list[dict[str, Any]] = []
        seen_modules: set[str] = set()

        for related in path.get("related_high_risk_modules", []):
            node_id = str(related.get("node_id", ""))
            if node_id not in node_ids:
                continue
            node = nodes_by_id.get(node_id)
            match = _find_high_risk_module(
                module_index,
                related.get("module_id"),
                related.get("module_name"),
                None if node is None else node.get("module_name"),
                None if node is None else node.get("node_name"),
            )
            reference = _require_high_risk_module(
                match,
                "Related high-risk module",
                related.get("module_id") or related.get("module_name"),
            )
            if node is not None:
                node_module_id = str(node.get("module_id") or "").strip()
                if node_module_id and node_module_id != reference.module_id:
                    raise ArtifactConsistencyError(
                        "Related high-risk module_id does not match its node: "
                        f"related={reference.module_id}, node={node_module_id}, node_id={node_id}"
                    )
                _apply_high_risk_module_to_node(node, reference)
            if reference.module_id in seen_modules:
                continue
            canonical_name = _module_name(reference.module)
            related["module_name"] = canonical_name
            related["module_id"] = reference.module_id
            related["external_exposure"] = _is_external_module(reference.module)
            related_modules.append(related)
            seen_modules.add(reference.module_id)

        for node_id in path.get("node_ids", []):
            node = nodes_by_id.get(str(node_id))
            if node is None:
                raise ArtifactConsistencyError(
                    f"Attack path references unknown node_id: {node_id}"
                )
            if node.get("is_high_risk_module") is not True:
                continue
            reference = _require_high_risk_module(
                _find_high_risk_module(
                    module_index,
                    node.get("module_id"),
                    node.get("module_name"),
                    node.get("node_name"),
                ),
                "Path high-risk node",
                node.get("module_id")
                or node.get("module_name")
                or node.get("node_name"),
            )
            _apply_high_risk_module_to_node(node, reference)
            if reference.module_id in seen_modules:
                continue
            canonical_name = _module_name(reference.module)
            related_modules.append(
                {
                    "module_id": reference.module_id,
                    "module_name": canonical_name,
                    "node_id": str(node_id),
                    "external_exposure": _is_external_module(reference.module),
                    "path_role": _path_role_for_node(node),
                    "association_description": "该节点在攻击路径中被标记为高风险模块，名称已与最终高风险模块列表对齐。",
                }
            )
            seen_modules.add(reference.module_id)

        path["related_high_risk_modules"] = related_modules


def _apply_high_risk_module_to_node(
    node: dict[str, Any],
    reference: "_HighRiskModuleReference",
) -> None:
    module_name = _module_name(reference.module)
    node["node_name"] = module_name
    node["module_name"] = module_name
    node["module_id"] = reference.module_id
    node["is_high_risk_module"] = True
    node["external_exposure"] = _is_external_module(reference.module)


def _normalize_unmatched_internal_node(node: dict[str, Any]) -> None:
    node["is_high_risk_module"] = False
    node["external_exposure"] = False
    node["external_interface_description"] = None


def _canonical_attack_tree_asset(asset: dict[str, Any]) -> dict[str, str]:
    return {
        "asset_name": _asset_name(asset),
        "asset_category": str(asset.get("资产类别") or asset.get("asset_category") or "").strip(),
        "asset_description": str(
            asset.get("资产描述") or asset.get("asset_description") or ""
        ).strip(),
        "attack_loss": str(asset.get("攻击损失") or asset.get("attack_loss") or "").strip(),
    }


def _asset_name(asset: dict[str, Any]) -> str:
    return str(asset.get("资产名") or asset.get("asset_name") or "").strip()


@dataclass(frozen=True)
class _HighRiskModuleReference:
    module_id: str
    module: dict[str, Any]


@dataclass(frozen=True)
class _HighRiskModuleIndex:
    by_id: dict[str, _HighRiskModuleReference]
    by_name: dict[str, _HighRiskModuleReference]


def _high_risk_module_references(
    high_risk_modules: Sequence[dict[str, Any]],
) -> list[_HighRiskModuleReference]:
    references: list[_HighRiskModuleReference] = []
    seen_ids: dict[str, str] = {}
    for module in high_risk_modules:
        module_id = _stable_high_risk_module_id(module)
        module_name = _module_name(module)
        previous_name = seen_ids.get(module_id)
        if previous_name is not None and previous_name != module_name:
            raise ArtifactConsistencyError(
                "Stable high-risk module_id collision: "
                f"{module_id} maps to both {previous_name!r} and {module_name!r}"
            )
        seen_ids[module_id] = module_name
        references.append(
            _HighRiskModuleReference(
                module_id=module_id,
                module=module,
            )
        )
    return references


def _high_risk_module_index(
    high_risk_modules: Sequence[dict[str, Any]],
) -> _HighRiskModuleIndex:
    by_id: dict[str, _HighRiskModuleReference] = {}
    by_name: dict[str, _HighRiskModuleReference] = {}
    ambiguous_names: set[str] = set()
    for reference in _high_risk_module_references(high_risk_modules):
        by_id[reference.module_id] = reference
        normalized_name = _normalize_name(_module_name(reference.module))
        if not normalized_name:
            continue
        if normalized_name in by_name:
            ambiguous_names.add(normalized_name)
            continue
        by_name[normalized_name] = reference
    for normalized_name in ambiguous_names:
        by_name.pop(normalized_name, None)
    return _HighRiskModuleIndex(by_id=by_id, by_name=by_name)


def _find_high_risk_module(
    module_index: _HighRiskModuleIndex,
    module_id: Any,
    *names: Any,
) -> _HighRiskModuleReference | None:
    normalized_module_id = str(module_id or "").strip()
    if normalized_module_id:
        return module_index.by_id.get(normalized_module_id)
    for name in names:
        normalized = _normalize_name(name)
        if normalized and normalized in module_index.by_name:
            return module_index.by_name[normalized]
    return None


def _require_high_risk_module(
    reference: _HighRiskModuleReference | None,
    label: str,
    name: Any,
) -> _HighRiskModuleReference:
    if reference is None:
        raise ArtifactConsistencyError(
            f"{label} cannot be matched to final high-risk modules: {name}"
        )
    return reference


def _stable_high_risk_module_id(module: dict[str, Any]) -> str:
    normalized_code_paths = {
        normalized
        for path in _module_code_paths(module)
        if (normalized := _normalize_code_path(path))
    }
    identity = {
        "module_name": _normalize_name(_module_name(module)),
        "code_paths": sorted(normalized_code_paths),
    }
    encoded = json.dumps(
        identity,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"hrm-{hashlib.sha256(encoded).hexdigest()[:20]}"


def _module_code_paths(module: dict[str, Any]) -> list[str]:
    value = module.get("代码目录")
    if isinstance(value, list):
        return [str(path).strip() for path in value if str(path).strip()]
    path = str(value or "").strip()
    return [path] if path else []


def _normalize_code_path(value: Any) -> str:
    normalized = re.sub(
        r"/+",
        "/",
        str(value or "").strip().replace("\\", "/"),
    )
    return normalized.rstrip("/").casefold()


def _attack_tree_task_schema(
    module_references: Sequence[_HighRiskModuleReference],
) -> dict[str, Any]:
    schema = copy.deepcopy(ATTACK_TREE_SCHEMA)
    allowed_module_ids = [reference.module_id for reference in module_references]
    tree_schema = schema["properties"]["attack_trees"]["items"]
    node_schema = tree_schema["properties"]["nodes"]["items"]
    node_schema["required"].append("module_id")
    node_schema["properties"]["module_id"] = {
        "type": ["string", "null"],
        "enum": [None, *allowed_module_ids],
    }
    node_schema["oneOf"] = [
        {
            "properties": {
                "node_type": {"const": "根节点"},
                "module_id": {"const": None},
            }
        },
        {
            "properties": {
                "node_type": {"const": "叶子节点"},
                "module_id": {
                    "type": "string",
                    "enum": allowed_module_ids,
                },
            }
        },
        {
            "properties": {
                "node_type": {"const": "内部节点"},
            }
        },
    ]
    related_schema = tree_schema["properties"]["attack_paths"]["items"]["properties"][
        "related_high_risk_modules"
    ]["items"]
    related_schema["required"].append("module_id")
    related_schema["properties"]["module_id"] = {
        "type": "string",
        "enum": allowed_module_ids,
    }
    return schema


def _strip_internal_module_ids(tree: dict[str, Any]) -> None:
    for node in tree.get("nodes", []):
        node.pop("module_id", None)
    for path in tree.get("attack_paths", []):
        for related in path.get("related_high_risk_modules", []):
            related.pop("module_id", None)


def _module_name(module: dict[str, Any]) -> str:
    return str(module.get("模块名称") or module.get("module_name") or "").strip()


def _is_external_module(module: dict[str, Any]) -> bool:
    value = module.get("是否外部暴露面")
    if isinstance(value, bool):
        return value
    if value is None:
        return bool(module.get("external_exposure"))
    return str(value).strip() == "是"


def _path_role_for_node(node: dict[str, Any]) -> str:
    if node.get("node_type") == "叶子节点" or node.get("external_exposure") is True:
        return "外部攻击入口"
    return "内部影响模块"


def _normalize_name(value: Any) -> str:
    return re.sub(r"\s+", "", str(value or "")).casefold()
