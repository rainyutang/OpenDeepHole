"""Read and validate lightweight threat-analysis files and tree directories."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path, PureWindowsPath
from typing import Any


class ArtifactValidationError(ValueError):
    """A generated artifact does not satisfy the threat-analysis contract."""


def load_attack_tree_artifact(path: Path) -> Any:
    """Expose both native representations as the existing in-memory tree list."""
    if path.is_dir():
        data, _ = load_attack_tree_directory(path)
        return data
    return _read_json(path, label="attack-tree artifact")


def load_attack_tree_directory(
    path: Path,
    *,
    files: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read a directory, or validate its persisted JSON-file snapshot."""
    errors: list[str] = []
    data, _, snapshot = _read_attack_tree_directory(path, errors, files=files)
    _raise_directory_errors(errors)
    return data, snapshot


def _read_attack_tree_directory(
    path: Path,
    errors: list[str],
    *,
    files: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
    trees: list[dict[str, Any]] = []
    sources: list[str] = []
    snapshot: dict[str, Any] = {}
    root = path.resolve()

    def read(name: str) -> Any:
        if files is not None:
            if name not in files:
                raise ArtifactValidationError(f"缺少文件 {name}")
            value = files[name]
        else:
            file_path = (root / name).resolve()
            if not file_path.is_relative_to(root):
                raise ArtifactValidationError(f"{name}: 文件路径超出攻击树目录")
            value = _read_json(file_path, label="attack-tree artifact")
        snapshot[name] = value
        return value

    try:
        index = read("index.json")
        if not isinstance(index, dict) or set(index) != {"attack_trees"}:
            raise ArtifactValidationError("index.json: 顶层必须仅包含 attack_trees 清单")
        entries = index["attack_trees"]
        if not isinstance(entries, list) or not entries:
            raise ArtifactValidationError("index.json $.attack_trees: 必须登记至少一棵攻击树")
    except ArtifactValidationError as exc:
        errors.append(str(exc))
        return {"attack_trees": trees}, sources, snapshot

    seen_ids: set[str] = set()
    seen_files: set[str] = set()
    for ordinal, entry in enumerate(entries):
        label = f"index.json $.attack_trees[{ordinal}]"
        if not isinstance(entry, dict) or set(entry) != {"tree_id", "file"}:
            errors.append(f"{label}: 必须且只能包含 tree_id 和 file")
            continue
        tree_id, name = entry["tree_id"], entry["file"]
        if not isinstance(tree_id, str) or not tree_id.strip():
            errors.append(f"{label}.tree_id: 必须是非空字符串")
            continue
        if (
            not isinstance(name, str)
            or not name.startswith("attack-tree-")
            or not name.endswith(".json")
            or name == "attack-tree-.json"
            or Path(name).name != name
            or PureWindowsPath(name).name != name
            or ":" in name
            or "\x00" in name
        ):
            errors.append(f"{label}.file: 必须是目录内的 attack-tree-xxx.json 文件名")
            continue
        if tree_id in seen_ids:
            errors.append(f"{label}: tree_id {tree_id!r} 重复")
        if name in seen_files:
            errors.append(f"{label}: 文件 {name!r} 重复")
            continue
        seen_ids.add(tree_id)
        seen_files.add(name)
        source = f"{name} [tree_id={tree_id!r}]"
        try:
            tree = read(name)
            if not isinstance(tree, dict) or "attack_trees" in tree:
                raise ArtifactValidationError("必须直接保存单棵树对象，不能使用 attack_trees 数组包装")
            if tree.get("tree_id") != tree_id:
                errors.append(
                    f"{source} $.tree_id: 清单要求 {tree_id!r}，实际为 {tree.get('tree_id')!r}"
                )
            trees.append(tree)
            sources.append(source)
        except ArtifactValidationError as exc:
            errors.append(f"{source}: 缺少攻击树或文件无效：{exc}")
    if len(trees) != len(entries):
        errors.insert(0, f"index.json: 计划 {len(entries)} 棵攻击树，成功读取 {len(trees)} 棵")
    return {"attack_trees": trees}, sources, snapshot


def _raise_directory_errors(errors: list[str]) -> None:
    if not errors:
        return
    # Keep the summary and complete per-file diagnostics inside the host's
    # 16 KiB output capture and correction-feedback budgets.
    message = f"攻击树目录校验失败，共 {len(errors)} 项问题：\n"
    shown = 0
    for error in errors:
        line = "- " + error
        if len(line.encode("utf-8")) > 2048:
            line = line.encode("utf-8")[:2048].decode("utf-8", errors="ignore") + "…"
        if len((message + line).encode("utf-8")) > 12 * 1024:
            break
        message += line + "\n"
        shown += 1
    if shown < len(errors):
        message += f"另有 {len(errors) - shown} 项未展示，请修复后重新校验。"
    raise ArtifactValidationError(message.rstrip())


def validate_artifacts(
    *,
    value_asset_path: Path,
    high_risk_modules_path: Path,
    attack_tree_path: Path,
    value_asset_schema_path: Path,
    high_risk_modules_schema_path: Path,
    attack_tree_schema_path: Path,
    attack_mode_path: Path,
) -> None:
    if attack_tree_path.is_dir():
        _validate_directory_artifacts(
            value_asset_path=value_asset_path,
            high_risk_modules_path=high_risk_modules_path,
            attack_tree_path=attack_tree_path,
            value_asset_schema_path=value_asset_schema_path,
            high_risk_modules_schema_path=high_risk_modules_schema_path,
            attack_tree_schema_path=attack_tree_schema_path,
            attack_mode_path=attack_mode_path,
        )
        return
    artifacts = (
        (
            _read_json(value_asset_path, label="artifact"),
            value_asset_path,
            value_asset_schema_path,
        ),
        (
            _read_json(high_risk_modules_path, label="artifact"),
            high_risk_modules_path,
            high_risk_modules_schema_path,
        ),
        (
            _read_json(attack_tree_path, label="artifact"),
            attack_tree_path,
            attack_tree_schema_path,
        ),
    )
    for value, path, schema_path in artifacts:
        schema = _read_json(schema_path, label="schema")
        if not isinstance(schema, Mapping):
            raise ArtifactValidationError(
                f"schema must contain a JSON object: {schema_path}"
            )
        _validate(value, schema, path="$")

    attack_modes = _read_json(attack_mode_path, label="attack mode reference")
    if not isinstance(attack_modes, list):
        raise ArtifactValidationError(
            f"attack mode reference must contain a JSON array: {attack_mode_path}"
        )
    _validate_artifact_relationships(
        value_assets=artifacts[0][0],
        high_risk_modules=artifacts[1][0],
        attack_trees=artifacts[2][0],
        attack_modes=attack_modes,
    )


def _validate_directory_artifacts(
    *,
    value_asset_path: Path,
    high_risk_modules_path: Path,
    attack_tree_path: Path,
    value_asset_schema_path: Path,
    high_risk_modules_schema_path: Path,
    attack_tree_schema_path: Path,
    attack_mode_path: Path,
) -> None:
    errors: list[str] = []
    bases: list[Any] = []
    for path, schema_path in (
        (value_asset_path, value_asset_schema_path),
        (high_risk_modules_path, high_risk_modules_schema_path),
    ):
        try:
            value = _read_json(path, label="artifact")
            _validate(value, _read_json(schema_path, label="schema"), path=f"{path.name} $")
            bases.append(value)
        except ArtifactValidationError as exc:
            errors.append(str(exc))
            bases.append(None)

    data, sources, _ = _read_attack_tree_directory(attack_tree_path, errors)
    single_schema = _read_json(
        attack_tree_schema_path.with_name("attack-tree.schema.json"), label="schema",
    )
    valid_trees: list[Any] = []
    valid_sources: list[str] = []
    for tree, source in zip(data["attack_trees"], sources):
        try:
            _validate(tree, single_schema, path=f"{source} $")
            valid_trees.append(tree)
            valid_sources.append(source)
        except ArtifactValidationError as exc:
            errors.append(str(exc))
    attack_modes = _read_json(attack_mode_path, label="attack mode reference")
    if not isinstance(attack_modes, list):
        errors.append(f"attack mode reference must contain a JSON array: {attack_mode_path}")
    elif all(value is not None for value in bases):
        _validate_artifact_relationships(
            value_assets=bases[0], high_risk_modules=bases[1],
            attack_trees={"attack_trees": valid_trees}, attack_modes=attack_modes,
            tree_sources=valid_sources, errors=errors,
        )
    _raise_directory_errors(errors)


def _validate_artifact_relationships(
    *,
    value_assets: Any,
    high_risk_modules: Any,
    attack_trees: Any,
    attack_modes: list[Any],
    tree_sources: list[str] | None = None,
    errors: list[str] | None = None,
) -> None:
    """Enforce semantic relationships that JSON Schema cannot express."""

    def report(error: ArtifactValidationError) -> None:
        if errors is None:
            raise error
        errors.append(str(error))

    asset_index = {
        _canonical_asset_from_value_asset(asset): asset
        for asset in value_assets
    }
    if len(asset_index) != len(value_assets):
        report(ArtifactValidationError("value-assets.json contains duplicate assets"))

    module_index: dict[str, Mapping[str, Any]] = {}
    for module in high_risk_modules:
        module_name = str(module["模块名称"])
        if module_name in module_index:
            report(ArtifactValidationError(
                f"high-risk-modules.json contains duplicate module name: {module_name!r}"
            ))
        module_index[module_name] = module

    allowed_patterns = {
        _canonical_attack_mode(mode)
        for mode in attack_modes
        if isinstance(mode, Mapping)
        and str(mode.get("攻击模式名称") or "").strip()
    }
    if not allowed_patterns:
        report(ArtifactValidationError("attack mode reference contains no usable patterns"))

    raw_trees = attack_trees["attack_trees"]
    try:
        _require_unique([tree["tree_id"] for tree in raw_trees], label="attack tree tree_id")
    except ArtifactValidationError as exc:
        report(exc)
    covered_assets: set[tuple[str, str, str, str]] = set()
    for tree_index, tree in enumerate(raw_trees):
        tree_path = (
            f"{tree_sources[tree_index]} $" if tree_sources is not None
            else f"$.attack_trees[{tree_index}]"
        )
        canonical_asset = _canonical_asset_from_tree(tree["value_asset"])
        if canonical_asset not in asset_index:
            report(ArtifactValidationError(
                f"{tree_path}.value_asset: must exactly match one value asset"
            ))
            continue
        covered_assets.add(canonical_asset)
        try:
            _validate_attack_tree(
                tree, canonical_asset=canonical_asset, module_index=module_index,
                allowed_patterns=allowed_patterns, path=tree_path,
            )
        except ArtifactValidationError as exc:
            report(exc)

    missing_assets = [
        asset[0] for asset in asset_index if asset not in covered_assets
    ]
    if missing_assets:
        report(ArtifactValidationError(
            "value assets without an attack tree: "
            + ", ".join(repr(value) for value in missing_assets)
        ))


def _validate_attack_tree(
    tree: Mapping[str, Any],
    *,
    canonical_asset: tuple[str, str, str, str],
    module_index: Mapping[str, Mapping[str, Any]],
    allowed_patterns: set[tuple[str, str]],
    path: str,
) -> None:
    nodes = tree["nodes"]
    edges = tree["edges"]
    attack_paths = tree["attack_paths"]
    _require_unique([node["node_id"] for node in nodes], label=f"{path} node_id")
    _require_unique([edge["edge_id"] for edge in edges], label=f"{path} edge_id")
    _require_unique(
        [attack_path["path_id"] for attack_path in attack_paths],
        label=f"{path} path_id",
    )
    nodes_by_id = {node["node_id"]: node for node in nodes}
    edges_by_id = {edge["edge_id"]: edge for edge in edges}

    root_nodes = [node for node in nodes if node["node_type"] == "根节点"]
    if len(root_nodes) != 1:
        raise ArtifactValidationError(f"{path}.nodes: expected exactly one root node")
    root = root_nodes[0]
    asset_name, _, _, _ = canonical_asset
    expected_root = {
        "module_name": None,
        "is_high_risk_module": False,
        "external_exposure": False,
        "external_interface_description": None,
    }
    for field, expected in expected_root.items():
        if root[field] != expected:
            raise ArtifactValidationError(
                f"{path}.nodes root {field}: must exactly equal {expected!r}"
            )
    if root["node_name"] != asset_name:
        raise ArtifactValidationError(
            f"{path}.nodes root node_name: must exactly equal value asset name "
            f"{asset_name!r}, got {root['node_name']!r}"
        )

    leaf_ids: set[str] = set()
    for node in nodes:
        node_type = node["node_type"]
        node_path = f"{path}.nodes[{node['node_id']!r}]"
        if node_type == "根节点":
            continue
        if node_type == "叶子节点":
            _validate_leaf_node(node, module_index=module_index, path=node_path)
            leaf_ids.add(node["node_id"])
            continue
        _validate_internal_node(node, module_index=module_index, path=node_path)

    if not leaf_ids:
        raise ArtifactValidationError(f"{path}.nodes: expected at least one leaf node")

    used_node_ids: set[str] = set()
    used_edge_ids: set[str] = set()
    covered_leaf_ids: set[str] = set()
    for attack_path in attack_paths:
        path_label = f"{path}.attack_paths[{attack_path['path_id']!r}]"
        path_node_ids = attack_path["node_ids"]
        path_edge_ids = attack_path["edge_ids"]
        _require_unique(path_node_ids, label=f"{path_label} node_ids")
        _require_unique(path_edge_ids, label=f"{path_label} edge_ids")
        if len(path_edge_ids) != len(path_node_ids) - 1:
            raise ArtifactValidationError(
                f"{path_label}: edge_ids must have exactly len(node_ids)-1 items"
            )
        try:
            path_nodes = [nodes_by_id[node_id] for node_id in path_node_ids]
            path_edges = [edges_by_id[edge_id] for edge_id in path_edge_ids]
        except KeyError as exc:
            raise ArtifactValidationError(
                f"{path_label}: references unknown node or edge ID {exc.args[0]!r}"
            ) from exc
        if path_nodes[0]["node_type"] != "叶子节点":
            raise ArtifactValidationError(f"{path_label}: first node must be a leaf")
        if path_nodes[-1]["node_id"] != root["node_id"]:
            raise ArtifactValidationError(
                f"{path_label}: last node must be this tree's root"
            )
        if any(node["node_type"] != "内部节点" for node in path_nodes[1:-1]):
            raise ArtifactValidationError(
                f"{path_label}: nodes between leaf and root must be internal nodes"
            )
        for index, edge in enumerate(path_edges):
            if (
                edge["source_node_id"] != path_node_ids[index]
                or edge["target_node_id"] != path_node_ids[index + 1]
            ):
                raise ArtifactValidationError(
                    f"{path_label}: edge {edge['edge_id']!r} does not connect adjacent nodes"
                )

        _validate_related_modules(
            attack_path,
            path_nodes=path_nodes,
            module_index=module_index,
            path=path_label,
        )
        _validate_attack_patterns(
            attack_path["attack_patterns"],
            allowed_patterns=allowed_patterns,
            path=path_label,
        )
        used_node_ids.update(path_node_ids)
        used_edge_ids.update(path_edge_ids)
        covered_leaf_ids.add(path_node_ids[0])

    missing_leaves = sorted(leaf_ids - covered_leaf_ids)
    if missing_leaves:
        raise ArtifactValidationError(
            f"{path}: leaf nodes without a complete attack path: {missing_leaves!r}"
        )
    orphan_nodes = sorted(set(nodes_by_id) - used_node_ids)
    orphan_edges = sorted(set(edges_by_id) - used_edge_ids)
    if orphan_nodes or orphan_edges:
        raise ArtifactValidationError(
            f"{path}: orphan nodes or edges are not allowed: "
            f"nodes={orphan_nodes!r}, edges={orphan_edges!r}"
        )


def _validate_leaf_node(
    node: Mapping[str, Any],
    *,
    module_index: Mapping[str, Mapping[str, Any]],
    path: str,
) -> None:
    module_name = node["module_name"]
    if not isinstance(module_name, str) or module_name not in module_index:
        raise ArtifactValidationError(
            f"{path}: leaf module_name must exactly match a high-risk module"
        )
    module = module_index[module_name]
    if module["是否外部暴露面"] != "是":
        raise ArtifactValidationError(
            f"{path}: leaf must reference a high-risk module with 是否外部暴露面=是"
        )
    if node["node_name"] != module_name:
        raise ArtifactValidationError(
            f"{path}: leaf node_name and module_name must be exactly identical"
        )
    if node["is_high_risk_module"] is not True or node["external_exposure"] is not True:
        raise ArtifactValidationError(
            f"{path}: leaf high-risk and external-exposure flags must both be true"
        )
    description = node["external_interface_description"]
    if not isinstance(description, str) or not description.strip():
        raise ArtifactValidationError(
            f"{path}: leaf requires a non-empty external interface description"
        )


def _validate_internal_node(
    node: Mapping[str, Any],
    *,
    module_index: Mapping[str, Mapping[str, Any]],
    path: str,
) -> None:
    module_name = node["module_name"]
    if not isinstance(module_name, str) or not module_name.strip():
        raise ArtifactValidationError(
            f"{path}: internal node must identify a concrete source module"
        )
    if node["node_name"] != module_name:
        raise ArtifactValidationError(
            f"{path}: internal node_name and module_name must be exactly identical"
        )
    if node["external_exposure"] is not False:
        raise ArtifactValidationError(
            f"{path}: internal node cannot be externally exposed"
        )
    if node["external_interface_description"] is not None:
        raise ArtifactValidationError(
            f"{path}: internal node external_interface_description must be null"
        )

    matched_module = module_index.get(module_name)
    if matched_module is None:
        if node["is_high_risk_module"] is not False:
            raise ArtifactValidationError(
                f"{path}: an internal node absent from high-risk modules must "
                "use is_high_risk_module=false"
            )
        return
    if matched_module["是否外部暴露面"] != "否":
        raise ArtifactValidationError(
            f"{path}: an externally exposed high-risk module must be a leaf, not an internal node"
        )
    if node["is_high_risk_module"] is not True:
        raise ArtifactValidationError(
            f"{path}: a matched internal high-risk module must use is_high_risk_module=true"
        )


def _validate_related_modules(
    attack_path: Mapping[str, Any],
    *,
    path_nodes: list[Mapping[str, Any]],
    module_index: Mapping[str, Mapping[str, Any]],
    path: str,
) -> None:
    related = attack_path["related_high_risk_modules"]
    related_by_node: dict[str, Mapping[str, Any]] = {}
    for item in related:
        node_id = item["node_id"]
        if node_id in related_by_node:
            raise ArtifactValidationError(
                f"{path}.related_high_risk_modules: duplicate node_id {node_id!r}"
            )
        related_by_node[node_id] = item

    expected_nodes = [
        node for node in path_nodes if node["is_high_risk_module"] is True
    ]
    if set(related_by_node) != {node["node_id"] for node in expected_nodes}:
        raise ArtifactValidationError(
            f"{path}.related_high_risk_modules: must exactly cover high-risk nodes on the path"
        )
    for index, node in enumerate(path_nodes):
        if node["is_high_risk_module"] is not True:
            continue
        item = related_by_node[node["node_id"]]
        module_name = node["module_name"]
        module = module_index.get(module_name)
        if module is None or item["module_name"] != module_name:
            raise ArtifactValidationError(
                f"{path}.related_high_risk_modules: module name must exactly match its path node"
            )
        expected_exposure = module["是否外部暴露面"] == "是"
        if item["external_exposure"] is not expected_exposure:
            raise ArtifactValidationError(
                f"{path}.related_high_risk_modules: external exposure does not "
                f"match {module_name!r}"
            )
        if node["node_type"] == "叶子节点":
            allowed_roles = {"外部攻击入口"}
        elif index == len(path_nodes) - 2:
            allowed_roles = {"内部影响模块", "直接资产影响模块"}
        else:
            allowed_roles = {"内部影响模块"}
        if item["path_role"] not in allowed_roles:
            raise ArtifactValidationError(
                f"{path}.related_high_risk_modules: invalid path_role for node {node['node_id']!r}"
            )


def _validate_attack_patterns(
    patterns: list[Mapping[str, Any]],
    *,
    allowed_patterns: set[tuple[str, str]],
    path: str,
) -> None:
    identities = [
        (pattern["pattern_id"], pattern["pattern_name"])
        for pattern in patterns
    ]
    _require_unique(identities, label=f"{path} attack patterns")
    for identity in identities:
        if identity not in allowed_patterns:
            raise ArtifactValidationError(
                f"{path}.attack_patterns: pattern must exactly match attack_mode.json: {identity!r}"
            )


def _canonical_asset_from_value_asset(
    asset: Mapping[str, Any],
) -> tuple[str, str, str, str]:
    return (
        asset["资产名"],
        asset["资产类别"],
        asset["资产描述"],
        asset["攻击损失"],
    )


def _canonical_asset_from_tree(asset: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return (
        asset["asset_name"],
        asset["asset_category"],
        asset["asset_description"],
        asset["attack_loss"],
    )


def _canonical_attack_mode(mode: Mapping[str, Any]) -> tuple[str, str]:
    raw_ids = mode.get("攻击模式编号")
    if isinstance(raw_ids, list):
        pattern_id = "、".join(
            str(value).strip() for value in raw_ids if str(value).strip()
        )
    else:
        pattern_id = str(raw_ids or "").strip()
    return pattern_id, str(mode.get("攻击模式名称") or "").strip()


def _require_unique(values: list[Any], *, label: str) -> None:
    seen: set[Any] = set()
    duplicates: list[Any] = []
    for value in values:
        if value in seen and value not in duplicates:
            duplicates.append(value)
        seen.add(value)
    if duplicates:
        raise ArtifactValidationError(f"{label} must be unique; duplicates={duplicates!r}")


def _read_json(path: Path, *, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ArtifactValidationError(f"required {label} is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ArtifactValidationError(
            f"{path}: JSON 第 {exc.lineno} 行第 {exc.colno} 列：{exc.msg}"
        ) from exc
    except (OSError, UnicodeError) as exc:
        raise ArtifactValidationError(
            f"{label} is not readable UTF-8 JSON: {path}"
        ) from exc


def _validate(value: Any, schema: Mapping[str, Any], *, path: str) -> None:
    if "enum" in schema and value not in schema["enum"]:
        raise ArtifactValidationError(
            f"{path}: value {value!r} is outside the allowed enum {schema['enum']!r}"
        )

    expected_type = schema.get("type")
    if expected_type is not None and not _matches_type(value, expected_type):
        raise ArtifactValidationError(
            f"{path}: expected {expected_type!r}, got {type(value).__name__}"
        )

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                raise ArtifactValidationError(
                    f"{path}: missing required property {key!r}"
                )
        if schema.get("additionalProperties") is False:
            extras = sorted(set(value) - set(properties))
            if extras:
                raise ArtifactValidationError(f"{path}: unexpected properties {extras!r}")
        for key, child_schema in properties.items():
            if key in value:
                _validate(value[key], child_schema, path=f"{path}.{key}")
        return

    if isinstance(value, list):
        minimum = schema.get("minItems")
        if minimum is not None and len(value) < int(minimum):
            raise ArtifactValidationError(
                f"{path}: expected at least {minimum} items, got {len(value)}"
            )
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                _validate(item, item_schema, path=f"{path}[{index}]")
        return

    if isinstance(value, str):
        minimum = schema.get("minLength")
        if minimum is not None and len(value) < int(minimum):
            raise ArtifactValidationError(f"{path}: string must not be empty")


def _matches_type(value: Any, expected: str | list[str]) -> bool:
    if isinstance(expected, list):
        return any(_matches_type(value, item) for item in expected)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    raise ArtifactValidationError(f"unsupported schema type: {expected!r}")


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate Codex Goal threat-analysis artifacts before completion."
    )
    parser.add_argument("--value-assets", type=Path, required=True)
    parser.add_argument("--high-risk-modules", type=Path, required=True)
    parser.add_argument("--attack-trees", type=Path, required=True)
    parser.add_argument("--references-root", type=Path, required=True)
    args = parser.parse_args(argv)
    references_root = args.references_root.resolve()
    try:
        validate_artifacts(
            value_asset_path=args.value_assets.resolve(),
            high_risk_modules_path=args.high_risk_modules.resolve(),
            attack_tree_path=args.attack_trees.resolve(),
            value_asset_schema_path=references_root / "value-assets.schema.json",
            high_risk_modules_schema_path=(
                references_root / "high-risk-modules.schema.json"
            ),
            attack_tree_schema_path=references_root / "attack-trees.schema.json",
            attack_mode_path=references_root / "attack_mode.json",
        )
    except ArtifactValidationError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    print("VALID: threat-analysis artifacts passed schema and relationship checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
