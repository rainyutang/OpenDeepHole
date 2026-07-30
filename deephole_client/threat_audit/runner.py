"""Audit code paths derived from a threat-analysis result."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from task_agent import run_opencode_task

from .audit_schema import (
    THREAT_AUDIT_VULNERABILITY_LIST_SCHEMA,
    threat_audit_output_instruction,
)

PROCESS_NAME = "threat_audit"
_ALLOWED_KEYS = {
    "project_path", "work_dir", "scan_id", "attack_tree_path",
    "high_risk_modules_path", "concurrency",
    "required_capability", "include_task_ids", "exclude_task_ids",
    "task_agent_config", "output", "cancel_event",
}
_REQUIRED_KEYS = {
    "project_path",
    "work_dir",
    "scan_id",
    "attack_tree_path",
    "high_risk_modules_path",
}
_GENERATED_THREAT_ID_PATTERN = re.compile(
    r"^(?:METHOD|NODE|AP|ASSET|RISK|GOAL|DOMAIN|SURFACE|TREE)-"
    r"[A-Z0-9][A-Z0-9-]*$",
    re.IGNORECASE,
)
async def _emit(output: Any, kind: str, message: str, **data: Any) -> None:
    if output is None:
        return
    result = output({"process": PROCESS_NAME, "kind": kind, "message": message, "data": data})
    if inspect.isawaitable(result):
        await result


_TASK_STATUS_FIELDS = {
    "task_id",
    "scan_id",
    "status",
    "surface_node_id",
    "surface_name",
    "method_node_id",
    "method_name",
    "attack_goal",
    "risk_id",
    "risk_name",
    "asset_id",
    "asset_name",
    "code_path",
    "code_path_description",
    "code_paths",
    "attack_path_id",
    "attack_path_fingerprint",
    "description",
    "result_vuln_indexes",
    "failure_reason",
    "output_source",
    "created_at",
    "started_at",
    "finished_at",
    "updated_at",
}


def _task_status_snapshot(task: dict[str, Any]) -> dict[str, Any]:
    """Return the stable, platform-neutral task lifecycle payload."""
    return {
        key: value
        for key, value in task.items()
        if key in _TASK_STATUS_FIELDS
    }


async def _emit_task_status(
    output: Any,
    task: dict[str, Any],
    message: str,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    task.setdefault("created_at", now)
    task["updated_at"] = now
    await _emit(
        output,
        "task_status",
        message,
        task=_task_status_snapshot(task),
    )


def _cancelled(cancel_event: Any) -> bool:
    return bool(cancel_event is not None and cancel_event.is_set())


def _display_label(value: Any, fallback: str) -> str:
    normalized = str(value or "").strip()
    if normalized and not _GENERATED_THREAT_ID_PATTERN.fullmatch(normalized):
        return normalized
    return fallback


def _stable_task_id(scan_id: str, identity: str) -> str:
    digest = hashlib.sha1(
        f"{scan_id}\0{identity}".encode("utf-8"),
    ).hexdigest()[:20]
    return f"threat-audit-{digest}"


def _task_description(
    *,
    attack_goal: str,
    surface_name: str,
    method_name: str,
    asset_name: str,
    risk_name: str,
) -> str:
    return (
        f"攻击目标：{attack_goal}；攻击面节点：{surface_name}；"
        f"攻击方式：{method_name}；资产：{asset_name}；风险：{risk_name}"
    )


def _load_json(path_value: Any, key: str) -> Any:
    path = Path(path_value).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"{key} is not a file: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{key} is not valid JSON: {path}") from exc


def _module_code_paths(module: dict[str, Any]) -> list[dict[str, str]]:
    raw_paths = module.get("代码目录")
    values = raw_paths if isinstance(raw_paths, list) else [raw_paths]
    description = str(
        module.get("判断为高风险模块的原因")
        or module.get("面临威胁")
        or ""
    )
    return [
        {"path": str(value).strip(), "description": description}
        for value in values
        if str(value or "").strip()
    ]


def _text(value: Any) -> str:
    return str(value or "").strip()


def _path_nodes(
    attack_path: dict[str, Any],
    nodes: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    related_by_node = {
        _text(item.get("node_id")): item
        for item in attack_path.get("related_high_risk_modules") or []
        if isinstance(item, dict) and _text(item.get("node_id"))
    }
    raw_node_ids = attack_path.get("node_ids")
    node_ids = [
        _text(item)
        for item in (raw_node_ids if isinstance(raw_node_ids, list) else [])
        if _text(item)
    ]
    if not node_ids:
        node_ids = list(related_by_node)
    result: list[dict[str, Any]] = []
    for node_id in dict.fromkeys(node_ids):
        node = nodes.get(node_id)
        if node is not None:
            result.append(node)
            continue
        related = related_by_node.get(node_id)
        if related is None:
            continue
        result.append({
            "node_id": node_id,
            "node_type": "",
            "node_name": _text(related.get("module_name")),
            "description": _text(related.get("association_description")),
            "module_name": _text(related.get("module_name")),
            "is_high_risk_module": True,
            "external_exposure": related.get("external_exposure") is True,
            "external_interface_description": "",
        })
    return result


def _code_path_contexts(
    related: list[dict[str, Any]],
    modules_by_name: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    contexts: list[dict[str, str]] = []
    matched_modules: list[dict[str, Any]] = []
    for item in related:
        module_name = _text(item.get("module_name"))
        module = modules_by_name.get(module_name)
        if module is None:
            continue
        if module not in matched_modules:
            matched_modules.append(module)
        for code_path in _module_code_paths(module):
            context = {
                "module_name": module_name,
                "path": code_path["path"],
                "description": code_path["description"],
            }
            if context not in contexts:
                contexts.append(context)
    return contexts, matched_modules


def _external_exposure_contexts(
    path_nodes: list[dict[str, Any]],
    related: list[dict[str, Any]],
    modules_by_name: dict[str, dict[str, Any]],
) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    nodes_by_id = {
        _text(node.get("node_id")): node
        for node in path_nodes
        if _text(node.get("node_id"))
    }
    for node in path_nodes:
        if node.get("external_exposure") is not True:
            continue
        context = {
            "node_name": _text(node.get("node_name")),
            "module_name": _text(node.get("module_name")),
            "description": _text(node.get("external_interface_description")),
            "source": "attack_tree",
        }
        if context not in result:
            result.append(context)
    for item in related:
        module_name = _text(item.get("module_name"))
        node = nodes_by_id.get(_text(item.get("node_id"))) or {}
        if item.get("external_exposure") is True:
            context = {
                "node_name": _text(node.get("node_name")),
                "module_name": module_name,
                "description": _text(node.get("external_interface_description")),
                "source": "attack_tree",
            }
            if context not in result:
                result.append(context)
        module = modules_by_name.get(module_name)
        if module is None or _text(module.get("是否外部暴露面")) != "是":
            continue
        if any(
            context["node_name"] == _text(node.get("node_name"))
            and context["module_name"] == module_name
            for context in result
        ):
            continue
        context = {
            "node_name": _text(node.get("node_name")),
            "module_name": module_name,
            "description": "",
            "source": "high_risk_module",
        }
        if context not in result:
            result.append(context)
    return result


def _edge_contexts(
    attack_path: dict[str, Any],
    node_id: str,
    edges: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
) -> list[dict[str, str]]:
    raw_edge_ids = attack_path.get("edge_ids")
    edge_ids = {
        _text(item)
        for item in (raw_edge_ids if isinstance(raw_edge_ids, list) else [])
        if _text(item)
    }
    result: list[dict[str, str]] = []
    for edge in edges:
        edge_id = _text(edge.get("edge_id"))
        if edge_ids and edge_id not in edge_ids:
            continue
        source_id = _text(edge.get("source_node_id"))
        target_id = _text(edge.get("target_node_id"))
        if node_id not in {source_id, target_id}:
            continue
        context = {
            "source": _text((nodes.get(source_id) or {}).get("node_name"))
            or source_id,
            "target": _text((nodes.get(target_id) or {}).get("node_name"))
            or target_id,
            "influence_type": _text(edge.get("influence_type")),
            "description": _text(edge.get("description")),
        }
        if context not in result:
            result.append(context)
    return result


def _tasks(
    scan_id: str,
    attack_tree_data: dict[str, Any],
    high_risk_modules: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    modules_by_name = {
        str(module.get("模块名称") or "").strip(): module
        for module in high_risk_modules
        if isinstance(module, dict) and str(module.get("模块名称") or "").strip()
    }
    tasks_by_identity: dict[str, dict[str, Any]] = {}
    raw_trees = attack_tree_data.get("attack_trees") or []
    for tree_index, tree in enumerate(raw_trees):
        if not isinstance(tree, dict):
            continue
        tree_id = str(tree.get("tree_id") or f"tree-{tree_index + 1}")
        asset = tree.get("value_asset")
        asset = asset if isinstance(asset, dict) else {}
        asset_name = _display_label(asset.get("asset_name"), "未命名资产")
        nodes = {
            _text(node.get("node_id")): node
            for node in tree.get("nodes") or []
            if isinstance(node, dict) and node.get("node_id")
        }
        edges = [
            edge
            for edge in tree.get("edges") or []
            if isinstance(edge, dict)
        ]
        for path_index, attack_path in enumerate(tree.get("attack_paths") or []):
            if not isinstance(attack_path, dict):
                continue
            path_id = str(
                attack_path.get("path_id")
                or f"{tree_id}-path-{path_index + 1}"
            )
            related = [
                item
                for item in attack_path.get("related_high_risk_modules") or []
                if isinstance(item, dict)
            ]
            code_path_contexts, matched_modules = _code_path_contexts(
                related,
                modules_by_name,
            )
            path_nodes = _path_nodes(attack_path, nodes)
            exposures = _external_exposure_contexts(
                path_nodes,
                related,
                modules_by_name,
            )
            path_context = {
                "path_id": _text(attack_path.get("path_id")),
                "path_name": _text(attack_path.get("path_name")),
                "path_description": _text(attack_path.get("path_description")),
            }
            module_associations = [
                {
                    "module_name": _text(item.get("module_name")),
                    "path_role": _text(item.get("path_role")),
                    "association_description": _text(
                        item.get("association_description"),
                    ),
                }
                for item in related
            ]
            patterns = [
                item
                for item in attack_path.get("attack_patterns") or []
                if isinstance(item, dict)
            ]
            for node_index, node in enumerate(path_nodes):
                node_id = _text(node.get("node_id")) or (
                    f"{path_id}-node-{node_index + 1}"
                )
                qualified_node_id = f"{tree_id}:{node_id}"
                surface_name = _display_label(
                    node.get("module_name") or node.get("node_name"),
                    "未命名威胁节点",
                )
                node_edges = _edge_contexts(
                    attack_path,
                    node_id,
                    edges,
                    nodes,
                )
                for pattern_index, pattern in enumerate(patterns):
                    raw_pattern_id = _text(pattern.get("pattern_id"))
                    pattern_name = _text(pattern.get("pattern_name"))
                    pattern_identity = (
                        raw_pattern_id
                        or pattern_name
                        or f"{path_id}-pattern-{pattern_index + 1}"
                    )
                    method_node_id = raw_pattern_id or pattern_identity
                    method_name = _display_label(
                        pattern_name,
                        "未命名攻击模式",
                    )
                    identity = (
                        f"{tree_id}\0{node_id}\0{pattern_identity}"
                    )
                    task = tasks_by_identity.get(identity)
                    if task is None:
                        attack_goal = _display_label(
                            attack_path.get("path_name"),
                            _text(node.get("node_name"))
                            or "未命名攻击目标",
                        )
                        task = {
                            "task_id": _stable_task_id(scan_id, identity),
                            "scan_id": scan_id,
                            "status": "pending",
                            "surface_node_id": qualified_node_id,
                            "surface_name": surface_name,
                            "method_node_id": method_node_id,
                            "method_name": method_name,
                            "attack_goal": attack_goal,
                            "risk_id": "",
                            "risk_name": "",
                            "asset_id": "",
                            "asset_name": asset_name,
                            "code_path": "",
                            "code_path_description": "",
                            "code_paths": [],
                            "attack_path_id": path_id,
                            "attack_path_fingerprint": "",
                            "native_node_id": node_id,
                            "audit_node": dict(node),
                            "value_asset": dict(asset),
                            "attack_pattern": dict(pattern),
                            "attack_path_contexts": [],
                            "native_attack_paths": [],
                            "code_path_contexts": [],
                            "external_exposures": [],
                            "pattern_associations": [],
                            "module_associations": [],
                            "edge_contexts": [],
                            "_risks": [],
                            "_identity": identity,
                        }
                        tasks_by_identity[identity] = task
                    if path_context not in task["attack_path_contexts"]:
                        task["attack_path_contexts"].append(path_context)
                        task["native_attack_paths"].append(dict(attack_path))
                    for context in code_path_contexts:
                        if context not in task["code_path_contexts"]:
                            task["code_path_contexts"].append(context)
                        code_path = {
                            "path": context["path"],
                            "description": context["description"],
                        }
                        if code_path not in task["code_paths"]:
                            task["code_paths"].append(code_path)
                    for context in exposures:
                        if context not in task["external_exposures"]:
                            task["external_exposures"].append(context)
                    association = _text(pattern.get("association_description"))
                    if (
                        association
                        and association not in task["pattern_associations"]
                    ):
                        task["pattern_associations"].append(association)
                    for context in module_associations:
                        if context not in task["module_associations"]:
                            task["module_associations"].append(context)
                    for context in node_edges:
                        if context not in task["edge_contexts"]:
                            task["edge_contexts"].append(context)
                    for module in matched_modules:
                        risk = _text(module.get("面临威胁"))
                        if risk and risk not in task["_risks"]:
                            task["_risks"].append(risk)

    result = list(tasks_by_identity.values())
    for task in result:
        first_code_path = task["code_paths"][0] if task["code_paths"] else {}
        task["code_path"] = _text(first_code_path.get("path"))
        task["code_path_description"] = _text(
            first_code_path.get("description"),
        )
        task["risk_name"] = "；".join(task.pop("_risks")) or "未命名风险"
        task["native_attack_path"] = (
            task["native_attack_paths"][0]
            if task["native_attack_paths"]
            else {}
        )
        path_ids = [
            context["path_id"]
            for context in task["attack_path_contexts"]
            if context["path_id"]
        ]
        fingerprint_input = "\0".join([
            task.pop("_identity"),
            *sorted(set(path_ids)),
        ])
        task["attack_path_fingerprint"] = hashlib.sha1(
            fingerprint_input.encode("utf-8"),
        ).hexdigest()
        task["description"] = _task_description(
            attack_goal=task["attack_goal"],
            surface_name=task["surface_name"],
            method_name=task["method_name"],
            asset_name=task["asset_name"],
            risk_name=task["risk_name"],
        )
    return result


def _append_prompt_items(
    lines: list[str],
    label: str,
    values: list[str],
) -> None:
    normalized = list(dict.fromkeys(value for value in values if value))
    if not normalized:
        return
    lines.append(f"- {label}：")
    lines.extend(f"  - {value}" for value in normalized)


def _prompt_context_text(*values: Any) -> str:
    return "；".join(dict.fromkeys(
        value
        for item in values
        if (value := _text(item))
    ))


def _threat_prompt(task: dict[str, Any]) -> str:
    node = task.get("audit_node")
    node = node if isinstance(node, dict) else {}
    pattern = task.get("attack_pattern")
    pattern = pattern if isinstance(pattern, dict) else {}
    asset = task.get("value_asset")
    asset = asset if isinstance(asset, dict) else {}
    target_name = _text(node.get("module_name")) or _text(
        node.get("node_name"),
    )
    pattern_name = _text(pattern.get("pattern_name"))
    asset_name = _text(asset.get("asset_name"))
    lines = [
        (
            f"你是一个白盒审计专家。请检查「{target_name}」是否存在可利用的"
            f"真实漏洞，能够导致「{pattern_name}」，并危害「{asset_name}」。"
        ),
        "",
        (
            "以下上下文全部来自威胁分析结果。缺失的信息直接省略，不得推测"
            "或自行补全："
        ),
    ]
    node_name = _text(node.get("node_name"))
    node_type = _text(node.get("node_type"))
    if node_name:
        lines.append(
            f"- 审计节点：{node_name}"
            + (f"（{node_type}）" if node_type else ""),
        )
    node_description = _text(node.get("description"))
    if node_description:
        lines.append(f"- 节点说明：{node_description}")
    _append_prompt_items(
        lines,
        "相关代码路径",
        [
            _prompt_context_text(
                context.get("module_name"),
                context.get("path"),
                context.get("description"),
            )
            for context in task.get("code_path_contexts") or []
            if isinstance(context, dict)
        ],
    )
    exposure_values: list[str] = []
    for context in task.get("external_exposures") or []:
        if not isinstance(context, dict):
            continue
        value = _prompt_context_text(
            context.get("node_name"),
            context.get("module_name"),
            context.get("description"),
        )
        if (
            value
            and context.get("source") == "high_risk_module"
            and not _text(context.get("description"))
        ):
            value += "；高风险模块分析标记为外部暴露面"
        if value:
            exposure_values.append(value)
    _append_prompt_items(lines, "对外暴露面", exposure_values)
    pattern_id = _text(pattern.get("pattern_id"))
    if pattern_name or pattern_id:
        pattern_label = pattern_name
        if pattern_id:
            pattern_label += f"（{pattern_id}）" if pattern_label else pattern_id
        lines.append(f"- 攻击模式：{pattern_label}")
    associations = [
        _text(value)
        for value in task.get("pattern_associations") or []
        if _text(value)
    ]
    if associations:
        lines.append(f"- 模式关联说明：{'；'.join(associations)}")
    asset_category = _text(asset.get("asset_category"))
    if asset_name:
        lines.append(
            f"- 目标资产：{asset_name}"
            + (f"（{asset_category}）" if asset_category else ""),
        )
    asset_description = _text(asset.get("asset_description"))
    if asset_description:
        lines.append(f"- 资产说明：{asset_description}")
    attack_loss = _text(asset.get("attack_loss"))
    if attack_loss:
        lines.append(f"- 预期危害：{attack_loss}")
    _append_prompt_items(
        lines,
        "攻击路径",
        [
            _prompt_context_text(
                context.get("path_name"),
                context.get("path_description"),
            )
            for context in task.get("attack_path_contexts") or []
            if isinstance(context, dict)
        ],
    )
    _append_prompt_items(
        lines,
        "模块关联说明",
        [
            _prompt_context_text(
                context.get("module_name"),
                context.get("path_role"),
                context.get("association_description"),
            )
            for context in task.get("module_associations") or []
            if isinstance(context, dict)
        ],
    )
    _append_prompt_items(
        lines,
        "节点影响关系",
        [
            (
                f"{_text(context.get('source'))}"
                f" --{_text(context.get('influence_type'))}--> "
                f"{_text(context.get('target'))}"
                + (
                    f"；{_text(context.get('description'))}"
                    if _text(context.get("description"))
                    else ""
                )
            )
            for context in task.get("edge_contexts") or []
            if isinstance(context, dict)
        ],
    )
    lines.extend([
        "",
        (
            "优先审计上述代码路径，必要时沿真实调用链和数据流检查相关代码。"
            "威胁分析只作为审计线索，不能作为漏洞成立的证据。必须通过真实"
            "代码验证从对外暴露面或外部输入到漏洞触发点，再到目标资产危害"
            "的完整可达路径，不得推测或凑结果。"
        ),
        "",
        (
            "只输出能够导致上述攻击模式并危害目标资产的真实漏洞。每个独立"
            "漏洞对应一个列表元素，不得合并不同漏洞的位置、代码或调用链。"
        ),
    ])
    return "\n".join(lines) + threat_audit_output_instruction(
        THREAT_AUDIT_VULNERABILITY_LIST_SCHEMA,
    )


def _normalize_vulnerability(raw: dict[str, Any], task: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    return {
        "file": str(raw.get("file") or task["code_path"] or "."),
        "line": max(1, int(raw.get("line") or 1)),
        "function": str(raw.get("function") or "__threat_path__"),
        "call_chain": [
            {
                "function": str(item.get("function") or "").strip(),
                "file": str(item.get("file") or "").strip(),
                "line": max(1, int(item.get("line") or 1)),
            }
            for item in raw.get("call_chain") or []
            if isinstance(item, dict)
            and str(item.get("function") or "").strip()
            and str(item.get("file") or "").strip()
        ],
        "vuln_type": str(raw.get("vuln_type") or "threat_path"),
        "severity": str(raw.get("severity") or "low"),
        "description": str(raw.get("description") or task["method_name"]),
        "impact": str(raw.get("impact") or ""),
        "vulnerable_code": str(raw.get("vulnerable_code") or ""),
        "attack_entry": str(raw.get("attack_entry") or ""),
        "root_cause": str(raw.get("root_cause") or ""),
        "trigger_conditions": str(raw.get("trigger_conditions") or ""),
        "ai_analysis": "",
        "vulnerability_report": "",
        "confirmed": True,
        "ai_verdict": "confirmed",
        "failure_reason": "",
        "analysis_source": "threat_audit",
        "source_task_id": task["task_id"],
        "threat_surface_node_id": task["surface_node_id"],
        "threat_method_node_id": task["method_node_id"],
        "threat_code_path": task["code_path"],
        "output_source": source,
    }


async def run_threat_audit(**kwargs: Any) -> dict[str, Any]:
    """Audit every threat-analysis node and associated attack-pattern pair."""
    unknown = sorted(set(kwargs) - _ALLOWED_KEYS)
    if unknown:
        raise TypeError(f"run_threat_audit() got unexpected key(s): {', '.join(unknown)}")
    missing = sorted(key for key in _REQUIRED_KEYS if kwargs.get(key) in (None, ""))
    if missing:
        raise TypeError(f"run_threat_audit() missing required key(s): {', '.join(missing)}")
    project = Path(kwargs["project_path"]).expanduser().resolve()
    work_dir = Path(kwargs["work_dir"]).expanduser().resolve()
    if not project.is_dir():
        raise FileNotFoundError(f"project_path is not a directory: {project}")
    work_dir.mkdir(parents=True, exist_ok=True)
    attack_tree_data = _load_json(
        kwargs["attack_tree_path"],
        "attack_tree_path",
    )
    if not isinstance(attack_tree_data, dict):
        raise TypeError("attack_tree_path must contain a JSON object")
    high_risk_modules = _load_json(
        kwargs["high_risk_modules_path"],
        "high_risk_modules_path",
    )
    if not isinstance(high_risk_modules, list):
        raise TypeError("high_risk_modules_path must contain a JSON array")
    output = kwargs.get("output")
    if output is not None and not callable(output):
        raise TypeError("output must be callable or None")
    cancel_event = kwargs.get("cancel_event")
    concurrency = max(1, int(kwargs.get("concurrency") or 1))
    capability = str(kwargs.get("required_capability") or "high").lower()
    if capability not in {"low", "high"}:
        raise ValueError("required_capability must be 'low' or 'high'")
    scan_id = str(kwargs["scan_id"]).strip()
    tasks = _tasks(scan_id, attack_tree_data, high_risk_modules)
    included = {str(item) for item in kwargs.get("include_task_ids") or []}
    excluded = {str(item) for item in kwargs.get("exclude_task_ids") or []}
    if included:
        tasks = [task for task in tasks if task["task_id"] in included]
    tasks = [task for task in tasks if task["task_id"] not in excluded]
    for task in tasks:
        await _emit_task_status(
            output,
            task,
            f"Prepared threat audit task {task['task_id']}",
        )
    await _emit(output, "progress", f"Prepared {len(tasks)} threat audit task(s)", total=len(tasks))

    semaphore = asyncio.Semaphore(concurrency)
    vulnerabilities: list[dict[str, Any]] = []
    result_lock = asyncio.Lock()

    async def audit(task: dict[str, Any]) -> None:
        try:
            if _cancelled(cancel_event):
                task["status"] = "cancelled"
                task["finished_at"] = datetime.now(timezone.utc).isoformat()
                await _emit_task_status(
                    output,
                    task,
                    f"Cancelled threat audit task {task['task_id']}",
                )
                return
            async with semaphore:
                if _cancelled(cancel_event):
                    task["status"] = "cancelled"
                    task["finished_at"] = datetime.now(timezone.utc).isoformat()
                    await _emit_task_status(
                        output,
                        task,
                        f"Cancelled threat audit task {task['task_id']}",
                    )
                    return
                task["status"] = "running"
                task["started_at"] = datetime.now(timezone.utc).isoformat()
                await _emit_task_status(
                    output,
                    task,
                    f"Running threat audit task {task['task_id']}",
                )
                await _emit(output, "progress", f"Auditing {task['task_id']}", task_id=task["task_id"])
                prompt = _threat_prompt(task)
                result = await run_opencode_task(
                    task_name=task["task_id"],
                    task_type="threat_audit",
                    prompt=prompt,
                    required_capability=capability,
                    output_schema=THREAT_AUDIT_VULNERABILITY_LIST_SCHEMA,
                    config_path=kwargs.get("task_agent_config"),
                    cancel_event=cancel_event,
                )
                task["finished_at"] = datetime.now(timezone.utc).isoformat()
                task["output_source"] = result.output_source
                if result.status != "success" or not isinstance(result.structured, list):
                    task["status"] = (
                        "failed"
                        if result.status in {"success", "failure"}
                        else result.status
                    )
                    task["failure_reason"] = (
                        result.text
                        if result.status != "success"
                        else "Threat audit returned no result list"
                    )
                    await _emit_task_status(
                        output,
                        task,
                        f"Finished threat audit task {task['task_id']} with {task['status']}",
                    )
                    return
                produced = [
                    _normalize_vulnerability(item, task, result.output_source)
                    for item in result.structured
                    if isinstance(item, dict)
                ]
                async with result_lock:
                    vulnerabilities.extend(produced)
                task["status"] = "completed"
                task["result_count"] = len(produced)
                await _emit_task_status(
                    output,
                    task,
                    f"Completed threat audit task {task['task_id']}",
                )
                await _emit(
                    output, "item", f"Completed {task['task_id']}",
                    task_id=task["task_id"], vulnerability_count=len(produced),
                )
        except asyncio.CancelledError:
            task["status"] = "cancelled"
            task["finished_at"] = datetime.now(timezone.utc).isoformat()
            await _emit_task_status(
                output,
                task,
                f"Cancelled threat audit task {task['task_id']}",
            )
            raise
        except Exception as exc:
            task["finished_at"] = datetime.now(timezone.utc).isoformat()
            task["status"] = "failed"
            task["failure_reason"] = str(exc)
            await _emit_task_status(
                output,
                task,
                f"Failed threat audit task {task['task_id']}",
            )
            await _emit(
                output,
                "error",
                f"Threat audit failed for {task['task_id']}: {exc}",
                task_id=task["task_id"],
            )
            return

    await asyncio.gather(*(audit(task) for task in tasks))
    status = "cancelled" if _cancelled(cancel_event) else "success"
    return {"status": status, "tasks": tasks, "vulnerabilities": vulnerabilities}
