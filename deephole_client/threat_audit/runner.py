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

PROCESS_NAME = "threat_audit"
_ALLOWED_KEYS = {
    "project_path", "work_dir", "scan_id", "threat_analysis", "concurrency",
    "required_capability", "include_task_ids", "exclude_task_ids",
    "task_agent_config", "output", "cancel_event",
}
_REQUIRED_KEYS = {"project_path", "work_dir", "scan_id", "threat_analysis"}
_GENERATED_THREAT_ID_PATTERN = re.compile(
    r"^(?:METHOD|NODE|AP|ASSET|RISK|GOAL|DOMAIN|SURFACE|TREE)-"
    r"[A-Z0-9][A-Z0-9-]*$",
    re.IGNORECASE,
)
_RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "vulnerabilities": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                    "function": {"type": "string"},
                    "call_chain": {"type": "array", "items": {"type": "string"}},
                    "vuln_type": {"type": "string"},
                    "severity": {"type": "string"},
                    "description": {"type": "string"},
                    "ai_analysis": {"type": "string"},
                    "vulnerability_report": {"type": "string"},
                    "confirmed": {"type": "boolean"},
                    "ai_verdict": {"type": "string"},
                },
                "required": [
                    "file", "line", "function", "vuln_type", "severity",
                    "description", "ai_analysis", "confirmed", "ai_verdict",
                ],
            },
        }
    },
    "required": ["vulnerabilities"],
}


async def _emit(output: Any, kind: str, message: str, **data: Any) -> None:
    if output is None:
        return
    result = output({"process": PROCESS_NAME, "kind": kind, "message": message, "data": data})
    if inspect.isawaitable(result):
        await result


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


def _attack_path_tasks(
    scan_id: str,
    analysis: dict[str, Any],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path_index, attack_path in enumerate(analysis.get("attack_paths") or []):
        if not isinstance(attack_path, dict):
            continue
        path_id = str(attack_path.get("path_id") or f"path-{path_index + 1}")
        identity = str(attack_path.get("fingerprint") or path_id).strip()
        if not identity:
            identity = json.dumps(attack_path, ensure_ascii=False, sort_keys=True)
        if identity in seen:
            continue
        seen.add(identity)
        code_paths: list[dict[str, str]] = []
        for raw_code_path in attack_path.get("code_paths") or []:
            if isinstance(raw_code_path, str):
                raw_code_path = {"path": raw_code_path}
            if not isinstance(raw_code_path, dict):
                continue
            code_paths.append({
                "path": str(raw_code_path.get("path") or ""),
                "description": str(raw_code_path.get("description") or ""),
            })
        first_code_path = code_paths[0] if code_paths else {}
        surface_name = _display_label(
            attack_path.get("attack_surface_name"),
            "未命名攻击面",
        )
        method_name = _display_label(
            attack_path.get("attack_method_name"),
            "未命名攻击方式",
        )
        attack_goal = _display_label(
            attack_path.get("attack_goal_name"),
            "未命名攻击目标",
        )
        risk_name = _display_label(
            attack_path.get("risk_name"),
            "未命名风险",
        )
        asset_name = _display_label(
            attack_path.get("asset_name"),
            "未命名资产",
        )
        result.append({
            "task_id": _stable_task_id(scan_id, identity),
            "scan_id": scan_id,
            "status": "pending",
            "surface_node_id": str(attack_path.get("attack_surface_id") or ""),
            "surface_name": surface_name,
            "method_node_id": str(attack_path.get("attack_method_id") or ""),
            "method_name": method_name,
            "attack_goal": attack_goal,
            "risk_id": str(attack_path.get("risk_id") or ""),
            "risk_name": risk_name,
            "asset_id": str(attack_path.get("asset_id") or ""),
            "asset_name": asset_name,
            "code_path": str(first_code_path.get("path") or ""),
            "code_path_description": str(
                first_code_path.get("description") or "",
            ),
            "code_paths": code_paths,
            "attack_path_id": path_id,
            "attack_path_fingerprint": str(
                attack_path.get("fingerprint") or "",
            ),
            "preconditions": list(attack_path.get("preconditions") or []),
            "evidence": list(attack_path.get("evidence") or []),
            "description": _task_description(
                attack_goal=attack_goal,
                surface_name=surface_name,
                method_name=method_name,
                asset_name=asset_name,
                risk_name=risk_name,
            ),
        })
    return result


def _legacy_tree_tasks(
    scan_id: str,
    analysis: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build surface/method tasks for schema versions without attack_paths."""
    risks: dict[str, tuple[str, str, str]] = {}
    for asset in analysis.get("assets") or []:
        if not isinstance(asset, dict):
            continue
        for risk in asset.get("risks") or []:
            if isinstance(risk, dict) and risk.get("risk_id"):
                risks[str(risk["risk_id"])] = (
                    str(risk.get("name") or ""),
                    str(asset.get("asset_id") or ""),
                    str(asset.get("name") or ""),
                )

    surfaces: dict[str, tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]] = {}
    for tree in analysis.get("attack_trees") or []:
        if not isinstance(tree, dict):
            continue
        nodes = [item for item in tree.get("nodes") or [] if isinstance(item, dict)]
        children: dict[str, list[dict[str, Any]]] = {}
        for node in nodes:
            parent_id = str(node.get("parent_id") or "")
            if parent_id:
                children.setdefault(parent_id, []).append(node)
        for group in children.values():
            group.sort(key=lambda item: int(item.get("order") or 0))
        for surface in nodes:
            if str(surface.get("node_type") or "").lower() != "surface":
                continue
            methods: list[dict[str, Any]] = []
            stack = list(reversed(children.get(str(surface.get("node_id") or ""), [])))
            while stack:
                node = stack.pop()
                if str(node.get("node_type") or "").lower() == "method":
                    methods.append(node)
                else:
                    stack.extend(
                        reversed(children.get(str(node.get("node_id") or ""), [])),
                    )
            surfaces[str(surface.get("node_id") or "")] = (
                tree,
                surface,
                methods or [{"node_type": "method", "name": "未标记攻击方式"}],
            )

    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for mapping in analysis.get("code_path_mappings") or []:
        if not isinstance(mapping, dict):
            continue
        surface_id = str(mapping.get("surface_node_id") or "")
        surface_info = surfaces.get(surface_id)
        if surface_info is None:
            continue
        tree, surface, methods = surface_info
        risk_name, asset_id, asset_name = risks.get(
            str(tree.get("risk_id") or ""),
            ("", str(tree.get("asset_id") or ""), ""),
        )
        code_paths = mapping.get("code_paths") or []
        if not isinstance(code_paths, list):
            code_paths = []
        for method in methods:
            method_id = str(method.get("node_id") or "").strip()
            method_identity = method_id or (
                f"name:{method.get('name') or ''}\0order:{method.get('order') or 0}"
            )
            key = (surface_id, method_identity)
            if key in seen:
                continue
            seen.add(key)
            surface_name = _display_label(
                surface.get("name"),
                "未命名攻击面",
            )
            method_name = _display_label(
                method.get("name"),
                "未命名攻击方式",
            )
            attack_goal = _display_label(
                tree.get("attack_goal"),
                "未命名攻击目标",
            )
            readable_risk_name = _display_label(
                risk_name,
                "未命名风险",
            )
            readable_asset_name = _display_label(
                asset_name,
                "未命名资产",
            )
            result.append({
                "task_id": _stable_task_id(
                    scan_id,
                    f"{surface_id}\0{method_identity}",
                ),
                "scan_id": scan_id,
                "status": "pending",
                "surface_node_id": surface_id,
                "surface_name": surface_name,
                "method_node_id": method_id or method_identity,
                "method_name": method_name,
                "attack_goal": attack_goal,
                "risk_id": str(tree.get("risk_id") or ""),
                "risk_name": readable_risk_name,
                "asset_id": asset_id,
                "asset_name": readable_asset_name,
                "code_path": "",
                "code_path_description": "",
                "code_paths": code_paths,
                "attack_path_id": "",
                "attack_path_fingerprint": "",
                "preconditions": [],
                "evidence": [],
                "description": _task_description(
                    attack_goal=attack_goal,
                    surface_name=surface_name,
                    method_name=method_name,
                    asset_name=readable_asset_name,
                    risk_name=readable_risk_name,
                ),
            })
    return result


def _tasks(scan_id: str, analysis: dict[str, Any]) -> list[dict[str, Any]]:
    attack_path_tasks = _attack_path_tasks(scan_id, analysis)
    return attack_path_tasks or _legacy_tree_tasks(scan_id, analysis)


def _normalize_vulnerability(raw: dict[str, Any], task: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    confirmed = bool(raw.get("confirmed"))
    return {
        "file": str(raw.get("file") or task["code_path"] or "."),
        "line": max(1, int(raw.get("line") or 1)),
        "function": str(raw.get("function") or "__threat_path__"),
        "call_chain": list(raw.get("call_chain") or []),
        "vuln_type": str(raw.get("vuln_type") or "threat_path"),
        "severity": str(raw.get("severity") or "unknown"),
        "description": str(raw.get("description") or task["method_name"]),
        "ai_analysis": str(raw.get("ai_analysis") or ""),
        "vulnerability_report": str(raw.get("vulnerability_report") or ""),
        "confirmed": confirmed,
        "ai_verdict": str(raw.get("ai_verdict") or ("confirmed" if confirmed else "not_confirmed")),
        "failure_reason": "",
        "analysis_source": "threat_audit",
        "source_task_id": task["task_id"],
        "threat_surface_node_id": task["surface_node_id"],
        "threat_method_node_id": task["method_node_id"],
        "threat_code_path": task["code_path"],
        "output_source": source,
    }


async def run_threat_audit(**kwargs: Any) -> dict[str, Any]:
    """Run a bounded model audit for every selected threat code path."""
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
    analysis = kwargs["threat_analysis"]
    if not isinstance(analysis, dict):
        raise TypeError("threat_analysis must be a dict")
    output = kwargs.get("output")
    if output is not None and not callable(output):
        raise TypeError("output must be callable or None")
    cancel_event = kwargs.get("cancel_event")
    concurrency = max(1, int(kwargs.get("concurrency") or 1))
    capability = str(kwargs.get("required_capability") or "high").lower()
    if capability not in {"low", "high"}:
        raise ValueError("required_capability must be 'low' or 'high'")
    scan_id = str(kwargs["scan_id"]).strip()
    tasks = _tasks(scan_id, analysis)
    included = {str(item) for item in kwargs.get("include_task_ids") or []}
    excluded = {str(item) for item in kwargs.get("exclude_task_ids") or []}
    if included:
        tasks = [task for task in tasks if task["task_id"] in included]
    tasks = [task for task in tasks if task["task_id"] not in excluded]
    await _emit(output, "progress", f"Prepared {len(tasks)} threat audit task(s)", total=len(tasks))

    semaphore = asyncio.Semaphore(concurrency)
    vulnerabilities: list[dict[str, Any]] = []
    result_lock = asyncio.Lock()

    async def audit(task: dict[str, Any]) -> None:
        if _cancelled(cancel_event):
            task["status"] = "cancelled"
            return
        async with semaphore:
            task["status"] = "running"
            task["started_at"] = datetime.now(timezone.utc).isoformat()
            await _emit(output, "progress", f"Auditing {task['task_id']}", task_id=task["task_id"])
            prompt = """请审计当前项目中的以下威胁路径，确认是否存在可利用的真实漏洞。
必须读取真实代码。不存在漏洞时返回空 vulnerabilities；不得为凑结果而推测。
威胁任务：
""" + json.dumps(task, ensure_ascii=False, indent=2)
            prompt += (
                "\n\n请将最终结果作为符合下方 JSON Schema 的纯 JSON 文本返回。"
                "最终回复只能包含这一个 JSON 值，不要使用 Markdown 代码围栏，"
                "也不要附加任何解释。应用程序会自行解析回复文本。\nJSON Schema：\n"
                + json.dumps(_RESULT_SCHEMA, ensure_ascii=False, indent=2)
            )
            try:
                result = await run_opencode_task(
                    task_name=task["task_id"],
                    task_type="threat_audit",
                    prompt=prompt,
                    required_capability=capability,
                    output_schema=_RESULT_SCHEMA,
                    config_path=kwargs.get("task_agent_config"),
                    output=None,
                    cancel_event=cancel_event,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                task["finished_at"] = datetime.now(timezone.utc).isoformat()
                task["status"] = "failed"
                task["failure_reason"] = str(exc)
                await _emit(
                    output,
                    "error",
                    f"Threat audit failed for {task['task_id']}: {exc}",
                    task_id=task["task_id"],
                )
                return
            task["finished_at"] = datetime.now(timezone.utc).isoformat()
            task["output_source"] = result.output_source
            if result.status != "success" or not isinstance(result.structured, dict):
                task["status"] = result.status
                task["failure_reason"] = result.text
                return
            produced = [
                _normalize_vulnerability(item, task, result.output_source)
                for item in result.structured.get("vulnerabilities") or []
                if isinstance(item, dict)
            ]
            async with result_lock:
                vulnerabilities.extend(produced)
            task["status"] = "completed"
            task["result_count"] = len(produced)
            await _emit(
                output, "item", f"Completed {task['task_id']}",
                task_id=task["task_id"], vulnerability_count=len(produced),
            )

    await asyncio.gather(*(audit(task) for task in tasks))
    status = "cancelled" if _cancelled(cancel_event) else "success"
    return {"status": status, "tasks": tasks, "vulnerabilities": vulnerabilities}
