"""Audit a batch of static-analysis candidates with Task Agent."""

from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path
from typing import Any

import yaml
from task_agent import opencode_task_context, run_opencode_task

from .audit_schema import (
    VULNERABILITY_ITEM_SCHEMA,
    VULNERABILITY_LIST_SCHEMA,
    audit_output_instruction,
)

PROCESS_NAME = "candidate_audit"
PROJECT_LEVEL_FUNCTION = "__project__"
_ALLOWED_KEYS = {
    "project_path", "work_dir", "scan_id", "candidates", "checker_dirs",
    "index_db_path", "checker_names", "concurrency", "required_capability",
    "pattern_filter_enabled", "pattern_filter_scope", "feedback_entries",
    "audit_index_offset", "task_agent_config", "output", "cancel_event",
    "on_candidate_result", "product_mcp",
}
_REQUIRED_KEYS = {
    "project_path", "work_dir", "scan_id", "candidates", "index_db_path",
}
async def _emit(output: Any, kind: str, message: str, **data: Any) -> None:
    if output is None:
        return
    result = output({"process": PROCESS_NAME, "kind": kind, "message": message, "data": data})
    if inspect.isawaitable(result):
        await result


def _cancelled(cancel_event: Any) -> bool:
    return bool(cancel_event is not None and cancel_event.is_set())


def _skill_name(skill_path: Path) -> str:
    content = skill_path.read_text(encoding="utf-8")
    lines = content.splitlines()
    if not lines or lines[0].strip() != "---":
        raise ValueError(
            f"candidate audit skill must start with YAML frontmatter: {skill_path}"
        )
    closing_index = next(
        (
            index
            for index, line in enumerate(lines[1:], start=1)
            if line.strip() == "---"
        ),
        None,
    )
    if closing_index is None:
        raise ValueError(
            f"candidate audit skill has unterminated YAML frontmatter: {skill_path}"
        )
    try:
        metadata = yaml.safe_load("\n".join(lines[1:closing_index]))
    except yaml.YAMLError as exc:
        raise ValueError(
            f"candidate audit skill has invalid YAML frontmatter: {skill_path}"
        ) from exc
    name = str(metadata.get("name") or "").strip() if isinstance(metadata, dict) else ""
    if not name:
        raise ValueError(
            f"candidate audit skill frontmatter is missing name: {skill_path}"
        )
    return name


def _checker_catalog(roots: list[Path]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    skill_owners: dict[str, str] = {}
    for root in roots:
        if not root.is_dir():
            raise FileNotFoundError(f"checker directory does not exist: {root}")
        for directory in sorted(root.iterdir()):
            manifest = directory / "audit.yaml"
            skill_path = directory / "SKILL.md"
            if not directory.is_dir() or not skill_path.is_file():
                continue
            raw: dict[str, Any] = {}
            if manifest.is_file():
                loaded = yaml.safe_load(manifest.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    raw = loaded
            name = str(raw.get("name") or directory.name).strip()
            if name in result:
                continue
            skill_name = _skill_name(skill_path)
            previous_owner = skill_owners.get(skill_name)
            if previous_owner is not None:
                raise ValueError(
                    "candidate audit skill name is duplicated: "
                    f"{skill_name} ({previous_owner}, {name})"
                )
            skill_owners[skill_name] = name
            result[name] = {
                "name": name,
                "label": str(raw.get("label") or name),
                "result_mode": str(raw.get("result_mode") or "vulnerabilities"),
                "skill_name": skill_name,
            }
    return result


def _normalize_vulnerability(
    raw: dict[str, Any], candidate: dict[str, Any], audit_index: int, source: dict[str, Any],
) -> dict[str, Any]:
    confirmed = bool(raw.get("confirmed"))
    vuln_type = (
        str(raw.get("vuln_type") or candidate.get("vuln_type") or "unknown")
        if candidate.get("function") == PROJECT_LEVEL_FUNCTION
        else str(candidate.get("vuln_type") or "unknown")
    )
    return {
        "file": str(raw.get("file") or candidate.get("file") or "."),
        "line": max(1, int(raw.get("line") or candidate.get("line") or 1)),
        "function": str(raw.get("function") or candidate.get("function") or "<unknown>"),
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
        "vuln_type": vuln_type,
        "severity": str(raw.get("severity") or ("unknown" if confirmed else "low")),
        "description": str(raw.get("description") or candidate.get("description") or ""),
        "impact": str(raw.get("impact") or ""),
        "vulnerable_code": str(raw.get("vulnerable_code") or ""),
        "attack_entry": str(raw.get("attack_entry") or ""),
        "root_cause": str(raw.get("root_cause") or ""),
        "trigger_conditions": str(raw.get("trigger_conditions") or ""),
        "ai_analysis": "",
        "vulnerability_report": "",
        "confirmed": confirmed,
        "ai_verdict": "confirmed" if confirmed else "not_confirmed",
        "failure_reason": "",
        "audit_index": audit_index,
        "analysis_source": "static_candidate",
        "output_source": source,
    }


def _fallback(candidate: dict[str, Any], audit_index: int, status: str, reason: str, source: dict[str, Any]) -> dict[str, Any]:
    verdict = "timeout" if status == "timeout" else "failed"
    return {
        "file": str(candidate.get("file") or "."),
        "line": max(1, int(candidate.get("line") or 1)),
        "function": str(candidate.get("function") or "<unknown>"),
        "call_chain": [],
        "vuln_type": str(candidate.get("vuln_type") or "unknown"),
        "severity": "unknown",
        "description": str(candidate.get("description") or ""),
        "impact": "",
        "vulnerable_code": "",
        "attack_entry": "",
        "root_cause": "",
        "trigger_conditions": "",
        "ai_analysis": reason or "No analysis result returned",
        "vulnerability_report": "",
        "confirmed": False,
        "ai_verdict": verdict,
        "failure_reason": reason,
        "audit_index": audit_index,
        "analysis_source": "static_candidate",
        "output_source": source,
    }


def _pattern_key(candidate: dict[str, Any], scope: str) -> tuple[str, ...]:
    if scope == "file":
        return (str(candidate.get("vuln_type")), str(candidate.get("file")))
    if scope == "global":
        return (str(candidate.get("vuln_type")),)
    return (str(candidate.get("vuln_type")), str(candidate.get("function")))


def _related_variable(candidate: dict[str, Any]) -> str:
    metadata = candidate.get("metadata")
    if not isinstance(metadata, dict):
        return "未指定"
    subject = str(metadata.get("subject") or "").strip()
    if subject:
        return subject
    values = [
        str(metadata.get(key) or "").strip()
        for key in ("focus_variable", "target_variable")
    ]
    variables = list(dict.fromkeys(value for value in values if value))
    return "、".join(variables) or "未指定"


def _candidate_prompt(
    checker: dict[str, Any],
    candidate: dict[str, Any],
    product_mcp: str,
) -> str:
    is_project = candidate.get("function") == PROJECT_LEVEL_FUNCTION
    if is_project:
        instruction = (
            "请按已加载的 Skill 对当前项目进行审计。必须读取项目真实代码并验证"
            "完整攻击路径；每个独立问题对应一个列表元素，不得合并不同漏洞的位置、"
            "代码或调用链。若 Skill 中的旧输出字段、枚举或模板与本提示冲突，"
            "以本提示及 JSON Schema 为准。"
        )
        target = (
            "项目级审计目标：\n"
            + json.dumps(candidate, ensure_ascii=False, indent=2)
        )
    else:
        instruction = (
            "你是一个白盒审计专家，使用该skill审计文件"
            f"{str(candidate.get('file') or '')}中"
            f"{max(1, int(candidate.get('line') or 1))}行函数"
            f"{str(candidate.get('function') or '')}变量"
            f"{_related_variable(candidate)}是否存在"
            f"{str(candidate.get('vuln_type') or '')}问题，是否可以触发。"
        )
        target = ""
    product_instruction = (
        f"\n已配置产品知识库，请使用 `{product_mcp}` 提供的工具获取产品知识，"
        "判断外部入口函数。"
        if product_mcp
        else ""
    )
    call_chain_instruction = (
        "\n输出的 `call_chain` 必须以外部入口函数为起点。"
    )
    parts = [
        f"/{checker['skill_name']}",
        instruction + product_instruction + call_chain_instruction,
    ]
    if target:
        parts.append(target)
    return "\n".join(parts)


async def _notify_candidate_result(
    callback: Any,
    *,
    audit_index: int,
    checker_name: str,
    candidate: dict[str, Any],
    vulnerabilities: list[dict[str, Any]],
    reports: list[dict[str, Any]],
    processed_key: dict[str, Any],
) -> None:
    if callback is None:
        return
    result = callback({
        "audit_index": audit_index,
        "checker_name": checker_name,
        "candidate": dict(candidate),
        "vulnerabilities": [dict(item) for item in vulnerabilities],
        "skill_reports": [dict(item) for item in reports],
        "processed_key": dict(processed_key),
    })
    if inspect.isawaitable(result):
        await result


async def run_candidate_audit(**kwargs: Any) -> dict[str, Any]:
    """Audit a whole candidate batch and return vulnerabilities and checkpoints."""
    unknown = sorted(set(kwargs) - _ALLOWED_KEYS)
    if unknown:
        raise TypeError(f"run_candidate_audit() got unexpected key(s): {', '.join(unknown)}")
    missing = sorted(key for key in _REQUIRED_KEYS if kwargs.get(key) in (None, ""))
    if missing:
        raise TypeError(f"run_candidate_audit() missing required key(s): {', '.join(missing)}")
    project = Path(kwargs["project_path"]).expanduser().resolve()
    work_dir = Path(kwargs["work_dir"]).expanduser().resolve()
    index_path = Path(kwargs["index_db_path"]).expanduser().resolve()
    if not project.is_dir():
        raise FileNotFoundError(f"project_path is not a directory: {project}")
    if not index_path.is_file():
        raise FileNotFoundError(f"index_db_path is not a file: {index_path}")
    work_dir.mkdir(parents=True, exist_ok=True)
    candidates = kwargs["candidates"]
    if not isinstance(candidates, list):
        raise TypeError("candidates must be a list")
    normalized_candidates = []
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            if hasattr(candidate, "model_dump"):
                candidate = candidate.model_dump()
            else:
                raise TypeError(f"candidates[{index}] must be a dict")
        normalized_candidates.append(dict(candidate))
    raw_checker_dirs = kwargs.get("checker_dirs")
    if raw_checker_dirs is None:
        raw_checker_dirs = [Path(__file__).resolve().parent / "rules"]
    if not isinstance(raw_checker_dirs, (list, tuple)):
        raise TypeError("checker_dirs must be a list or tuple")
    checker_dirs = [
        Path(item).expanduser().resolve()
        for item in raw_checker_dirs
    ]
    catalog = _checker_catalog(checker_dirs)
    selected = {str(item) for item in kwargs.get("checker_names") or []}
    if selected:
        normalized_candidates = [
            item for item in normalized_candidates if str(item.get("vuln_type")) in selected
        ]
    missing_checkers = sorted({str(item.get("vuln_type")) for item in normalized_candidates} - set(catalog))
    if missing_checkers:
        raise ValueError(f"candidate checker(s) not found: {', '.join(missing_checkers)}")
    output = kwargs.get("output")
    if output is not None and not callable(output):
        raise TypeError("output must be callable or None")
    on_candidate_result = kwargs.get("on_candidate_result")
    if on_candidate_result is not None and not callable(on_candidate_result):
        raise TypeError("on_candidate_result must be callable or None")
    cancel_event = kwargs.get("cancel_event")
    concurrency = max(1, int(kwargs.get("concurrency") or 1))
    capability = str(kwargs.get("required_capability") or "high").lower()
    if capability not in {"low", "high"}:
        raise ValueError("required_capability must be 'low' or 'high'")
    audit_offset = max(0, int(kwargs.get("audit_index_offset") or 0))
    feedback = kwargs.get("feedback_entries") or []
    if not isinstance(feedback, list):
        raise TypeError("feedback_entries must be a list")
    filter_enabled = bool(kwargs.get("pattern_filter_enabled", False))
    filter_scope = str(kwargs.get("pattern_filter_scope") or "function")
    product_mcp = str(kwargs.get("product_mcp") or "").strip()

    vulnerabilities: list[dict[str, Any]] = []
    skill_reports: dict[str, list[dict[str, Any]]] = {}
    processed_keys: list[dict[str, Any]] = []
    rejected_patterns: set[tuple[str, ...]] = set()
    result_lock = asyncio.Lock()
    semaphore = asyncio.Semaphore(concurrency)
    await _emit(output, "progress", f"Starting audit of {len(normalized_candidates)} candidate(s)", total=len(normalized_candidates))

    async def audit(local_index: int, candidate: dict[str, Any]) -> None:
        audit_index = audit_offset + local_index
        key = _pattern_key(candidate, filter_scope)
        if _cancelled(cancel_event):
            return
        async with semaphore:
            async with result_lock:
                skip = filter_enabled and key in rejected_patterns
            if skip:
                result = _fallback(candidate, audit_index, "success", "Filtered by a previously rejected same-pattern candidate", {})
                result["ai_verdict"] = "filtered_same_pattern"
                processed_key = {
                    name: candidate.get(name)
                    for name in ("file", "line", "function", "vuln_type")
                }
                async with result_lock:
                    vulnerabilities.append(result)
                    processed_keys.append(processed_key)
                await _notify_candidate_result(
                    on_candidate_result,
                    audit_index=audit_index,
                    checker_name=str(candidate.get("vuln_type")),
                    candidate=candidate,
                    vulnerabilities=[result],
                    reports=[],
                    processed_key=processed_key,
                )
                await _emit(
                    output, "item", f"Candidate {audit_index + 1} completed",
                    audit_index=audit_index, vulnerability_count=1, report_count=0,
                )
                return
            checker = catalog[str(candidate.get("vuln_type"))]
            prompt = _candidate_prompt(
                checker,
                candidate,
                product_mcp,
            )
            if feedback:
                prompt += "\n\n历史人工反馈（只作判定参考）：\n" + json.dumps(feedback, ensure_ascii=False, indent=2)
            is_project = candidate.get("function") == PROJECT_LEVEL_FUNCTION
            result_schema = (
                VULNERABILITY_LIST_SCHEMA
                if is_project
                else VULNERABILITY_ITEM_SCHEMA
            )
            prompt += audit_output_instruction(
                result_schema,
                list_result=is_project,
                severity_basis="具体判定遵循已加载的 Skill。",
            )
            await _emit(output, "progress", f"Auditing candidate {audit_index + 1}", audit_index=audit_index)
            task_name_prefix = "project-audit" if is_project else "candidate-audit"
            task_result = await run_opencode_task(
                task_name=f"{task_name_prefix}-{kwargs['scan_id']}-{audit_index}",
                task_type="vulnerability_mining",
                prompt=prompt,
                required_capability=capability,
                output_schema=result_schema,
                config_path=kwargs.get("task_agent_config"),
                cancel_event=cancel_event,
            )
            produced: list[dict[str, Any]] = []
            reports: list[dict[str, Any]] = []
            raw_items: list[dict[str, Any]] = []
            if (
                task_result.status == "success"
                and is_project
                and isinstance(task_result.structured, list)
            ):
                raw_items = [
                    item
                    for item in task_result.structured
                    if isinstance(item, dict)
                ]
            elif (
                task_result.status == "success"
                and not is_project
                and isinstance(task_result.structured, dict)
            ):
                raw_items = [task_result.structured]
            if raw_items:
                produced = [
                    _normalize_vulnerability(item, candidate, audit_index, task_result.output_source)
                    for item in raw_items
                ]
            else:
                reason = (
                    task_result.text
                    if task_result.status != "success"
                    else "No result returned"
                )
                produced = [
                    _fallback(
                        candidate,
                        audit_index,
                        task_result.status,
                        reason,
                        task_result.output_source,
                    )
                ]
                if task_result.status == "success":
                    produced[0]["ai_verdict"] = "no_result"
            processed_key = {
                name: candidate.get(name)
                for name in ("file", "line", "function", "vuln_type")
            }
            async with result_lock:
                vulnerabilities.extend(produced)
                if reports:
                    skill_reports.setdefault(str(candidate.get("vuln_type")), []).extend(reports)
                if filter_enabled and produced and all(
                    not item["confirmed"] and item["ai_verdict"] == "not_confirmed" for item in produced
                ):
                    rejected_patterns.add(key)
                processed_keys.append(processed_key)
            await _notify_candidate_result(
                on_candidate_result,
                audit_index=audit_index,
                checker_name=str(candidate.get("vuln_type")),
                candidate=candidate,
                vulnerabilities=produced,
                reports=reports,
                processed_key=processed_key,
            )
            await _emit(
                output, "item", f"Candidate {audit_index + 1} completed",
                audit_index=audit_index, vulnerability_count=len(produced), report_count=len(reports),
            )

    with opencode_task_context(
        project_dir=project,
        work_dir=work_dir,
        scan_id=str(kwargs["scan_id"]),
        feedback_entries=feedback,
        config_path=kwargs.get("task_agent_config"),
        skill_paths=checker_dirs,
        cancel_event=cancel_event,
    ):
        await asyncio.gather(*(
            audit(index, candidate)
            for index, candidate in enumerate(normalized_candidates)
        ))
    status = "cancelled" if _cancelled(cancel_event) else "success"
    return {
        "status": status,
        "vulnerabilities": sorted(vulnerabilities, key=lambda item: int(item.get("audit_index") or 0)),
        "skill_reports": skill_reports,
        "processed_keys": processed_keys,
    }
