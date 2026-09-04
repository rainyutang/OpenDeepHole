"""Compact, report-oriented prompts shared by false-positive review methods."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from deephole_client.vulnerability_mining.engine_report import (
    build_engine_vulnerability_report,
)


def original_vulnerability_report(value: Any) -> str:
    """Return the model-facing Markdown report for one vulnerability."""
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    if not isinstance(value, dict):
        raise TypeError("vulnerability must be a dict")
    return build_engine_vulnerability_report(dict(value)).strip()


def stage_markdown_report(value: Any) -> str:
    """Project a structured stage result to its integrated Markdown report."""
    if not isinstance(value, dict):
        return ""
    return str(
        value.get("stage_markdown")
        or value.get("reason")
        or ""
    ).strip()


def build_skill_prompt(
    *,
    skill_name: str,
    task: str,
    sections: Iterable[tuple[str, str]],
    output_schema: dict[str, Any],
) -> str:
    """Build ``/skill`` + task + reports + schema + language instruction."""
    normalized_skill = str(skill_name or "").strip().lstrip("/")
    normalized_task = str(task or "").strip()
    if not normalized_skill:
        raise ValueError("skill_name must be non-empty")
    if not normalized_task:
        raise ValueError("task must be non-empty")
    if not isinstance(output_schema, dict) or not output_schema:
        raise ValueError("output_schema must be a non-empty dict")
    parts = [f"/{normalized_skill}", "", f"任务：{normalized_task}"]
    for title, content in sections:
        normalized_title = str(title or "").strip()
        normalized_content = str(content or "").strip()
        if not normalized_title or not normalized_content:
            continue
        parts.extend(["", f"## {normalized_title}", "", normalized_content])
    parts.extend([
        "",
        "## 输出 JSON Schema",
        "",
        "最终只返回符合以下 JSON Schema 的 JSON 对象：",
        "",
        "```json",
        json.dumps(output_schema, ensure_ascii=False, indent=2),
        "```",
        "",
        "请使用中文输出",
    ])
    return "\n".join(parts)


def completed_stage_reports(
    stages: Iterable[tuple[str, dict[str, Any]]],
) -> str:
    """Render completed structured stages as labelled Markdown reports."""
    parts: list[str] = []
    for label, payload in stages:
        report = stage_markdown_report(payload)
        if not report:
            continue
        parts.append(f"### {str(label or '').strip()}\n\n{report}")
    return "\n\n".join(parts)


__all__ = [
    "build_skill_prompt",
    "completed_stage_reports",
    "original_vulnerability_report",
    "stage_markdown_report",
]
