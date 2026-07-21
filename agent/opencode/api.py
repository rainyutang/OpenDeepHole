"""The single public OpenCode task interface used by OpenDeepHole components."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Literal


class OpenCodeTaskType(str, Enum):
    CANDIDATE_AUDIT = "audit"
    PROJECT_AUDIT = "project_audit"
    SENSITIVE_CLEAR = "sensitive_clear"
    REPORT_AUDIT = "report_audit"
    THREAT_ANALYSIS = "threat_analysis"
    THREAT_AUDIT = "threat_audit"
    FP_REVIEW = "fp_review"
    VULNERABILITY_VALIDATION = "vulnerability_validation"
    GIT_HISTORY = "git_history"
    VARIANT_HUNT = "variant_hunt"
    MEMORY_API_DISCOVERY = "memory_api_discovery"
    SKILL_CREATE = "skill_create"


@dataclass(frozen=True)
class OpenCodeResult:
    session_id: str
    status: Literal["success", "failure", "timeout"]
    text: str
    structured: Any
    model: str


async def run_opencode_task(
    *,
    task_name: str,
    task_type: OpenCodeTaskType,
    prompt: str,
    required_capability: Literal["low", "high"],
    output_schema: dict[str, Any] | None = None,
    invalid_json_retry_count: int = 2,
    session_id: str | None = None,
) -> OpenCodeResult:
    """Run one OpenCode task using Agent-bound project and work directories."""
    normalized_name = str(task_name or "").strip()
    normalized_prompt = str(prompt or "")
    if not normalized_name:
        raise ValueError("OpenCode task_name is required")
    if not normalized_prompt.strip():
        raise ValueError("OpenCode prompt is required")
    if not isinstance(task_type, OpenCodeTaskType):
        raise ValueError(f"Unsupported OpenCode task_type: {task_type!r}")
    capability = str(required_capability or "").strip().lower()
    if capability not in {"low", "high"}:
        raise ValueError("OpenCode required_capability must be 'low' or 'high'")
    if output_schema is not None and not isinstance(output_schema, dict):
        raise TypeError("OpenCode output_schema must be a dict or None")
    retry_count = int(invalid_json_retry_count)
    if retry_count < 0:
        raise ValueError("OpenCode invalid_json_retry_count cannot be negative")

    from .task_service import _run_component_task

    return await _run_component_task(
        task_name=normalized_name,
        task_type=task_type,
        prompt=normalized_prompt,
        required_capability=capability,
        output_schema=output_schema,
        invalid_json_retry_count=retry_count,
        session_id=str(session_id or "").strip() or None,
    )
