"""Per-vulnerability adversarial false-positive review method."""

from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path
from typing import Any

from deephole_client.fp_review.prompts import (
    build_skill_prompt,
    original_vulnerability_report,
    stage_markdown_report,
)
from task_agent import run_opencode_task


PROCESS_NAME = "fp_review"
_ALLOWED_KEYS = {
    "scan_mode",
    "method_id",
    "project_path",
    "code_scan_path",
    "work_dir",
    "scan_id",
    "review_id",
    "vuln_index",
    "vulnerability",
    "feedback_entries",
    "history",
    "required_capability",
    "invalid_json_retry_count",
    "task_agent_config",
    "output",
    "cancel_event",
}
_REQUIRED_KEYS = {
    "project_path",
    "code_scan_path",
    "work_dir",
    "scan_id",
    "review_id",
    "vuln_index",
    "vulnerability",
}
_STAGE_SKILLS = {
    "prove_bug": "prove-bug",
    "prove_fp": "prove-fp",
    "final_judge": "final-judge",
}
_STAGE_TASKS = {
    "prove_bug": (
        "请使用中文针对下面的原始漏洞报告进行漏洞成立论证。必须读取项目中的真实代码，"
        "验证外部输入源、调用链、变量可控性、现有校验、危险操作和实际影响；"
        "不得修改任何项目文件。最终只返回本 Skill 约定的 JSON。"
    ),
    "prove_fp": (
        "请使用中文针对下面的原始漏洞报告进行误报论证。必须独立读取项目中的真实代码，"
        "重点寻找不可达、不可控、校验充分、容量与索引绑定、危险操作实际安全或错误路径"
        "提前终止等反证；不得修改任何项目文件。最终只返回本 Skill 约定的 JSON。"
    ),
    "final_judge": (
        "请使用中文结合下面三份报告完成最终裁决。必须重新核对项目中的真实代码，"
        "分别判断正方和反方证据是否成立，不得按两边结论投票，也不得修改任何项目文件。"
        "最终只返回本 Skill 约定的 JSON。"
    ),
}
_STAGE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["true_positive", "false_positive", "uncertain"],
        },
        "reason": {"type": "string"},
        "evidence": {"type": "array", "items": {"type": "string"}},
        "revised_severity": {"type": "string"},
        "vulnerability_report": {"type": "string"},
        "stage_markdown": {"type": "string"},
    },
    "required": [
        "verdict",
        "reason",
        "evidence",
        "revised_severity",
        "vulnerability_report",
        "stage_markdown",
    ],
}


async def _emit(output: Any, kind: str, message: str, **data: Any) -> None:
    if output is None:
        return
    value = output({
        "process": PROCESS_NAME,
        "kind": kind,
        "message": message,
        "data": data,
    })
    if inspect.isawaitable(value):
        await value


def _cancelled(cancel_event: Any) -> bool:
    return bool(cancel_event is not None and cancel_event.is_set())


def _normalize_vulnerability(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    if not isinstance(value, dict):
        raise TypeError("vulnerability must be a dict")
    return dict(value)


def _stage_payload(result: Any) -> dict[str, Any]:
    if result.status != "success" or not isinstance(result.structured, dict):
        return {
            "status": result.status,
            "verdict": "uncertain",
            "reason": str(result.text or "Stage returned no structured result"),
            "evidence": [],
            "revised_severity": "",
            "vulnerability_report": "",
            "stage_markdown": str(result.text or ""),
            "match_type": "",
            "match_reference": "",
            "output_source": dict(result.output_source or {}),
        }
    raw = result.structured
    verdict = str(raw.get("verdict") or "uncertain")
    if verdict not in {"true_positive", "false_positive", "uncertain"}:
        verdict = "uncertain"
    return {
        "status": "success",
        "verdict": verdict,
        "reason": str(raw.get("reason") or ""),
        "evidence": [
            str(item)
            for item in raw.get("evidence") or []
            if str(item).strip()
        ],
        "revised_severity": str(raw.get("revised_severity") or ""),
        "vulnerability_report": str(raw.get("vulnerability_report") or ""),
        "stage_markdown": str(raw.get("stage_markdown") or ""),
        "match_type": str(raw.get("match_type") or ""),
        "match_reference": str(raw.get("match_reference") or ""),
        "output_source": dict(result.output_source or {}),
    }


def _write_stage_artifact(
    directory: Path,
    stage: str,
    payload: dict[str, Any],
) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{stage}.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (directory / f"{stage}.md").write_text(
        str(payload.get("stage_markdown") or payload.get("reason") or "") + "\n",
        encoding="utf-8",
    )


async def run(**kwargs: Any) -> dict[str, Any]:
    """Review exactly one vulnerability with debate and final-judge stages."""
    unknown = sorted(set(kwargs) - _ALLOWED_KEYS)
    if unknown:
        raise TypeError(
            "run() got unexpected key(s): " + ", ".join(unknown),
        )
    missing = sorted(
        key for key in _REQUIRED_KEYS if kwargs.get(key) in (None, "")
    )
    if missing:
        raise TypeError(
            "run() missing required key(s): " + ", ".join(missing),
        )

    project = Path(kwargs["project_path"]).expanduser().resolve()
    if not project.is_dir():
        raise FileNotFoundError(f"project_path is not a directory: {project}")
    code_scan_path = Path(kwargs["code_scan_path"]).expanduser().resolve()
    if not code_scan_path.is_dir():
        raise FileNotFoundError(
            f"code_scan_path is not a directory: {code_scan_path}"
        )
    work_dir = Path(kwargs["work_dir"]).expanduser().resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    vulnerability = _normalize_vulnerability(kwargs["vulnerability"])
    vuln_index = int(kwargs["vuln_index"])
    feedback_entries = kwargs.get("feedback_entries") or []
    history = kwargs.get("history") or []
    if not isinstance(feedback_entries, list) or not all(
        isinstance(item, dict) for item in feedback_entries
    ):
        raise TypeError("feedback_entries must be a list of dicts")
    if not isinstance(history, list) or not all(
        isinstance(item, dict) for item in history
    ):
        raise TypeError("history must be a list of dicts")
    output = kwargs.get("output")
    if output is not None and not callable(output):
        raise TypeError("output must be callable or None")
    cancel_event = kwargs.get("cancel_event")
    capability = str(kwargs.get("required_capability") or "high").lower()
    if capability not in {"low", "high"}:
        raise ValueError("required_capability must be 'low' or 'high'")
    retry_count = max(0, int(kwargs.get("invalid_json_retry_count") or 2))
    report_markdown = original_vulnerability_report(vulnerability)

    await _emit(
        output,
        "progress",
        f"Starting adversarial FP review for vulnerability {vuln_index}",
        total=1,
        vuln_index=vuln_index,
    )

    async def run_stage(
        *,
        item_index: int,
        stage: str,
        report_sections: tuple[tuple[str, str], ...] = (),
    ) -> dict[str, Any]:
        await _emit(
            output,
            "progress",
            f"Running {stage} for vulnerability {item_index}",
            vuln_index=item_index,
            stage=stage,
        )
        prompt = build_skill_prompt(
            skill_name=_STAGE_SKILLS[stage],
            task=_STAGE_TASKS[stage],
            sections=(
                ("原始漏洞报告", report_markdown),
                *report_sections,
            ),
            output_schema=_STAGE_SCHEMA,
        )
        result = await run_opencode_task(
            task_name=(
                f"fp-review-{kwargs['review_id']}-{item_index}-{stage}"
            ),
            task_type="fp_review",
            prompt=prompt,
            required_capability=capability,
            output_schema=_STAGE_SCHEMA,
            invalid_json_retry_count=retry_count,
            config_path=kwargs.get("task_agent_config"),
            output=None,
            cancel_event=cancel_event,
        )
        payload = _stage_payload(result)
        _write_stage_artifact(
            work_dir / "artifacts",
            stage,
            payload,
        )
        await _emit(
            output,
            "stage",
            f"Completed {stage} for vulnerability {item_index}",
            vuln_index=item_index,
            stage=stage,
            verdict=payload["verdict"],
            markdown=str(
                payload.get("stage_markdown")
                or payload.get("reason")
                or ""
            ),
            output_source=dict(payload.get("output_source") or {}),
        )
        return payload

    stages: dict[str, dict[str, Any]] = {}
    final: dict[str, Any] | None = None
    try:
        if _cancelled(cancel_event):
            return {
                "status": "cancelled",
                "error_message": "用户手动停止",
                "stage_outputs": {},
                "stage_output_sources": {},
            }
        stages["prove_bug"] = await run_stage(
            item_index=vuln_index,
            stage="prove_bug",
        )
        if stages["prove_bug"]["verdict"] == "false_positive":
            final = stages["prove_bug"]
            final["revised_severity"] = (
                final.get("revised_severity") or "low"
            )
        else:
            stages["prove_fp"] = await run_stage(
                item_index=vuln_index,
                stage="prove_fp",
            )
            stages["final_judge"] = await run_stage(
                item_index=vuln_index,
                stage="final_judge",
                report_sections=(
                    (
                        "正方论证报告",
                        stage_markdown_report(stages["prove_bug"]),
                    ),
                    (
                        "反方论证报告",
                        stage_markdown_report(stages["prove_fp"]),
                    ),
                ),
            )
            final = stages["final_judge"]
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        await _emit(
            output,
            "error",
            f"FP review failed for vulnerability {vuln_index}: {exc}",
            vuln_index=vuln_index,
        )
        return {
            "status": "error",
            "error_message": str(exc),
            "stage_outputs": {
                stage: str(payload.get("stage_markdown") or "")
                for stage, payload in stages.items()
            },
            "stage_output_sources": {
                stage: dict(payload.get("output_source") or {})
                for stage, payload in stages.items()
            },
        }

    stage_outputs = {
        stage: str(payload.get("stage_markdown") or "")
        for stage, payload in stages.items()
    }
    stage_sources = {
        stage: dict(payload.get("output_source") or {})
        for stage, payload in stages.items()
    }
    if _cancelled(cancel_event):
        return {
            "status": "cancelled",
            "error_message": "用户手动停止",
            "stage_outputs": stage_outputs,
            "stage_output_sources": stage_sources,
        }
    verdict = str((final or {}).get("verdict") or "uncertain")
    reason = str((final or {}).get("reason") or "").strip()
    if verdict not in {"true_positive", "false_positive"} or not reason:
        error_message = reason or "单项复核未生成有效 TP/FP 结果"
        await _emit(
            output,
            "error",
            f"漏洞 {vuln_index} 复核失败：{error_message}",
            vuln_index=vuln_index,
        )
        return {
            "status": "error",
            "error_message": error_message,
            "stage_outputs": stage_outputs,
            "stage_output_sources": stage_sources,
        }
    return {
        "status": "success",
        "verdict": verdict,
        "reason": reason,
        "revised_severity": str(
            (final or {}).get("revised_severity")
            or vulnerability.get("severity")
            or ""
        ),
        "vulnerability_report": str(
            (final or {}).get("vulnerability_report")
            or (report_markdown if verdict == "true_positive" else "")
            or ""
        ),
        "match_reference": "",
        "match_type": "",
        "stage_outputs": stage_outputs,
        "stage_output_sources": stage_sources,
        "output_source": dict((final or {}).get("output_source") or {}),
    }
