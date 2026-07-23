"""Independent multi-stage false-positive review process."""

from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path
from typing import Any

from task_agent import run_opencode_task


PROCESS_NAME = "fp_review"
_ALLOWED_KEYS = {
    "project_path",
    "work_dir",
    "scan_id",
    "review_id",
    "vulnerabilities",
    "feedback_entries",
    "history",
    "processed_offset",
    "concurrency",
    "required_capability",
    "invalid_json_retry_count",
    "task_agent_config",
    "output",
    "cancel_event",
}
_REQUIRED_KEYS = {
    "project_path",
    "work_dir",
    "scan_id",
    "review_id",
    "vulnerabilities",
}
_STAGE_FILES = {
    "history_match": "history_match.md",
    "prove_bug": "prove_bug.md",
    "prove_fp": "prove_fp.md",
    "final_judge": "final_judge.md",
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
        "match_type": {"type": "string"},
        "match_reference": {"type": "string"},
    },
    "required": [
        "verdict",
        "reason",
        "evidence",
        "revised_severity",
        "vulnerability_report",
        "stage_markdown",
        "match_type",
        "match_reference",
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


def _normalize_vulnerability(value: Any, index: int) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    if not isinstance(value, dict):
        raise TypeError(f"vulnerabilities[{index}] must be a dict")
    return dict(value)


def _read_skills() -> dict[str, str]:
    skills_dir = Path(__file__).resolve().parent / "skills"
    result: dict[str, str] = {}
    for stage, filename in _STAGE_FILES.items():
        path = skills_dir / filename
        if not path.is_file():
            raise FileNotFoundError(f"FP review skill is missing: {path}")
        result[stage] = path.read_text(encoding="utf-8")
    return result


def _stage_prompt(
    *,
    stage: str,
    skill: str,
    vulnerability: dict[str, Any],
    feedback_entries: list[dict[str, Any]],
    history: list[dict[str, Any]],
    prior_stages: dict[str, dict[str, Any]],
) -> str:
    context: dict[str, Any] = {
        "vulnerability": vulnerability,
        "feedback_entries": feedback_entries,
        "history": history,
        "prior_stages": prior_stages,
    }
    return (
        f"{skill}\n\n"
        f"当前阶段：{stage}\n"
        "必须读取当前项目中的真实代码，不得仅依据原报告复述结论。"
        "请严格返回约定 JSON；stage_markdown 写出本阶段可独立阅读的分析。\n\n"
        "输入上下文：\n"
        + json.dumps(context, ensure_ascii=False, indent=2)
    )


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


async def run_fp_review(**kwargs: Any) -> dict[str, Any]:
    """Review a vulnerability batch with match, debate and final-judge stages."""
    unknown = sorted(set(kwargs) - _ALLOWED_KEYS)
    if unknown:
        raise TypeError(
            "run_fp_review() got unexpected key(s): " + ", ".join(unknown),
        )
    missing = sorted(
        key for key in _REQUIRED_KEYS if kwargs.get(key) in (None, "")
    )
    if missing:
        raise TypeError(
            "run_fp_review() missing required key(s): " + ", ".join(missing),
        )

    project = Path(kwargs["project_path"]).expanduser().resolve()
    if not project.is_dir():
        raise FileNotFoundError(f"project_path is not a directory: {project}")
    work_dir = Path(kwargs["work_dir"]).expanduser().resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    raw_vulnerabilities = kwargs["vulnerabilities"]
    if not isinstance(raw_vulnerabilities, list):
        raise TypeError("vulnerabilities must be a list")
    vulnerabilities = [
        _normalize_vulnerability(value, index)
        for index, value in enumerate(raw_vulnerabilities)
    ]
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
    concurrency = max(1, int(kwargs.get("concurrency") or 1))
    retry_count = max(0, int(kwargs.get("invalid_json_retry_count") or 2))
    offset = max(0, int(kwargs.get("processed_offset") or 0))
    skills = _read_skills()
    semaphore = asyncio.Semaphore(concurrency)
    result_lock = asyncio.Lock()
    ordered_results: list[tuple[int, dict[str, Any]]] = []

    await _emit(
        output,
        "progress",
        f"Starting FP review of {len(vulnerabilities)} item(s)",
        total=len(vulnerabilities),
    )

    async def run_stage(
        *,
        item_index: int,
        vulnerability: dict[str, Any],
        stage: str,
        prior_stages: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        await _emit(
            output,
            "progress",
            f"Running {stage} for vulnerability {item_index}",
            vuln_index=item_index,
            stage=stage,
        )
        prompt = _stage_prompt(
            stage=stage,
            skill=skills[stage],
            vulnerability=vulnerability,
            feedback_entries=feedback_entries,
            history=history,
            prior_stages=prior_stages,
        )
        prompt += (
            "\n\n请将最终结果作为符合下方 JSON Schema 的纯 JSON 文本返回。"
            "最终回复只能包含这一个 JSON 值，不要使用 Markdown 代码围栏，"
            "也不要附加任何解释。应用程序会自行解析回复文本。\nJSON Schema：\n"
            + json.dumps(_STAGE_SCHEMA, ensure_ascii=False, indent=2)
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
            work_dir / "artifacts" / str(item_index),
            stage,
            payload,
        )
        await _emit(
            output,
            "item",
            f"Completed {stage} for vulnerability {item_index}",
            vuln_index=item_index,
            stage=stage,
            verdict=payload["verdict"],
        )
        return payload

    async def review(local_index: int, vulnerability: dict[str, Any]) -> None:
        if _cancelled(cancel_event):
            return
        item_index = int(
            vulnerability.get("index")
            if vulnerability.get("index") is not None
            else offset + local_index
        )
        async with semaphore:
            stages: dict[str, dict[str, Any]] = {}
            try:
                if history or vulnerability.get("variant_of"):
                    stages["history_match"] = await run_stage(
                        item_index=item_index,
                        vulnerability=vulnerability,
                        stage="history_match",
                        prior_stages=stages,
                    )
                if (
                    stages.get("history_match", {}).get("verdict")
                    == "true_positive"
                ):
                    final = stages["history_match"]
                    final["revised_severity"] = (
                        final.get("revised_severity") or "high"
                    )
                else:
                    stages["prove_bug"] = await run_stage(
                        item_index=item_index,
                        vulnerability=vulnerability,
                        stage="prove_bug",
                        prior_stages=stages,
                    )
                    if stages["prove_bug"]["verdict"] == "false_positive":
                        final = stages["prove_bug"]
                        final["revised_severity"] = (
                            final.get("revised_severity") or "low"
                        )
                    else:
                        stages["prove_fp"] = await run_stage(
                            item_index=item_index,
                            vulnerability=vulnerability,
                            stage="prove_fp",
                            prior_stages=stages,
                        )
                        stages["final_judge"] = await run_stage(
                            item_index=item_index,
                            vulnerability=vulnerability,
                            stage="final_judge",
                            prior_stages=stages,
                        )
                        final = stages["final_judge"]
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                final = {
                    "status": "failure",
                    "verdict": "uncertain",
                    "reason": str(exc),
                    "evidence": [],
                    "revised_severity": "",
                    "vulnerability_report": "",
                    "stage_markdown": "",
                    "match_type": "",
                    "match_reference": "",
                    "output_source": {},
                }
                await _emit(
                    output,
                    "error",
                    f"FP review failed for vulnerability {item_index}: {exc}",
                    vuln_index=item_index,
                )

            item = {
                "vuln_index": item_index,
                "status": str(final.get("status") or "success"),
                "verdict": str(final.get("verdict") or "uncertain"),
                "reason": str(final.get("reason") or ""),
                "evidence": list(final.get("evidence") or []),
                "revised_severity": str(
                    final.get("revised_severity")
                    or vulnerability.get("severity")
                    or ""
                ),
                "vulnerability_report": str(
                    final.get("vulnerability_report") or ""
                ),
                "match_type": str(final.get("match_type") or ""),
                "match_reference": str(
                    final.get("match_reference")
                    or vulnerability.get("variant_of")
                    or ""
                ),
                "stage_outputs": {
                    stage: str(payload.get("stage_markdown") or "")
                    for stage, payload in stages.items()
                },
                "stage_output_sources": {
                    stage: dict(payload.get("output_source") or {})
                    for stage, payload in stages.items()
                },
                "output_source": dict(final.get("output_source") or {}),
            }
            async with result_lock:
                ordered_results.append((offset + local_index, item))

    await asyncio.gather(*(
        review(index, vulnerability)
        for index, vulnerability in enumerate(vulnerabilities)
    ))
    results = [
        item
        for _, item in sorted(ordered_results, key=lambda pair: pair[0])
    ]
    return {
        "status": "cancelled" if _cancelled(cancel_event) else "success",
        "review_id": str(kwargs["review_id"]),
        "results": results,
        "processed": len(results),
    }
