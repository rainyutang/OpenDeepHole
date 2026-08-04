"""Per-vulnerability evidence-gated fp-check review method."""

from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path
from typing import Any

from task_agent import run_opencode_task


PROCESS_NAME = "fp_review"
FP_CHECK_STAGE_KEYS = (
    "claim_context",
    "standard_verification",
    "data_flow",
    "exploitability",
    "impact",
    "poc",
    "devil_advocate",
    "gate_review",
)
_DEEP_STAGE_KEYS = FP_CHECK_STAGE_KEYS[2:]
_ALLOWED_KEYS = {
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
_GATE_NAMES = (
    "process",
    "reachability",
    "real_impact",
    "poc_validation",
    "math_bounds",
    "environment",
)
_GATES_SCHEMA = {
    "type": "object",
    "properties": {
        name: {"type": "boolean"}
        for name in _GATE_NAMES
    },
    "required": list(_GATE_NAMES),
    "additionalProperties": True,
}
_STANDARD_CHECKPOINTS = (
    "claim_restatement",
    "data_flow",
    "escalation_checkpoint_one",
    "exploitability",
    "impact",
    "escalation_checkpoint_two",
    "poc",
    "devil_advocate",
    "gate_review",
)
_DEEP_CHECKPOINTS = {
    "data_flow": ("phase_1_1", "phase_1_2", "phase_1_3", "phase_1_4"),
    "exploitability": ("phase_2_1", "phase_2_2", "phase_2_3", "phase_2_4"),
    "impact": (
        "confidentiality",
        "integrity",
        "availability",
        "authentication",
        "authorization",
        "primary_vs_defense_in_depth",
    ),
    "poc": ("phase_4_1", "phase_4_2", "phase_4_3", "phase_4_4", "phase_4_5"),
    "devil_advocate": tuple(
        f"challenge_{index}" for index in range(1, 14)
    ),
}


def _checks_schema(names: tuple[str, ...]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            name: {"type": "boolean"}
            for name in names
        },
        "required": list(names),
        "additionalProperties": True,
    }


_CLAIM_SCHEMA = {
    "type": "object",
    "properties": {
        "route": {"type": "string", "enum": ["standard", "deep"]},
        "claim": {"type": "string"},
        "root_cause": {"type": "string"},
        "trigger": {"type": "string"},
        "claimed_impact": {"type": "string"},
        "threat_model": {"type": "string"},
        "bug_class": {"type": "string"},
        "stage_markdown": {"type": "string"},
    },
    "required": [
        "route",
        "claim",
        "root_cause",
        "trigger",
        "claimed_impact",
        "threat_model",
        "bug_class",
        "stage_markdown",
    ],
    "additionalProperties": True,
}
_STANDARD_SCHEMA = {
    "type": "object",
    "properties": {
        "decision": {
            "type": "string",
            "enum": ["verdict", "escalate", "incomplete"],
        },
        "reason": {"type": "string"},
        "evidence": {"type": "array", "items": {"type": "string"}},
        "gates": _GATES_SCHEMA,
        "completeness": _checks_schema(_STANDARD_CHECKPOINTS),
        "stage_markdown": {"type": "string"},
    },
    "required": [
        "decision",
        "reason",
        "evidence",
        "gates",
        "completeness",
        "stage_markdown",
    ],
    "additionalProperties": True,
}


def _phase_schema(stage: str) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "complete": {"type": "boolean"},
            "reason": {"type": "string"},
            "evidence": {"type": "array", "items": {"type": "string"}},
            "completeness": _checks_schema(_DEEP_CHECKPOINTS[stage]),
            "stage_markdown": {"type": "string"},
        },
        "required": [
            "complete",
            "reason",
            "evidence",
            "completeness",
            "stage_markdown",
        ],
        "additionalProperties": True,
    }
_GATE_SCHEMA = {
    "type": "object",
    "properties": {
        "complete": {"type": "boolean"},
        "reason": {"type": "string"},
        "evidence": {"type": "array", "items": {"type": "string"}},
        "gates": _GATES_SCHEMA,
        "stage_markdown": {"type": "string"},
    },
    "required": [
        "complete",
        "reason",
        "evidence",
        "gates",
        "stage_markdown",
    ],
    "additionalProperties": True,
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


def _skill_root() -> Path:
    return Path(__file__).resolve().parent / "skills" / "fp-check"


def _read_skill(relative: str) -> str:
    path = _skill_root() / relative
    if not path.is_file():
        raise FileNotFoundError(f"fp-check 中文 Skill 文件缺失: {path}")
    return path.read_text(encoding="utf-8")


def _schema_instruction(schema: dict[str, Any]) -> str:
    return (
        "\n\n最终回复只能是一个符合下列 JSON Schema 的纯 JSON 值，"
        "不得使用 Markdown 代码围栏或附加解释。所有必填阶段必须有具体证据；"
        "无法完成时将 complete/decision 标为不完整，不得猜测结论。\nJSON Schema：\n"
        + json.dumps(schema, ensure_ascii=False, indent=2)
    )


def _artifact_dir(work_dir: Path) -> Path:
    return work_dir / "artifacts"


def _write_artifact(
    work_dir: Path,
    stage: str,
    payload: dict[str, Any],
) -> None:
    directory = _artifact_dir(work_dir)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{stage}.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    markdown = str(
        payload.get("stage_markdown")
        or payload.get("reason")
        or ""
    )
    (directory / f"{stage}.md").write_text(markdown + "\n", encoding="utf-8")


def _task_payload(result: Any) -> dict[str, Any]:
    if result.status != "success" or not isinstance(result.structured, dict):
        return {
            "_task_status": str(result.status),
            "_output_source": dict(result.output_source or {}),
            "complete": False,
            "reason": str(result.text or "模型未返回完整结构化结果"),
            "evidence": [],
            "stage_markdown": str(result.text or ""),
        }
    payload = dict(result.structured)
    payload["_task_status"] = "success"
    payload["_output_source"] = dict(result.output_source or {})
    return payload


def _public_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in payload.items()
        if not key.startswith("_")
    }


def _all_gates_pass(payload: dict[str, Any]) -> bool:
    gates = payload.get("gates")
    return (
        isinstance(gates, dict)
        and all(gates.get(name) is True for name in _GATE_NAMES)
    )


def _all_checks_complete(
    payload: dict[str, Any],
    names: tuple[str, ...],
) -> bool:
    checks = payload.get("completeness")
    return (
        isinstance(checks, dict)
        and all(checks.get(name) is True for name in names)
    )


def _retry_instruction(schema: dict[str, Any]) -> str:
    return (
        "上一条回复未通过结构化校验。请完全替换上一条回复，只返回一个纯 JSON 对象，"
        "不要使用 Markdown 代码围栏、前后说明或省略字段。可以包含附加说明字段，"
        "但下列必填字段、类型和枚举必须满足：\n"
        + json.dumps(schema, ensure_ascii=False, indent=2)
    )


async def run(**kwargs: Any) -> dict[str, Any]:
    """Run Trail of Bits fp-check for exactly one vulnerability."""
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
    output = kwargs.get("output")
    if output is not None and not callable(output):
        raise TypeError("output must be callable or None")
    cancel_event = kwargs.get("cancel_event")
    capability = str(kwargs.get("required_capability") or "high").lower()
    if capability not in {"low", "high"}:
        raise ValueError("required_capability must be 'low' or 'high'")
    retry_count = max(0, int(kwargs.get("invalid_json_retry_count") or 2))
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
    state: dict[str, Any] = {
        "vulnerability": vulnerability,
        "stages": {},
        "failed": False,
        "route": "",
    }

    async def call_stage(
        stage: str,
        instructions: str,
        schema: dict[str, Any],
    ) -> dict[str, Any]:
        context = {
            "vulnerability": state["vulnerability"],
            "feedback_entries": feedback_entries,
            "history": history,
            "prior_stages": {
                key: _public_payload(value)
                for key, value in state["stages"].items()
            },
        }
        prompt = (
            "/fp-check\n\n"
            + instructions
            + f"\n\n当前漏洞编号：{vuln_index}\n"
            + "必须读取项目中的真实代码并引用具体 file:line；不得仅复述原报告。"
            + "只执行当前单漏洞阶段，不得生成跨漏洞结论。"
            + "\n\n输入上下文：\n"
            + json.dumps(context, ensure_ascii=False, indent=2)
            + _schema_instruction(schema)
        )
        await _emit(
            output,
            "progress",
            f"漏洞 {vuln_index}：开始 {stage}",
            vuln_index=vuln_index,
            stage=stage,
        )
        try:
            result = await run_opencode_task(
                task_name=(
                    f"fp-check-{kwargs['review_id']}-{vuln_index}-{stage}"
                ),
                task_type="fp_review",
                prompt=prompt,
                required_capability=capability,
                output_schema=schema,
                invalid_json_retry_count=retry_count,
                invalid_json_retry_prompt=_retry_instruction(schema),
                config_path=kwargs.get("task_agent_config"),
                cancel_event=cancel_event,
            )
            payload = _task_payload(result)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            payload = {
                "_task_status": "failure",
                "_output_source": {},
                "complete": False,
                "reason": str(exc),
                "evidence": [],
                "stage_markdown": f"# 阶段执行失败\n\n{exc}",
            }
        state["stages"][stage] = payload
        _write_artifact(work_dir, stage, payload)
        await _emit(
            output,
            "stage",
            (
                f"漏洞 {vuln_index}：完成 {stage}"
                if payload.get("_task_status") == "success"
                else f"漏洞 {vuln_index}：{stage} 失败"
            ),
            vuln_index=vuln_index,
            stage=stage,
            markdown=str(
                payload.get("stage_markdown")
                or payload.get("reason")
                or ""
            ),
            output_source=dict(payload.get("_output_source") or {}),
        )
        return payload

    await _emit(
        output,
        "progress",
        f"Trail of Bits fp-check 单项复核开始：漏洞 {vuln_index}",
        total=1,
        active_indices=[vuln_index],
        vuln_index=vuln_index,
    )
    if _cancelled(cancel_event):
        return {
            "status": "cancelled",
            "error_message": "用户手动停止",
            "stage_outputs": {},
            "stage_output_sources": {},
            "output_source": {},
        }
    claim_payload = await call_stage(
        "claim_context",
        "只执行步骤 0：精确重述主张、调用关系、执行上下文、威胁模型和漏洞类别，"
        "并选择 standard 或 deep 路径。",
        _CLAIM_SCHEMA,
    )
    standard = False
    deep = False
    if claim_payload.get("_task_status") != "success":
        state["failed"] = True
    else:
        state["route"] = str(claim_payload.get("route") or "")
        deep = state["route"] == "deep"
        standard = not deep

    completed_result: dict[str, Any] | None = None

    def make_result(
        final_payload: dict[str, Any],
        verdict: str,
    ) -> dict[str, Any]:
        return {
            "verdict": verdict,
            "reason": str(final_payload.get("reason") or ""),
            "evidence": [
                str(value)
                for value in final_payload.get("evidence") or []
                if str(value).strip()
            ],
            "revised_severity": "high" if verdict == "true_positive" else "low",
            "vulnerability_report": (
                str(vulnerability.get("vulnerability_report") or "")
                if verdict == "true_positive"
                else ""
            ),
            "match_type": "",
            "match_reference": "",
            "stage_outputs": {
                key: str(value.get("stage_markdown") or value.get("reason") or "")
                for key, value in state["stages"].items()
            },
            "stage_output_sources": {
                key: dict(value.get("_output_source") or {})
                for key, value in state["stages"].items()
            },
            "output_source": dict(final_payload.get("_output_source") or {}),
        }

    if standard and not state["failed"] and not _cancelled(cancel_event):
        payload = await call_stage(
            "standard_verification",
            "执行完整标准验证及两个升级检查点。需要升级时 decision=escalate；"
            "否则完成全部检查点并评估六道门。",
            _STANDARD_SCHEMA,
        )
        decision = str(payload.get("decision") or "incomplete")
        if (
            payload.get("_task_status") != "success"
            or decision == "incomplete"
            or not _all_checks_complete(payload, _STANDARD_CHECKPOINTS)
        ):
            state["failed"] = True
        elif decision == "escalate":
            deep = True
            state["route"] = "deep"
        else:
            completed_result = make_result(
                payload,
                (
                    "true_positive"
                    if _all_gates_pass(payload)
                    else "false_positive"
                ),
            )

    deep_specs = (
        (
            "data_flow",
            "执行深度验证阶段 1.1 至 1.4，完整追踪攻击者输入到危险操作的数据流。",
            _phase_schema("data_flow"),
        ),
        (
            "exploitability",
            "执行阶段 2.1 至 2.4，验证可达性、约束和实际可利用性。",
            _phase_schema("exploitability"),
        ),
        (
            "impact",
            "执行阶段 3，分别评估机密性、完整性、可用性、认证和授权边界，"
            "并区分主要安全控制与纵深防御。",
            _phase_schema("impact"),
        ),
        (
            "poc",
            "执行阶段 4.1 至 4.5；不能执行 PoC 时必须写明具体原因及替代证据。",
            _phase_schema("poc"),
        ),
        (
            "devil_advocate",
            "执行阶段 5，逐项回答全部 13 个反方挑战问题。",
            _phase_schema("devil_advocate"),
        ),
        (
            "gate_review",
            "综合既有证据评估六道门。任何一道门失败即为误报，"
            "只有六道门全部通过才能确认真实漏洞。",
            _GATE_SCHEMA,
        ),
    )
    if deep and not state["failed"]:
        for stage, instructions, schema in deep_specs:
            if _cancelled(cancel_event):
                break
            payload = await call_stage(stage, instructions, schema)
            complete = (
                payload.get("_task_status") == "success"
                and payload.get("complete") is True
            )
            if stage in _DEEP_CHECKPOINTS:
                complete = complete and _all_checks_complete(
                    payload,
                    _DEEP_CHECKPOINTS[stage],
                )
            if not complete:
                state["failed"] = True
                break
            if stage == "gate_review":
                completed_result = make_result(
                    payload,
                    (
                        "true_positive"
                        if _all_gates_pass(payload)
                        else "false_positive"
                    ),
                )

    error_message: str | None = None
    if completed_result is None and not _cancelled(cancel_event):
        for payload in reversed(list(state["stages"].values())):
            reason = str(payload.get("reason") or "").strip()
            if reason:
                error_message = reason
                break
        error_message = error_message or "单项复核未生成有效 TP/FP 结果"
        await _emit(
            output,
            "error",
            f"漏洞 {vuln_index} 复核失败：{error_message}",
            vuln_index=vuln_index,
        )
    incomplete_result = {
        "stage_outputs": {
            key: str(value.get("stage_markdown") or value.get("reason") or "")
            for key, value in state["stages"].items()
        },
        "stage_output_sources": {
            key: dict(value.get("_output_source") or {})
            for key, value in state["stages"].items()
        },
        "output_source": {},
    }
    return {
        "status": (
            "cancelled"
            if _cancelled(cancel_event)
            else "success"
            if completed_result is not None
            else "error"
        ),
        "error_message": (
            "用户手动停止"
            if _cancelled(cancel_event)
            else error_message
        ),
        **(completed_result or incomplete_result),
    }
