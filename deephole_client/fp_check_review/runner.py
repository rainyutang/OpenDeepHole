"""Batch evidence-gated false-positive review derived from the fp-check workflow."""

from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path
from typing import Any

from task_agent import run_opencode_task


PROCESS_NAME = "fp_check_review"
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
    "additionalProperties": False,
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
        "additionalProperties": False,
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
    "additionalProperties": False,
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
    "additionalProperties": False,
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
        "additionalProperties": False,
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
    "additionalProperties": False,
}
_CHAIN_SCHEMA = {
    "type": "object",
    "properties": {
        "complete": {"type": "boolean"},
        "chains": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "member_indices": {
                        "type": "array",
                        "items": {"type": "integer"},
                    },
                    "reason": {"type": "string"},
                    "gates": _GATES_SCHEMA,
                },
                "required": ["title", "member_indices", "reason", "gates"],
                "additionalProperties": False,
            },
        },
        "summary_markdown": {"type": "string"},
    },
    "required": ["complete", "chains", "summary_markdown"],
    "additionalProperties": False,
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


def _artifact_dir(work_dir: Path, vuln_index: int) -> Path:
    return work_dir / "artifacts" / str(vuln_index)


def _write_artifact(
    work_dir: Path,
    vuln_index: int,
    stage: str,
    payload: dict[str, Any],
) -> None:
    directory = _artifact_dir(work_dir, vuln_index)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{stage}.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    markdown = str(
        payload.get("stage_markdown")
        or payload.get("summary_markdown")
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


def _local_summary(
    results: list[dict[str, Any]],
    unresolved_indices: list[int],
) -> str:
    true_positive = [item for item in results if item["verdict"] == "true_positive"]
    false_positive = [item for item in results if item["verdict"] == "false_positive"]
    lines = [
        "# Trail of Bits fp-check 复核汇总",
        "",
        f"- TRUE POSITIVE：{len(true_positive)}",
        f"- FALSE POSITIVE：{len(false_positive)}",
        f"- 未完成：{len(unresolved_indices)}",
    ]
    if true_positive:
        lines.extend(["", "## TRUE POSITIVE"])
        lines.extend(
            f"- 漏洞 #{item['vuln_index']}：{item['reason']}"
            for item in true_positive
        )
    if false_positive:
        lines.extend(["", "## FALSE POSITIVE"])
        lines.extend(
            f"- 漏洞 #{item['vuln_index']}：{item['reason']}"
            for item in false_positive
        )
    if unresolved_indices:
        lines.extend([
            "",
            "## 未完成",
            "- " + "、".join(f"漏洞 #{index}" for index in unresolved_indices),
            "- 结构化输出或证据链不完整，未生成 TP/FP，可再次复核。",
        ])
    return "\n".join(lines)


async def run_fp_check_review(**kwargs: Any) -> dict[str, Any]:
    """Run Step 0, standard-first verification, deep waves and chain review."""
    unknown = sorted(set(kwargs) - _ALLOWED_KEYS)
    if unknown:
        raise TypeError(
            "run_fp_check_review() got unexpected key(s): " + ", ".join(unknown),
        )
    missing = sorted(
        key for key in _REQUIRED_KEYS if kwargs.get(key) in (None, "")
    )
    if missing:
        raise TypeError(
            "run_fp_check_review() missing required key(s): " + ", ".join(missing),
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
    semaphore = asyncio.Semaphore(concurrency)
    states: dict[int, dict[str, Any]] = {}

    main_skill = _read_skill("SKILL.md")
    references = {
        name: _read_skill(f"references/{name}.md")
        for name in (
            "bug-class-verification",
            "standard-verification",
            "deep-verification",
            "gate-reviews",
            "false-positive-patterns",
            "evidence-templates",
        )
    }
    agents = {
        name: _read_skill(f"agents/{name}.md")
        for name in (
            "data-flow-analyzer",
            "exploitability-verifier",
            "poc-builder",
        )
    }

    for local_index, vulnerability in enumerate(vulnerabilities):
        vuln_index = int(
            vulnerability.get("index")
            if vulnerability.get("index") is not None
            else offset + local_index
        )
        states[vuln_index] = {
            "vulnerability": vulnerability,
            "stages": {},
            "failed": False,
            "route": "",
        }

    async def call_stage(
        vuln_index: int,
        stage: str,
        instructions: str,
        schema: dict[str, Any],
    ) -> dict[str, Any]:
        state = states[vuln_index]
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
            instructions
            + f"\n\n当前批次漏洞编号：{vuln_index}\n"
            + "必须读取项目中的真实代码并引用具体 file:line；不得仅复述原报告。"
            + "影响评估必须分别检查机密性、完整性、可用性及认证/授权边界。"
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
            async with semaphore:
                result = await run_opencode_task(
                    task_name=(
                        f"fp-check-{kwargs['review_id']}-{vuln_index}-{stage}"
                    ),
                    task_type="fp_review",
                    prompt=prompt,
                    required_capability=capability,
                    output_schema=schema,
                    invalid_json_retry_count=retry_count,
                    config_path=kwargs.get("task_agent_config"),
                    output=None,
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
        _write_artifact(work_dir, vuln_index, stage, payload)
        await _emit(
            output,
            "stage",
            f"漏洞 {vuln_index}：完成 {stage}",
            vuln_index=vuln_index,
            stage=stage,
            markdown=str(payload.get("stage_markdown") or payload.get("reason") or ""),
            output_source=dict(payload.get("_output_source") or {}),
        )
        return payload

    async def gather_stage(
        indices: list[int],
        stage: str,
        instructions: str,
        schema: dict[str, Any],
    ) -> dict[int, dict[str, Any]]:
        selected = [
            index for index in indices
            if not _cancelled(cancel_event)
        ]
        values = await asyncio.gather(
            *(
                call_stage(index, stage, instructions, schema)
                for index in selected
            ),
        )
        return {
            index: value
            for index, value in zip(selected, values)
        }

    indices = list(states)
    await _emit(
        output,
        "progress",
        f"Trail of Bits fp-check 复核开始，共 {len(indices)} 个漏洞",
        total=len(indices),
        active_indices=indices,
    )

    claim_instruction = (
        main_skill
        + "\n\n"
        + references["bug-class-verification"]
        + "\n\n只执行步骤 0：精确重述主张、调用关系、执行上下文、威胁模型和漏洞类别，"
        "并独立选择 standard 或 deep 路径。"
    )
    claim_values = await gather_stage(
        indices,
        "claim_context",
        claim_instruction,
        _CLAIM_SCHEMA,
    )
    standard_indices: list[int] = []
    deep_indices: list[int] = []
    for index, payload in claim_values.items():
        if payload.get("_task_status") != "success":
            states[index]["failed"] = True
            continue
        route = str(payload.get("route") or "")
        states[index]["route"] = route
        (deep_indices if route == "deep" else standard_indices).append(index)

    standard_instruction = (
        main_skill
        + "\n\n"
        + references["standard-verification"]
        + "\n\n"
        + references["gate-reviews"]
        + "\n\n"
        + references["false-positive-patterns"]
        + "\n\n"
        + references["evidence-templates"]
        + "\n\n执行完整标准验证，严格执行两个升级检查点。若任一检查点需要升级，"
        "decision 必须为 escalate，并保留已完成证据；否则评估全部六道门。"
    )
    standard_values = await gather_stage(
        standard_indices,
        "standard_verification",
        standard_instruction,
        _STANDARD_SCHEMA,
    )
    completed_results: dict[int, dict[str, Any]] = {}

    def make_result(
        index: int,
        final_payload: dict[str, Any],
        verdict: str,
    ) -> dict[str, Any]:
        state = states[index]
        vulnerability = state["vulnerability"]
        return {
            "vuln_index": index,
            "status": "success",
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

    for index, payload in standard_values.items():
        decision = str(payload.get("decision") or "incomplete")
        if payload.get("_task_status") != "success" or decision == "incomplete":
            states[index]["failed"] = True
        elif decision == "escalate":
            deep_indices.append(index)
            states[index]["route"] = "deep"
        else:
            if not _all_checks_complete(payload, _STANDARD_CHECKPOINTS):
                states[index]["failed"] = True
                continue
            verdict = (
                "true_positive"
                if _all_gates_pass(payload)
                else "false_positive"
            )
            completed_results[index] = make_result(index, payload, verdict)

    deep_indices = [
        index
        for index in dict.fromkeys(deep_indices)
        if not states[index]["failed"]
    ]
    deep_specs = (
        (
            "data_flow",
            references["deep-verification"]
            + "\n\n"
            + agents["data-flow-analyzer"]
            + "\n\n"
            + references["bug-class-verification"]
            + "\n\n完整执行阶段 1.1 至 1.4。",
            _phase_schema("data_flow"),
        ),
        (
            "exploitability",
            references["deep-verification"]
            + "\n\n"
            + agents["exploitability-verifier"]
            + "\n\n完整执行阶段 2.1 至 2.4。",
            _phase_schema("exploitability"),
        ),
        (
            "impact",
            references["deep-verification"]
            + "\n\n执行阶段 3：分别评估机密性、完整性、可用性、认证和授权边界，"
            "并区分主要安全控制与纵深防御。拒绝仅因影响是 DoS 或资源耗尽就判为误报。",
            _phase_schema("impact"),
        ),
        (
            "poc",
            references["deep-verification"]
            + "\n\n"
            + agents["poc-builder"]
            + "\n\n完整执行阶段 4.1 至 4.5；不能执行的 PoC 必须写明具体理由。",
            _phase_schema("poc"),
        ),
        (
            "devil_advocate",
            references["deep-verification"]
            + "\n\n"
            + references["false-positive-patterns"]
            + "\n\n执行阶段 5，逐项回答全部 13 个反方挑战问题。",
            _phase_schema("devil_advocate"),
        ),
        (
            "gate_review",
            references["gate-reviews"]
            + "\n\n综合所有既有证据评估六道门。任何一道门失败都必须判为误报；"
            "只有六道门全部通过才可确认真实漏洞。",
            _GATE_SCHEMA,
        ),
    )
    active = list(deep_indices)
    for stage, instructions, schema in deep_specs:
        if not active or _cancelled(cancel_event):
            break
        values = await gather_stage(active, stage, instructions, schema)
        next_active: list[int] = []
        for index in active:
            payload = values.get(index)
            if payload is None:
                states[index]["failed"] = True
                continue
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
                states[index]["failed"] = True
                continue
            if stage == "gate_review":
                verdict = (
                    "true_positive"
                    if _all_gates_pass(payload)
                    else "false_positive"
                )
                completed_results[index] = make_result(index, payload, verdict)
            else:
                next_active.append(index)
        active = next_active

    results = [
        completed_results[index]
        for index in indices
        if index in completed_results
    ]
    unresolved_indices = [
        index for index in indices
        if index not in completed_results
    ]

    chain_context = {
        "vulnerabilities": [
            {
                "index": index,
                **states[index]["vulnerability"],
                "individual_verdict": completed_results.get(index, {}).get("verdict", "unresolved"),
                "individual_reason": completed_results.get(index, {}).get("reason", ""),
            }
            for index in indices
        ],
        "unresolved_indices": unresolved_indices,
    }
    chain_prompt = (
        main_skill
        + "\n\n"
        + references["gate-reviews"]
        + "\n\n所有单项复核已经完成或标记为未完成。现在只检查跨漏洞攻击链。"
        "仅当一条攻击链本身通过相同的六道门时，才列为有效攻击链；"
        "它只能把已有 FALSE POSITIVE 成员提升为 TRUE POSITIVE，不能替未完成项补结论。"
        "\n\n批次上下文：\n"
        + json.dumps(chain_context, ensure_ascii=False, indent=2)
        + _schema_instruction(_CHAIN_SCHEMA)
    )
    chain_payload: dict[str, Any]
    if _cancelled(cancel_event):
        chain_payload = {
            "complete": False,
            "chains": [],
            "summary_markdown": "",
            "_task_status": "cancelled",
            "_output_source": {},
        }
    else:
        try:
            chain_result = await run_opencode_task(
                task_name=f"fp-check-{kwargs['review_id']}-exploit-chain",
                task_type="fp_review",
                prompt=chain_prompt,
                required_capability=capability,
                output_schema=_CHAIN_SCHEMA,
                invalid_json_retry_count=retry_count,
                config_path=kwargs.get("task_agent_config"),
                output=None,
                cancel_event=cancel_event,
            )
            chain_payload = _task_payload(chain_result)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            chain_payload = {
                "complete": False,
                "chains": [],
                "summary_markdown": "",
                "_task_status": "failure",
                "_output_source": {},
                "reason": str(exc),
            }
    _write_artifact(work_dir, -1, "exploit_chain", chain_payload)

    chain_complete = (
        chain_payload.get("_task_status") == "success"
        and chain_payload.get("complete") is True
    )
    if chain_complete:
        for chain in chain_payload.get("chains") or []:
            if not isinstance(chain, dict) or not _all_gates_pass(chain):
                continue
            reason = str(chain.get("reason") or "攻击链通过六道门复核")
            for raw_index in chain.get("member_indices") or []:
                try:
                    index = int(raw_index)
                except (TypeError, ValueError):
                    continue
                item = completed_results.get(index)
                if item is None or item["verdict"] != "false_positive":
                    continue
                item["verdict"] = "true_positive"
                item["revised_severity"] = "high"
                item["reason"] = f"{item['reason']}；攻击链提升：{reason}".strip("；")
                item["vulnerability_report"] = str(
                    states[index]["vulnerability"].get("vulnerability_report") or ""
                )
    else:
        completed_results.clear()
        unresolved_indices = list(indices)

    results = [
        completed_results[index]
        for index in indices
        if index in completed_results
    ]
    summary_markdown = str(chain_payload.get("summary_markdown") or "").strip()
    if not summary_markdown:
        summary_markdown = _local_summary(results, unresolved_indices)
    summary_source = dict(chain_payload.get("_output_source") or {})
    await _emit(
        output,
        "summary",
        "Trail of Bits fp-check 复核批次汇总已生成",
        markdown=summary_markdown,
        output_source=summary_source,
        unresolved_indices=unresolved_indices,
    )
    return {
        "status": "cancelled" if _cancelled(cancel_event) else "success",
        "review_id": str(kwargs["review_id"]),
        "results": results,
        "processed": len(results),
        "unresolved_indices": unresolved_indices,
        "summary_markdown": summary_markdown,
        "summary_output_source": summary_source,
    }
