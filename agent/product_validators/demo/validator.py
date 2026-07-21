"""Minimal asynchronous product-validator example."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from agent.validation_debug import run_validator_debug
from agent.vulnerability_validation import ValidationResult
from backend.opencode import OpenCodeTaskType, run_opencode_task


RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "is_problem": {"type": "boolean"},
        "summary": {"type": "string", "minLength": 1},
        "evidence": {"type": "string"},
    },
    "required": ["is_problem", "summary", "evidence"],
    "additionalProperties": False,
}


async def validate(**kwargs) -> ValidationResult:
    emit_stdout = kwargs["emit_stdout"]
    publish_artifact = kwargs["publish_artifact"]
    validation_entry_function = kwargs["validation_entry_function"]
    vulnerable_function = kwargs["vulnerable_function"]
    vulnerability_type = kwargs["vulnerability_type"]
    call_chain = kwargs["call_chain"]
    report_markdown = kwargs["report_markdown"]
    required_capability = kwargs["required_capability"]
    work_dir = kwargs["work_dir"]
    target_ip = kwargs.get("target_ip", "")

    await emit_stdout(
        "验证过程",
        f"入口={validation_entry_function} 漏洞函数={vulnerable_function} "
        f"类型={vulnerability_type} 目标={target_ip or '自动发现'}",
    )
    prompt = (
        "请根据当前项目代码和以下 Markdown 漏洞报告验证问题是否真实可触发。"
        "重点从验证入口沿函数调用链检查输入是否能够到达漏洞函数。\n\n"
        f"调用链：{' -> '.join(call_chain)}\n\n"
        f"{report_markdown}"
    )
    try:
        result = await run_opencode_task(
            task_name=f"漏洞验证 {vulnerability_type}",
            task_type=OpenCodeTaskType.VULNERABILITY_VALIDATION,
            prompt=prompt,
            required_capability=required_capability,
            output_schema=RESULT_SCHEMA,
        )
        if result.status != "success":
            raise RuntimeError(result.text)
    except Exception as exc:
        return ValidationResult(
            validation_success=False,
            is_problem=True,
            requires_human_intervention=True,
            status="failed",
            summary=f"OpenCode validation failed: {exc}",
        )

    payload = result.structured if isinstance(result.structured, dict) else {}
    artifact_path = work_dir / "opencode-result.json"
    artifact_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    await publish_artifact(
        "opencode-result.json",
        path=artifact_path,
        title="验证产物",
        kind="result",
    )
    await emit_stdout("验证过程", str(payload.get("summary") or "验证完成"))
    return ValidationResult(
        validation_success=True,
        is_problem=bool(payload.get("is_problem")),
        requires_human_intervention=False,
        summary=str(payload.get("summary") or "验证完成"),
    )


async def main() -> None:
    """Optional local debug entry; edit these values for the target project."""
    repo_root = Path(__file__).resolve().parents[3]
    await run_validator_debug(
        validate=validate,
        validator_dir=Path(__file__).resolve().parent,
        config_path=repo_root / "agent.yaml",
        project_path="/absolute/path/to/project",
        code_scan_path="/absolute/path/to/project/src",
        product="LTE",
        validation_environment="仿真UBBPi板环境",
        vulnerability={
            "file": "src/parser.c",
            "line": 120,
            "function": "parse_payload",
            "call_chain": ["handle_packet", "parse_message", "parse_payload"],
            "vuln_type": "oob",
            "severity": "high",
            "description": "长度字段可导致越界读取",
            "ai_analysis": "完整分析",
            "vulnerability_report": "# 漏洞报告\n\n验证该越界路径。",
            "confirmed": True,
            "ai_verdict": "confirmed",
        },
        report_markdown="# 漏洞报告\n\n验证该越界路径。",
    )


if __name__ == "__main__":
    asyncio.run(main())
