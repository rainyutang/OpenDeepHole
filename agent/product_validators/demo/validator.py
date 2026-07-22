"""Minimal concurrent product-validator example."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from agent.vulnerability_validation import ValidationResult
from agent.task_agent import run_opencode_task


RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "is_problem": {"type": "boolean"},
        "summary": {"type": "string", "minLength": 1},
        "evidence": {
            "type": "array",
            "minItems": 5,
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "name": {"type": ["string", "null"]},
                },
                "required": ["id", "name"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["is_problem", "summary", "evidence"],
    "additionalProperties": False,
}


async def validate(**kwargs) -> ValidationResult:
    emit_stdout = kwargs["emit_stdout"]
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
    reachability_prompt = (
        "请根据当前项目代码和以下 Markdown 漏洞报告验证问题是否真实可触发。"
        "重点从验证入口沿函数调用链检查输入是否能够到达漏洞函数。\n\n"
        f"调用链：{' -> '.join(call_chain)}\n\n"
        f"{report_markdown}"
    )
    exploitability_prompt = (
        "请根据当前项目代码和以下 Markdown 漏洞报告分析漏洞利用条件。"
        "重点检查攻击者是否能够控制关键输入，以及触发条件是否能够满足。\n\n"
        f"漏洞函数：{vulnerable_function}\n\n"
        f"{report_markdown}"
    )
    try:
        # 不传 session_id 时，两个任务会各自创建 Session，并由模型池并发调度。
        reachability_result, exploitability_result = await asyncio.gather(
            run_opencode_task(
                task_name=f"代码可达性分析 {vulnerability_type}",
                task_type="vulnerability_validation",
                prompt=reachability_prompt,
                required_capability=required_capability,
                output_schema=RESULT_SCHEMA,
            ),
            run_opencode_task(
                task_name=f"利用条件分析 {vulnerability_type}",
                task_type="vulnerability_validation",
                prompt=exploitability_prompt,
                required_capability=required_capability,
                output_schema=RESULT_SCHEMA,
            ),
        )
    except Exception as exc:
        return ValidationResult(
            validation_success=False,
            is_problem=True,
            requires_human_intervention=True,
            status="failed",
            summary=f"OpenCode validation failed: {exc}",
        )

    # 两个任务完成后分别检查状态、解析结果并保存产物。
    failed_tasks: list[str] = []

    reachability_payload: dict = {}
    if reachability_result.status == "success":
        if isinstance(reachability_result.structured, dict):
            reachability_payload = reachability_result.structured
        reachability_artifact = work_dir / "reachability-result.json"
        reachability_artifact.write_text(
            json.dumps(reachability_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        reachability_summary = str(
            reachability_payload.get("summary") or "代码可达性分析完成"
        )
        await emit_stdout("代码可达性结果", reachability_summary)
        print(f"[代码可达性结果] {reachability_result.structured}", flush=True)
    else:
        reachability_summary = reachability_result.text or reachability_result.status
        failed_tasks.append(f"代码可达性分析失败：{reachability_summary}")
        await emit_stdout("代码可达性结果", failed_tasks[-1])

    exploitability_payload: dict = {}
    if exploitability_result.status == "success":
        if isinstance(exploitability_result.structured, dict):
            exploitability_payload = exploitability_result.structured
        exploitability_artifact = work_dir / "exploitability-result.json"
        exploitability_artifact.write_text(
            json.dumps(exploitability_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        exploitability_summary = str(
            exploitability_payload.get("summary") or "利用条件分析完成"
        )
        await emit_stdout("利用条件结果", exploitability_summary)
        print(f"[利用条件结果] {exploitability_result.structured}", flush=True)
    else:
        exploitability_summary = exploitability_result.text or exploitability_result.status
        failed_tasks.append(f"利用条件分析失败：{exploitability_summary}")
        await emit_stdout("利用条件结果", failed_tasks[-1])

    if failed_tasks:
        return ValidationResult(
            validation_success=False,
            is_problem=True,
            requires_human_intervention=True,
            status="failed",
            summary="；".join(failed_tasks),
        )

    summary = (
        f"代码可达性：{reachability_summary}；"
        f"利用条件：{exploitability_summary}"
    )
    combined_artifact = work_dir / "opencode-result.json"
    combined_artifact.write_text(
        json.dumps(
            {
                "reachability": reachability_payload,
                "exploitability": exploitability_payload,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return ValidationResult(
        validation_success=True,
        # 示例策略：代码可达且利用条件成立时，才判定漏洞真实存在。
        is_problem=(
            bool(reachability_payload.get("is_problem"))
            and bool(exploitability_payload.get("is_problem"))
        ),
        requires_human_intervention=False,
        summary=summary,
    )


async def main() -> None:
    """Run this example with the standalone Task Agent component configuration."""
    work_dir = (Path.cwd() / ".opendeephole" / "validator-demo").resolve()
    work_dir.mkdir(parents=True, exist_ok=True)

    async def emit_stdout(title, content=None) -> None:
        if content is None:
            print(str(title), flush=True)
        else:
            print(f"[{title}] {content}", flush=True)

    result = await validate(
        emit_stdout=emit_stdout,
        validation_entry_function="handle_packet",
        vulnerable_function="parse_payload",
        vulnerability_type="oob",
        call_chain=("handle_packet", "parse_message", "parse_payload"),
        report_markdown="# 漏洞报告\n\n验证该越界路径。",
        required_capability="high",
        work_dir=work_dir,
        target_ip="",
    )
    print(f"[validator-demo] status={result.status}", flush=True)
    print(f"[validator-demo] conclusion={result.summary}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
