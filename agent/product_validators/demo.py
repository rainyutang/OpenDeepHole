"""Example product validators.

Copy this file or add new files in this directory. Each file can register one
or more products by exposing register(registry).
"""

from __future__ import annotations

import json
import time

from agent.vulnerability_validation import ValidationResult


def register(registry) -> None:
    registry.register("LTE", validate_demo)


def validate_demo(ctx) -> ValidationResult:
    report_markdown = ctx.get_report_markdown()
    validation_info = ctx.get_validation_info()
    vulnerability = validation_info["vulnerability"]

    ctx.emit_stdout(f"demo validator started for product={ctx.product}")
    ctx.emit_stdout(
        "validating "
        f"{vulnerability.get('vuln_type')} at {vulnerability.get('file')}:{vulnerability.get('line')}; "
        f"report_chars={len(report_markdown)}"
    )
    ctx.publish_artifact(
        "demo_validation.py",
        "\n".join([
            "from agent.vulnerability_validation import ValidationResult",
            "",
            "def validate_product(ctx):",
            "    report = ctx.get_report_markdown()",
            "    info = ctx.get_validation_info()",
            "    vuln = info['vulnerability']",
            "    ctx.emit_stdout(f\"validating {vuln['file']}:{vuln['line']}\")",
            "    return ValidationResult(",
            "        validation_success=True,",
            "        is_problem=True,",
            "        requires_human_intervention=False,",
            "        summary='validated by product-specific proof of concept',",
            "    )",
            "",
        ]),
        kind="code",
    )
    ctx.publish_artifact(
        "validation_info.json",
        json.dumps(validation_info, ensure_ascii=False, indent=2),
        kind="metadata",
    )
    total_stages = 13
    seconds_per_stage = 10
    for stage in range(1, total_stages + 1):
        for _second in range(seconds_per_stage):
            if ctx.cancelled():
                return ValidationResult(
                    False,
                    False,
                    "demo validation cancelled",
                    status="cancelled",
                    requires_human_intervention=True,
                )
            time.sleep(1)
        elapsed = stage * seconds_per_stage
        ctx.emit_stdout(f"demo stage {stage}/{total_stages} completed, elapsed={elapsed}s")
    return ValidationResult(
        validation_success=True,
        is_problem=True,
        requires_human_intervention=False,
        summary="Demo validator completed. Replace this implementation with a real product validator.",
    )
