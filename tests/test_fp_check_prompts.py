import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from deephole_client.fp_review import run_fp_review
from deephole_client.fp_review.prompts import original_vulnerability_report


def _prompt_schema(prompt: str) -> dict:
    raw = prompt.rsplit("```json\n", 1)[1].split("\n```", 1)[0]
    return json.loads(raw)


_GATE_NAMES = (
    "process",
    "reachability",
    "real_impact",
    "poc_validation",
    "math_bounds",
    "environment",
)
_STANDARD_CHECKS = (
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


def _result(structured: dict) -> SimpleNamespace:
    return SimpleNamespace(
        status="success",
        text="",
        structured=structured,
        output_source={"model": "provider/model"},
    )


def _claim(route: str) -> SimpleNamespace:
    return _result({
        "route": route,
        "claim": "claim",
        "root_cause": "root cause",
        "trigger": "trigger",
        "claimed_impact": "impact",
        "threat_model": "remote attacker",
        "bug_class": "out of bounds",
        "stage_markdown": "# claim_context report",
    })


def _phase(stage: str, checks: tuple[str, ...]) -> SimpleNamespace:
    return _result({
        "complete": True,
        "reason": f"{stage} complete",
        "evidence": [f"src/{stage}.c:10"],
        "completeness": {name: True for name in checks},
        "stage_markdown": f"# {stage} report",
    })


def _gate() -> SimpleNamespace:
    return _result({
        "complete": True,
        "reason": "all gates pass",
        "evidence": ["src/gate.c:10"],
        "gates": {name: True for name in _GATE_NAMES},
        "stage_markdown": "# gate_review report",
    })


def _vulnerability() -> dict:
    return {
        "index": 4,
        "file": "src/parser.c",
        "line": 18,
        "function": "parse",
        "vuln_type": "out_of_bounds",
        "severity": "high",
        "description": "structured description must not be serialized",
        "ai_analysis": "platform-only analysis must not be serialized",
        "confirmed": True,
        "vulnerability_report": "# 原始漏洞报告\n\n只把这份 Markdown 交给复核模型。",
        "output_source": {"model": "platform-only-model"},
    }


class FpCheckPromptTests(unittest.IsolatedAsyncioTestCase):
    async def test_standard_path_uses_compact_report_prompts(self) -> None:
        standard = _result({
            "decision": "verdict",
            "reason": "standard path passes",
            "evidence": ["src/parser.c:18"],
            "gates": {name: True for name in _GATE_NAMES},
            "completeness": {name: True for name in _STANDARD_CHECKS},
            "stage_markdown": "# standard_verification report",
        })
        invoke = AsyncMock(side_effect=[_claim("standard"), standard])

        with tempfile.TemporaryDirectory() as tmp, patch(
            "task_agent.run_opencode_task",
            new=invoke,
        ):
            result = await run_fp_review(
                method_id="fp_check",
                project_path=tmp,
                code_scan_path=tmp,
                work_dir=Path(tmp) / "work",
                scan_id="scan-1",
                review_id="review-standard",
                vuln_index=4,
                vulnerability=_vulnerability(),
                feedback_entries=[{"reason": "platform feedback"}],
                history=[{"reference": "historical pattern"}],
            )

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["verdict"], "true_positive")
        self.assertEqual(invoke.await_count, 2)
        claim_prompt = invoke.await_args_list[0].kwargs["prompt"]
        standard_prompt = invoke.await_args_list[1].kwargs["prompt"]

        self.assertTrue(claim_prompt.startswith("/fp-check\n\n任务："))
        self.assertIn("“主张与上下文”阶段", claim_prompt)
        self.assertIn("## 原始漏洞报告", claim_prompt)
        self.assertIn("只把这份 Markdown 交给复核模型。", claim_prompt)
        self.assertNotIn("## 已完成阶段报告", claim_prompt)

        self.assertTrue(standard_prompt.startswith("/fp-check\n\n任务："))
        self.assertIn("“标准验证”阶段", standard_prompt)
        self.assertIn("## 已完成阶段报告", standard_prompt)
        self.assertIn("### 主张与上下文", standard_prompt)
        self.assertIn("# claim_context report", standard_prompt)

        for prompt in (claim_prompt, standard_prompt):
            self.assertNotIn('"index"', prompt)
            self.assertNotIn("platform-only analysis", prompt)
            self.assertNotIn("platform-only-model", prompt)
            self.assertNotIn("platform feedback", prompt)
            self.assertNotIn("historical pattern", prompt)
            self.assertNotIn('"prior_stages"', prompt)
            self.assertNotIn("# Trail of Bits fp-check 复核", prompt)
            self.assertIn("## 输出 JSON Schema", prompt)
            self.assertTrue(prompt.endswith("\n\n请使用中文输出"))
            self.assertEqual(prompt.count("请使用中文输出"), 1)
        self.assertIn('"route"', claim_prompt)
        self.assertIn('"decision"', standard_prompt)
        self.assertIn("output_schema", invoke.await_args_list[0].kwargs)
        for call in invoke.await_args_list:
            self.assertEqual(
                _prompt_schema(call.kwargs["prompt"]),
                call.kwargs["output_schema"],
            )

    async def test_deep_path_passes_ordered_stage_markdown_reports(self) -> None:
        invoke = AsyncMock(side_effect=[
            _claim("deep"),
            _phase("data_flow", ("phase_1_1", "phase_1_2", "phase_1_3", "phase_1_4")),
            _phase("exploitability", ("phase_2_1", "phase_2_2", "phase_2_3", "phase_2_4")),
            _phase(
                "impact",
                (
                    "confidentiality",
                    "integrity",
                    "availability",
                    "authentication",
                    "authorization",
                    "primary_vs_defense_in_depth",
                ),
            ),
            _phase("poc", ("phase_4_1", "phase_4_2", "phase_4_3", "phase_4_4", "phase_4_5")),
            _phase("devil_advocate", tuple(f"challenge_{index}" for index in range(1, 14))),
            _gate(),
        ])

        with tempfile.TemporaryDirectory() as tmp, patch(
            "task_agent.run_opencode_task",
            new=invoke,
        ):
            result = await run_fp_review(
                method_id="fp_check",
                project_path=tmp,
                code_scan_path=tmp,
                work_dir=Path(tmp) / "work",
                scan_id="scan-1",
                review_id="review-deep",
                vuln_index=4,
                vulnerability=_vulnerability(),
            )

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["verdict"], "true_positive")
        self.assertEqual(invoke.await_count, 7)
        self.assertTrue(all(
            call.kwargs["prompt"].startswith("/fp-check\n\n任务：")
            for call in invoke.await_args_list
        ))

        gate_prompt = invoke.await_args_list[-1].kwargs["prompt"]
        expected = (
            "# claim_context report",
            "# data_flow report",
            "# exploitability report",
            "# impact report",
            "# poc report",
            "# devil_advocate report",
        )
        positions = [gate_prompt.index(value) for value in expected]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("“六道门复核”阶段", gate_prompt)
        self.assertIn("## 原始漏洞报告", gate_prompt)
        self.assertIn("## 已完成阶段报告", gate_prompt)
        self.assertIn("## 输出 JSON Schema", gate_prompt)
        self.assertIn('"complete"', gate_prompt)
        self.assertIn('"gates"', gate_prompt)
        for call in invoke.await_args_list:
            self.assertEqual(
                _prompt_schema(call.kwargs["prompt"]),
                call.kwargs["output_schema"],
            )


class FpReviewReportProjectionTests(unittest.TestCase):
    def test_empty_legacy_report_gets_markdown_fallback(self) -> None:
        vulnerability = _vulnerability()
        vulnerability["vulnerability_report"] = ""

        report = original_vulnerability_report(vulnerability)

        self.assertTrue(report.startswith("# 漏洞报告"))
        self.assertIn("src/parser.c", report)
        self.assertIn("structured description must not be serialized", report)
        self.assertNotIn('"file"', report)


if __name__ == "__main__":
    unittest.main()
