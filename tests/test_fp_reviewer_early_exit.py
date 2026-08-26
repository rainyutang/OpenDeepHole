import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from deephole_client.fp_review import run_fp_review


def _prompt_schema(prompt: str) -> dict:
    raw = prompt.rsplit("```json\n", 1)[1].split("\n```", 1)[0]
    return json.loads(raw)


def _stage_result(
    verdict: str,
    *,
    severity: str = "",
    reason: str = "stage result",
) -> SimpleNamespace:
    return SimpleNamespace(
        status="success",
        text="",
        structured={
            "verdict": verdict,
            "reason": reason,
            "evidence": ["source evidence"],
            "revised_severity": severity,
            "vulnerability_report": "",
            "stage_markdown": f"# Stage\n\n{reason}",
            "match_type": "",
            "match_reference": "",
        },
        output_source={"model": "provider/model", "session_id": "ses-test"},
    )


def _vulnerability() -> dict:
    return {
        "index": 3,
        "file": "a.c",
        "line": 10,
        "function": "f",
        "vuln_type": "npd",
        "severity": "medium",
        "description": "desc",
        "ai_analysis": "analysis",
        "vulnerability_report": "# 原始漏洞报告\n\n来自漏洞挖掘阶段的完整 Markdown。",
    }


class FpReviewerEarlyExitTests(unittest.IsolatedAsyncioTestCase):
    async def test_prove_bug_false_positive_skips_later_stages(self) -> None:
        invoke = AsyncMock(return_value=_stage_result("false_positive"))
        with tempfile.TemporaryDirectory() as tmp, patch(
            "task_agent.run_opencode_task",
            new=invoke,
        ):
            result = await run_fp_review(
                method_id="adversarial",
                project_path=tmp,
                code_scan_path=tmp,
                work_dir=Path(tmp) / "work",
                scan_id="scan-1",
                review_id="review-1",
                vuln_index=3,
                vulnerability=_vulnerability(),
            )

        self.assertEqual(invoke.await_count, 1)
        self.assertIn("prove_bug", invoke.await_args.kwargs["task_name"])
        prompt = invoke.await_args.kwargs["prompt"]
        self.assertTrue(prompt.startswith("/prove-bug\n\n任务："))
        self.assertIn("## 原始漏洞报告", prompt)
        self.assertIn("来自漏洞挖掘阶段的完整 Markdown。", prompt)
        self.assertNotIn('"index"', prompt)
        self.assertNotIn('"feedback_entries"', prompt)
        self.assertNotIn('"history"', prompt)
        self.assertNotIn('"prior_stages"', prompt)
        self.assertNotIn("# Prove Bug Skill", prompt)
        self.assertIn("## 输出 JSON Schema", prompt)
        self.assertIn('"verdict"', prompt)
        self.assertNotIn("invalid_json_retry_prompt", invoke.await_args.kwargs)
        self.assertIn("output_schema", invoke.await_args.kwargs)
        self.assertEqual(
            _prompt_schema(prompt),
            invoke.await_args.kwargs["output_schema"],
        )
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["verdict"], "false_positive")
        self.assertEqual(result["revised_severity"], "low")
        self.assertEqual(
            list(result["stage_outputs"]),
            ["prove_bug"],
        )

    async def test_prove_bug_non_fp_runs_the_full_debate(self) -> None:
        invoke = AsyncMock(side_effect=[
            _stage_result(
                "true_positive",
                severity="high",
                reason="正方整合报告",
            ),
            _stage_result("uncertain", reason="反方整合报告"),
            _stage_result(
                "true_positive",
                severity="high",
                reason="最终裁决报告",
            ),
        ])
        with tempfile.TemporaryDirectory() as tmp, patch(
            "task_agent.run_opencode_task",
            new=invoke,
        ):
            result = await run_fp_review(
                method_id="adversarial",
                project_path=tmp,
                code_scan_path=tmp,
                work_dir=Path(tmp) / "work",
                scan_id="scan-1",
                review_id="review-2",
                vuln_index=3,
                vulnerability=_vulnerability(),
            )

        self.assertEqual(invoke.await_count, 3)
        self.assertEqual(
            [
                call.kwargs["task_name"].rsplit("-", 1)[-1]
                for call in invoke.await_args_list
            ],
            ["prove_bug", "prove_fp", "final_judge"],
        )
        self.assertEqual(result["verdict"], "true_positive")
        self.assertEqual(result["revised_severity"], "high")

        prove_bug_prompt = invoke.await_args_list[0].kwargs["prompt"]
        prove_fp_prompt = invoke.await_args_list[1].kwargs["prompt"]
        final_prompt = invoke.await_args_list[2].kwargs["prompt"]
        self.assertTrue(prove_bug_prompt.startswith("/prove-bug\n\n任务："))
        self.assertTrue(prove_fp_prompt.startswith("/prove-fp\n\n任务："))
        self.assertNotIn("正方整合报告", prove_fp_prompt)
        self.assertIn("来自漏洞挖掘阶段的完整 Markdown。", prove_fp_prompt)
        self.assertTrue(final_prompt.startswith("/final-judge\n\n任务："))
        self.assertIn("## 原始漏洞报告", final_prompt)
        self.assertIn("## 正方论证报告", final_prompt)
        self.assertIn("正方整合报告", final_prompt)
        self.assertIn("## 反方论证报告", final_prompt)
        self.assertIn("反方整合报告", final_prompt)
        self.assertNotIn('"prior_stages"', final_prompt)
        self.assertIn("## 输出 JSON Schema", final_prompt)
        self.assertIn('"verdict"', final_prompt)
        for call in invoke.await_args_list:
            self.assertEqual(
                _prompt_schema(call.kwargs["prompt"]),
                call.kwargs["output_schema"],
            )

    async def test_history_input_no_longer_adds_history_match_stage(self) -> None:
        invoke = AsyncMock(return_value=_stage_result("false_positive"))
        vulnerability = _vulnerability()
        vulnerability["variant_of"] = "legacy-history-pattern"
        with tempfile.TemporaryDirectory() as tmp, patch(
            "task_agent.run_opencode_task",
            new=invoke,
        ):
            result = await run_fp_review(
                method_id="adversarial",
                project_path=tmp,
                code_scan_path=tmp,
                work_dir=Path(tmp) / "work",
                scan_id="scan-1",
                review_id="review-3",
                vuln_index=3,
                vulnerability=vulnerability,
                history=[{"reference": "known issue"}],
            )

        self.assertEqual(invoke.await_count, 1)
        self.assertIn("prove_bug", invoke.await_args.kwargs["task_name"])
        self.assertNotIn("history_match", invoke.await_args.kwargs["task_name"])
        self.assertNotIn("known issue", invoke.await_args.kwargs["prompt"])
        self.assertNotIn("legacy-history-pattern", invoke.await_args.kwargs["prompt"])
        self.assertEqual(result["verdict"], "false_positive")
        self.assertEqual(result["revised_severity"], "low")
