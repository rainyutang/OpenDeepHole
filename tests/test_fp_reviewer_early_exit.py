import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from deephole_client.fp_review import run_fp_review


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
    }


class FpReviewerEarlyExitTests(unittest.IsolatedAsyncioTestCase):
    async def test_prove_bug_false_positive_skips_later_stages(self) -> None:
        invoke = AsyncMock(return_value=_stage_result("false_positive"))
        with tempfile.TemporaryDirectory() as tmp, patch(
            "deephole_client.fp_review.runner.run_opencode_task",
            new=invoke,
        ):
            result = await run_fp_review(
                project_path=tmp,
                work_dir=Path(tmp) / "work",
                scan_id="scan-1",
                review_id="review-1",
                vulnerabilities=[_vulnerability()],
            )

        self.assertEqual(invoke.await_count, 1)
        self.assertIn("prove_bug", invoke.await_args.kwargs["task_name"])
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"][0]["verdict"], "false_positive")
        self.assertEqual(result["results"][0]["revised_severity"], "low")
        self.assertEqual(
            list(result["results"][0]["stage_outputs"]),
            ["prove_bug"],
        )

    async def test_prove_bug_non_fp_runs_the_full_debate(self) -> None:
        invoke = AsyncMock(side_effect=[
            _stage_result("true_positive", severity="high"),
            _stage_result("uncertain"),
            _stage_result("true_positive", severity="high"),
        ])
        with tempfile.TemporaryDirectory() as tmp, patch(
            "deephole_client.fp_review.runner.run_opencode_task",
            new=invoke,
        ):
            result = await run_fp_review(
                project_path=tmp,
                work_dir=Path(tmp) / "work",
                scan_id="scan-1",
                review_id="review-2",
                vulnerabilities=[_vulnerability()],
            )

        self.assertEqual(invoke.await_count, 3)
        self.assertEqual(
            [
                call.kwargs["task_name"].rsplit("-", 1)[-1]
                for call in invoke.await_args_list
            ],
            ["prove_bug", "prove_fp", "final_judge"],
        )
        self.assertEqual(result["results"][0]["verdict"], "true_positive")
        self.assertEqual(result["results"][0]["revised_severity"], "high")

    async def test_history_match_true_positive_short_circuits_debate(self) -> None:
        invoke = AsyncMock(return_value=_stage_result("true_positive"))
        with tempfile.TemporaryDirectory() as tmp, patch(
            "deephole_client.fp_review.runner.run_opencode_task",
            new=invoke,
        ):
            result = await run_fp_review(
                project_path=tmp,
                work_dir=Path(tmp) / "work",
                scan_id="scan-1",
                review_id="review-3",
                vulnerabilities=[_vulnerability()],
                history=[{"reference": "known issue"}],
            )

        self.assertEqual(invoke.await_count, 1)
        self.assertIn("history_match", invoke.await_args.kwargs["task_name"])
        self.assertEqual(result["results"][0]["verdict"], "true_positive")
        self.assertEqual(result["results"][0]["revised_severity"], "high")
