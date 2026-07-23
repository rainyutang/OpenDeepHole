import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from deephole_client.fp_review import run_fp_review


def _result(verdict: str) -> SimpleNamespace:
    return SimpleNamespace(
        status="success",
        text="",
        structured={
            "verdict": verdict,
            "reason": "checked source",
            "evidence": ["a.c:10"],
            "revised_severity": "low",
            "vulnerability_report": "",
            "stage_markdown": "# Review\n\nchecked source",
            "match_type": "",
            "match_reference": "",
        },
        output_source={"model": "provider/model"},
    )


class AgentFeedbackTests(unittest.IsolatedAsyncioTestCase):
    async def test_fp_process_passes_feedback_without_platform_dependency(self) -> None:
        invoke = AsyncMock(return_value=_result("false_positive"))
        events: list[dict] = []

        async def output(event: dict) -> None:
            events.append(event)

        with tempfile.TemporaryDirectory() as tmp, patch(
            "deephole_client.fp_review.runner.run_opencode_task",
            new=invoke,
        ):
            work_dir = Path(tmp) / "review"
            result = await run_fp_review(
                project_path=tmp,
                work_dir=work_dir,
                scan_id="scan-1",
                review_id="review-1",
                vulnerabilities=[{
                    "index": 7,
                    "file": "a.c",
                    "line": 10,
                    "function": "parse",
                    "vuln_type": "npd",
                    "description": "candidate",
                }],
                feedback_entries=[{
                    "vuln_type": "npd",
                    "reason": "caller already checks the pointer",
                }],
                output=output,
            )

            prompt = invoke.await_args.kwargs["prompt"]
            self.assertIn("caller already checks the pointer", prompt)
            self.assertEqual(result["results"][0]["vuln_index"], 7)
            self.assertTrue(
                (work_dir / "artifacts" / "7" / "prove_bug.json").is_file()
            )
            self.assertTrue(
                (work_dir / "artifacts" / "7" / "prove_bug.md").is_file()
            )

        self.assertTrue(any(event["kind"] == "progress" for event in events))
        self.assertTrue(any(event["kind"] == "item" for event in events))
