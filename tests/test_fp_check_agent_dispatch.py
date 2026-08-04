import asyncio
import tempfile
import threading
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from deephole_client import server


class FpReviewAgentDispatchTests(unittest.IsolatedAsyncioTestCase):
    def tearDown(self) -> None:
        server._fp_review_tasks.clear()
        server._fp_review_cancel_events.clear()
        server._fp_review_scan_ids.clear()
        server._fp_review_queues.clear()
        server._fp_review_active_items.clear()
        server._fp_review_running_indices.clear()

    async def test_manifest_controls_worker_concurrency(self) -> None:
        original_config = server._config
        original_reporter = server._reporter
        server._config = SimpleNamespace()
        reporter = SimpleNamespace(
            push_fp_progress=AsyncMock(),
            finish_fp_review=AsyncMock(),
        )
        server._reporter = reporter
        active = 0
        maximum = 0

        async def run_item(item):
            nonlocal active, maximum
            active += 1
            maximum = max(maximum, active)
            await asyncio.sleep(0.01)
            active -= 1
            return {"status": "success", "verdict": "true_positive"}

        try:
            with patch(
                "deephole_client.server._run_single_fp_review_item",
                new=run_item,
            ):
                await server.handle_fp_review(
                    scan_id="scan-1",
                    review_id="review-1",
                    method="fp_check",
                    project_path="/repo",
                    code_scan_path="/repo/src",
                    vulnerabilities=[{"index": index} for index in range(5)],
                )
                await server._fp_review_tasks["review-1"]

            self.assertEqual(maximum, 4)
            self.assertEqual(reporter.finish_fp_review.await_args.args[2], "complete")
            self.assertEqual(server._fp_review_queues, {})
        finally:
            server._config = original_config
            server._reporter = original_reporter

    async def test_adapter_passes_one_vulnerability_and_pushes_one_result(self) -> None:
        reporter = SimpleNamespace(
            get_git_history=AsyncMock(return_value=[]),
            send_event=AsyncMock(),
            push_fp_stage_output=AsyncMock(),
            push_fp_result=AsyncMock(),
        )
        runtime_result = {
            "status": "success",
            "method_id": "fp_check",
            "method_label": "fp-check",
            "verdict": "true_positive",
            "revised_severity": "high",
            "reason": "all six gates pass",
            "vulnerability_report": "# report",
            "stage_outputs": {"gate_review": "# gates"},
            "stage_output_sources": {},
            "output_source": {},
            "error_message": "",
        }

        with (
            tempfile.TemporaryDirectory() as tmp,
            patch(
                "deephole_client.fp_review.run_fp_review",
                new=AsyncMock(return_value=runtime_result),
            ) as run_review,
            patch(
                "task_agent.opencode_task_context",
                return_value=nullcontext(),
            ) as task_context,
            patch("deephole_client.server.Path.home", return_value=Path(tmp)),
        ):
            result = await server._run_single_fp_review_item(
                server._FpReviewQueueItem(
                    config=SimpleNamespace(),
                    reporter=reporter,
                    scan_id="scan-1",
                    review_id="review-2",
                    method="fp_check",
                    project_path=tmp,
                    code_scan_path=tmp,
                    vulnerability={"index": 3, "vulnerability_report": "# report"},
                    feedback_entries=[],
                    code_graph_mcp=None,
                    cancel_event=threading.Event(),
                ),
            )

        kwargs = run_review.await_args.kwargs
        self.assertEqual(kwargs["method_id"], "fp_check")
        self.assertEqual(kwargs["vuln_index"], 3)
        self.assertEqual(kwargs["vulnerability"]["index"], 3)
        self.assertNotIn("vulnerabilities", kwargs)
        self.assertNotIn("operation", kwargs)
        self.assertEqual(result["status"], "success")
        reporter.push_fp_result.assert_awaited_once()
        skill_paths = task_context.call_args.kwargs["skill_paths"]
        self.assertTrue(skill_paths)
        self.assertTrue(any(path.name == "skills" for path in skill_paths))

    async def test_stage_events_are_uploaded_for_every_method(self) -> None:
        reporter = SimpleNamespace(
            get_git_history=AsyncMock(return_value=[]),
            send_event=AsyncMock(),
            push_fp_stage_output=AsyncMock(),
            push_fp_result=AsyncMock(),
        )

        async def run_review(**kwargs):
            await kwargs["output"]({
                "kind": "stage",
                "message": "done",
                "data": {
                    "vuln_index": 2,
                    "stage": "final_judge",
                    "markdown": "# result",
                    "output_source": {},
                },
            })
            return {"status": "error", "error_message": "incomplete"}

        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("deephole_client.fp_review.run_fp_review", new=run_review),
            patch("task_agent.opencode_task_context", return_value=nullcontext()),
            patch("deephole_client.server.Path.home", return_value=Path(tmp)),
        ):
            await server._run_single_fp_review_item(
                server._FpReviewQueueItem(
                    config=SimpleNamespace(),
                    reporter=reporter,
                    scan_id="scan-1",
                    review_id="review-3",
                    method="adversarial",
                    project_path=tmp,
                    code_scan_path=tmp,
                    vulnerability={"index": 2},
                    feedback_entries=[],
                    cancel_event=threading.Event(),
                ),
            )

        reporter.push_fp_stage_output.assert_awaited_once()
