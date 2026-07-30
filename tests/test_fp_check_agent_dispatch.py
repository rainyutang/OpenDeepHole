import asyncio
import tempfile
import threading
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from deephole_client import server


class FpCheckAgentDispatchTests(unittest.IsolatedAsyncioTestCase):
    def tearDown(self) -> None:
        server._fp_review_tasks.clear()
        server._fp_review_summary_tasks.clear()
        server._fp_review_cancel_events.clear()
        server._fp_review_scan_ids.clear()
        server._fp_review_queues.clear()
        server._fp_review_active_items.clear()
        server._fp_review_running_indices.clear()

    async def test_fp_check_command_dispatches_items_with_max_four_concurrency(self) -> None:
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

        async def run_item(item, processed_offset):
            nonlocal active, maximum
            active += 1
            maximum = max(maximum, active)
            await asyncio.sleep(0.01)
            active -= 1
            return {
                "status": "success",
                "results": [{"vuln_index": item.vulnerability["index"]}],
                "error_message": None,
            }

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
                    vulnerabilities=[
                        {"index": index}
                        for index in range(5)
                    ],
                )
                task = server._fp_review_tasks["review-1"]
                await task

            self.assertEqual(maximum, 4)
            self.assertEqual(reporter.finish_fp_review.await_args.args[2], "complete")
            self.assertEqual(server._fp_review_queues, {})
        finally:
            server._config = original_config
            server._reporter = original_reporter

    async def test_item_adapter_pushes_only_single_effective_result(self) -> None:
        reporter = SimpleNamespace(
            get_git_history=AsyncMock(return_value=[]),
            send_event=AsyncMock(),
            push_fp_stage_output=AsyncMock(),
            push_fp_progress=AsyncMock(),
            push_fp_result=AsyncMock(),
        )
        runtime_result = {
            "status": "success",
            "results": [{
                "vuln_index": 3,
                "verdict": "true_positive",
                "revised_severity": "high",
                "reason": "all six gates pass",
                "vulnerability_report": "# report",
                "stage_outputs": {"gate_review": "# gates"},
                "stage_output_sources": {},
                "output_source": {},
            }],
            "processed": 1,
            "unresolved_indices": [],
            "summary_markdown": "",
            "summary_output_source": {},
            "error_message": None,
        }

        with (
            tempfile.TemporaryDirectory() as tmp,
            patch(
                "deephole_client.fp_check_review.run_fp_check_review",
                new=AsyncMock(return_value=runtime_result),
            ) as run_review,
            patch(
                "task_agent.opencode_task_context",
                return_value=nullcontext(),
            ),
            patch(
                "deephole_client.server.Path.home",
                return_value=Path(tmp),
            ),
        ):
            result = await server._run_single_fp_review_item(
                server._FpReviewQueueItem(
                config=SimpleNamespace(),
                reporter=reporter,
                scan_id="scan-1",
                review_id="review-2",
                method="fp_check",
                project_path=tmp,
                vulnerability={"index": 3, "vulnerability_report": "# report"},
                feedback_entries=[],
                code_graph_mcp=None,
                cancel_event=threading.Event(),
                ),
                0,
            )

        self.assertEqual(run_review.await_count, 1)
        self.assertEqual(run_review.await_args.kwargs["operation"], "item")
        self.assertEqual(reporter.push_fp_result.await_count, 1)
        self.assertEqual(
            reporter.push_fp_result.await_args.args[3:6],
            ("tp", "high", "all six gates pass"),
        )
        self.assertEqual(result["status"], "success")

    async def test_all_no_result_items_finish_as_retryable_error(self) -> None:
        original_config = server._config
        original_reporter = server._reporter
        server._config = SimpleNamespace()
        reporter = SimpleNamespace(
            push_fp_progress=AsyncMock(),
            finish_fp_review=AsyncMock(),
        )
        server._reporter = reporter

        async def no_result(item, processed_offset):
            return {
                "status": "error",
                "results": [],
                "error_message": "OpenCode exhausted same-session JSON corrections",
            }

        try:
            with patch(
                "deephole_client.server._run_single_fp_review_item",
                new=no_result,
            ):
                await server.handle_fp_review(
                    scan_id="scan-1",
                    review_id="review-failed",
                    method="fp_check",
                    project_path="/repo",
                    vulnerabilities=[
                        {"index": index}
                        for index in range(16)
                    ],
                )
                await server._fp_review_tasks["review-failed"]

            finish_args = reporter.finish_fp_review.await_args.args
            self.assertEqual(finish_args[2], "error")
            self.assertIn("16 个单项复核均未生成有效结果", finish_args[3])
            processed_values = [
                call.args[3]
                for call in reporter.push_fp_progress.await_args_list
                if call.args[3] is not None
            ]
            self.assertEqual(max(processed_values), 16)
        finally:
            server._config = original_config
            server._reporter = original_reporter

    async def test_summary_adapter_uses_persisted_context_and_separate_finish(self) -> None:
        reporter = SimpleNamespace(
            fetch_config=AsyncMock(return_value=None),
            get_fp_review_summary_context=AsyncMock(return_value={
                "vulnerabilities": [{"index": 3}, {"index": 4}],
                "results": [
                    {"vuln_index": 3, "verdict": "tp", "reason": "valid"},
                    {"vuln_index": 4, "verdict": "fp", "reason": "blocked"},
                ],
                "unresolved_indices": [],
            }),
            send_event=AsyncMock(),
            finish_fp_review_summary=AsyncMock(),
        )
        runtime_result = {
            "status": "success",
            "summary_markdown": "# independent summary",
            "summary_output_source": {},
            "error_message": None,
        }
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch(
                "deephole_client.fp_check_review.run_fp_check_review",
                new=AsyncMock(return_value=runtime_result),
            ) as run_review,
            patch(
                "task_agent.opencode_task_context",
                return_value=nullcontext(),
            ),
            patch(
                "deephole_client.server.Path.home",
                return_value=Path(tmp),
            ),
        ):
            await server._run_fp_check_summary(
                config=SimpleNamespace(),
                reporter=reporter,
                scan_id="scan-1",
                review_id="review-3",
                project_path=tmp,
                feedback_entries=[],
                code_graph_mcp=None,
                cancel_event=threading.Event(),
            )

        self.assertEqual(run_review.await_args.kwargs["operation"], "summary")
        finish_args = reporter.finish_fp_review_summary.await_args.args
        self.assertEqual(finish_args[2], "complete")
        self.assertEqual(finish_args[4], "# independent summary")
