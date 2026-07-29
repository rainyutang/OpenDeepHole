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
        server._fp_review_cancel_events.clear()
        server._fp_review_scan_ids.clear()
        server._fp_review_queues.clear()
        server._fp_review_active_items.clear()

    async def test_fp_check_command_dispatches_one_batch_task(self) -> None:
        original_config = server._config
        original_reporter = server._reporter
        server._config = SimpleNamespace()
        server._reporter = SimpleNamespace()
        try:
            with patch(
                "deephole_client.server._run_fp_check_batch",
                new=AsyncMock(),
            ) as run_batch:
                await server.handle_fp_review(
                    scan_id="scan-1",
                    review_id="review-1",
                    method="fp_check",
                    project_path="/repo",
                    vulnerabilities=[{"index": 1}, {"index": 2}],
                )
                await server._fp_review_tasks["review-1"]

            self.assertEqual(run_batch.await_count, 1)
            self.assertEqual(
                [item["index"] for item in run_batch.await_args.kwargs["vulnerabilities"]],
                [1, 2],
            )
            self.assertEqual(server._fp_review_queues, {})
        finally:
            server._config = original_config
            server._reporter = original_reporter

    async def test_batch_adapter_pushes_only_effective_results_and_summary(self) -> None:
        reporter = SimpleNamespace(
            get_git_history=AsyncMock(return_value=[]),
            send_event=AsyncMock(),
            push_fp_stage_output=AsyncMock(),
            push_fp_progress=AsyncMock(),
            push_fp_result=AsyncMock(),
            finish_fp_review=AsyncMock(),
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
            "unresolved_indices": [4],
            "summary_markdown": "# batch summary",
            "summary_output_source": {},
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
        ):
            await server._run_fp_check_batch(
                config=SimpleNamespace(),
                reporter=reporter,
                scan_id="scan-1",
                review_id="review-2",
                project_path=tmp,
                vulnerabilities=[
                    {"index": 3, "vulnerability_report": "# report"},
                    {"index": 4},
                ],
                feedback_entries=[],
                processed_offset=0,
                code_graph_mcp=None,
                cancel_event=threading.Event(),
            )

        self.assertEqual(run_review.await_count, 1)
        self.assertEqual(reporter.push_fp_result.await_count, 1)
        self.assertEqual(
            reporter.push_fp_result.await_args.args[3:6],
            ("tp", "high", "all six gates pass"),
        )
        finish_args = reporter.finish_fp_review.await_args.args
        self.assertEqual(finish_args[2], "complete")
        self.assertEqual(finish_args[4], "# batch summary")
