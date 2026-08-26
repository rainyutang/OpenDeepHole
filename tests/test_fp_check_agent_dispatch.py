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
        server._fp_review_queue_events.clear()
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

    async def test_failed_wave_does_not_block_later_incremental_item(self) -> None:
        reporter = SimpleNamespace(
            push_fp_progress=AsyncMock(),
            finish_fp_review=AsyncMock(),
        )
        seen: list[int] = []

        async def run_item(item):
            vuln_index = int(item.vulnerability["index"])
            seen.append(vuln_index)
            if vuln_index == 0:
                return {"status": "error", "error_message": "first item failed"}
            return {"status": "success", "verdict": "true_positive"}

        with patch(
            "deephole_client.server._run_single_fp_review_item",
            new=run_item,
        ):
            queued = await server.enqueue_fp_review(
                config=SimpleNamespace(),
                reporter=reporter,
                scan_id="scan-1",
                review_id="review-incremental",
                method="adversarial",
                project_path="/repo",
                code_scan_path="/repo/src",
                vulnerability={"index": 0},
            )
            self.assertTrue(queued)
            await server._fp_review_tasks["review-incremental"]

            first_finish = reporter.finish_fp_review.await_args_list[0].args
            self.assertEqual(first_finish[2], "error")
            self.assertIn("first item failed", first_finish[3])

            queued = await server.enqueue_fp_review(
                config=SimpleNamespace(),
                reporter=reporter,
                scan_id="scan-1",
                review_id="review-incremental",
                method="adversarial",
                project_path="/repo",
                code_scan_path="/repo/src",
                vulnerability={"index": 1},
            )
            self.assertTrue(queued)
            await server._fp_review_tasks["review-incremental"]

        self.assertEqual(seen, [0, 1])
        second_finish = reporter.finish_fp_review.await_args_list[1].args
        self.assertEqual(second_finish[2], "complete")
        self.assertEqual(server._fp_review_queues, {})
        self.assertEqual(server._fp_review_active_items, set())

    async def test_incremental_item_fills_free_slot_before_first_finishes(self) -> None:
        reporter = SimpleNamespace(
            push_fp_progress=AsyncMock(),
            finish_fp_review=AsyncMock(),
        )
        first_started = asyncio.Event()
        second_started = asyncio.Event()
        third_started = asyncio.Event()
        release = asyncio.Event()

        async def run_item(item):
            vuln_index = int(item.vulnerability["index"])
            if vuln_index == 0:
                first_started.set()
            elif vuln_index == 1:
                second_started.set()
            else:
                third_started.set()
            if vuln_index < 2:
                await release.wait()
            return {"status": "success", "verdict": "true_positive"}

        with patch(
            "deephole_client.server._run_single_fp_review_item",
            new=run_item,
        ):
            queued = await server.enqueue_fp_review(
                config=SimpleNamespace(),
                reporter=reporter,
                scan_id="scan-1",
                review_id="review-sliding-window",
                method="adversarial",
                project_path="/repo",
                code_scan_path="/repo/src",
                vulnerability={"index": 0},
            )
            self.assertTrue(queued)
            await asyncio.wait_for(first_started.wait(), timeout=1)

            queued = await server.enqueue_fp_review(
                config=SimpleNamespace(),
                reporter=reporter,
                scan_id="scan-1",
                review_id="review-sliding-window",
                method="adversarial",
                project_path="/repo",
                code_scan_path="/repo/src",
                vulnerability={"index": 1},
            )
            self.assertTrue(queued)
            await asyncio.wait_for(second_started.wait(), timeout=1)
            self.assertFalse(
                server._fp_review_tasks["review-sliding-window"].done()
            )

            queued = await server.enqueue_fp_review(
                config=SimpleNamespace(),
                reporter=reporter,
                scan_id="scan-1",
                review_id="review-sliding-window",
                method="adversarial",
                project_path="/repo",
                code_scan_path="/repo/src",
                vulnerability={"index": 2},
            )
            self.assertTrue(queued)
            await asyncio.sleep(0)
            self.assertFalse(third_started.is_set())
            release.set()
            await asyncio.wait_for(third_started.wait(), timeout=1)
            await server._fp_review_tasks["review-sliding-window"]

        self.assertEqual(reporter.finish_fp_review.await_args.args[2], "complete")
        self.assertEqual(server._fp_review_queues, {})

    async def test_unexpected_item_cancellation_does_not_clear_later_items(self) -> None:
        reporter = SimpleNamespace(
            push_fp_progress=AsyncMock(),
            finish_fp_review=AsyncMock(),
        )
        seen: list[int] = []

        async def run_item(item):
            vuln_index = int(item.vulnerability["index"])
            seen.append(vuln_index)
            if vuln_index == 0:
                raise asyncio.CancelledError("model task was interrupted")
            return {"status": "success", "verdict": "true_positive"}

        with patch(
            "deephole_client.server._run_single_fp_review_item",
            new=run_item,
        ):
            for vuln_index in (0, 1):
                queued = await server.enqueue_fp_review(
                    config=SimpleNamespace(),
                    reporter=reporter,
                    scan_id="scan-1",
                    scan_mode="quick",
                    review_id="review-unexpected-cancel",
                    method="adversarial",
                    project_path="/repo",
                    code_scan_path="/repo/src",
                    vulnerability={"index": vuln_index},
                )
                self.assertTrue(queued)
            await server._fp_review_tasks["review-unexpected-cancel"]

        self.assertEqual(seen, [0, 1])
        finish = reporter.finish_fp_review.await_args.args
        self.assertEqual(finish[2], "complete")
        self.assertIn("model task was interrupted", finish[3])
        self.assertEqual(server._fp_review_queues, {})

    async def test_explicit_stop_still_cancels_the_review_queue(self) -> None:
        reporter = SimpleNamespace(
            push_fp_progress=AsyncMock(),
            finish_fp_review=AsyncMock(),
        )
        started = asyncio.Event()
        release = asyncio.Event()

        async def run_item(_item):
            started.set()
            await release.wait()
            return {"status": "success", "verdict": "true_positive"}

        with patch(
            "deephole_client.server._run_single_fp_review_item",
            new=run_item,
        ):
            for vuln_index in (0, 1):
                queued = await server.enqueue_fp_review(
                    config=SimpleNamespace(),
                    reporter=reporter,
                    scan_id="scan-1",
                    review_id="review-user-stop",
                    method="adversarial",
                    project_path="/repo",
                    code_scan_path="/repo/src",
                    vulnerability={"index": vuln_index},
                )
                self.assertTrue(queued)
            task = server._fp_review_tasks["review-user-stop"]
            await started.wait()
            await server.handle_fp_review_stop("scan-1", "review-user-stop")
            with self.assertRaises(asyncio.CancelledError):
                await task

        finish = reporter.finish_fp_review.await_args.args
        self.assertEqual(finish[2], "cancelled")
        self.assertEqual(finish[3], "用户手动停止")
        self.assertNotIn("review-user-stop", server._fp_review_queues)
        self.assertEqual(server._fp_review_active_items, set())

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
                    scan_mode="quick",
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
        self.assertEqual(kwargs["scan_mode"], "quick")
        self.assertEqual(kwargs["vuln_index"], 3)
        self.assertEqual(kwargs["vulnerability"]["index"], 3)
        self.assertNotIn("vulnerabilities", kwargs)
        self.assertNotIn("operation", kwargs)
        self.assertEqual(result["status"], "success")
        reporter.push_fp_result.assert_awaited_once()
        reporter.get_git_history.assert_not_awaited()
        skill_paths = task_context.call_args.kwargs["skill_paths"]
        self.assertEqual(
            task_context.call_args.kwargs["task_metadata"]["scan_mode"],
            "quick",
        )
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
