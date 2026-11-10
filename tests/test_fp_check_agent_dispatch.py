import asyncio
import tempfile
import threading
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

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
        server._fp_review_execution_revisions.clear()

    async def test_duplicate_dispatch_updates_revision_before_queue_dedup(self) -> None:
        reporter = SimpleNamespace(
            set_fp_review_execution=MagicMock(return_value=2),
        )
        review_id = "review-revision"
        item_key = (review_id, 7)
        server._fp_review_active_items.add(item_key)
        server._fp_review_execution_revisions[review_id] = 1

        queued = await server.enqueue_fp_review(
            config=SimpleNamespace(),
            reporter=reporter,
            scan_id="scan-1",
            review_id=review_id,
            method="adversarial",
            project_path="/repo",
            code_scan_path="/repo/src",
            vulnerability={"index": 7},
            execution_revision=2,
        )

        self.assertFalse(queued)
        self.assertEqual(server._fp_review_execution_revisions[review_id], 2)
        reporter.set_fp_review_execution.assert_called_once_with(review_id, 2)

    async def test_delayed_dispatch_cannot_downgrade_known_revision(self) -> None:
        reporter = SimpleNamespace(
            set_fp_review_execution=MagicMock(return_value=3),
        )
        server._fp_review_execution_revisions["review-stale"] = 3

        queued = await server.enqueue_fp_review(
            config=SimpleNamespace(),
            reporter=reporter,
            scan_id="scan-1",
            review_id="review-stale",
            method="adversarial",
            project_path="/repo",
            code_scan_path="/repo/src",
            vulnerability={"index": 8},
            execution_revision=2,
        )

        self.assertFalse(queued)
        self.assertEqual(server._fp_review_execution_revisions["review-stale"], 3)
        self.assertNotIn(("review-stale", 8), server._fp_review_active_items)

    async def _assert_worker_capacity(self, method, config, expected_capacity):
        """Keep a whole launch window blocked so its bound is observable."""
        reporter = SimpleNamespace(
            push_fp_progress=AsyncMock(),
            finish_fp_review=AsyncMock(),
        )
        release = asyncio.Event()
        window_started = asyncio.Event()
        active = 0
        maximum = 0
        review_id = f"capacity-{method}-{expected_capacity}"
        scan_id = f"scan-{review_id}"

        async def run_item(item):
            nonlocal active, maximum
            active += 1
            maximum = max(maximum, active)
            if active == expected_capacity:
                window_started.set()
            try:
                await release.wait()
                return {"status": "success", "verdict": "true_positive"}
            finally:
                active -= 1

        with (
            patch.object(server, "_config", config),
            patch.object(server, "_reporter", reporter),
            patch(
                "deephole_client.server._run_single_fp_review_item",
                new=run_item,
            ),
        ):
            worker = None
            try:
                await server.handle_fp_review(
                    scan_id=scan_id,
                    review_id=review_id,
                    method=method,
                    project_path="/repo",
                    code_scan_path="/repo/src",
                    vulnerabilities=[
                        {"index": index} for index in range(expected_capacity + 1)
                    ],
                )
                worker = server._fp_review_tasks[review_id]
                await asyncio.wait_for(window_started.wait(), 1)
                self.assertEqual(active, expected_capacity)
                self.assertEqual(len(server._fp_review_queues[review_id]), 1)
            finally:
                release.set()
                if worker is not None:
                    await asyncio.wait_for(worker, 1)

        self.assertEqual(maximum, expected_capacity)
        self.assertEqual(reporter.finish_fp_review.await_args.args[2], "complete")
        self.assertNotIn(review_id, server._fp_review_queues)

    async def test_builtin_methods_follow_agent_capacity(self) -> None:
        for method in ("adversarial", "fp_check"):
            for capacity in (1, 8):
                with self.subTest(method=method, capacity=capacity):
                    await self._assert_worker_capacity(
                        method, SimpleNamespace(opencode_concurrency=capacity), capacity,
                    )

    async def test_auto_capacity_keeps_one_worker_without_configured_capacity(self) -> None:
        for config in (SimpleNamespace(), SimpleNamespace(opencode_concurrency=0)):
            with self.subTest(config=config):
                await self._assert_worker_capacity("adversarial", config, 1)

    async def test_custom_manifest_preserves_fixed_worker_limit(self) -> None:
        with patch("deephole_client.fp_review.load_fp_review_methods", return_value={
            "custom": SimpleNamespace(manifest=SimpleNamespace(max_concurrency=3)),
        }):
            await self._assert_worker_capacity(
                "custom", SimpleNamespace(opencode_concurrency=8), 3,
            )

    async def test_capacity_decrease_keeps_running_items_and_limits_refill(self) -> None:
        config = SimpleNamespace(opencode_concurrency=3)
        started = [asyncio.Event() for _ in range(4)]
        release = [asyncio.Event() for _ in range(4)]
        completed = [asyncio.Event() for _ in range(4)]
        cancelled = []

        async def progress(_scan, _review, index, processed, _running):
            if processed is not None:
                completed[index].set()

        reporter = SimpleNamespace(
            push_fp_progress=AsyncMock(side_effect=progress),
            finish_fp_review=AsyncMock(),
        )

        async def run_item(item):
            index = item.vulnerability["index"]
            started[index].set()
            try:
                await release[index].wait()
            except asyncio.CancelledError:
                cancelled.append(index)
                raise
            return {"status": "success", "verdict": "true_positive"}

        with patch("deephole_client.server._run_single_fp_review_item", new=run_item):
            worker = None
            try:
                for index in range(4):
                    await server.enqueue_fp_review(
                        config=config, reporter=reporter, scan_id="decrease-scan",
                        review_id="decrease-review", method="adversarial",
                        project_path="/repo", code_scan_path="/repo/src",
                        vulnerability={"index": index},
                    )
                worker = server._fp_review_tasks["decrease-review"]
                await asyncio.wait_for(asyncio.gather(*(event.wait() for event in started[:3])), 1)
                config.opencode_concurrency = 1
                for index in range(2):
                    release[index].set()
                    await asyncio.wait_for(completed[index].wait(), 1)
                    self.assertFalse(started[3].is_set())
                    self.assertEqual(cancelled, [])
                release[2].set()
                await asyncio.wait_for(started[3].wait(), 1)
                self.assertTrue(completed[2].is_set())
                self.assertEqual(cancelled, [])
            finally:
                for event in release:
                    event.set()
                if worker is not None:
                    await asyncio.wait_for(worker, 1)

    async def test_multiple_reviews_share_actual_model_pool_capacity(self) -> None:
        import task_agent.model_pool as pool

        cli_config = SimpleNamespace(models=[{
            "id": "fp-shared-capacity", "model": "p/fp-shared-capacity",
            "max_concurrency": 2,
        }])
        config = SimpleNamespace(opencode_concurrency=2)
        reporter = SimpleNamespace(push_fp_progress=AsyncMock(), finish_fp_review=AsyncMock())
        release = asyncio.Event()
        windows_submitted = asyncio.Event()
        requests = 0
        active = 0
        maximum = 0

        async def run_item(item):
            nonlocal requests, active, maximum
            requests += 1
            if requests == 4:
                windows_submitted.set()
            lease = await pool.acquire_model_lease(
                cli_config, stats_scope_id=item.scan_id,
                task_context={"planned_task_id": item.planned_task_id, "task_type": "fp_review"},
            )
            active += 1
            maximum = max(maximum, active)
            try:
                await release.wait()
                return {"status": "success", "verdict": "true_positive"}
            finally:
                active -= 1
                await pool.release_model_lease(lease, outcome="success")

        with patch.object(pool, "_condition", asyncio.Condition()), patch(
            "deephole_client.server._run_single_fp_review_item", new=run_item,
        ):
            workers = []
            try:
                for scan_id in ("shared-scan-a", "shared-scan-b"):
                    for index in range(3):
                        await server.enqueue_fp_review(
                            config=config, reporter=reporter, scan_id=scan_id,
                            review_id=f"review-{scan_id}", method="adversarial",
                            project_path="/repo", code_scan_path="/repo/src",
                            vulnerability={"index": index},
                        )
                    workers.append(server._fp_review_tasks[f"review-{scan_id}"])
                await asyncio.wait_for(windows_submitted.wait(), 1)
                self.assertEqual(active, 2)
                snapshots = [pool.model_pool_snapshot(scan_id) for scan_id in ("shared-scan-a", "shared-scan-b")]
                self.assertEqual(sum(len(snapshot["queued_tasks"]) for snapshot in snapshots), 2)
                self.assertEqual(sum(len(snapshot["planned_tasks"]) for snapshot in snapshots), 2)
            finally:
                release.set()
                await asyncio.wait_for(asyncio.gather(*workers), 1)
            self.assertEqual(maximum, 2)
            self.assertEqual(requests, 6)
            for scan_id in ("shared-scan-a", "shared-scan-b"):
                snapshot = pool.model_pool_snapshot(scan_id)
                self.assertEqual(snapshot["planned_tasks"], [])
                self.assertEqual(snapshot["queued_tasks"], [])
                self.assertEqual(snapshot["global_running"], 0)

    async def test_review_only_publishes_backlog_then_model_queue_and_cleans_up(self) -> None:
        import task_agent.model_pool as pool

        review_id, scan_id = "visible-review", "visible-review-scan"
        config = SimpleNamespace(models=[{"id": "fp-visible", "model": "p/fp-visible", "max_concurrency": 1}])
        stop = asyncio.Event()
        publisher_started = asyncio.Event()
        publisher_stopped = asyncio.Event()
        item_started = asyncio.Event()
        owner = None

        async def publish(scope, stop_event, *, execution_owner):
            nonlocal owner
            self.assertEqual(scope, scan_id)
            owner = execution_owner
            publisher_started.set()
            await stop_event.wait()
            publisher_stopped.set()

        reporter = SimpleNamespace(agent_session_id="review-agent", push_fp_progress=AsyncMock(),
                                   finish_fp_review=AsyncMock(), publish_opencode_pool_until=publish)
        processed = []

        async def run_item(item):
            lease = await pool.acquire_model_lease(config, stats_scope_id=scan_id, task_context={
                "planned_task_id": item.planned_task_id, "task_type": "fp_review",
                "execution_kind": "fp_review", "execution_id": review_id,
                "execution_revision": item.execution_revision, "agent_session_id": "review-agent",
            })
            try:
                processed.append(item.vulnerability["index"])
                item_started.set()
                await stop.wait()
                return {"status": "success", "verdict": "true_positive"}
            finally:
                await pool.release_model_lease(lease, outcome="success")

        with patch.object(pool, "_condition", asyncio.Condition()), patch(
            "deephole_client.server._run_single_fp_review_item", new=run_item,
        ), patch("deephole_client.fp_review.load_fp_review_methods", return_value={
            "adversarial": SimpleNamespace(manifest=SimpleNamespace(max_concurrency=1)),
        }):
            occupied = await pool.acquire_model_lease(config, stats_scope_id="other-scan")
            worker = None
            try:
                for index in range(2):
                    await server.enqueue_fp_review(config=config, reporter=reporter, scan_id=scan_id,
                        review_id=review_id, method="adversarial", project_path="/repo", code_scan_path="/repo/src",
                        vulnerability={"index": index}, execution_revision=3)
                worker = server._fp_review_tasks[review_id]
                self.assertEqual(len(pool.model_pool_snapshot(scan_id)["planned_tasks"]), 2)
                await asyncio.wait_for(publisher_started.wait(), 1)
                async def wait_for_queue():
                    while not pool.model_pool_snapshot(scan_id)["queued_tasks"]:
                        await asyncio.sleep(0.001)
                await asyncio.wait_for(wait_for_queue(), 1)
                snapshot = pool.model_pool_snapshot(scan_id)
                self.assertEqual(len(snapshot["planned_tasks"]), 1)
                self.assertEqual(len(snapshot["queued_tasks"]), 1)
                self.assertEqual(snapshot["queued_tasks"][0]["execution_revision"], 3)
                self.assertEqual(owner, {"kind": "fp_review", "id": review_id, "revision": 3})
                await pool.release_model_lease(occupied, outcome="success")
                await asyncio.wait_for(item_started.wait(), 1)
                self.assertEqual(pool.model_pool_snapshot(scan_id)["global_running"], 1)
                self.assertFalse(publisher_stopped.is_set())
                stop.set()
                await asyncio.wait_for(worker, 1)
                self.assertEqual(processed, [0, 1])
                self.assertTrue(publisher_stopped.is_set())
                snapshot = pool.model_pool_snapshot(scan_id)
                self.assertEqual(snapshot["global_running"], 0)
                self.assertEqual(snapshot["planned_tasks"], [])
                self.assertEqual(snapshot["queued_tasks"], [])
            finally:
                stop.set()
                await pool.release_model_lease(occupied, outcome="success")
                if worker is not None and not worker.done():
                    worker.cancel()
                    await asyncio.gather(worker, return_exceptions=True)

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
        config = SimpleNamespace(opencode_concurrency=2)
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
                config=config,
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
                config=config,
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
                config=config,
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
        import task_agent.model_pool as pool

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
        self.assertEqual(pool.model_pool_snapshot("scan-1")["planned_tasks"], [])

    async def test_stop_clears_model_waiters_and_unlaunched_backlog(self) -> None:
        import task_agent.model_pool as pool

        cli_config = SimpleNamespace(models=[{
            "id": "fp-cancel-waiters", "model": "p/fp-cancel-waiters", "max_concurrency": 1,
        }])
        config = SimpleNamespace(opencode_concurrency=2)
        reporter = SimpleNamespace(push_fp_progress=AsyncMock(), finish_fp_review=AsyncMock())
        window_submitted = asyncio.Event()
        submitted = 0

        async def run_item(item):
            nonlocal submitted
            submitted += 1
            if submitted == 2:
                window_submitted.set()
            lease = await pool.acquire_model_lease(
                cli_config, stats_scope_id=item.scan_id, cancel_event=item.cancel_event,
                task_context={"planned_task_id": item.planned_task_id, "task_type": "fp_review"},
            )
            await pool.release_model_lease(lease, outcome="success")
            self.fail("The occupied model must not admit this review")

        with patch.object(pool, "_condition", asyncio.Condition()), patch(
            "deephole_client.server._run_single_fp_review_item", new=run_item,
        ):
            occupied = await pool.acquire_model_lease(cli_config, stats_scope_id="cancel-blocker")
            worker = None
            try:
                for index in range(3):
                    await server.enqueue_fp_review(
                        config=config, reporter=reporter, scan_id="cancel-waiting-scan",
                        review_id="cancel-waiting-review", method="adversarial",
                        project_path="/repo", code_scan_path="/repo/src",
                        vulnerability={"index": index},
                    )
                worker = server._fp_review_tasks["cancel-waiting-review"]
                await asyncio.wait_for(window_submitted.wait(), 1)
                snapshot = pool.model_pool_snapshot("cancel-waiting-scan")
                self.assertEqual(len(snapshot["queued_tasks"]), 2)
                self.assertEqual(len(snapshot["planned_tasks"]), 1)
                await server.handle_fp_review_stop("cancel-waiting-scan", "cancel-waiting-review")
                with self.assertRaises(asyncio.CancelledError):
                    await worker
                snapshot = pool.model_pool_snapshot("cancel-waiting-scan")
                self.assertEqual(snapshot["queued_tasks"], [])
                self.assertEqual(snapshot["planned_tasks"], [])
                self.assertEqual(submitted, 2)
                self.assertEqual(server._fp_review_active_items, set())
                self.assertNotIn("cancel-waiting-review", server._fp_review_queues)
                self.assertEqual(reporter.finish_fp_review.await_args.args[2], "cancelled")
            finally:
                if worker is not None and not worker.done():
                    worker.cancel()
                    await asyncio.gather(worker, return_exceptions=True)
                await pool.release_model_lease(occupied, outcome="success")

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
