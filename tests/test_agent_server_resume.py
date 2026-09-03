from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from deephole_client import main as agent_main
from deephole_client import server
from deephole_client.task_manager import TaskManager


class AgentServerResumeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.previous_manager = server._task_manager
        server._task_manager = TaskManager()

    async def asyncTearDown(self) -> None:
        manager = server._task_manager
        if manager is not None:
            for snapshot in list(manager._tasks.values()):
                if snapshot.asyncio_task is not None and not snapshot.asyncio_task.done():
                    snapshot.asyncio_task.cancel()
                    await asyncio.gather(
                        snapshot.asyncio_task,
                        return_exceptions=True,
                    )
        server._task_manager = self.previous_manager

    async def test_resume_replaces_running_task_with_fresh_cancel_event(self) -> None:
        manager = server._task_manager
        previous = manager.create(
            scan_id="scan-race",
            project_path="/repo/project",
            code_scan_path="/repo/project/src",
            checkers=["npd"],
            scan_name="old",
        )
        old_finished = asyncio.Event()
        old_terminal_suppressed: list[bool] = []

        async def old_run() -> None:
            try:
                while not previous.cancel_event.is_set():
                    await asyncio.sleep(0)
            finally:
                old_terminal_suppressed.append(
                    previous.cancel_event.suppress_terminal_report
                )
                old_finished.set()
                manager.remove(previous.scan_id, previous)

        previous.asyncio_task = asyncio.create_task(old_run())
        await asyncio.sleep(0)

        resumed_started = asyncio.Event()
        release_resumed = asyncio.Event()
        resumed_cancelled: list[bool] = []

        async def resumed_run(task, is_resume: bool) -> None:
            self.assertTrue(is_resume)
            resumed_cancelled.append(task.cancel_event.is_set())
            resumed_started.set()
            await release_resumed.wait()

        with patch.object(server, "_run", new=resumed_run):
            await server.handle_resume(
                scan_id="scan-race",
                project_path="/repo/project",
                code_scan_path="/repo/project/src",
                checkers=["npd"],
                scan_name="resumed",
                retry_mining_engine_ids=["static_candidate"],
            )
            await asyncio.wait_for(resumed_started.wait(), timeout=1)
            resumed = manager.get("scan-race")
            self.assertIsNotNone(resumed)
            self.assertTrue(old_finished.is_set())
            self.assertEqual(old_terminal_suppressed, [True])
            self.assertTrue(previous.cancel_event.is_set())
            self.assertIsNot(resumed, previous)
            self.assertEqual(resumed_cancelled, [False])
            self.assertFalse(resumed.cancel_event.is_set())
            self.assertEqual(
                resumed.retry_mining_engine_ids,
                ["static_candidate"],
            )
            self.assertFalse(manager.remove("scan-race", previous))
            self.assertIs(manager.get("scan-race"), resumed)
            release_resumed.set()
            await resumed.asyncio_task
            manager.remove("scan-race", resumed)

    async def test_stop_keeps_task_visible_until_it_finishes_and_acknowledges(self) -> None:
        manager = server._task_manager
        task = manager.create(
            scan_id="scan-stop",
            project_path="/repo/project",
            code_scan_path="/repo/project/src",
            checkers=[],
            scan_name="stop",
        )

        async def running() -> None:
            while not task.cancel_event.is_set():
                await asyncio.sleep(0)

        task.asyncio_task = asyncio.create_task(running())
        await asyncio.sleep(0)
        cancellation = AsyncMock(return_value={
            "matched_tasks": 1,
            "cancelled_tasks": 1,
            "active_tasks": 0,
        })

        with patch("task_agent.cancel_opencode_execution", new=cancellation):
            response = await server.handle_stop("scan-stop")

        self.assertTrue(task.cancel_event.is_set())
        self.assertFalse(response["still_active"])
        self.assertEqual(response["cancelled_opencode_tasks"], 1)
        cancellation.assert_awaited_once_with(
            "scan",
            "scan-stop",
            timeout_seconds=5.0,
        )
        self.assertEqual(manager.active_snapshots(), [])

    async def test_stop_requested_scan_stays_in_hello_snapshot_until_done(self) -> None:
        manager = server._task_manager
        release = asyncio.Event()
        task = manager.create(
            scan_id="scan-stopping",
            project_path="/repo/project",
            code_scan_path="/repo/project/src",
            checkers=[],
            scan_name="stopping",
        )
        task.asyncio_task = asyncio.create_task(release.wait())

        manager.stop("scan-stopping")
        snapshots = manager.active_snapshots()

        self.assertEqual(len(snapshots), 1)
        self.assertTrue(snapshots[0]["cancel_requested"])
        release.set()
        await task.asyncio_task

    async def test_stop_command_with_request_id_returns_agent_ack(self) -> None:
        result = {
            "found": True,
            "cancelled_opencode_tasks": 1,
            "still_active": False,
            "error": "",
        }
        handler = AsyncMock(return_value=result)

        with patch("deephole_client.server.handle_stop", new=handler):
            response = await agent_main._handle_command(
                {
                    "type": "stop",
                    "scan_id": "scan-ack",
                    "request_id": "request-1",
                },
                None,
                None,
                None,
            )

        self.assertEqual(response, {
            "type": "scan_stop_result",
            "request_id": "request-1",
            "scan_id": "scan-ack",
            **result,
        })


if __name__ == "__main__":
    unittest.main()
