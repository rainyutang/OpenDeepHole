from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

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


if __name__ == "__main__":
    unittest.main()
