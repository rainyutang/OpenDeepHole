"""Drain logical OpenCode tasks before applying a new Provider configuration.

Admission and lease-grant callbacks run on the Agent event loop without awaits.
An admitted task retains its permit across every Session retry and formatter.
"""

from __future__ import annotations

import asyncio
import copy
import logging
from collections.abc import Awaitable, Callable
from typing import Any


logger = logging.getLogger(__name__)
ApplyConfig = Callable[[Any, str], Awaitable[None]]


class ConfigReloadCoordinator:
    def __init__(self) -> None:
        self._state = "active"
        self._desired_revision = ""
        self._applied_revision = ""
        self._error = ""
        self._active_tasks: set[str] = set()
        self._payload: Any = None
        self._apply: ApplyConfig | None = None
        self._generation = 0
        self._changed = asyncio.Event()
        self._worker: asyncio.Task[None] | None = None

    def initialize(self, applied_revision: str) -> None:
        """Record the initial runtime without overwriting an outstanding update."""
        if self._desired_revision or self._worker is not None:
            return
        self._applied_revision = str(applied_revision)
        self._desired_revision = str(applied_revision)

    def status(self) -> dict[str, Any]:
        return {
            "state": self._state,
            "desired_revision": self._desired_revision,
            "applied_revision": self._applied_revision,
            "active_tasks": len(self._active_tasks),
            "error": self._error,
        }

    def admission(self, task_id: str) -> bool:
        return self._state == "active" or task_id in self._active_tasks

    def admit_task(self, task_id: str) -> None:
        """Called atomically with the first model lease grant, never at submit."""
        if not self.admission(task_id):
            raise RuntimeError("OpenCode configuration reload has paused task admission")
        self._active_tasks.add(task_id)

    def release_task(self, task_id: str) -> None:
        self._active_tasks.discard(task_id)
        self._changed.set()

    def stage(self, revision: str, payload: Any, apply: ApplyConfig) -> None:
        """Save the latest desired inputs and close admission before yielding."""
        revision = str(revision)
        if revision == self._applied_revision and self._state == "active":
            return
        if (
            self._state in {"draining", "applying"}
            and revision == self._desired_revision
            and payload == self._payload
        ):
            return
        self._desired_revision = revision
        self._payload = copy.deepcopy(payload)
        self._apply = apply
        self._generation += 1
        self._error = ""
        self._state = "draining" if self._active_tasks else "applying"
        self._changed.set()
        self._start_worker()

    def retry(self) -> bool:
        if self._apply is None or self._state != "failed":
            return False
        self._generation += 1
        self._error = ""
        self._state = "draining" if self._active_tasks else "applying"
        self._changed.set()
        self._start_worker()
        return True

    def _start_worker(self) -> None:
        if self._worker is None or self._worker.done():
            self._worker = asyncio.create_task(self._run(), name="opencode-provider-reload")

    async def _notify_model_pool(self) -> None:
        from .model_pool import notify_model_pool_config_changed

        await notify_model_pool_config_changed()

    async def _run(self) -> None:
        try:
            await self._notify_model_pool()
            while True:
                while self._active_tasks:
                    self._state = "draining"
                    self._changed.clear()
                    # No await between checking the permits and registering
                    # this Event wait; a release cannot be lost.
                    if self._active_tasks:
                        await self._changed.wait()
                generation = self._generation
                revision = self._desired_revision
                payload = copy.deepcopy(self._payload)
                apply = self._apply
                assert apply is not None
                self._state = "applying"
                try:
                    await apply(payload, revision)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    if generation != self._generation:
                        continue
                    # Callback diagnostics can contain credentials or URLs.
                    # The public status never copies arbitrary exception text.
                    self._error = f"OpenCode 配置应用失败（{type(exc).__name__}），请重试或检查 Agent 日志。"
                    logger.error("OpenCode Provider reload failed: %s", type(exc).__name__)
                    self._state = "failed"
                    self._changed.set()
                    await self._notify_model_pool()
                    if generation != self._generation:
                        continue
                    return
                self._applied_revision = revision
                if generation != self._generation:
                    continue
                self._state = "active"
                self._error = ""
                self._changed.set()
                await self._notify_model_pool()
                # A save can arrive while notification yields. Keep the same
                # worker until that newer generation has also been applied.
                if generation == self._generation:
                    return
        finally:
            self._worker = None

    async def wait_ready(self, cancel_event: Any = None) -> None:
        """Wait outside model deadlines; failed updates stay paused until retry."""
        while self._state != "active":
            if cancel_event is not None and cancel_event.is_set():
                raise asyncio.CancelledError
            self._changed.clear()
            try:
                await asyncio.wait_for(self._changed.wait(), timeout=0.2)
            except asyncio.TimeoutError:
                pass
        if cancel_event is not None and cancel_event.is_set():
            raise asyncio.CancelledError

    async def shutdown(self) -> None:
        worker = self._worker
        if worker is not None:
            worker.cancel()
            try:
                await worker
            except asyncio.CancelledError:
                pass


_coordinator: ConfigReloadCoordinator | None = None


def get_config_reload_coordinator() -> ConfigReloadCoordinator:
    global _coordinator
    if _coordinator is None:
        _coordinator = ConfigReloadCoordinator()
    return _coordinator
