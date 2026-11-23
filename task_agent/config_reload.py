"""Drain logical OpenCode tasks before applying a new Provider configuration.

Admission and lease-grant callbacks run on the Agent event loop without awaits.
An admitted task retains its permit across every Session retry and formatter.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import copy
import logging
from collections.abc import Awaitable, Callable, Iterator
from typing import Any
from uuid import uuid4


logger = logging.getLogger(__name__)
ApplyConfig = Callable[[Any, str], Awaitable[None]]
_CURRENT_LOCAL_WORK_UNITS: contextvars.ContextVar[tuple[str, ...]] = (
    contextvars.ContextVar("task_agent_current_local_work_units", default=())
)


class ConfigReloadCoordinator:
    def __init__(self) -> None:
        self._state = "active"
        self._desired_revision = ""
        self._applied_revision = ""
        self._error = ""
        self._active_tasks: set[str] = set()
        self._admission_holds: set[str] = set()
        self._active_local_work: dict[str, str] = {}
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
            "active_local_work": len(self._active_local_work),
            "admission_holds": sorted(self._admission_holds),
            "error": self._error,
        }

    def admission(self, task_id: str) -> bool:
        if task_id and task_id in self._active_tasks:
            return True
        return self._state == "active" and not self._admission_holds

    def admit_task(self, task_id: str) -> None:
        """Called atomically with the first model lease grant, never at submit."""
        if not self.admission(task_id):
            raise RuntimeError("OpenCode configuration reload has paused task admission")
        self._active_tasks.add(task_id)

    def release_task(self, task_id: str) -> None:
        self._active_tasks.discard(task_id)
        self._changed.set()

    def hold_admission(self, hold_id: str) -> None:
        """Pause new task admission without cancelling already-admitted work."""
        normalized = str(hold_id or "").strip()
        if not normalized:
            raise ValueError("hold_id must be non-empty")
        if normalized not in self._admission_holds:
            self._admission_holds.add(normalized)
            self._changed.set()

    def release_admission_hold(self, hold_id: str) -> None:
        normalized = str(hold_id or "").strip()
        if normalized in self._admission_holds:
            self._admission_holds.discard(normalized)
            self._changed.set()

    def has_admission_hold(self, hold_id: str | None = None) -> bool:
        if hold_id is None:
            return bool(self._admission_holds)
        return str(hold_id).strip() in self._admission_holds

    def active_task_count(self) -> int:
        return len(self._active_tasks)

    def active_local_work_count(self) -> int:
        return len(self._active_local_work)

    def has_pending_work(self) -> bool:
        return bool(
            self._active_tasks
            or self._active_local_work
            or self._state == "applying"
        )

    @contextlib.contextmanager
    def track_local_work(self, kind: str = "local_work") -> Iterator[str]:
        """Track non-OpenCode work or post-lease settlement that must finish before restart."""
        unit_id = f"{kind or 'local_work'}:{uuid4().hex}"
        self._active_local_work[unit_id] = str(kind or "local_work")
        current = _CURRENT_LOCAL_WORK_UNITS.get()
        token = _CURRENT_LOCAL_WORK_UNITS.set((*current, unit_id))
        self._changed.set()
        try:
            yield unit_id
        finally:
            _CURRENT_LOCAL_WORK_UNITS.reset(token)
            if self._active_local_work.pop(unit_id, None) is not None:
                self._changed.set()

    @contextlib.contextmanager
    def suspend_local_work_while_waiting(self) -> Iterator[None]:
        """Temporarily release local-work guards when parked on closed admission."""
        current = _CURRENT_LOCAL_WORK_UNITS.get()
        suspended: list[tuple[str, str]] = []
        for unit_id in current:
            kind = self._active_local_work.pop(unit_id, None)
            if kind is not None:
                suspended.append((unit_id, kind))
        if suspended:
            self._changed.set()
        try:
            yield
        finally:
            if suspended:
                active_stack = set(_CURRENT_LOCAL_WORK_UNITS.get())
                restored = False
                for unit_id, kind in suspended:
                    if unit_id in active_stack:
                        self._active_local_work[unit_id] = kind
                        restored = True
                if restored:
                    self._changed.set()

    async def wait_for_change(self, timeout: float = 0.2) -> None:
        self._changed.clear()
        try:
            await asyncio.wait_for(self._changed.wait(), timeout=max(0.01, float(timeout)))
        except asyncio.TimeoutError:
            pass

    async def wait_for_admission_open(
        self,
        hold_id: str | None = None,
        cancel_event: Any = None,
    ) -> None:
        """Pause before starting non-OpenCode work while an admission hold is active."""
        while self.has_admission_hold(hold_id):
            if cancel_event is not None and cancel_event.is_set():
                raise asyncio.CancelledError
            await self.wait_for_change(timeout=0.2)
        if cancel_event is not None and cancel_event.is_set():
            raise asyncio.CancelledError

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
        self._state = "draining" if (self._active_tasks or self._admission_holds) else "applying"
        self._changed.set()
        self._start_worker()

    def retry(self) -> bool:
        if self._apply is None or self._state != "failed":
            return False
        self._generation += 1
        self._error = ""
        self._state = "draining" if (self._active_tasks or self._admission_holds) else "applying"
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
                while self._active_tasks or self._admission_holds:
                    self._state = "draining"
                    self._changed.clear()
                    # No await between checking the permits and registering
                    # this Event wait; a release cannot be lost.
                    if self._active_tasks or self._admission_holds:
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
