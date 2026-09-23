"""Wall-clock deadlines that do not wait indefinitely for cancellation."""

from __future__ import annotations

import asyncio
import contextlib
import time
from typing import Any, Awaitable, TypeVar


T = TypeVar("T")
CLEANUP_TIMEOUT_SECONDS = 10.0
_POLL_SECONDS = 0.1
_retired_tasks: set[asyncio.Future] = set()


def retire_task(task: asyncio.Future) -> None:
    """Keep a cancelled operation alive and consume any eventual exception."""
    _retired_tasks.add(task)

    def done(completed: asyncio.Future) -> None:
        _retired_tasks.discard(completed)
        with contextlib.suppress(BaseException):
            completed.result()

    task.add_done_callback(done)


async def cancel_tasks_bounded(
    tasks: list[asyncio.Future], *, expires_at: float,
) -> bool:
    """Cancel background work without awaiting cancellation acknowledgement forever."""
    for task in tasks:
        if not task.done():
            task.cancel()
        retire_task(task)
    pending = {task for task in tasks if not task.done()}
    if pending:
        _, pending = await asyncio.wait(
            pending, timeout=max(0.0, expires_at - time.monotonic()),
        )
    return not pending


class OperationDeadline:
    def __init__(
        self,
        timeout: float,
        *,
        cancel_event: Any = None,
        expires_at: float | None = None,
    ) -> None:
        self.started_at = time.monotonic()
        self.expires_at = (
            self.started_at + max(0.0, float(timeout))
            if expires_at is None else expires_at
        )
        self.cancel_event = cancel_event
        self.phase = "preparing"
        self.pending: set[asyncio.Future] = set()

    def remaining(self) -> float:
        return max(0.0, self.expires_at - time.monotonic())

    async def wait(self, operation: Awaitable[T], *, phase: str) -> T:
        self.phase = phase
        task = asyncio.ensure_future(operation)
        try:
            while True:
                # Cancellation takes priority over a response arriving at the
                # same instant, including during preparation and validation.
                if self.cancel_event is not None and self.cancel_event.is_set():
                    raise asyncio.CancelledError()
                remaining = self.remaining()
                if remaining <= 0:
                    raise asyncio.TimeoutError(f"OpenCode call timed out during {phase}")
                if task.done():
                    return task.result()
                await asyncio.wait({task}, timeout=min(_POLL_SECONDS, remaining))
        except BaseException:
            if not task.done():
                task.cancel()
                self.pending.add(task)
                retire_task(task)
            else:
                # A simultaneous cancellation may leave an exception unread.
                with contextlib.suppress(BaseException):
                    task.result()
            raise

    async def drain(self, *, expires_at: float) -> bool:
        """Reap cooperative operations within the caller's shared cleanup budget."""
        pending = {task for task in self.pending if not task.done()}
        if pending:
            _, pending = await asyncio.wait(
                pending, timeout=max(0.0, expires_at - time.monotonic()),
            )
        return not pending
