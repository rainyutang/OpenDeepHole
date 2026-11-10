"""Async boundary for synchronous persistence implementations.

SQLite work is deliberately serialized on one thread.  PostgreSQL uses a
small bounded pool so independent reads can overlap without blocking FastAPI's
event loop or Agent heartbeat handling.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, TypeVar

from backend.logger import get_logger
from backend.runtime_metrics import runtime_metrics

logger = get_logger(__name__)
T = TypeVar("T")

_executors: dict[str, ThreadPoolExecutor] = {}
_executor_lock = threading.Lock()
_STORE_STALL_SECONDS = 5.0
_STORE_STALL_REPEAT_SECONDS = 30.0


def _slow_store_ms() -> float:
    try:
        return max(1.0, float(os.environ.get("OPENDEEPHOLE_SLOW_STORE_MS", "250")))
    except (TypeError, ValueError):
        return 250.0


def _get_executor(store: Any) -> ThreadPoolExecutor:
    distributed = bool(getattr(store, "distributed", False))
    key = "postgres" if distributed else "sqlite"
    with _executor_lock:
        executor = _executors.get(key)
        if executor is None:
            workers = (
                max(2, min(16, int(getattr(store, "executor_workers", 4))))
                if distributed
                else 1
            )
            executor = ThreadPoolExecutor(
                max_workers=workers,
                thread_name_prefix=f"opendeephole-{key}",
            )
            _executors[key] = executor
        return executor


async def run_store_call(
    store: Any,
    operation: str | Callable[..., T],
    *args: Any,
    **kwargs: Any,
) -> T:
    """Execute one synchronous store operation without blocking the event loop."""

    if isinstance(operation, str):
        name = operation
        function = getattr(store, operation)
    else:
        name = getattr(operation, "__name__", operation.__class__.__name__)
        function = operation

    enqueued_at = time.perf_counter()
    runtime_metrics.store_enqueued()
    started_at: float | None = None
    caller_cancelled = False
    watchdog: asyncio.TimerHandle | None = None
    loop = asyncio.get_running_loop()

    def invoke() -> T:
        nonlocal started_at
        started_at = time.perf_counter()
        return function(*args, **kwargs)

    def record_finished(ok: bool) -> None:
        finished_at = time.perf_counter()
        queue_ms = max(0.0, ((started_at or finished_at) - enqueued_at) * 1000)
        duration_ms = max(0.0, (finished_at - started_at) * 1000) if started_at is not None else 0.0
        runtime_metrics.store_finished(
            name=name,
            queue_ms=queue_ms,
            duration_ms=duration_ms,
            ok=ok,
        )
        slow_ms = _slow_store_ms()
        if queue_ms >= slow_ms or duration_ms >= slow_ms:
            logger.warning(
                "Slow store operation name=%s queue_ms=%.1f duration_ms=%.1f",
                name,
                queue_ms,
                duration_ms,
            )

    try:
        operation_future = _get_executor(store).submit(invoke)
    except BaseException:
        record_finished(False)
        raise

    def cancel_watchdog() -> None:
        if watchdog is not None:
            watchdog.cancel()

    def operation_finished(future) -> None:
        # A cancelled HTTP waiter cannot stop a running database operation.
        # Account for the actual executor future, including queued cancellation,
        # rather than claiming that the worker was released by coroutine exit.
        record_finished(not future.cancelled() and future.exception() is None)
        try:
            loop.call_soon_threadsafe(cancel_watchdog)
        except RuntimeError:
            # The event loop may already be closed during process shutdown.
            pass

    def warn_if_stalled() -> None:
        nonlocal watchdog
        if operation_future.done():
            return
        now = time.perf_counter()
        started = started_at
        logger.warning(
            "Store operation still pending name=%s phase=%s queue_ms=%.1f "
            "duration_ms=%.1f caller_cancelled=%s",
            name,
            "queued" if started is None else "running",
            max(0.0, ((started or now) - enqueued_at) * 1000),
            max(0.0, (now - started) * 1000) if started is not None else 0.0,
            caller_cancelled,
        )
        watchdog = loop.call_later(_STORE_STALL_REPEAT_SECONDS, warn_if_stalled)

    operation_future.add_done_callback(operation_finished)
    if not operation_future.done():
        watchdog = loop.call_later(_STORE_STALL_SECONDS, warn_if_stalled)
    try:
        return await asyncio.wrap_future(operation_future, loop=loop)
    except asyncio.CancelledError:
        caller_cancelled = True
        # Cancel only work which has not started. Running work keeps its
        # watchdog and remains pending in metrics until its real completion.
        operation_future.cancel()
        raise


async def shutdown_store_executor() -> None:
    """Drain and release the dedicated store executor during app shutdown."""

    with _executor_lock:
        executors = list(_executors.values())
        _executors.clear()
    for executor in executors:
        await asyncio.to_thread(executor.shutdown, True)
