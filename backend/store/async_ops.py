"""Async boundary for synchronous persistence implementations.

SQLite work is deliberately serialized on one thread.  PostgreSQL uses a
small bounded pool so independent reads can overlap without blocking FastAPI's
event loop or Agent heartbeat handling.
"""

from __future__ import annotations

import asyncio
import functools
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
    started_at = enqueued_at

    def invoke() -> T:
        nonlocal started_at
        started_at = time.perf_counter()
        return function(*args, **kwargs)

    ok = False
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            _get_executor(store),
            functools.partial(invoke),
        )
        ok = True
        return result
    finally:
        finished_at = time.perf_counter()
        queue_ms = max(0.0, (started_at - enqueued_at) * 1000)
        duration_ms = max(0.0, (finished_at - started_at) * 1000)
        runtime_metrics.store_finished(
            name=name,
            queue_ms=queue_ms,
            duration_ms=duration_ms,
            ok=ok,
        )
        slow_ms = _slow_store_ms()
        if duration_ms >= slow_ms:
            logger.warning(
                "Slow store operation name=%s queue_ms=%.1f duration_ms=%.1f",
                name,
                queue_ms,
                duration_ms,
            )


async def shutdown_store_executor() -> None:
    """Drain and release the dedicated store executor during app shutdown."""

    with _executor_lock:
        executors = list(_executors.values())
        _executors.clear()
    for executor in executors:
        await asyncio.to_thread(executor.shutdown, True)
