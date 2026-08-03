"""Low-overhead runtime metrics and request latency instrumentation.

The project intentionally keeps this dependency-free.  Metrics are exposed as
JSON for operators and the slow-path logs remain useful when no external
metrics stack is installed.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
import uuid
from collections import Counter, deque
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from starlette.datastructures import MutableHeaders

from backend.logger import get_logger

logger = get_logger(__name__)


def _env_float(name: str, default: float, *, minimum: float = 0.0) -> float:
    try:
        return max(minimum, float(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * percentile)))
    return round(ordered[index], 3)


@dataclass(frozen=True)
class _StoreCall:
    name: str
    queue_ms: float
    duration_ms: float
    ok: bool


class RuntimeMetrics:
    """Thread-safe rolling metrics used by the HTTP and store boundaries."""

    def __init__(self, sample_size: int = 2048) -> None:
        self._lock = threading.Lock()
        self._started_at = time.time()
        self._request_total = 0
        self._request_in_flight = 0
        self._request_statuses: Counter[str] = Counter()
        self._request_durations: deque[float] = deque(maxlen=sample_size)
        self._request_slow_total = 0
        self._store_total = 0
        self._store_errors = 0
        self._store_pending = 0
        self._store_pending_peak = 0
        self._store_calls: deque[_StoreCall] = deque(maxlen=sample_size)
        self._store_by_operation: Counter[str] = Counter()
        self._event_loop_lag_ms = 0.0
        self._event_loop_lag_peak_ms = 0.0
        self._stream_events_enqueued = 0
        self._stream_events_persisted = 0
        self._stream_events_dropped = 0
        self._stream_event_queue = 0
        self._stream_event_queue_peak = 0

    def request_started(self) -> None:
        with self._lock:
            self._request_in_flight += 1

    def request_finished(self, *, status: int, duration_ms: float, slow: bool) -> None:
        with self._lock:
            self._request_total += 1
            self._request_in_flight = max(0, self._request_in_flight - 1)
            self._request_statuses[str(status)] += 1
            self._request_durations.append(duration_ms)
            if slow:
                self._request_slow_total += 1

    def store_enqueued(self) -> None:
        with self._lock:
            self._store_pending += 1
            self._store_pending_peak = max(self._store_pending_peak, self._store_pending)

    def store_finished(
        self,
        *,
        name: str,
        queue_ms: float,
        duration_ms: float,
        ok: bool,
    ) -> None:
        with self._lock:
            self._store_pending = max(0, self._store_pending - 1)
            self._store_total += 1
            self._store_by_operation[name] += 1
            if not ok:
                self._store_errors += 1
            self._store_calls.append(
                _StoreCall(
                    name=name,
                    queue_ms=queue_ms,
                    duration_ms=duration_ms,
                    ok=ok,
                )
            )

    def set_event_loop_lag(self, lag_ms: float) -> None:
        with self._lock:
            self._event_loop_lag_ms = lag_ms
            self._event_loop_lag_peak_ms = max(self._event_loop_lag_peak_ms, lag_ms)

    def stream_event_enqueued(self, queue_size: int) -> None:
        with self._lock:
            self._stream_events_enqueued += 1
            self._stream_event_queue = max(0, int(queue_size))
            self._stream_event_queue_peak = max(
                self._stream_event_queue_peak,
                self._stream_event_queue,
            )

    def stream_events_persisted(self, count: int, queue_size: int) -> None:
        with self._lock:
            self._stream_events_persisted += max(0, int(count))
            self._stream_event_queue = max(0, int(queue_size))

    def stream_event_dropped(self, queue_size: int) -> None:
        self.stream_events_dropped(1, queue_size)

    def stream_events_dropped(self, count: int, queue_size: int) -> None:
        with self._lock:
            self._stream_events_dropped += max(0, int(count))
            self._stream_event_queue = max(0, int(queue_size))

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            request_durations = list(self._request_durations)
            store_calls = list(self._store_calls)
            store_durations = [item.duration_ms for item in store_calls]
            store_queue = [item.queue_ms for item in store_calls]
            return {
                "process": {
                    "uptime_seconds": round(time.time() - self._started_at, 3),
                    "pid": os.getpid(),
                },
                "requests": {
                    "total": self._request_total,
                    "in_flight": self._request_in_flight,
                    "slow_total": self._request_slow_total,
                    "by_status": dict(self._request_statuses),
                    "latency_ms": {
                        "p50": _percentile(request_durations, 0.50),
                        "p95": _percentile(request_durations, 0.95),
                        "p99": _percentile(request_durations, 0.99),
                        "max": round(max(request_durations, default=0.0), 3),
                    },
                },
                "store": {
                    "total": self._store_total,
                    "errors": self._store_errors,
                    "pending": self._store_pending,
                    "pending_peak": self._store_pending_peak,
                    "by_operation": dict(self._store_by_operation),
                    "execution_ms": {
                        "p50": _percentile(store_durations, 0.50),
                        "p95": _percentile(store_durations, 0.95),
                        "p99": _percentile(store_durations, 0.99),
                        "max": round(max(store_durations, default=0.0), 3),
                    },
                    "queue_ms": {
                        "p50": _percentile(store_queue, 0.50),
                        "p95": _percentile(store_queue, 0.95),
                        "p99": _percentile(store_queue, 0.99),
                        "max": round(max(store_queue, default=0.0), 3),
                    },
                },
                "event_loop": {
                    "lag_ms": round(self._event_loop_lag_ms, 3),
                    "lag_peak_ms": round(self._event_loop_lag_peak_ms, 3),
                },
                "stream_events": {
                    "enqueued": self._stream_events_enqueued,
                    "persisted": self._stream_events_persisted,
                    "dropped": self._stream_events_dropped,
                    "queue": self._stream_event_queue,
                    "queue_peak": self._stream_event_queue_peak,
                },
            }


runtime_metrics = RuntimeMetrics()


class RequestMetricsMiddleware:
    """Measure the complete ASGI response, including serialization/compression."""

    def __init__(self, app) -> None:
        self.app = app
        self._slow_seconds = _env_float(
            "OPENDEEPHOLE_SLOW_REQUEST_SECONDS",
            1.0,
            minimum=0.01,
        )

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        status = 500
        response_bytes = 0
        request_id = ""
        for raw_name, raw_value in scope.get("headers") or []:
            if raw_name.lower() == b"x-request-id":
                request_id = raw_value.decode("latin-1", errors="replace")[:128]
                break
        request_id = request_id or uuid.uuid4().hex
        runtime_metrics.request_started()

        async def send_with_metrics(message) -> None:
            nonlocal status, response_bytes
            if message["type"] == "http.response.start":
                status = int(message.get("status") or 500)
                headers = MutableHeaders(scope=message)
                headers.append("X-Request-ID", request_id)
                elapsed_ms = (time.perf_counter() - started) * 1000
                headers.append("Server-Timing", f"app;dur={elapsed_ms:.3f}")
            elif message["type"] == "http.response.body":
                response_bytes += len(message.get("body") or b"")
            await send(message)

        try:
            await self.app(scope, receive, send_with_metrics)
        finally:
            duration = time.perf_counter() - started
            slow = duration >= self._slow_seconds
            runtime_metrics.request_finished(
                status=status,
                duration_ms=duration * 1000,
                slow=slow,
            )
            if slow:
                route = scope.get("route")
                route_path = getattr(route, "path", None) or scope.get("path", "")
                logger.warning(
                    "Slow request method=%s path=%s status=%d duration_ms=%.1f bytes=%d request_id=%s",
                    scope.get("method", ""),
                    route_path,
                    status,
                    duration * 1000,
                    response_bytes,
                    request_id,
                )


async def monitor_event_loop_lag() -> None:
    """Continuously record event-loop scheduling delay and log large stalls."""

    interval = _env_float("OPENDEEPHOLE_EVENT_LOOP_PROBE_SECONDS", 1.0, minimum=0.1)
    warning = _env_float("OPENDEEPHOLE_EVENT_LOOP_WARN_SECONDS", 0.25, minimum=0.01)
    loop = asyncio.get_running_loop()
    expected = loop.time() + interval
    while True:
        await asyncio.sleep(max(0.0, expected - loop.time()))
        now = loop.time()
        lag = max(0.0, now - expected)
        runtime_metrics.set_event_loop_lag(lag * 1000)
        if lag >= warning:
            logger.warning("Event loop lag detected: %.1fms", lag * 1000)
        expected = max(expected + interval, now + interval)
