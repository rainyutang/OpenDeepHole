"""Lightweight per-scan Server-Sent Events pub/sub using asyncio.Queue."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from backend.logger import get_logger
from backend.runtime_metrics import runtime_metrics
from backend.store.async_ops import run_store_call


# scan_id -> set of subscriber queues
_scan_subscribers: dict[str, set[asyncio.Queue[dict]]] = {}
_distributed_store = None
_source_worker = ""
_distributed_event_queue: asyncio.Queue[tuple[str, str, Any]] | None = None
_last_drop_log_at = 0.0
logger = get_logger(__name__)


def configure_distributed_sse(store, worker_id: str) -> None:
    global _distributed_store, _source_worker, _distributed_event_queue
    _distributed_store = store if getattr(store, "distributed", False) else None
    _source_worker = worker_id
    _distributed_event_queue = (
        asyncio.Queue(maxsize=10000)
        if _distributed_store is not None
        else None
    )


def subscribe(scan_id: str) -> asyncio.Queue[dict]:
    """Create a new subscriber queue for the given scan.

    Returns an asyncio.Queue that will receive published events.
    The queue has a bounded size; slow consumers will have events dropped.
    """
    queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=200)
    _scan_subscribers.setdefault(scan_id, set()).add(queue)
    return queue


def unsubscribe(scan_id: str, queue: asyncio.Queue[dict]) -> None:
    """Remove a subscriber queue.  Cleans up empty scan entries."""
    subs = _scan_subscribers.get(scan_id)
    if subs is not None:
        subs.discard(queue)
        if not subs:
            del _scan_subscribers[scan_id]


def publish_local(
    scan_id: str,
    event_type: str,
    data: Any,
    *,
    event_id: int | None = None,
) -> None:
    """Broadcast an event to all subscribers of a scan.

    Non-blocking.  If a subscriber's queue is full the event is silently
    dropped (the 30s fallback poll on the frontend will compensate).
    """
    subs = _scan_subscribers.get(scan_id)
    if not subs:
        return
    msg = {"event": event_type, "data": data, "id": event_id}
    for queue in list(subs):
        try:
            queue.put_nowait(msg)
        except asyncio.QueueFull:
            pass


def publish(scan_id: str, event_type: str, data: Any) -> None:
    """Publish locally and durably fan out when PostgreSQL is configured."""
    global _last_drop_log_at
    publish_local(scan_id, event_type, data)
    queue = _distributed_event_queue
    if _distributed_store is None or queue is None:
        return
    try:
        queue.put_nowait((scan_id, event_type, data))
        runtime_metrics.stream_event_enqueued(queue.qsize())
    except asyncio.QueueFull:
        runtime_metrics.stream_event_dropped(queue.qsize())
        now = time.monotonic()
        if now - _last_drop_log_at >= 5.0:
            logger.error(
                "Distributed SSE persistence queue full; events are being dropped"
            )
            _last_drop_log_at = now


async def run_distributed_sse_writer() -> None:
    """Persist fan-out events in bounded batches instead of one task per event."""
    queue = _distributed_event_queue
    if _distributed_store is None or queue is None:
        return
    while True:
        first = await queue.get()
        batch = [first]
        deadline = asyncio.get_running_loop().time() + 0.05
        while len(batch) < 200:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                break
            try:
                batch.append(await asyncio.wait_for(queue.get(), timeout=remaining))
            except asyncio.TimeoutError:
                break
        for attempt in range(3):
            try:
                persisted = await run_store_call(
                    _distributed_store,
                    "publish_stream_events_batch",
                    batch,
                    source_worker=_source_worker,
                )
                runtime_metrics.stream_events_persisted(persisted, queue.qsize())
                break
            except asyncio.CancelledError:
                raise
            except Exception:
                if attempt == 2:
                    runtime_metrics.stream_events_dropped(
                        len(batch),
                        queue.qsize(),
                    )
                    logger.exception(
                        "Failed to persist %d distributed SSE event(s)",
                        len(batch),
                    )
                else:
                    await asyncio.sleep(0.1 * (attempt + 1))
        for _item in batch:
            queue.task_done()


def format_sse(event_type: str, data: Any, event_id: int | None = None) -> str:
    """Format a single SSE message according to the spec."""
    payload = json.dumps(data, ensure_ascii=False, default=str)
    id_line = f"id: {event_id}\n" if event_id is not None else ""
    return f"{id_line}event: {event_type}\ndata: {payload}\n\n"


SSE_KEEPALIVE = ": keepalive\n\n"
