"""PostgreSQL-backed cross-worker command and SSE fan-out runtime."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import time
import uuid

from backend.logger import get_logger
from backend.store.async_ops import run_store_call

logger = get_logger(__name__)
WORKER_ID = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
_DATABASE_RETRY_SECONDS = 2.0


async def _listen_notifications(dsn: str, wake: asyncio.Event) -> None:
    """Use LISTEN/NOTIFY as a wake-up hint; durable rows are always re-read."""
    try:
        import asyncpg
    except ImportError:
        logger.warning("asyncpg unavailable; distributed fan-out uses periodic sweeps")
        await asyncio.Future()
        return

    unavailable = False
    while True:
        connection = None
        try:
            connection = await asyncpg.connect(dsn)

            def notified(*_args) -> None:
                wake.set()

            await connection.add_listener("opendeephole_agent_commands", notified)
            await connection.add_listener("opendeephole_scan_events", notified)
            if unavailable:
                logger.info("PostgreSQL notification listener reconnected")
            unavailable = False
            while True:
                await asyncio.sleep(60)
                await connection.execute("SELECT 1")
        except asyncio.CancelledError:
            raise
        except Exception:
            if not unavailable:
                logger.exception("PostgreSQL notification listener disconnected")
            unavailable = True
            await asyncio.sleep(_DATABASE_RETRY_SECONDS)
        finally:
            if connection is not None:
                try:
                    await connection.close()
                except Exception:
                    # A server restart can make close fail too.  The listener
                    # must still continue to its next connection attempt.
                    pass


async def _initialize_runtime(store) -> int:
    """Wait for durable coordination storage without terminating the task."""
    unavailable = False
    while True:
        try:
            await run_store_call(store, "register_worker", WORKER_ID)
            last_id = await run_store_call(store, "get_latest_stream_event_id")
        except asyncio.CancelledError:
            raise
        except Exception:
            if not unavailable:
                logger.exception(
                    "PostgreSQL distributed runtime unavailable during initialization"
                )
            unavailable = True
            await asyncio.sleep(_DATABASE_RETRY_SECONDS)
            continue
        if unavailable:
            logger.info("PostgreSQL distributed runtime initialization recovered")
        return last_id


async def _deliver_commands(store) -> None:
    from backend.api.agent import _agent_ws, _send_agent_json

    commands = await run_store_call(
        store,
        "claim_agent_commands",
        WORKER_ID,
        100,
    )
    for command in commands:
        command_id = int(command["id"])
        agent_id = str(command["agent_id"])
        error = ""
        try:
            if agent_id not in _agent_ws:
                raise RuntimeError("Agent WebSocket is no longer owned by this worker")
            payload = json.loads(str(command["payload_json"]))
            await _send_agent_json(agent_id, payload)
        except Exception as exc:
            error = str(exc)
            logger.warning(
                "Failed distributed command id=%d agent=%s: %s",
                command_id,
                agent_id,
                exc,
            )
        await run_store_call(
            store,
            "finish_agent_command",
            command_id,
            error=error,
        )


async def _fan_out_stream_events(store, last_id: int) -> int:
    from backend.sse import publish_local

    while True:
        rows = await run_store_call(store, "list_stream_events", last_id, 1000)
        if not rows:
            return last_id
        for row in rows:
            event_id = int(row["id"])
            last_id = max(last_id, event_id)
            if str(row["source_worker"]) == WORKER_ID:
                continue
            try:
                data = json.loads(str(row["data_json"]))
            except Exception:
                data = {}
            publish_local(
                str(row["scan_id"]),
                str(row["event_type"]),
                data,
                event_id=event_id,
            )
        if len(rows) < 1000:
            return last_id


async def run_distributed_runtime(store, *, leader: bool = False) -> None:
    """Run reliable command delivery and SSE catch-up for one worker."""
    last_id = await _initialize_runtime(store)
    wake = asyncio.Event()
    listener = asyncio.create_task(_listen_notifications(store.dsn, wake))
    from backend.sse import run_distributed_sse_writer

    stream_writer = asyncio.create_task(run_distributed_sse_writer())
    started_at = time.monotonic()
    last_maintenance = 0.0
    unavailable = False
    try:
        while True:
            try:
                await _deliver_commands(store)
                last_id = await _fan_out_stream_events(store, last_id)
                now = time.monotonic()
                if now - last_maintenance >= 30.0:
                    await run_store_call(store, "register_worker", WORKER_ID)
                    recovered = await run_store_call(
                        store,
                        "recover_stale_agent_commands",
                        30,
                    )
                    if recovered:
                        logger.warning(
                            "Recovered %d interrupted Agent command(s)",
                            recovered,
                        )
                    if leader and now - started_at >= 120.0:
                        stale_scans = await run_store_call(
                            store,
                            "cancel_stale_agent_work",
                            stale_seconds=120,
                            error_message="Agent 断开连接",
                        )
                        if stale_scans:
                            from backend.sse import publish

                            for scan_id in stale_scans:
                                loaded = await run_store_call(
                                    store,
                                    "load_scan_overview",
                                    scan_id,
                                )
                                persisted = loaded[0] if loaded is not None else None
                                publish(scan_id, "scan_status", {
                                    "status": "cancelled",
                                    "error_message": "Agent 断开连接",
                                    "opencode_pool": (
                                        persisted.opencode_pool.model_dump(mode="json")
                                        if persisted is not None
                                        and persisted.opencode_pool is not None
                                        else None
                                    ),
                                })
                            logger.warning(
                                "Cancelled %d scan(s) with stale Agent sessions",
                                len(stale_scans),
                            )
                    last_maintenance = now
                if unavailable:
                    logger.info("PostgreSQL distributed runtime recovered")
                unavailable = False
                try:
                    await asyncio.wait_for(wake.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    pass
                wake.clear()
            except asyncio.CancelledError:
                raise
            except Exception:
                if not unavailable:
                    logger.exception(
                        "PostgreSQL distributed runtime disconnected; retrying"
                    )
                unavailable = True
                # Force worker registration and stale-command recovery on the
                # first successful iteration after the database returns.
                last_maintenance = float("-inf")
                await asyncio.sleep(_DATABASE_RETRY_SECONDS)
    finally:
        listener.cancel()
        stream_writer.cancel()
        await asyncio.gather(listener, stream_writer, return_exceptions=True)
