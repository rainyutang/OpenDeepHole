"""Scan events services."""

from typing import AsyncGenerator
import asyncio
import json
from backend.application import ApplicationError, get_runtime, get_scan_store, run_store_call


async def scan_events_sse(
    scan_id: str,
    last_event_id_header: str,
    token: str = ...,
) -> AsyncGenerator[str, None]:
    """SSE stream for real-time scan and FP review status updates.

    The browser EventSource API does not support custom headers, so the
    JWT is passed as a query parameter.
    """
    from backend.auth import decode_token
    from backend.sse import subscribe, unsubscribe, format_sse, SSE_KEEPALIVE
    import jwt as _jwt

    try:
        payload = decode_token(token)
    except _jwt.ExpiredSignatureError:
        raise ApplicationError(status_code=401, detail="Token expired")
    except Exception:
        raise ApplicationError(status_code=401, detail="Invalid token")

    user_id = payload.get("sub", "")
    role = payload.get("role", "")
    if role != "admin":
        store = get_scan_store()
        meta = await run_store_call(store, "get_scan_meta", scan_id)
        if meta is not None:
            if meta.user_id != user_id:
                raise ApplicationError(status_code=403, detail="Access denied")
        elif scan_id not in get_runtime().scans.scan_owners or get_runtime().scans.scan_owners[scan_id] != user_id:
            raise ApplicationError(status_code=403, detail="Access denied")

    async def event_generator() -> AsyncGenerator[str, None]:
        queue = subscribe(scan_id)
        try:
            last_event_id = 0
            try:
                last_event_id = max(0, int(last_event_id_header or 0))
            except (TypeError, ValueError):
                pass
            # Every reconnect invalidates derived client state. A bounded
            # replay can be incomplete after retention or a worker restart.
            yield format_sse("resync_required", {"reason": "connected"})
            if last_event_id and getattr(get_scan_store(), "distributed", False):
                replay = await run_store_call(
                    get_scan_store(),
                    "list_stream_events",
                    last_event_id,
                    1000,
                    scan_id=scan_id,
                )
                for item in replay:
                    try:
                        data = json.loads(str(item["data_json"]))
                    except Exception:
                        data = {}
                    from backend.sse import storage_notification
                    event_type, data = storage_notification(str(item["event_type"]), data)
                    yield format_sse(
                        event_type,
                        data,
                        int(item["id"]),
                    )
                    last_event_id = int(item["id"])
            yield format_sse("connected", {"scan_id": scan_id})
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=30)
                    if msg.get("id") is not None and int(msg["id"]) <= last_event_id:
                        continue
                    if msg.get("id") is not None:
                        last_event_id = int(msg["id"])
                    yield format_sse(msg["event"], msg["data"], msg.get("id"))
                except asyncio.TimeoutError:
                    yield SSE_KEEPALIVE
        except (asyncio.CancelledError, GeneratorExit):
            pass
        finally:
            unsubscribe(scan_id, queue)

    return event_generator()
