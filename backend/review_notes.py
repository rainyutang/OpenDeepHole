"""Deliver the current scan review notes over the existing Agent connection."""

from __future__ import annotations

import asyncio
import uuid

from backend.logger import get_logger
from backend.store import get_scan_store
from backend.store.async_ops import run_store_call

logger = get_logger(__name__)


async def scan_review_notes_payload(scan_id: str, *, store=None) -> dict | None:
    state = await run_store_call(store or get_scan_store(), "get_scan_review_notes", scan_id)
    # Old scans have no configuration and need no new Agent-side files.
    return state if state["revision"] or state["enabled"] else None


async def review_notes_for_agent(agent_key: str, reported_revisions: object, *, store=None) -> list[dict]:
    """Reconcile on reconnect, including completed and FP-only scans."""
    if not agent_key:
        return []
    known = reported_revisions if isinstance(reported_revisions, dict) else {}
    states = await run_store_call(store or get_scan_store(), "list_agent_review_notes", agent_key)
    return [
        state for state in states
        if type(known.get(state["scan_id"])) is not int
        or known[state["scan_id"]] != state["revision"]
    ]


async def sync_scan_review_notes(scan_id: str) -> str:
    """Return synced only after the Agent confirms the files were written."""
    from backend.api import agent as agent_api
    from backend.api.scan import _resolve_scan_agent_id

    store = get_scan_store()
    request_id = uuid.uuid4().hex
    try:
        meta = await run_store_call(store, "get_scan_meta", scan_id)
        if meta is None:
            return "pending"
        agent_id = await _resolve_scan_agent_id(meta)
        if agent_id is None:
            return "pending"
        state = await run_store_call(store, "get_scan_review_notes", scan_id)
        waiter = asyncio.get_running_loop().create_future()
        agent_api._review_notes_waiters[request_id] = waiter
        if not await agent_api.send_agent_command(agent_id, {
            **state,
            "type": "review_notes_update",
            "request_id": request_id,
        }):
            return "pending"
        response = await agent_api._wait_agent_response(request_id, waiter, timeout=10.0)
        if (
            response.get("ok") is True
            and response.get("scan_id") == scan_id
            and type(response.get("revision")) is int
            and response["revision"] >= state["revision"]
        ):
            return "synced"
        logger.warning("Review notes sync failed for scan %s: %s", scan_id, response.get("error", "invalid acknowledgement"))
        return "error"
    except asyncio.TimeoutError:
        logger.warning("Review notes sync acknowledgement timed out for scan %s", scan_id)
        return "pending"
    except Exception:
        logger.exception("Review notes sync failed for scan %s", scan_id)
        return "error"
    finally:
        waiter = agent_api._review_notes_waiters.pop(request_id, None)
        if waiter is not None and not waiter.done():
            waiter.cancel()
