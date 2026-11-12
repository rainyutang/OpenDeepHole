"""Scan agent binding services."""

from backend.application import get_runtime, get_scan_store, run_store_call
from backend.models import ScanMeta


def _is_agent_disconnect_error(error_message: str | None) -> bool:
    """Check if an error message indicates an agent disconnect (not user action)."""
    from backend.scan_runtime import AGENT_DISCONNECT_ERROR
    return error_message == AGENT_DISCONNECT_ERROR


async def _resolve_scan_agent_id(meta: ScanMeta) -> str | None:
    from backend.agents.directory import resolve_agent_connection_async

    if meta.agent_key:
        resolved = await resolve_agent_connection_async(meta.agent_key)
        # A stable binding must not fall back to a different, same-named Agent
        # while offline (scan commands can carry private review notes).
        return resolved[0] if resolved is not None else None
    agent_id = meta.agent_id
    if agent_id and agent_id in get_runtime().agents.agent_ws:
        return agent_id
    if meta.agent_name:
        for aid, ainfo in get_runtime().agents.registered_agents.items():
            if (ainfo.name == meta.agent_name and aid in get_runtime().agents.agent_ws
                    and (not meta.user_id or ainfo.user_id == meta.user_id)):
                return aid
    store = get_scan_store()
    if getattr(store, "distributed", False):
        if agent_id:
            session = await run_store_call(
                store,
                "get_live_agent_session",
                agent_id=agent_id,
            )
            if session is not None:
                return str(session["agent_id"])
        if meta.agent_name:
            session = await run_store_call(
                store,
                "get_live_agent_session_by_name",
                meta.agent_name,
                user_id=meta.user_id or None,
            )
            if session is not None:
                return str(session["agent_id"])
    return None
