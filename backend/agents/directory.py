"""Directory services for Agent-backed scans."""

from __future__ import annotations
from backend.agents import constants
from backend.models import AgentInfo
import asyncio
import time
from datetime import datetime, timezone
from backend.application import get_runtime, get_scan_store, run_store_call
from backend.logger import get_logger
logger = get_logger(__name__)


def _live_agent_for_key(agent_key: str) -> tuple[str, AgentInfo] | None:
    candidates = [
        (agent_id, agent)
        for agent_id, agent in get_runtime().agents.registered_agents.items()
        if agent.agent_key == agent_key and agent_id in get_runtime().agents.agent_ws
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda item: item[1].last_seen)


def resolve_agent_connection(agent_key: str) -> tuple[str, AgentInfo] | None:
    """Resolve a stable Agent key to its current WebSocket connection."""
    return _live_agent_for_key(str(agent_key or "").strip())


def _agent_info_from_shared_session(session: dict) -> AgentInfo:
    agent_id = str(session["agent_id"])
    return AgentInfo(
        agent_id=agent_id,
        agent_key=str(session["agent_key"]),
        name=str(session["name"]),
        machine_name=str(session["machine_name"] or ""),
        ip="shared-worker",
        last_seen=str(session["last_seen"]),
        user_id=str(session["user_id"] or ""),
        runtime_hash=str(session.get("runtime_hash") or ""),
        agent_session_id=str(session.get("agent_session_id") or agent_id),
        accepting_tasks=bool(session.get("accepting_tasks", 1)),
        protocol_version=int(session["protocol_version"] or 1),
        scan_code_graph_updates=bool(session.get("scan_code_graph_updates", 0)),
        scan_paths_probe=bool(session.get("scan_paths_probe", 0)),
        llm_api_test=session.get("llm_api_test"),
    )


async def resolve_agent_connection_async(agent_key: str) -> tuple[str, AgentInfo] | None:
    """Resolve local or PostgreSQL-owned Agent sessions without blocking."""
    normalized = str(agent_key or "").strip()
    local = _live_agent_for_key(normalized)
    if local is not None:
        return local
    store = get_scan_store()
    if not getattr(store, "distributed", False):
        return None
    session = await run_store_call(
        store,
        "get_live_agent_session",
        agent_key=normalized,
        stale_seconds=constants._WEBSOCKET_AGENT_STALE_SECONDS,
    )
    if session is None:
        return None
    agent = _agent_info_from_shared_session(session)
    return agent.agent_id, agent


async def resolve_agent_id_connection_async(agent_id: str) -> tuple[str, AgentInfo] | None:
    normalized = str(agent_id or "").strip()
    local = get_runtime().agents.registered_agents.get(normalized)
    store = get_scan_store()
    if local is not None and (
        normalized in get_runtime().agents.agent_ws
        or local.port > 0
        or not getattr(store, "distributed", False)
    ):
        return normalized, local
    if not normalized or not getattr(store, "distributed", False):
        return None
    session = await run_store_call(
        store,
        "get_live_agent_session",
        agent_id=normalized,
        stale_seconds=constants._WEBSOCKET_AGENT_STALE_SECONDS,
    )
    if session is None:
        return None
    agent = _agent_info_from_shared_session(session)
    return agent.agent_id, agent


async def _persist_agent_touch(agent_id: str, delay: float) -> None:
    try:
        if delay > 0:
            await asyncio.sleep(delay)
        agent = get_runtime().agents.registered_agents.get(agent_id)
        if agent is None or not agent.agent_key:
            return
        try:
            await run_store_call(
                get_scan_store(),
                "touch_agent_record",
                agent.agent_key,
                agent_id,
                agent.last_seen,
            )
            store = get_scan_store()
            if getattr(store, "distributed", False):
                await run_store_call(
                    store,
                    "touch_agent_session",
                    agent_id,
                    agent.last_seen,
                )
            get_runtime().agents.agent_touch_persisted_at[agent_id] = time.monotonic()
        except (NotImplementedError, AttributeError):
            pass
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("Failed to persist Agent heartbeat: %s", agent_id)
    finally:
        get_runtime().agents.agent_touch_tasks.pop(agent_id, None)


def _schedule_agent_touch_persistence(agent_id: str) -> None:
    task = get_runtime().agents.agent_touch_tasks.get(agent_id)
    if task is not None and not task.done():
        return
    elapsed = time.monotonic() - get_runtime().agents.agent_touch_persisted_at.get(agent_id, 0.0)
    delay = max(0.0, constants._AGENT_TOUCH_PERSIST_INTERVAL_SECONDS - elapsed)
    get_runtime().agents.agent_touch_tasks[agent_id] = asyncio.create_task(
        _persist_agent_touch(agent_id, delay)
    )


def _touch_agent(agent_id: str, *, persist: bool=True) -> None:
    agent = get_runtime().agents.registered_agents.get(agent_id)
    if agent is not None:
        agent.last_seen = datetime.now(timezone.utc).isoformat()
        if persist and agent.agent_key:
            _schedule_agent_touch_persistence(agent_id)


def _is_agent_online(agent: AgentInfo) -> bool:
    try:
        last = datetime.fromisoformat(agent.last_seen)
        fresh = (datetime.now(timezone.utc) - last).total_seconds() < constants._WEBSOCKET_AGENT_STALE_SECONDS
    except Exception:
        fresh = False
    if agent.agent_id in get_runtime().agents.agent_ws:
        return fresh
    return fresh and agent.port > 0


def is_agent_name_online(agent_name: str) -> bool:
    """Check if any registered agent with the given name has an active WebSocket."""
    for ainfo in get_runtime().agents.registered_agents.values():
        if ainfo.name == agent_name and _is_agent_online(ainfo):
            return True
    return False
