"""Queries services for Agent-backed scans."""

from __future__ import annotations
from backend.agents import constants
from backend.models import (
    AgentInfo,
    AgentOpenCodePoolStatus,
    AgentRemoteConfig,
    OpenCodePoolStatus,
    OpenCodeTaskReport,
    User,
)
from backend.application import (
    ApplicationError as HTTPException,
    get_runtime,
    get_scan_store,
    publish,
    run_store_call,
)
from typing import Optional
import asyncio
from backend.logger import get_logger
logger = get_logger(__name__)


async def update_agent_opencode_pool(agent_id: str, status: OpenCodePoolStatus) -> dict:
    """Agent pushes its Agent-wide OpenCode model-pool status snapshot."""
    from backend.agents.directory import resolve_agent_id_connection_async
    resolved = await resolve_agent_id_connection_async(agent_id)
    agent = resolved[1] if resolved is not None else None
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if status.agent_session_id and status.agent_session_id != agent.agent_session_id:
        raise HTTPException(status_code=409, detail="stale Agent session")
    status.agent_name = agent.name
    status.agent_session_id = status.agent_session_id or agent.agent_session_id
    get_runtime().agents.agent_opencode_pool_latest[agent_id] = status
    store = get_scan_store()
    if hasattr(store, "upsert_agent_opencode_pool_status"):
        await run_store_call(
            store,
            "upsert_agent_opencode_pool_status",
            agent_name=agent.agent_key or agent.name,
            user_id=agent.user_id,
            agent_session_id=status.agent_session_id,
            status=status,
        )
    if hasattr(store, "upsert_agent_opencode_token_usage") and agent.agent_key:
        await run_store_call(
            store,
            "upsert_agent_opencode_token_usage",
            agent_key=agent.agent_key,
            user_id=agent.user_id,
            agent_session_id=status.agent_session_id,
            status=status,
        )
    return {"ok": True}


async def report_agent_opencode_task(agent_id: str, body: OpenCodeTaskReport) -> dict:
    """Persist one terminal logical task without resending prior Session history."""
    from backend.agents.directory import resolve_agent_id_connection_async
    def not_found(code: str) -> HTTPException:
        detail = {
            "code": code,
            "endpoint": "opencode-task-report",
            "agent_id": agent_id,
            "scan_id": body.scope_id,
            "scope_id": body.scope_id,
            "task_id": body.task_id,
            "revision": body.revision,
            "agent_session_id": body.agent_session_id,
        }
        logger.warning(
            "OPENCODE_TASK_REPORT_REJECTED code=%s agent_id=%s scope_id=%s "
            "task_id=%s revision=%s agent_session_id=%s",
            code, agent_id, body.scope_id, body.task_id, body.revision, body.agent_session_id,
        )
        return HTTPException(status_code=404, detail=detail)

    resolved = await resolve_agent_id_connection_async(agent_id)
    agent = resolved[1] if resolved is not None else None
    if agent is None:
        raise not_found("agent_not_found")
    store = get_scan_store()
    loaded = await run_store_call(store, "get_scan_identity", body.scope_id)
    if loaded is None:
        raise not_found("scan_not_found")
    try:
        inserted = await run_store_call(
            store,
            "upsert_opencode_task_report",
            agent_key=agent.agent_key or agent.name,
            scan_id=body.scope_id,
            agent_session_id=body.agent_session_id or agent.agent_session_id,
            task_id=body.task_id,
            revision=body.revision,
            task=body.task,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    status = await run_store_call(store, "get_opencode_pool_status", body.scope_id)
    scan = get_runtime().scans.running_scans.get(body.scope_id)
    if scan is not None and status is not None:
        scan.opencode_pool = status
    if inserted:
        from backend.application import publish

        publish(body.scope_id, "opencode_task_report", {
            "task_id": body.task_id,
            "revision": body.revision,
            "completed_task_count": status.completed_task_count if status else 0,
            "total_tasks": status.total_tasks if status else 0,
        })
    return {"ok": True, "duplicate": not inserted}


async def get_agent_opencode_pool(
    agent_id: str,
    current_user: User=None,
) -> AgentOpenCodePoolStatus:
    """Return persisted per-model usage for one Agent plus current active tasks."""
    from backend.agents.directory import _is_agent_online
    from backend.agents.directory import resolve_agent_id_connection_async
    resolved = await resolve_agent_id_connection_async(agent_id)
    agent = resolved[1] if resolved is not None else None
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if current_user.role != "admin" and agent.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    online = (
        _is_agent_online(agent)
        if agent_id in get_runtime().agents.agent_ws
        else resolved is not None
    )
    store = get_scan_store()
    if hasattr(store, "get_agent_opencode_pool_status"):
        result = await run_store_call(
            store,
            "get_agent_opencode_pool_status",
            agent_name=agent.agent_key or agent.name,
            user_id=agent.user_id,
            agent_id=agent_id,
            agent_session_id=agent.agent_session_id,
            online=online,
        )
    else:
        result = AgentOpenCodePoolStatus(
            agent_id=agent_id,
            agent_name=agent.name,
            agent_session_id=agent.agent_session_id,
            online=online,
        )
    result.agent_name = agent.name
    if hasattr(store, "get_agent_opencode_token_usage") and agent.agent_key:
        result.token_usage = await run_store_call(
            store,
            "get_agent_opencode_token_usage",
            agent_key=agent.agent_key,
            user_id=agent.user_id,
        )
    latest = get_runtime().agents.agent_opencode_pool_latest.get(agent_id)
    if online and latest is not None and latest.agent_session_id == agent.agent_session_id:
        live_by_model = {model.id: model for model in latest.models}
        for model in result.models:
            live = live_by_model.get(model.id)
            if live is not None:
                # The current session snapshot owns configuration and transient
                # state.  Historical rows only contribute cumulative counters.
                model.model = live.model
                model.use_default_model = live.use_default_model
                model.capability = live.capability
                model.weight = live.weight
                model.effective_weight = live.effective_weight
                model.health_penalty_level = live.health_penalty_level
                model.last_health_failure_at = live.last_health_failure_at
                model.last_health_failure_kind = live.last_health_failure_kind
                model.max_concurrency = live.max_concurrency
                model.running = live.running
                model.queued = live.queued
                model.available = live.available
                model.enabled = live.enabled
                model.time_windows = live.time_windows
                model.active_tasks = live.active_tasks
                model.last_status = live.last_status
                model.last_started_at = live.last_started_at
                model.last_finished_at = live.last_finished_at
            else:
                # A live report is a complete snapshot.  Models absent from it
                # remain visible for usage history but are no longer usable.
                model.enabled = False
                model.available = False
                model.running = 0
                model.queued = 0
                model.active_tasks = []
                model.effective_weight = model.weight
                model.health_penalty_level = 0
                model.last_health_failure_at = ""
                model.last_health_failure_kind = ""
        known_ids = {model.id for model in result.models}
        for model in latest.models:
            if model.id not in known_ids:
                result.models.append(model.model_copy(deep=True))
        result.models.sort(key=lambda model: model.id)
        result.global_running = latest.global_running
        result.global_queued = latest.global_queued
        result.queued_tasks = latest.queued_tasks
        result.planned_tasks = latest.planned_tasks
        if result.token_usage is None:
            result.token_usage = latest.token_usage
        result.updated_at = latest.updated_at or result.updated_at
    if not online:
        for model in result.models:
            model.available = False
    return result


async def list_agents_prefixed(current_user: User=None) -> list:
    """Return all registered agents with online status (alias for /api/agents)."""
    return await list_agents(current_user)


async def list_agents(current_user: User=None) -> list:
    """Return agents with online status. Admin sees all; users see only their own.

    Online agents come first; each group retains registration order.
    WebSocket agents: online = WebSocket connection is active.
    Legacy HTTP agents: online = last heartbeat < 90 seconds ago.
    """
    from backend.agents.directory import _agent_info_from_shared_session
    from backend.agents.directory import _is_agent_online
    from backend.agents.directory import _live_agent_for_key
    from backend.agents.runtime_updates import _runtime_update_status
    from backend.agents.configuration import _stored_agent_config
    from backend.agents.configuration import agent_config_has_explicit_model
    store = get_scan_store()
    records = await run_store_call(
        store,
        "list_agent_records",
        None if current_user.role == "admin" else current_user.user_id,
    )
    shared_by_key: dict[str, tuple[str, AgentInfo]] = {}
    if getattr(store, "distributed", False):
        sessions = await run_store_call(
            store,
            "list_live_agent_sessions",
            constants._WEBSOCKET_AGENT_STALE_SECONDS,
        )
        for session in sessions:
            agent = _agent_info_from_shared_session(session)
            shared_by_key.setdefault(agent.agent_key, (agent.agent_id, agent))
    result = []
    known_keys: set[str] = set()
    owner_usernames: dict[str, str] = {"": ""}
    for record in records:
        agent_key = str(record.get("agent_key") or "")
        user_id = str(record.get("user_id") or "")
        owner_username = str(record.get("owner_username") or "")
        owner_usernames[user_id] = owner_username
        local_live = _live_agent_for_key(agent_key)
        live = local_live or shared_by_key.get(agent_key)
        agent = live[1] if live else None
        known_keys.add(agent_key)
        result.append({
            "agent_id": live[0] if live else str(record.get("last_agent_id") or ""),
            "agent_key": agent_key,
            "name": agent.name if agent else str(record.get("display_name") or ""),
            "machine_name": agent.machine_name if agent else str(record.get("machine_name") or ""),
            "ip": agent.ip if agent else str(record.get("ip") or ""),
            "port": agent.port if agent else 0,
            "last_seen": agent.last_seen if agent else str(record.get("last_seen") or ""),
            "user_id": user_id,
            "owner_username": owner_username,
            "runtime_hash": agent.runtime_hash if agent else "",
            "agent_session_id": agent.agent_session_id if agent else "",
            "online": bool(
                agent
                and (
                    _is_agent_online(agent)
                    if local_live is not None
                    else live is not None
                )
            ),
            "runtime_update_status": _runtime_update_status(record),
            "runtime_update_target_hash": str(
                record.get("runtime_update_target_hash") or ""
            ),
            "runtime_update_error": str(record.get("runtime_update_error") or ""),
            "accepting_tasks": (
                _runtime_update_status(record) != constants._RUNTIME_UPDATE_UPDATING
            ),
            "has_explicit_model": agent_config_has_explicit_model(
                _stored_agent_config(record)
            ),
        })
    # Keep legacy HTTP agents visible until they migrate to the stable catalog.
    for agent in list(get_runtime().agents.registered_agents.values()):
        if agent.agent_key in known_keys:
            continue
        if current_user.role != "admin" and agent.user_id != current_user.user_id:
            continue
        compatibility_config = (
            get_runtime().agents.agent_configs.get(agent.agent_key)
            or get_runtime().agents.agent_configs.get(agent.name)
            or AgentRemoteConfig()
        )
        if agent.user_id not in owner_usernames:
            owner = await run_store_call(store, "get_user_by_id", agent.user_id)
            owner_usernames[agent.user_id] = owner.username if owner else ""
        result.append({
            **agent.model_dump(),
            "owner_username": owner_usernames[agent.user_id],
            "online": _is_agent_online(agent),
            "has_explicit_model": agent_config_has_explicit_model(
                compatibility_config
            ),
        })
    # Python's stable sort preserves catalog and legacy registration order.
    return sorted(result, key=lambda item: not item["online"])


async def agent_get_feedback(vuln_types: Optional[str]=None) -> list:
    """Return feedback entries for the agent to enrich SKILLs."""
    store = get_scan_store()
    if vuln_types:
        names = [v.strip() for v in vuln_types.split(",") if v.strip()]
        pages = await asyncio.gather(*(
            run_store_call(store, "list_feedback", vuln_type=name)
            for name in names
        ))
        entries = [entry for page in pages for entry in page]
    else:
        entries = await run_store_call(store, "list_feedback")
    return [e.model_dump() for e in entries]
