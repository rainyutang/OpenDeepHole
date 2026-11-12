"""Connections services for Agent-backed scans."""

from __future__ import annotations
from backend.agents import constants
from dataclasses import dataclass
from backend.models import AgentInfo, AgentRemoteConfig, AgentValidatorCatalog
from backend.agents.interfaces import AgentConnection as WebSocket
from starlette.websockets import WebSocketDisconnect
from backend.agents.schemas import _AgentRegisterBody
import asyncio
import socket
import uuid
from datetime import datetime, timezone
from backend.application import get_runtime, get_scan_store, run_store_call
from backend.logger import get_logger
logger = get_logger(__name__)


@dataclass(frozen=True)
class ReconnectState:
    pending_scan_stops: list[dict]
    pending_validation_stops: list[dict]
    recovery_scan_ids: list[str]
    promoted_by_scan: dict[str, list[int]]
    accepted_scan_executions: list[dict]
    review_notes: list[dict]
    code_graph_updates: list[dict]


async def agent_websocket(websocket: WebSocket) -> None:
    """Agent connects here and receives task/stop/resume commands."""
    from backend.agents.runtime_updates import _runtime_update_status
    from backend.agents.transport import _send_agent_json
    from backend.agents.recovery import _websocket_server_url
    from backend.agents.gateway import send_agent_command
    await websocket.accept()
    agent_id = None
    recovery_task: asyncio.Task | None = None
    try:
        msg = await websocket.receive_json()
        if msg.get("type") != "hello":
            await websocket.close(code=4000)
            return

        name = str(msg.get("name") or socket.gethostname()).strip()
        machine_name = str(msg.get("machine_name") or name or socket.gethostname()).strip()
        owner_token = msg.get("owner_token", "")
        offered_protocols = msg.get("protocol_versions")
        if not isinstance(offered_protocols, list):
            offered_protocols = [1]
        protocol_version = 2 if 2 in offered_protocols else 1
        reported_capabilities = (
            msg.get("capabilities")
            if isinstance(msg.get("capabilities"), dict)
            else {}
        )
        final_vulnerability_callbacks = (
            reported_capabilities.get(
                constants._FINAL_VULNERABILITY_CALLBACKS_CAPABILITY,
            )
            is True
        )
        incremental_opencode_task_reports = (
            reported_capabilities.get(
                constants._INCREMENTAL_OPENCODE_TASK_REPORTS_CAPABILITY,
            )
            is True
        )
        agent_id = uuid.uuid4().hex
        ip = websocket.client.host if websocket.client else "unknown"
        now = datetime.now(timezone.utc).isoformat()

        # Resolve owner_token to user_id
        user_id = ""
        if owner_token:
            store = get_scan_store()
            owner = await run_store_call(
                store,
                "get_user_by_agent_token",
                owner_token,
            )
            if owner:
                user_id = owner.user_id

        catalog, initial_config = _parse_hello_configuration(msg, name)

        record, cfg = await _persist_registration(
            msg, name=name, machine_name=machine_name, user_id=user_id, ip=ip,
            agent_id=agent_id, now=now, catalog=catalog, initial_config=initial_config,
        )
        stable_key = str(record["agent_key"])
        reported_runtime_hash = str(msg.get("runtime_hash") or "")
        store = get_scan_store()

        agent_info = AgentInfo(
            agent_id=agent_id,
            agent_key=stable_key,
            name=name,
            machine_name=machine_name,
            ip=ip,
            port=0,
            last_seen=now,
            user_id=user_id,
            runtime_hash=reported_runtime_hash,
            agent_session_id=str(msg.get("agent_session_id") or agent_id),
            runtime_update_status=_runtime_update_status(record),
            runtime_update_target_hash=str(
                record.get("runtime_update_target_hash") or ""
            ),
            runtime_update_error=str(record.get("runtime_update_error") or ""),
            accepting_tasks=_runtime_update_status(record) != constants._RUNTIME_UPDATE_UPDATING,
            protocol_version=protocol_version,
            scan_code_graph_updates=reported_capabilities.get("scan_code_graph_updates") is True,
            scan_paths_probe=reported_capabilities.get("scan_paths_probe") is True,
            llm_api_config=reported_capabilities.get("llm_api_config") is True,
            llm_api_test=reported_capabilities.get("llm_api_test") is True,
        )
        get_runtime().agents.registered_agents[agent_id] = agent_info
        get_runtime().agents.agent_ws[agent_id] = websocket
        get_runtime().agents.agent_ws_locks[agent_id] = asyncio.Lock()
        if getattr(store, "distributed", False):
            from backend.distributed import WORKER_ID

            await run_store_call(
                store,
                "register_agent_session",
                agent_info,
                WORKER_ID,
            )

        reconnect = await _prepare_reconnect(
            agent_id, agent_info, msg, final_callbacks=final_vulnerability_callbacks,
        )
        await _send_agent_json(agent_id, {
            "type": "welcome",
            "agent_id": agent_id,
            "agent_key": stable_key,
            "config": cfg.model_dump(),
            "protocol_version": protocol_version,
            "scan_executions": reconnect.accepted_scan_executions,
            "review_notes": reconnect.review_notes,
            "code_graph_updates": reconnect.code_graph_updates,
            "capabilities": {
                "candidate_batches": protocol_version >= 2,
                "event_batches": protocol_version >= 2,
                "lightweight_finish": protocol_version >= 2,
                "resume_manifest": protocol_version >= 2,
                "incremental_validation_output": reported_capabilities.get("incremental_validation_output") is True,
                "incremental_opencode_task_reports": (
                    incremental_opencode_task_reports
                ),
            },
        })
        for command in reconnect.pending_scan_stops:
            await send_agent_command(agent_id, command)
        for command in reconnect.pending_validation_stops:
            await send_agent_command(agent_id, command)
        # Recovery can issue stop RPCs; their replies and heartbeats must be
        # received while recovery awaits them.
        recovery_task = asyncio.create_task(_recover_after_welcome(
            agent_id, agent_info, msg, reconnect, final_vulnerability_callbacks,
            _websocket_server_url(websocket),
        ))

        logger.info("Agent connected via WebSocket: %s (%s) user=%s", agent_id, name, user_id or "(none)")

        await _receive_messages(websocket, agent_id, agent_info)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning("Agent WebSocket error for %s: %s", agent_id, e)
    finally:
        await _close_connection(agent_id, recovery_task)


async def agent_register(body: _AgentRegisterBody, client_host: str) -> dict:
    """Agent calls this on startup to get an agent_id. (Legacy HTTP mode)"""
    agent_id = uuid.uuid4().hex
    ip = client_host
    now = datetime.now(timezone.utc).isoformat()
    agent_name = body.name or socket.gethostname()
    get_runtime().agents.registered_agents[agent_id] = AgentInfo(
        agent_id=agent_id,
        name=agent_name,
        ip=ip,
        port=body.port,
        last_seen=now,
    )
    logger.info("Agent registered (HTTP): %s (%s:%d)", agent_id, ip, body.port)
    cfg = get_runtime().agents.agent_configs.get(agent_name)
    return {
        "agent_id": agent_id,
        "config": cfg.model_dump(exclude_defaults=True) if cfg else None,
    }


async def agent_heartbeat(agent_id: str) -> dict:
    """Agent sends heartbeat every 30s to stay in the online list. (Legacy HTTP mode)"""
    if agent_id in get_runtime().agents.registered_agents:
        get_runtime().agents.registered_agents[agent_id].last_seen = datetime.now(timezone.utc).isoformat()
    return {"ok": True}


async def agent_unregister(agent_id: str) -> dict:
    """Agent calls this on graceful shutdown."""
    from backend.agents.recovery import _mark_agent_scans_cancelled_async
    old_task = get_runtime().agents.agent_disconnect_tasks.pop(agent_id, None)
    if old_task is not None:
        old_task.cancel()
    await _mark_agent_scans_cancelled_async(agent_id)
    get_runtime().agents.registered_agents.pop(agent_id, None)
    get_runtime().agents.agent_ws.pop(agent_id, None)
    get_runtime().agents.agent_ws_locks.pop(agent_id, None)
    get_runtime().agents.agent_opencode_pool_latest.pop(agent_id, None)
    logger.info("Agent unregistered: %s", agent_id)
    return {"ok": True}


def _parse_hello_configuration(
    msg: dict,
    name: str,
) -> tuple[AgentValidatorCatalog, AgentRemoteConfig]:
    from backend.agents.configuration import _validate_managed_config
    reported_catalog = msg.get("validator_catalog")
    try:
        catalog = (
            AgentValidatorCatalog(**reported_catalog)
            if isinstance(reported_catalog, dict)
            else AgentValidatorCatalog()
        )
    except Exception as exc:
        catalog = AgentValidatorCatalog(errors=[str(exc)])
    reported_config = msg.get("config")
    try:
        initial_config = (
            AgentRemoteConfig(**reported_config)
            if isinstance(reported_config, dict)
            else AgentRemoteConfig()
        )
        _validate_managed_config(initial_config, catalog)
    except Exception as exc:
        logger.warning(
            "Ignoring invalid config reported by agent %s: %s",
            name,
            type(exc).__name__,
        )
        initial_config = AgentRemoteConfig()
    return catalog, initial_config


async def _persist_registration(
    msg: dict,
    *,
    name: str,
    machine_name: str,
    user_id: str,
    ip: str,
    agent_id: str,
    now: str,
    catalog: AgentValidatorCatalog,
    initial_config: AgentRemoteConfig,
) -> tuple[dict, AgentRemoteConfig]:
    from backend.agents.runtime_updates import _runtime_update_status
    from backend.agents.configuration import _stored_agent_config
    store = get_scan_store()
    existing = await run_store_call(
        store,
        "find_agent_record",
        user_id,
        ip,
        machine_name,
    )
    if existing is None:
        # A newly registered client always starts without model capacity.
        # Other reported settings are retained, while existing stable
        # records continue using their persisted model pool on reconnect.
        initial_config.model_pool.models = []
    stable_key = str(existing.get("agent_key") or "") if existing else uuid.uuid4().hex
    record = await run_store_call(
        store,
        "upsert_agent_record",
        agent_key=stable_key,
        user_id=user_id,
        ip=ip,
        machine_name=machine_name,
        display_name=name,
        agent_id=agent_id,
        last_seen=now,
        initial_config_json=initial_config.model_dump_json(),
        validator_catalog_json=catalog.model_dump_json(),
    )
    stable_key = str(record["agent_key"])
    reported_runtime_hash = str(msg.get("runtime_hash") or "")
    update_target_hash = str(record.get("runtime_update_target_hash") or "")
    if (
        _runtime_update_status(record)
        and update_target_hash
        and reported_runtime_hash == update_target_hash
    ):
        await run_store_call(
            store,
            "set_agent_runtime_update_record",
            stable_key,
            status="",
        )
        record = (
            await run_store_call(store, "get_agent_record", stable_key)
            or record
        )
    cfg = _stored_agent_config(record)
    get_runtime().agents.agent_configs[stable_key] = cfg
    return record, cfg


async def _prepare_reconnect(
    agent_id: str,
    agent_info: AgentInfo,
    msg: dict,
    *,
    final_callbacks: bool,
) -> ReconnectState:
    from backend.agents.reattachment import _reattach_active_agent_scans_async, _reattach_active_fp_reviews_async, _reattach_active_validations_async
    from backend.agents.recovery import _promote_final_callback_agent_reports, _adopt_reported_agent_work
    store = get_scan_store()
    stable_key = agent_info.agent_key
    pending_scan_stops: list[dict] = []
    reattached_scan_ids = await _reattach_active_agent_scans_async(
        agent_id,
        agent_info,
        msg.get("active_scans") or [],
        pending_scan_stops,
    )
    await _reattach_active_fp_reviews_async(
        agent_id,
        agent_info,
        msg.get("active_fp_reviews") or [],
    )
    pending_validation_stops = await _reattach_active_validations_async(
        agent_id,
        agent_info,
        msg.get("active_validations") or [],
    )
    recovery_scan_ids: list[str] = []
    promoted_by_scan: dict[str, list[int]] = {}
    if final_callbacks:
        recovery_scan_ids, promoted_by_scan = (
            await _promote_final_callback_agent_reports(
                agent_id,
                agent_info,
                reattached_scan_ids,
            )
        )

    accepted_scan_executions = await _adopt_reported_agent_work(agent_id, agent_info, msg)
    from backend.review_notes import review_notes_for_agent

    review_notes = await review_notes_for_agent(stable_key, msg.get("review_notes_revisions"), store=store)
    from backend.code_graph import code_graph_for_agent

    code_graph_updates = (
        await code_graph_for_agent(stable_key, msg.get("code_graph_mcp_revisions"), store=store)
        if agent_info.scan_code_graph_updates else []
    )
    return ReconnectState(pending_scan_stops, pending_validation_stops, recovery_scan_ids, promoted_by_scan, accepted_scan_executions, review_notes, code_graph_updates)


async def _recover_after_welcome(
    agent_id: str, agent_info: AgentInfo, msg: dict, reconnect: ReconnectState,
    final_callbacks: bool, server_url: str,
) -> None:
    from backend.agents.recovery import _recover_missing_agent_work, _resume_final_callback_downstream

    try:
        await _recover_missing_agent_work(agent_id, agent_info, msg, server_url=server_url)
        if final_callbacks:
            await _resume_final_callback_downstream(
                agent_info, reconnect.recovery_scan_ids, reconnect.promoted_by_scan,
                server_url=server_url,
            )
    except Exception:
        logger.exception("Agent reconnect recovery failed for %s", agent_id)


async def _receive_messages(websocket: WebSocket, agent_id: str, agent_info: AgentInfo) -> None:
    from backend.agents.directory import _touch_agent, _schedule_agent_touch_persistence
    from backend.agents.transport import _send_agent_json
    from backend.agents.rpc import _complete_agent_response
    # Keep connection alive; agent sends application-level heartbeats.
    while True:
        incoming = await websocket.receive_json()
        if isinstance(incoming, dict) and incoming.get("type") == "heartbeat":
            # Heartbeat health is independent from persistence latency: update
            # memory, ACK immediately, then coalesce the durable write.
            _touch_agent(agent_id, persist=False)
            await _send_agent_json(agent_id, {"type": "heartbeat_ack"})
            _schedule_agent_touch_persistence(agent_id)
            continue
        _touch_agent(agent_id)
        response_waiters = (
            get_runtime().agents.agent_response_waiters.get(str(incoming.get("type") or ""))
            if isinstance(incoming, dict)
            else None
        )
        if response_waiters is not None:
            if incoming.get("type") == "code_graph_result":
                from backend.code_graph import accept_code_graph_result

                await accept_code_graph_result(incoming, agent_info)
            await _complete_agent_response(incoming, response_waiters)
            continue
        if isinstance(incoming, dict) and incoming.get("type") == "skill_create_result":
            from backend.skill_creation import handle_skill_create_result

            handle_skill_create_result(incoming)
            continue


async def _close_connection(agent_id: str | None, recovery_task: asyncio.Task | None) -> None:
    from backend.agents.recovery import _schedule_agent_disconnect_cancel
    if recovery_task is not None:
        recovery_task.cancel()
        await asyncio.gather(recovery_task, return_exceptions=True)
    if agent_id:
        store = get_scan_store()
        if getattr(store, "distributed", False):
            try:
                await run_store_call(
                    store,
                    "unregister_agent_session",
                    agent_id,
                )
            except Exception:
                logger.exception("Failed to unregister Agent session %s", agent_id)
        _schedule_agent_disconnect_cancel(agent_id)
        get_runtime().agents.agent_ws.pop(agent_id, None)
        get_runtime().agents.agent_ws_locks.pop(agent_id, None)
        get_runtime().agents.agent_opencode_pool_latest.pop(agent_id, None)
        get_runtime().agents.registered_agents.pop(agent_id, None)
        logger.info("Agent disconnected: %s", agent_id)
