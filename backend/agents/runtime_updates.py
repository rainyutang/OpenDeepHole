"""Runtime updates services for Agent-backed scans."""

from __future__ import annotations
from backend.agents import constants
from backend.application import ApplicationError as HTTPException, get_scan_store, run_store_call
from backend.models import User
import asyncio
from datetime import datetime, timezone
from backend.logger import get_logger
logger = get_logger(__name__)


def _runtime_update_status(record: dict | None) -> str:
    return str((record or {}).get("runtime_update_status") or "")


def is_agent_accepting_tasks(agent_key: str) -> bool:
    """Return whether a stable Agent may receive a new workload command."""
    if not agent_key:
        return True
    record = get_scan_store().get_agent_record(agent_key)
    return _runtime_update_status(record) != constants._RUNTIME_UPDATE_UPDATING


def ensure_agent_accepting_tasks(agent_key: str) -> None:
    if not is_agent_accepting_tasks(agent_key):
        raise HTTPException(
            status_code=409,
            detail="Agent 正在更新并等待重连，请稍后再提交任务",
        )


async def ensure_agent_accepting_tasks_async(agent_key: str) -> None:
    if not agent_key:
        return
    record = await run_store_call(
        get_scan_store(),
        "get_agent_record",
        agent_key,
    )
    if _runtime_update_status(record) == constants._RUNTIME_UPDATE_UPDATING:
        raise HTTPException(
            status_code=409,
            detail="Agent 正在更新并等待重连，请稍后再提交任务",
        )


def _runtime_update_age_seconds(value: str) -> float | None:
    if not value:
        return None
    try:
        timestamp = datetime.fromisoformat(value)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return max(0.0, (datetime.now(timezone.utc) - timestamp).total_seconds())
    except Exception:
        return None


def _scan_belongs_to_agent(scan_id: str, agent_key: str, agent_id: str) -> bool:
    meta = get_scan_store().get_scan_meta(scan_id)
    if meta is None:
        return False
    if agent_key and meta.agent_key:
        return meta.agent_key == agent_key
    return bool(agent_id and meta.agent_id == agent_id)


async def _agent_has_active_work(agent_key: str, agent_id: str) -> bool:
    """Use durable task lifecycle state to decide whether an update is safe.

    The Agent-wide OpenCode pool is intentionally not consulted here.  Its
    snapshot is observational and may briefly retain running/queued entries
    after the user has stopped a task.  Scan, FP-review, and validation rows
    are the authoritative lifecycle state for manual runtime updates.
    """
    return await run_store_call(
        get_scan_store(),
        "has_active_work_for_agent",
        agent_key,
        agent_id,
    )


async def _clear_agent_runtime_update(agent_key: str) -> None:
    store = get_scan_store()
    await run_store_call(
        store,
        "set_agent_runtime_update_record",
        agent_key,
        status="",
    )


async def _process_agent_runtime_updates() -> None:
    """Advance all durable manual Agent update requests by one scheduler tick."""
    from backend.agents.artifacts import _agent_runtime_hash
    from backend.agents.artifacts import create_agent_runtime_update_payload
    from backend.agents.directory import resolve_agent_connection_async
    from backend.agents.gateway import send_agent_command
    store = get_scan_store()
    records = await run_store_call(store, "list_agent_records")
    for record in records:
        status = _runtime_update_status(record)
        if status not in constants._RUNTIME_UPDATE_ACTIVE_STATUSES:
            continue

        agent_key = str(record.get("agent_key") or "")
        target_hash = str(record.get("runtime_update_target_hash") or "")
        live = await resolve_agent_connection_async(agent_key)

        if live is not None and target_hash and live[1].runtime_hash == target_hash:
            await _clear_agent_runtime_update(agent_key)
            logger.info("Agent runtime update completed: agent_key=%s", agent_key)
            continue

        if status == constants._RUNTIME_UPDATE_UPDATING:
            age = _runtime_update_age_seconds(
                str(record.get("runtime_update_started_at") or "")
            )
            if age is not None and age > constants._RUNTIME_UPDATE_TIMEOUT_SECONDS:
                await run_store_call(
                    store,
                    "set_agent_runtime_update_record",
                    agent_key,
                    status=constants._RUNTIME_UPDATE_FAILED,
                    target_hash=target_hash,
                    server_url=str(record.get("runtime_update_server_url") or ""),
                    requested_at=str(record.get("runtime_update_requested_at") or ""),
                    started_at=str(record.get("runtime_update_started_at") or ""),
                    error="Agent 更新后未在规定时间内以目标版本重连",
                )
                logger.warning(
                    "Agent runtime update timed out: agent_key=%s target=%s",
                    agent_key,
                    target_hash[:12],
                )
            continue

        if live is None:
            continue
        agent_id, agent = live
        if await _agent_has_active_work(agent_key, agent_id):
            continue

        server_url = str(record.get("runtime_update_server_url") or "")
        if not server_url:
            await run_store_call(
                store,
                "set_agent_runtime_update_record",
                agent_key,
                status=constants._RUNTIME_UPDATE_FAILED,
                target_hash=target_hash,
                requested_at=str(record.get("runtime_update_requested_at") or ""),
                error="更新请求缺少服务端地址，请重新点击更新",
            )
            continue

        try:
            target_hash = await asyncio.to_thread(_agent_runtime_hash)
            if agent.runtime_hash and agent.runtime_hash == target_hash:
                await _clear_agent_runtime_update(agent_key)
                continue
            now = datetime.now(timezone.utc).isoformat()
            await run_store_call(
                store,
                "set_agent_runtime_update_record",
                agent_key,
                status=constants._RUNTIME_UPDATE_UPDATING,
                target_hash=target_hash,
                server_url=server_url,
                requested_at=str(record.get("runtime_update_requested_at") or now),
                started_at=now,
            )

            # Let concurrent task-creation requests observe the updating state,
            # then recheck in case one was already committed before the handoff.
            await asyncio.sleep(0)
            live = await resolve_agent_connection_async(agent_key)
            if live is None:
                await run_store_call(
                    store,
                    "set_agent_runtime_update_record",
                    agent_key,
                    status=constants._RUNTIME_UPDATE_PENDING,
                    target_hash=target_hash,
                    server_url=server_url,
                    requested_at=str(record.get("runtime_update_requested_at") or now),
                )
                continue
            agent_id, _agent = live
            if await _agent_has_active_work(agent_key, agent_id):
                await run_store_call(
                    store,
                    "set_agent_runtime_update_record",
                    agent_key,
                    status=constants._RUNTIME_UPDATE_PENDING,
                    target_hash=target_hash,
                    server_url=server_url,
                    requested_at=str(record.get("runtime_update_requested_at") or now),
                )
                continue

            update_payload = await asyncio.to_thread(
                create_agent_runtime_update_payload,
                server_url,
            )
            sent = await send_agent_command(
                agent_id,
                {
                    "type": "task",
                    "runtime_update_only": True,
                    "agent_runtime_update": update_payload,
                },
            )
            if not sent:
                await run_store_call(
                    store,
                    "set_agent_runtime_update_record",
                    agent_key,
                    status=constants._RUNTIME_UPDATE_PENDING,
                    target_hash=target_hash,
                    server_url=server_url,
                    requested_at=str(record.get("runtime_update_requested_at") or now),
                )
                continue
            logger.info(
                "Agent runtime update dispatched at idle boundary: agent_key=%s target=%s",
                agent_key,
                target_hash[:12],
            )
        except Exception as exc:
            logger.exception(
                "Failed to dispatch Agent runtime update for %s",
                agent_key,
            )
            await run_store_call(
                store,
                "set_agent_runtime_update_record",
                agent_key,
                status=constants._RUNTIME_UPDATE_FAILED,
                target_hash=target_hash,
                server_url=server_url,
                requested_at=str(record.get("runtime_update_requested_at") or ""),
                error=f"下发 Agent 更新失败：{exc}",
            )


async def run_agent_runtime_update_scheduler() -> None:
    """Continuously dispatch durable manual updates at safe idle boundaries."""
    while True:
        try:
            await _process_agent_runtime_updates()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Agent runtime update scheduler tick failed")
        await asyncio.sleep(constants._RUNTIME_UPDATE_POLL_SECONDS)


async def request_stable_agent_runtime_update(
    agent_key: str,
    server_url: str,
    current_user: User=None,
) -> dict:
    from backend.agents.artifacts import _agent_runtime_hash
    from backend.agents.configuration import _authorize_agent_record
    from backend.agents.directory import resolve_agent_connection_async
    store = get_scan_store()
    record = _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    live = await resolve_agent_connection_async(agent_key)
    if live is None:
        raise HTTPException(status_code=409, detail="Agent 当前离线，无法提交更新")

    target_hash = _agent_runtime_hash()
    if live[1].runtime_hash and live[1].runtime_hash == target_hash:
        await run_store_call(
            store,
            "set_agent_runtime_update_record",
            agent_key,
            status="",
        )
        return {
            "status": "up_to_date",
            "target_hash": target_hash,
            "message": "Agent 已是最新版本",
        }

    current_status = _runtime_update_status(record)
    current_target = str(record.get("runtime_update_target_hash") or "")
    if (
        current_status in constants._RUNTIME_UPDATE_ACTIVE_STATUSES
        and current_target == target_hash
    ):
        return {
            "status": current_status,
            "target_hash": target_hash,
            "message": (
                "Agent 正在更新"
                if current_status == constants._RUNTIME_UPDATE_UPDATING
                else "更新请求已在等待 Agent 空闲"
            ),
        }

    now = datetime.now(timezone.utc).isoformat()
    await run_store_call(
        store,
        "set_agent_runtime_update_record",
        agent_key,
        status=constants._RUNTIME_UPDATE_PENDING,
        target_hash=target_hash,
        server_url=server_url,
        requested_at=now,
    )
    logger.info(
        "Agent runtime update requested: agent_key=%s user=%s target=%s",
        agent_key,
        current_user.username,
        target_hash[:12],
    )
    return {
        "status": constants._RUNTIME_UPDATE_PENDING,
        "target_hash": target_hash,
        "message": "更新请求已提交，Agent 将在全部任务空闲后自动更新",
    }
