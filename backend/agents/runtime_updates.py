"""Runtime updates services for Agent-backed scans."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import os
import time
from datetime import datetime, timezone

from backend.agents import constants
from backend.application import (
    ApplicationError as HTTPException,
    get_runtime,
    get_scan_store,
    run_store_call,
)
from backend.logger import get_logger
from backend.models import AgentInfo, User

logger = get_logger(__name__)

_LAST_STAT_CHECK_MONOTONIC: float = 0.0


@dataclass
class _LegacyRuntimeUpdateAttempt:
    agent_id: str
    agent_session_id: str
    target_hash: str
    dispatched_at: float
    retry_count: int = 0
    tokens: list[str] = field(default_factory=list)
    downloaded_at: float | None = None
    download_count: int = 0


def note_agent_stop_dispatched(
    agent_key: str,
    *,
    settle_seconds: float = constants._LEGACY_STOP_SETTLE_SECONDS,
    replace: bool = False,
) -> None:
    """Delay legacy idle-boundary update dispatch briefly after sending stop commands."""
    normalized = str(agent_key or "").strip()
    if not normalized:
        return
    duration = max(0.0, float(settle_seconds))
    if duration <= 0.0:
        clear_agent_stop_settle(normalized)
        return
    deadline = time.monotonic() + duration
    deadlines = get_runtime().agents.legacy_stop_settle_until
    if replace:
        deadlines[normalized] = deadline
    else:
        deadlines[normalized] = max(deadlines.get(normalized, 0.0), deadline)


def clear_agent_stop_settle(agent_key: str) -> None:
    normalized = str(agent_key or "").strip()
    if not normalized:
        return
    get_runtime().agents.legacy_stop_settle_until.pop(normalized, None)


def _is_in_legacy_stop_settle(agent_key: str) -> bool:
    normalized = str(agent_key or "").strip()
    if not normalized:
        return False
    deadlines = get_runtime().agents.legacy_stop_settle_until
    deadline = deadlines.get(normalized)
    if deadline is None:
        return False
    if time.monotonic() < deadline:
        return True
    deadlines.pop(normalized, None)
    return False


def _clear_legacy_runtime_update_tracking(agent_key: str) -> None:
    normalized = str(agent_key or "").strip()
    if not normalized:
        return
    get_runtime().agents.legacy_runtime_update_attempts.pop(normalized, None)
    get_runtime().agents.legacy_stop_settle_until.pop(normalized, None)


def record_runtime_update_download_consumed(token: str) -> None:
    """Mark a legacy update attempt as downloaded once the Agent fetches its archive."""
    normalized = str(token or "").strip()
    if not normalized:
        return
    now_mono = time.monotonic()
    for attempt in get_runtime().agents.legacy_runtime_update_attempts.values():
        if normalized in attempt.tokens:
            attempt.downloaded_at = now_mono
            attempt.download_count += 1
            return


def _record_legacy_runtime_update_dispatch(
    agent_key: str,
    agent_id: str,
    agent: AgentInfo,
    target_hash: str,
    update_payload: dict,
    *,
    existing: _LegacyRuntimeUpdateAttempt | None = None,
) -> _LegacyRuntimeUpdateAttempt:
    now_mono = time.monotonic()
    token = str(update_payload.get("token") or "").strip()
    session_id = str(agent.agent_session_id or "")
    if (
        existing is not None
        and existing.target_hash == target_hash
        and existing.agent_session_id == session_id
        and (session_id or existing.agent_id == agent_id)
    ):
        existing.agent_id = agent_id
        existing.dispatched_at = now_mono
        existing.retry_count += 1
        if token:
            existing.tokens.append(token)
            if len(existing.tokens) > 8:
                del existing.tokens[:-8]
        attempt = existing
    else:
        attempt = _LegacyRuntimeUpdateAttempt(
            agent_id=agent_id,
            agent_session_id=session_id,
            target_hash=target_hash,
            dispatched_at=now_mono,
            retry_count=0,
            tokens=[token] if token else [],
        )
    get_runtime().agents.legacy_runtime_update_attempts[agent_key] = attempt
    return attempt


def _runtime_update_status(record: dict | None) -> str:
    return str((record or {}).get("runtime_update_status") or "")


def _blocking_detail_for_status(status: str) -> str:
    if status == constants._RUNTIME_UPDATE_DRAINING:
        return "Agent 正在等待当前在途任务完成并更新，请稍后再提交任务"
    return "Agent 正在更新并等待重连，请稍后再提交任务"


def is_agent_accepting_tasks(agent_key: str) -> bool:
    """Return whether a stable Agent may receive a new workload command."""
    if not agent_key:
        return True
    record = get_scan_store().get_agent_record(agent_key)
    return _runtime_update_status(record) not in constants._RUNTIME_UPDATE_BLOCKING_STATUSES


def ensure_agent_accepting_tasks(agent_key: str) -> None:
    if not agent_key:
        return
    record = get_scan_store().get_agent_record(agent_key)
    status = _runtime_update_status(record)
    if status in constants._RUNTIME_UPDATE_BLOCKING_STATUSES:
        raise HTTPException(
            status_code=409,
            detail=_blocking_detail_for_status(status),
        )


async def ensure_agent_accepting_tasks_async(agent_key: str) -> None:
    if not agent_key:
        return
    record = await run_store_call(
        get_scan_store(),
        "get_agent_record",
        agent_key,
    )
    status = _runtime_update_status(record)
    if status in constants._RUNTIME_UPDATE_BLOCKING_STATUSES:
        raise HTTPException(
            status_code=409,
            detail=_blocking_detail_for_status(status),
        )


def auto_runtime_update_enabled() -> bool:
    raw = str(os.environ.get("OPENDEEPHOLE_AUTO_AGENT_UPDATE", "1")).strip().lower()
    return raw not in {"0", "false", "no", "off"}


def _stat_check_interval_seconds() -> float:
    raw = os.environ.get("OPENDEEPHOLE_RUNTIME_STAT_CHECK_SECONDS")
    if raw is None or not str(raw).strip():
        return constants._RUNTIME_UPDATE_STAT_CHECK_SECONDS
    try:
        return max(0.0, float(raw))
    except ValueError:
        return constants._RUNTIME_UPDATE_STAT_CHECK_SECONDS


def reset_runtime_update_stat_check_clock() -> None:
    global _LAST_STAT_CHECK_MONOTONIC
    _LAST_STAT_CHECK_MONOTONIC = 0.0


async def get_server_runtime_hash_async(*, check_stat: bool = False) -> str:
    from backend.agents.artifacts import get_cached_agent_runtime_hash

    return await asyncio.to_thread(
        get_cached_agent_runtime_hash,
        check_stat=check_stat,
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
    """Use durable task lifecycle state to decide whether an Agent has active work.

    The Agent-wide OpenCode pool is intentionally not consulted here.  Its
    snapshot is observational and may briefly retain running/queued entries
    after the user has stopped a task.  Scan, FP-review, and validation rows
    are the authoritative lifecycle state for runtime updates.
    """
    return await run_store_call(
        get_scan_store(),
        "has_active_work_for_agent",
        agent_key,
        agent_id,
    )


def _sync_live_agent_update_state(
    agent_key: str,
    *,
    status: str,
    target_hash: str = "",
    error: str = "",
) -> None:
    if not agent_key:
        return
    accepting = status not in constants._RUNTIME_UPDATE_BLOCKING_STATUSES
    for agent in get_runtime().agents.registered_agents.values():
        if agent.agent_key != agent_key:
            continue
        agent.runtime_update_status = status
        agent.runtime_update_target_hash = target_hash if status else ""
        agent.runtime_update_error = error if status == constants._RUNTIME_UPDATE_FAILED else ""
        agent.accepting_tasks = accepting


async def _clear_agent_runtime_update(agent_key: str) -> None:
    store = get_scan_store()
    await run_store_call(
        store,
        "set_agent_runtime_update_record",
        agent_key,
        status="",
    )
    _clear_legacy_runtime_update_tracking(agent_key)
    _sync_live_agent_update_state(agent_key, status="")


async def handle_agent_runtime_update_status(
    agent_info: AgentInfo,
    payload: dict,
) -> None:
    """Persist runtime-update lifecycle progress reported by a connected Agent."""
    agent_key = str(agent_info.agent_key or "").strip()
    if not agent_key:
        return
    state = str(payload.get("state") or "").strip().lower()
    reported_target = str(payload.get("target_hash") or "").strip()
    error = str(payload.get("error") or "").strip()
    store = get_scan_store()
    record = await run_store_call(store, "get_agent_record", agent_key)
    if record is None:
        return

    current_status = _runtime_update_status(record)
    current_target = str(record.get("runtime_update_target_hash") or "")
    server_url = str(record.get("runtime_update_server_url") or agent_info.server_url or "")
    requested_at = str(record.get("runtime_update_requested_at") or "")
    started_at = str(record.get("runtime_update_started_at") or "")
    now = datetime.now(timezone.utc).isoformat()

    if state == "up_to_date":
        await _clear_agent_runtime_update(agent_key)
        logger.info("Agent reported runtime already up to date: agent_key=%s", agent_key)
        return

    if current_target and reported_target and reported_target != current_target:
        # Ignore stale status notifications from an older update generation.
        return

    effective_target = reported_target or current_target
    if state == constants._RUNTIME_UPDATE_DRAINING:
        try:
            reported_active = int(payload.get("active_tasks") or 0)
        except (TypeError, ValueError):
            reported_active = 0
        if (
            current_status == constants._RUNTIME_UPDATE_UPDATING
            and current_target == effective_target
            and reported_active <= 0
        ):
            return
        await run_store_call(
            store,
            "set_agent_runtime_update_record",
            agent_key,
            status=constants._RUNTIME_UPDATE_DRAINING,
            target_hash=effective_target,
            server_url=server_url,
            requested_at=requested_at or now,
            started_at=started_at or now,
        )
        _sync_live_agent_update_state(
            agent_key,
            status=constants._RUNTIME_UPDATE_DRAINING,
            target_hash=effective_target,
        )
    elif state == constants._RUNTIME_UPDATE_UPDATING:
        # Start the reconnect timeout clock only when install/restart begins.
        await run_store_call(
            store,
            "set_agent_runtime_update_record",
            agent_key,
            status=constants._RUNTIME_UPDATE_UPDATING,
            target_hash=effective_target,
            server_url=server_url,
            requested_at=requested_at or now,
            started_at=now,
        )
        _sync_live_agent_update_state(
            agent_key,
            status=constants._RUNTIME_UPDATE_UPDATING,
            target_hash=effective_target,
        )
        logger.info(
            "Agent finished draining and is applying runtime update: agent_key=%s target=%s",
            agent_key,
            effective_target[:12],
        )
    elif state == constants._RUNTIME_UPDATE_FAILED:
        detail = error or "Agent 更新失败，请检查客户端日志或点击重试更新"
        await run_store_call(
            store,
            "set_agent_runtime_update_record",
            agent_key,
            status=constants._RUNTIME_UPDATE_FAILED,
            target_hash=effective_target,
            server_url=server_url,
            requested_at=requested_at or now,
            started_at=started_at or now,
            error=detail,
        )
        _sync_live_agent_update_state(
            agent_key,
            status=constants._RUNTIME_UPDATE_FAILED,
            target_hash=effective_target,
            error=detail,
        )
        logger.warning(
            "Agent runtime update failed: agent_key=%s target=%s error=%s",
            agent_key,
            effective_target[:12],
            detail,
        )


async def dispatch_graceful_runtime_update(
    agent_key: str,
    agent_id: str,
    agent: AgentInfo,
    *,
    server_url: str = "",
    target_hash: str = "",
    record: dict | None = None,
    active_work_hint: bool = False,
    is_manual: bool = False,
) -> str:
    """Send a drain-and-update command to a graceful-update-capable Agent."""
    from backend.agents.artifacts import create_agent_runtime_update_payload
    from backend.agents.gateway import send_agent_command

    store = get_scan_store()
    if record is None:
        record = await run_store_call(store, "get_agent_record", agent_key)
    resolved_target = target_hash or await get_server_runtime_hash_async(check_stat=False)
    if not resolved_target:
        return ""
    if agent.runtime_hash and agent.runtime_hash == resolved_target:
        await _clear_agent_runtime_update(agent_key)
        return "up_to_date"

    effective_server_url = (
        str(server_url or "").strip()
        or str(agent.server_url or "").strip()
        or str((record or {}).get("runtime_update_server_url") or "").strip()
    )
    has_active = bool(active_work_hint) or await _agent_has_active_work(agent_key, agent_id)
    next_status = (
        constants._RUNTIME_UPDATE_DRAINING
        if has_active
        else constants._RUNTIME_UPDATE_UPDATING
    )
    now = datetime.now(timezone.utc).isoformat()
    requested_at = str((record or {}).get("runtime_update_requested_at") or now)

    try:
        update_payload = await asyncio.to_thread(
            create_agent_runtime_update_payload,
            effective_server_url,
        )
        resolved_target = str(update_payload.get("hash") or resolved_target)
        if agent.runtime_hash and agent.runtime_hash == resolved_target:
            await _clear_agent_runtime_update(agent_key)
            return "up_to_date"

        latest_record = await run_store_call(store, "get_agent_record", agent_key)
        latest_status = _runtime_update_status(latest_record)
        latest_target = str((latest_record or {}).get("runtime_update_target_hash") or "")
        already_updating_same_target = (
            latest_status == constants._RUNTIME_UPDATE_UPDATING
            and latest_target == resolved_target
        )
        effective_started_at = now
        if already_updating_same_target and next_status == constants._RUNTIME_UPDATE_DRAINING:
            next_status = constants._RUNTIME_UPDATE_UPDATING
            effective_started_at = str((latest_record or {}).get("runtime_update_started_at") or now)

        await run_store_call(
            store,
            "set_agent_runtime_update_record",
            agent_key,
            status=next_status,
            target_hash=resolved_target,
            server_url=effective_server_url,
            requested_at=requested_at,
            started_at=effective_started_at,
        )
        _sync_live_agent_update_state(
            agent_key,
            status=next_status,
            target_hash=resolved_target,
        )

        sent = await send_agent_command(
            agent_id,
            {
                "type": "runtime_update",
                "mode": "drain",
                "agent_runtime_update": update_payload,
            },
        )
        if not sent:
            if already_updating_same_target:
                return constants._RUNTIME_UPDATE_UPDATING
            rollback_status = constants._RUNTIME_UPDATE_PENDING if is_manual else ""
            await run_store_call(
                store,
                "set_agent_runtime_update_record",
                agent_key,
                status=rollback_status,
                target_hash=resolved_target if rollback_status else "",
                server_url=effective_server_url if rollback_status else "",
                requested_at=requested_at if rollback_status else "",
            )
            _sync_live_agent_update_state(
                agent_key,
                status=rollback_status,
                target_hash=resolved_target if rollback_status else "",
            )
            return ""
        logger.info(
            "Agent graceful runtime update dispatched: agent_key=%s state=%s target=%s manual=%s",
            agent_key,
            next_status,
            resolved_target[:12],
            is_manual,
        )
        return next_status
    except Exception as exc:
        logger.exception(
            "Failed to dispatch graceful Agent runtime update for %s",
            agent_key,
        )
        await run_store_call(
            store,
            "set_agent_runtime_update_record",
            agent_key,
            status=constants._RUNTIME_UPDATE_FAILED,
            target_hash=resolved_target,
            server_url=effective_server_url,
            requested_at=requested_at,
            started_at=now,
            error=f"下发 Agent 更新失败：{exc}",
        )
        _sync_live_agent_update_state(
            agent_key,
            status=constants._RUNTIME_UPDATE_FAILED,
            target_hash=resolved_target,
            error=f"下发 Agent 更新失败：{exc}",
        )
        return ""


async def maybe_auto_trigger_agent_runtime_update_on_connect(
    agent_id: str,
    agent: AgentInfo,
    hello_msg: dict,
    *,
    server_url: str,
) -> bool:
    """Reconcile or auto-trigger drain-and-update on WebSocket hello.

    Returns True when an update is already draining or just dispatched so the
    caller can defer orphaned-work recovery until the updated Agent reconnects.
    """
    if not agent.graceful_runtime_update or not agent.agent_key or not agent.runtime_hash:
        return False

    target_hash = await get_server_runtime_hash_async(check_stat=False)
    if not target_hash or agent.runtime_hash == target_hash:
        return False

    store = get_scan_store()
    record = await run_store_call(store, "get_agent_record", agent.agent_key)
    current_status = _runtime_update_status(record)
    current_target = str((record or {}).get("runtime_update_target_hash") or "")
    if current_status == constants._RUNTIME_UPDATE_FAILED and current_target == target_hash:
        return False

    hello_state = hello_msg.get("runtime_update_state")
    reported_state = (
        str(hello_state.get("state") or "").strip().lower()
        if isinstance(hello_state, dict)
        else ""
    )
    reported_target = (
        str(hello_state.get("target_hash") or "").strip()
        if isinstance(hello_state, dict)
        else ""
    )
    if reported_state in {"staging", "draining", "updating"} and reported_target == target_hash:
        persisted_state = (
            constants._RUNTIME_UPDATE_UPDATING
            if reported_state == "updating"
            else constants._RUNTIME_UPDATE_DRAINING
        )
        now = datetime.now(timezone.utc).isoformat()
        await run_store_call(
            store,
            "set_agent_runtime_update_record",
            agent.agent_key,
            status=persisted_state,
            target_hash=target_hash,
            server_url=server_url or str((record or {}).get("runtime_update_server_url") or ""),
            requested_at=str((record or {}).get("runtime_update_requested_at") or now),
            started_at=str((record or {}).get("runtime_update_started_at") or now),
        )
        _sync_live_agent_update_state(
            agent.agent_key,
            status=persisted_state,
            target_hash=target_hash,
        )
        logger.info(
            "Agent reconnected while already %s for target=%s: agent_key=%s",
            persisted_state,
            target_hash[:12],
            agent.agent_key,
        )
        return True

    if (
        current_status == constants._RUNTIME_UPDATE_UPDATING
        and current_target == target_hash
        and reported_state in {"", "idle"}
    ):
        # A fresh Agent process came back after an update attempt still reporting
        # an outdated hash. Stop auto-retrying this exact target to avoid loops.
        now = datetime.now(timezone.utc).isoformat()
        error = "Agent 重启后运行版本仍未变为目标版本，已暂停自动重试；请检查客户端目录权限或点击重试更新"
        await run_store_call(
            store,
            "set_agent_runtime_update_record",
            agent.agent_key,
            status=constants._RUNTIME_UPDATE_FAILED,
            target_hash=target_hash,
            server_url=server_url or str((record or {}).get("runtime_update_server_url") or ""),
            requested_at=str((record or {}).get("runtime_update_requested_at") or now),
            started_at=str((record or {}).get("runtime_update_started_at") or now),
            error=error,
        )
        _sync_live_agent_update_state(
            agent.agent_key,
            status=constants._RUNTIME_UPDATE_FAILED,
            target_hash=target_hash,
            error=error,
        )
        logger.warning(
            "Agent reconnected after updating with mismatched hash (expected=%s actual=%s): agent_key=%s",
            target_hash[:12],
            agent.runtime_hash[:12],
            agent.agent_key,
        )
        return False

    is_manual_pending = current_status == constants._RUNTIME_UPDATE_PENDING
    if not is_manual_pending and not auto_runtime_update_enabled():
        return False

    has_local_work = bool(
        hello_msg.get("active_scans")
        or hello_msg.get("active_fp_reviews")
        or hello_msg.get("active_validations")
    )
    dispatched = await dispatch_graceful_runtime_update(
        agent.agent_key,
        agent_id,
        agent,
        server_url=server_url,
        target_hash=target_hash,
        record=record,
        active_work_hint=has_local_work,
        is_manual=is_manual_pending,
    )
    return dispatched in constants._RUNTIME_UPDATE_BLOCKING_STATUSES


async def _maybe_retry_legacy_updating_agent(
    store,
    *,
    agent_key: str,
    record: dict,
    target_hash: str,
    age: float | None,
    agent_id: str,
    agent: AgentInfo,
) -> None:
    """Self-heal legacy Agents that deferred runtime_update_only while local work wound down."""
    from backend.agents.artifacts import (
        _agent_runtime_hash,
        create_agent_runtime_update_payload,
    )
    from backend.agents.gateway import send_agent_command

    if agent_id not in get_runtime().agents.agent_ws:
        return

    server_url = str(
        record.get("runtime_update_server_url") or agent.server_url or ""
    ).strip()
    requested_at = str(record.get("runtime_update_requested_at") or "")
    started_at = str(record.get("runtime_update_started_at") or "")

    async def _mark_failed(error: str) -> None:
        await run_store_call(
            store,
            "set_agent_runtime_update_record",
            agent_key,
            status=constants._RUNTIME_UPDATE_FAILED,
            target_hash=target_hash,
            server_url=server_url,
            requested_at=requested_at,
            started_at=started_at,
            error=error,
        )
        _clear_legacy_runtime_update_tracking(agent_key)
        _sync_live_agent_update_state(
            agent_key,
            status=constants._RUNTIME_UPDATE_FAILED,
            target_hash=target_hash,
            error=error,
        )

    attempts = get_runtime().agents.legacy_runtime_update_attempts
    attempt: _LegacyRuntimeUpdateAttempt | None = attempts.get(agent_key)
    now_mono = time.monotonic()
    fresh_session_reconnected = False

    if attempt is not None:
        if target_hash and attempt.target_hash and attempt.target_hash != target_hash:
            attempts.pop(agent_key, None)
            attempt = None
        elif (
            attempt.agent_session_id
            and agent.agent_session_id
            and attempt.agent_session_id != agent.agent_session_id
        ):
            if attempt.downloaded_at is not None:
                error = (
                    "Agent 重启后运行版本仍未变为目标版本，已暂停自动重试；"
                    "请检查客户端目录权限或点击重试更新"
                )
                await _mark_failed(error)
                logger.warning(
                    "Legacy Agent reconnected after downloading update with mismatched hash "
                    "(expected=%s actual=%s): agent_key=%s",
                    target_hash[:12],
                    agent.runtime_hash[:12],
                    agent_key,
                )
                return
            attempts.pop(agent_key, None)
            attempt = None
            fresh_session_reconnected = True
        elif attempt.downloaded_at is not None:
            last_activity = max(attempt.dispatched_at, attempt.downloaded_at)
            if (
                now_mono - last_activity
                < constants._LEGACY_RUNTIME_UPDATE_POST_DOWNLOAD_RETRY_SECONDS
            ):
                return
            if (
                attempt.download_count >= constants._LEGACY_RUNTIME_UPDATE_MAX_POST_DOWNLOAD_ATTEMPTS
                or attempt.dispatched_at > attempt.downloaded_at
            ):
                error = "旧版 Agent 已下载更新包但未完成重启，请检查客户端控制台日志或点击重试更新"
                await _mark_failed(error)
                logger.warning(
                    "Legacy Agent downloaded runtime update without restarting: agent_key=%s target=%s",
                    agent_key,
                    target_hash[:12],
                )
                return
        else:
            delay = min(
                constants._LEGACY_RUNTIME_UPDATE_REDISPATCH_MAX_SECONDS,
                constants._LEGACY_RUNTIME_UPDATE_REDISPATCH_INITIAL_SECONDS
                * (2 ** min(attempt.retry_count, 3)),
            )
            if now_mono - attempt.dispatched_at < delay:
                return

    if attempt is None and not fresh_session_reconnected:
        if age is None or age < constants._LEGACY_RUNTIME_UPDATE_REDISPATCH_INITIAL_SECONDS:
            return

    if _is_in_legacy_stop_settle(agent_key):
        return
    if await _agent_has_active_work(agent_key, agent_id):
        return
    if not server_url:
        return

    try:
        latest_hash = await asyncio.to_thread(_agent_runtime_hash)
        if agent.runtime_hash and agent.runtime_hash == latest_hash:
            await _clear_agent_runtime_update(agent_key)
            return
        update_payload = await asyncio.to_thread(
            create_agent_runtime_update_payload,
            server_url,
        )
        effective_target = str(update_payload.get("hash") or latest_hash or target_hash)
        if effective_target and effective_target != target_hash:
            now = datetime.now(timezone.utc).isoformat()
            await run_store_call(
                store,
                "set_agent_runtime_update_record",
                agent_key,
                status=constants._RUNTIME_UPDATE_UPDATING,
                target_hash=effective_target,
                server_url=server_url,
                requested_at=requested_at or now,
                started_at=started_at or now,
            )
            _sync_live_agent_update_state(
                agent_key,
                status=constants._RUNTIME_UPDATE_UPDATING,
                target_hash=effective_target,
            )
        sent = await send_agent_command(
            agent_id,
            {
                "type": "task",
                "runtime_update_only": True,
                "agent_runtime_update": update_payload,
            },
        )
        if sent:
            recorded = _record_legacy_runtime_update_dispatch(
                agent_key,
                agent_id,
                agent,
                effective_target,
                update_payload,
                existing=attempt,
            )
            logger.info(
                "Re-dispatched legacy Agent runtime update: agent_key=%s target=%s retry=%d downloaded=%s",
                agent_key,
                effective_target[:12],
                recorded.retry_count,
                recorded.downloaded_at is not None,
            )
    except Exception:
        logger.exception(
            "Failed to re-dispatch legacy Agent runtime update for %s",
            agent_key,
        )


async def _process_agent_runtime_updates() -> None:
    """Advance manual and automatic Agent runtime updates by one scheduler tick."""
    global _LAST_STAT_CHECK_MONOTONIC
    from backend.agents.artifacts import _agent_runtime_hash
    from backend.agents.artifacts import create_agent_runtime_update_payload
    from backend.agents.directory import resolve_agent_connection_async
    from backend.agents.gateway import send_agent_command

    store = get_scan_store()
    records = await run_store_call(store, "list_agent_records")

    live_by_key: dict[str, tuple[str, AgentInfo] | None] = {}
    has_graceful_live_agent = False
    for record in records:
        agent_key = str(record.get("agent_key") or "")
        if not agent_key:
            continue
        status = _runtime_update_status(record)
        if status in constants._RUNTIME_UPDATE_ACTIVE_STATUSES or auto_runtime_update_enabled():
            live = await resolve_agent_connection_async(agent_key)
            live_by_key[agent_key] = live
            if live is not None and live[1].graceful_runtime_update:
                has_graceful_live_agent = True

    auto_server_hash = ""
    if has_graceful_live_agent:
        stat_interval = _stat_check_interval_seconds()
        now_mono = time.monotonic()
        do_stat_check = (
            stat_interval > 0
            and (_LAST_STAT_CHECK_MONOTONIC <= 0 or now_mono - _LAST_STAT_CHECK_MONOTONIC >= stat_interval)
        )
        if do_stat_check:
            _LAST_STAT_CHECK_MONOTONIC = now_mono
        try:
            auto_server_hash = await get_server_runtime_hash_async(check_stat=do_stat_check)
        except Exception:
            logger.exception("Failed to resolve server Agent runtime hash in scheduler")

    for record in records:
        agent_key = str(record.get("agent_key") or "")
        if not agent_key:
            continue
        status = _runtime_update_status(record)
        target_hash = str(record.get("runtime_update_target_hash") or "")
        live = live_by_key.get(agent_key)

        if status in constants._RUNTIME_UPDATE_ACTIVE_STATUSES:
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
                    _clear_legacy_runtime_update_tracking(agent_key)
                    _sync_live_agent_update_state(
                        agent_key,
                        status=constants._RUNTIME_UPDATE_FAILED,
                        target_hash=target_hash,
                        error="Agent 更新后未在规定时间内以目标版本重连",
                    )
                    logger.warning(
                        "Agent runtime update timed out: agent_key=%s target=%s",
                        agent_key,
                        target_hash[:12],
                    )
                    continue
                if live is not None and not live[1].graceful_runtime_update:
                    await _maybe_retry_legacy_updating_agent(
                        store,
                        agent_key=agent_key,
                        record=record,
                        target_hash=target_hash,
                        age=age,
                        agent_id=live[0],
                        agent=live[1],
                    )
                continue

            if status == constants._RUNTIME_UPDATE_DRAINING:
                if live is None:
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
                            error="Agent 在等待任务排空期间离线超时",
                        )
                        _sync_live_agent_update_state(
                            agent_key,
                            status=constants._RUNTIME_UPDATE_FAILED,
                            target_hash=target_hash,
                            error="Agent 在等待任务排空期间离线超时",
                        )
                    continue
                agent_id, agent = live
                if (
                    agent.graceful_runtime_update
                    and auto_server_hash
                    and auto_server_hash != target_hash
                ):
                    await dispatch_graceful_runtime_update(
                        agent_key,
                        agent_id,
                        agent,
                        server_url=str(record.get("runtime_update_server_url") or agent.server_url or ""),
                        target_hash=auto_server_hash,
                        record=record,
                        active_work_hint=True,
                        is_manual=True,
                    )
                continue

            # status == pending
            if live is None:
                continue
            agent_id, agent = live
            if agent.graceful_runtime_update:
                await dispatch_graceful_runtime_update(
                    agent_key,
                    agent_id,
                    agent,
                    server_url=str(record.get("runtime_update_server_url") or agent.server_url or ""),
                    target_hash=auto_server_hash or target_hash,
                    record=record,
                    is_manual=True,
                )
                continue

            # Legacy Agent without graceful drain support: wait until fully idle.
            if _is_in_legacy_stop_settle(agent_key):
                continue
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
                _clear_legacy_runtime_update_tracking(agent_key)
                _sync_live_agent_update_state(
                    agent_key,
                    status=constants._RUNTIME_UPDATE_FAILED,
                    target_hash=target_hash,
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
                _sync_live_agent_update_state(
                    agent_key,
                    status=constants._RUNTIME_UPDATE_UPDATING,
                    target_hash=target_hash,
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
                    _sync_live_agent_update_state(
                        agent_key,
                        status=constants._RUNTIME_UPDATE_PENDING,
                        target_hash=target_hash,
                    )
                    continue
                agent_id, latest_agent = live
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
                    _sync_live_agent_update_state(
                        agent_key,
                        status=constants._RUNTIME_UPDATE_PENDING,
                        target_hash=target_hash,
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
                    _sync_live_agent_update_state(
                        agent_key,
                        status=constants._RUNTIME_UPDATE_PENDING,
                        target_hash=target_hash,
                    )
                    continue
                _record_legacy_runtime_update_dispatch(
                    agent_key,
                    agent_id,
                    latest_agent,
                    str(update_payload.get("hash") or target_hash),
                    update_payload,
                )
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
                _clear_legacy_runtime_update_tracking(agent_key)
                _sync_live_agent_update_state(
                    agent_key,
                    status=constants._RUNTIME_UPDATE_FAILED,
                    target_hash=target_hash,
                    error=f"下发 Agent 更新失败：{exc}",
                )
            continue

        # Automatic detection for online graceful-update Agents (busy or idle).
        if not auto_runtime_update_enabled() or not auto_server_hash or live is None:
            continue
        agent_id, agent = live
        if not agent.graceful_runtime_update or not agent.runtime_hash:
            continue
        if agent.runtime_hash == auto_server_hash:
            if status == constants._RUNTIME_UPDATE_FAILED:
                await _clear_agent_runtime_update(agent_key)
            continue
        if status == constants._RUNTIME_UPDATE_FAILED and target_hash == auto_server_hash:
            continue
        await dispatch_graceful_runtime_update(
            agent_key,
            agent_id,
            agent,
            server_url=str(agent.server_url or record.get("runtime_update_server_url") or ""),
            target_hash=auto_server_hash,
            record=record,
            is_manual=False,
        )


async def run_agent_runtime_update_scheduler() -> None:
    """Continuously advance manual and automatic Agent runtime updates."""
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
    current_user: User = None,
) -> dict:
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

    agent_id, agent = live
    target_hash = await get_server_runtime_hash_async(check_stat=True)
    if agent.runtime_hash and agent.runtime_hash == target_hash:
        await _clear_agent_runtime_update(agent_key)
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
        message = (
            "Agent 正在更新"
            if current_status == constants._RUNTIME_UPDATE_UPDATING
            else (
                "Agent 已暂停创建新会话，正在等待当前在途任务完成后更新"
                if current_status == constants._RUNTIME_UPDATE_DRAINING
                else "更新请求已在等待 Agent 空闲"
            )
        )
        return {
            "status": current_status,
            "target_hash": target_hash,
            "message": message,
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
    get_runtime().agents.legacy_runtime_update_attempts.pop(agent_key, None)
    _sync_live_agent_update_state(
        agent_key,
        status=constants._RUNTIME_UPDATE_PENDING,
        target_hash=target_hash,
    )
    logger.info(
        "Agent runtime update requested: agent_key=%s user=%s target=%s graceful=%s",
        agent_key,
        current_user.username,
        target_hash[:12],
        agent.graceful_runtime_update,
    )

    if agent.graceful_runtime_update:
        dispatched = await dispatch_graceful_runtime_update(
            agent_key,
            agent_id,
            agent,
            server_url=server_url,
            target_hash=target_hash,
            record={
                **(record or {}),
                "runtime_update_server_url": server_url,
                "runtime_update_requested_at": now,
            },
            is_manual=True,
        )
        if dispatched == constants._RUNTIME_UPDATE_DRAINING:
            return {
                "status": constants._RUNTIME_UPDATE_DRAINING,
                "target_hash": target_hash,
                "message": "已通知 Agent 暂停创建新会话，将在当前在途任务完成后自动更新并继续扫描",
            }
        if dispatched == constants._RUNTIME_UPDATE_UPDATING:
            return {
                "status": constants._RUNTIME_UPDATE_UPDATING,
                "target_hash": target_hash,
                "message": "已下发更新，Agent 正在更新并重连",
            }
        if dispatched == "up_to_date":
            return {
                "status": "up_to_date",
                "target_hash": target_hash,
                "message": "Agent 已是最新版本",
            }

    return {
        "status": constants._RUNTIME_UPDATE_PENDING,
        "target_hash": target_hash,
        "message": "更新请求已提交，Agent 将在全部任务空闲后自动更新",
    }
