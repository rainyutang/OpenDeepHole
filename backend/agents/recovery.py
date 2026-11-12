"""Recovery services for Agent-backed scans."""

from __future__ import annotations
from backend.agents import constants
from backend.scan_runtime import (
    AGENT_DISCONNECT_ERROR,
    AGENT_RECOVERY_FAILED_PREFIX,
    AGENT_RECOVERY_IN_PROGRESS,
    RUNNING_SCAN_STATUSES as _RUNNING_SCAN_STATUSES,
    terminal_opencode_pool_status as _terminal_opencode_pool_status,
    is_agent_recovery_interruption,
)
from backend.models import AgentInfo, ScanItemStatus, User
from backend.application import (
    ApplicationError as HTTPException,
    get_runtime,
    get_scan_store,
    publish,
    run_store_call,
)
from backend.agents.interfaces import AgentConnection as WebSocket
import asyncio
from datetime import datetime, timezone
from backend.logger import get_logger
logger = get_logger(__name__)


def _schedule_agent_disconnect_cancel(agent_id: str) -> None:
    agent_key = str(
        getattr(get_runtime().agents.registered_agents.get(agent_id), "agent_key", "") or ""
    )
    old_task = get_runtime().agents.agent_disconnect_tasks.pop(agent_id, None)
    if old_task is not None:
        old_task.cancel()

    async def _delayed_cancel() -> None:
        try:
            await asyncio.sleep(constants._AGENT_DISCONNECT_GRACE_SECONDS)
            store = get_scan_store()
            if agent_key and getattr(store, "distributed", False):
                live = await run_store_call(
                    store,
                    "get_live_agent_session",
                    agent_key=agent_key,
                    stale_seconds=constants._WEBSOCKET_AGENT_STALE_SECONDS,
                )
                if live is not None and str(live["agent_id"]) != agent_id:
                    return
            await _mark_agent_scans_cancelled_async(agent_id)
        except asyncio.CancelledError:
            return
        finally:
            get_runtime().agents.agent_disconnect_tasks.pop(agent_id, None)

    get_runtime().agents.agent_disconnect_tasks[agent_id] = asyncio.create_task(_delayed_cancel())


def _is_infrastructure_interruption(scan_status: ScanItemStatus, error_message: str | None) -> bool:
    """Return True for states caused by server/connection loss, not user intent."""
    if is_agent_recovery_interruption(scan_status, error_message):
        return True
    if scan_status == ScanItemStatus.CANCELLED:
        return error_message == AGENT_DISCONNECT_ERROR
    if scan_status == ScanItemStatus.ERROR:
        return error_message == constants._SERVER_RESTART_ERROR
    return scan_status in (
        ScanItemStatus.PENDING,
        ScanItemStatus.ANALYZING,
        ScanItemStatus.AUDITING,
    )


def _best_running_status(scan_total_candidates: int, static_done: bool) -> ScanItemStatus:
    if static_done or scan_total_candidates > 0:
        return ScanItemStatus.AUDITING
    return ScanItemStatus.ANALYZING


def _agent_disconnect_grace_elapsed() -> bool:
    return (
        datetime.now(timezone.utc) - constants._SERVER_STARTED_AT
    ).total_seconds() >= constants._AGENT_DISCONNECT_GRACE_SECONDS


def _cancel_scan_if_agent_offline(
    scan_id: str,
    agent_name: str,
    status: ScanItemStatus,
) -> tuple[bool, bool]:
    """Cancel a running scan once its owning agent is offline past the grace period.

    Returns ``(agent_online, cancelled)``.
    """
    from backend.agents.directory import is_agent_name_online
    # In PostgreSQL mode the WebSocket may belong to another Uvicorn worker.
    # The leader's durable stale-session sweep owns cancellation; a process-
    # local registry must never cancel shared work.
    if getattr(get_scan_store(), "distributed", False):
        return False, False
    agent_online = is_agent_name_online(agent_name)
    if agent_online or status not in _RUNNING_SCAN_STATUSES:
        return agent_online, False
    if not _agent_disconnect_grace_elapsed():
        return agent_online, False

    store = get_scan_store()
    store.update_scan_progress(
        scan_id,
        status=ScanItemStatus.CANCELLED,
        error_message=AGENT_DISCONNECT_ERROR,
        clear_current_candidate=True,
    )
    store.mark_fp_reviews_for_scan_error(scan_id, AGENT_DISCONNECT_ERROR)
    get_runtime().scans.running_scans.pop(scan_id, None)
    get_runtime().scans.scan_owners.pop(scan_id, None)
    logger.info("Scan %s cancelled because agent %s is offline", scan_id, agent_name)
    return agent_online, True


def reconcile_offline_agent_scan_state(scan_id: str, scan: ScanStatus) -> ScanStatus:
    """Cancel a running scan once its owning agent is offline past the grace period."""
    if not scan.agent_name:
        return scan

    agent_online, cancelled = _cancel_scan_if_agent_offline(
        scan_id, scan.agent_name, scan.status
    )
    scan.agent_online = agent_online
    if cancelled:
        scan.status = ScanItemStatus.CANCELLED
        scan.error_message = AGENT_DISCONNECT_ERROR
        scan.current_candidate = None
        scan.opencode_pool = _terminal_opencode_pool_status(scan.opencode_pool)
    return scan


def reconcile_offline_agent_summary_state(summary: ScanSummary) -> ScanSummary:
    """Summary-level variant of reconcile that avoids loading the full ScanStatus."""
    if not summary.agent_name:
        return summary

    agent_online, cancelled = _cancel_scan_if_agent_offline(
        summary.scan_id, summary.agent_name, summary.status
    )
    summary.agent_online = agent_online
    if cancelled:
        summary.status = ScanItemStatus.CANCELLED
    return summary


def _reported_work_ids(items: object, *keys: str) -> set[tuple[str, ...]]:
    values: set[tuple[str, ...]] = set()
    if not isinstance(items, list):
        return values
    for item in items:
        if not isinstance(item, dict):
            continue
        identity = tuple(
            str(item.get(key)) if item.get(key) is not None else ""
            for key in keys
        )
        if all(identity):
            values.add(identity)
    return values


def _reported_execution_matches(item: dict, revision: int) -> bool:
    if item.get("cancel_requested"):
        return False
    try:
        reported_revision = int(item.get("execution_revision") or 0)
    except (TypeError, ValueError):
        return False
    return reported_revision == revision


def _matching_active_execution(items: object, row: dict, *keys: str) -> bool:
    return isinstance(items, list) and any(
        isinstance(item, dict)
        and all(str(item.get(key, "")) == str(row.get(key, "")) for key in keys)
        and _reported_execution_matches(item, int(row.get("execution_revision") or 0))
        for item in items
    )


async def _adopt_reported_agent_work(agent_id: str, agent: AgentInfo, hello: dict) -> list[dict]:
    """Finish execution ownership transfer before welcome releases publishers."""
    kinds = (
        ("scan", "scans", "active_scans", ("scan_id",)),
        ("fp_review", "fp_reviews", "active_fp_reviews", ("scan_id", "review_id")),
        ("validation", "validations", "active_validations", ("scan_id", "vuln_index")),
    )
    if not any(hello.get(active) for _, _, active, _ in kinds):
        return []
    store = get_scan_store()
    inflight = await run_store_call(store, "list_agent_inflight_executions", agent.agent_key, agent_id)
    accepted_scans: list[dict] = []
    for kind, collection, active, keys in kinds:
        for row in inflight.get(collection, []):
            if not _matching_active_execution(hello.get(active), row, *keys):
                continue
            previous = str(row.get("execution_agent_session_id") or "")
            adopted = previous == agent.agent_session_id
            if not adopted:
                adopted = await run_store_call(
                    store, "adopt_active_execution", kind,
                    str(row["review_id"] if kind == "fp_review" else row["scan_id"]),
                    int(row["vuln_index"]) if kind == "validation" else None,
                    previous_session_id=previous,
                    agent_session_id=agent.agent_session_id,
                    execution_revision=int(row.get("execution_revision") or 0),
                )
            if adopted and kind == "scan":
                accepted_scans.append({
                    "scan_id": row["scan_id"],
                    "execution_revision": int(row.get("execution_revision") or 0),
                })
    return accepted_scans


async def _recover_missing_agent_work(
    agent_id: str,
    agent: AgentInfo,
    hello: dict,
    *,
    server_url: str,
) -> None:
    """Resume durable non-terminal work missing from this Agent process."""
    store = get_scan_store()
    inflight = await run_store_call(
        store,
        "list_agent_inflight_executions",
        agent.agent_key,
        agent_id,
    )
    active_scans = {
        (str(row["scan_id"]),) for row in inflight.get("scans", [])
        if _matching_active_execution(hello.get("active_scans"), row, "scan_id")
    }
    active_fp = {
        (str(row["scan_id"]), str(row["review_id"])) for row in inflight.get("fp_reviews", [])
        if _matching_active_execution(hello.get("active_fp_reviews"), row, "scan_id", "review_id")
    }
    active_validations = _reported_work_ids(
        hello.get("active_validations"),
        "scan_id",
        "vuln_index",
    )
    pending = (
        hello.get("pending_terminal_reports")
        if isinstance(hello.get("pending_terminal_reports"), dict)
        else {}
    )
    pending_scans = {
        (str(scan_id),)
        for scan_id in pending.get("scans", [])
        if str(scan_id or "")
    }
    if "scan_executions" in pending:
        pending_scans = {
            (str(row["scan_id"]),) for row in inflight.get("scans", [])
            if _matching_active_execution(pending["scan_executions"], row, "scan_id")
        }
    pending_fp = _reported_work_ids(
        pending.get("fp_reviews"),
        "scan_id",
        "review_id",
    )
    pending_validations = _reported_work_ids(
        pending.get("validations"),
        "scan_id",
        "vuln_index",
    )

    async def adopt(kind: str, work_id: str, sub_id: int | None, row: dict) -> None:
        previous_session = str(row.get("execution_agent_session_id") or "")
        if previous_session == agent.agent_session_id:
            return
        await run_store_call(
            store,
            "adopt_active_execution",
            kind,
            work_id,
            sub_id,
            previous_session_id=previous_session,
            agent_session_id=agent.agent_session_id,
            execution_revision=int(row.get("execution_revision") or 0),
        )

    async def recovery_failed(
        kind: str,
        work_id: str,
        scan_id: str,
        revision: int,
        exc: Exception,
    ) -> None:
        detail = str(exc.detail if isinstance(exc, HTTPException) else exc) or type(exc).__name__
        error = AGENT_RECOVERY_FAILED_PREFIX + detail[:500]
        changed = await run_store_call(
            store, "fail_scan_recovery" if kind == "scan" else "fail_fp_review_recovery", work_id,
            agent_session_id=agent.agent_session_id, execution_revision=revision, error_message=error,
        )
        logger.warning(
            "Agent recovery failed kind=%s id=%s session=%s revision=%s persisted=%s reason=%s",
            kind, work_id, agent.agent_session_id, revision, changed, detail,
        )
        if not changed:
            return
        from backend.application import publish

        if kind == "scan":
            cached = get_runtime().scans.running_scans.get(scan_id)
            if cached is not None and cached.execution_revision == revision:
                get_runtime().scans.running_scans.pop(scan_id, None)
                get_runtime().scans.scan_owners.pop(scan_id, None)
            loaded = await run_store_call(store, "load_scan_runtime", scan_id)
            if loaded is not None:
                scan = loaded[0]
                publish(scan_id, "scan_status", {
                    "execution_revision": scan.execution_revision,
                    "status": scan.status, "error_message": scan.error_message,
                    "opencode_pool": scan.opencode_pool.model_dump(mode="json") if scan.opencode_pool else None,
                })
        else:
            publish(scan_id, "fp_review_finish", {
                "review_id": work_id, "execution_revision": revision,
                "status": "error", "error_message": error,
            })

    for row in inflight.get("scans", []):
        scan_id = str(row.get("scan_id") or "")
        identity = (scan_id,)
        if identity in active_scans:
            await adopt("scan", scan_id, None, row)
            continue
        if identity in pending_scans:
            logger.info(
                "Deferring scan recovery while its terminal outbox report is pending: %s",
                scan_id,
            )
            continue
        previous_session = str(row.get("execution_agent_session_id") or "")
        revision = await run_store_call(
            store,
            "claim_scan_for_agent_recovery",
            scan_id,
            previous_session_id=previous_session,
            agent_id=agent_id,
            agent_session_id=agent.agent_session_id,
            error_message=AGENT_RECOVERY_IN_PROGRESS,
            expected_revision=int(row.get("execution_revision") or 0),
        )
        if revision is None:
            continue
        meta = await run_store_call(store, "get_scan_meta", scan_id)
        if meta is None:
            continue
        from backend.scans.continuation import _continue_scan

        try:
            await _continue_scan(
                scan_id,
                None,
                User(
                    user_id=meta.user_id or agent.user_id,
                    username="agent-recovery",
                    role="admin",
                ),
                server_url_override=server_url,
                skip_owner_check=True,
                claimed_execution_revision=revision,
            )
            logger.warning(
                "Automatically resumed orphaned scan %s after Agent process restart "
                "session=%s revision=%d",
                scan_id,
                agent.agent_session_id,
                revision,
            )
        except Exception as exc:
            await recovery_failed("scan", scan_id, scan_id, revision, exc)

    for row in inflight.get("fp_reviews", []):
        scan_id = str(row.get("scan_id") or "")
        review_id = str(row.get("review_id") or "")
        identity = (scan_id, review_id)
        if identity in active_fp:
            await adopt("fp_review", review_id, None, row)
            continue
        if identity in pending_fp:
            continue
        previous_session = str(row.get("execution_agent_session_id") or "")
        revision = await run_store_call(
            store,
            "claim_fp_review_for_agent_recovery",
            review_id,
            previous_session_id=previous_session,
            agent_session_id=agent.agent_session_id,
        )
        if revision is None:
            continue
        from backend.scans.fp_review import _start_fp_review

        try:
            result = await _start_fp_review(
                scan_id,
                server_url,
                raise_on_error=True,
                require_unresolved=True,
                claimed_execution_revision=revision,
            )
            if result is None:
                raise RuntimeError("去误报恢复未启动，请再次续扫")
            logger.warning(
                "Automatically resumed orphaned FP review %s revision=%d",
                review_id,
                revision,
            )
        except Exception as exc:
            await recovery_failed("fp_review", review_id, scan_id, revision, exc)

    for row in inflight.get("validations", []):
        scan_id = str(row.get("scan_id") or "")
        vuln_index = int(row.get("vuln_index") or 0)
        identity = (scan_id, str(vuln_index))
        if identity in active_validations:
            await adopt("validation", scan_id, vuln_index, row)
            continue
        if identity in pending_validations:
            continue
        previous_session = str(row.get("execution_agent_session_id") or "")
        revision = await run_store_call(
            store,
            "claim_validation_for_agent_recovery",
            scan_id,
            vuln_index,
            previous_session_id=previous_session,
            agent_session_id=agent.agent_session_id,
        )
        if revision is None:
            continue
        from backend.scans.validation import _trigger_vulnerability_validation

        try:
            await _trigger_vulnerability_validation(
                scan_id,
                vuln_index,
                server_url,
                claimed_execution_revision=revision,
            )
            logger.warning(
                "Automatically resumed orphaned validation %s#%d revision=%d",
                scan_id,
                vuln_index,
                revision,
            )
        except Exception:
            logger.exception(
                "Automatic vulnerability validation recovery failed for %s#%d",
                scan_id,
                vuln_index,
            )


def _run_reconnect_helper(coroutine):
    """Keep the established synchronous test/maintenance helper contract."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    raise RuntimeError("Use the async reconnect helper from an event loop")


def _reattach_active_agent_scans(
    agent_id: str,
    agent: AgentInfo,
    active_scans: list,
    pending_stops: list[dict] | None=None,
) -> list[str]:
    from backend.agents.reattachment import _reattach_active_agent_scans_async
    return _run_reconnect_helper(
        _reattach_active_agent_scans_async(
            agent_id,
            agent,
            active_scans,
            pending_stops,
        )
    )


def _reattach_active_fp_reviews(agent_id: str, agent: AgentInfo, active_fp_reviews: list) -> None:
    from backend.agents.reattachment import _reattach_active_fp_reviews_async
    return _run_reconnect_helper(
        _reattach_active_fp_reviews_async(agent_id, agent, active_fp_reviews)
    )


def _reattach_active_validations(
    agent_id: str,
    agent: AgentInfo,
    active_validations: list,
) -> list[dict]:
    from backend.agents.reattachment import _reattach_active_validations_async
    return _run_reconnect_helper(
        _reattach_active_validations_async(agent_id, agent, active_validations)
    )


def _websocket_server_url(websocket: WebSocket) -> str:
    server_url = str(getattr(websocket, "base_url", "http://localhost/")).rstrip("/")
    if server_url.startswith("ws://"):
        return "http://" + server_url[len("ws://"):]
    if server_url.startswith("wss://"):
        return "https://" + server_url[len("wss://"):]
    return server_url


async def _promote_final_callback_agent_reports(
    agent_id: str,
    agent: AgentInfo,
    reattached_scan_ids: list[str],
) -> tuple[list[str], dict[str, list[int]]]:
    """Make callback reports from an upgraded Agent immediately actionable."""
    store = get_scan_store()
    provisional_scan_ids = await run_store_call(
        store,
        "list_provisional_scan_ids_for_agent",
        agent.agent_key,
    )
    candidate_scan_ids = list(dict.fromkeys([
        *reattached_scan_ids,
        *provisional_scan_ids,
    ]))
    recoverable_scan_ids: list[str] = []
    promoted_by_scan: dict[str, list[int]] = {}
    if not candidate_scan_ids:
        return recoverable_scan_ids, promoted_by_scan

    from backend.application import publish

    for scan_id in candidate_scan_ids:
        meta = await run_store_call(store, "get_scan_meta", scan_id)
        if meta is None or not agent.agent_key or meta.agent_key != agent.agent_key:
            continue
        if (
            meta.agent_id
            and meta.agent_id != agent_id
            and meta.agent_id in get_runtime().agents.agent_ws
        ):
            logger.info(
                "Deferred provisional vulnerability promotion for scan %s: "
                "the previous Agent session is still connected",
                scan_id,
            )
            continue

        promoted_indexes = await run_store_call(
            store,
            "promote_provisional_vulnerability_indexes",
            scan_id,
        )
        recoverable_scan_ids.append(scan_id)
        if not promoted_indexes:
            continue

        vulnerabilities = await run_store_call(
            store,
            "get_vulnerabilities",
            scan_id,
        )
        live_scan = get_runtime().scans.running_scans.get(scan_id)
        if live_scan is not None:
            live_scan.vulnerabilities = vulnerabilities
        promoted_by_scan[scan_id] = promoted_indexes
        publish(scan_id, "scan_vulnerabilities_changed", {
            "count": len(vulnerabilities),
        })
        logger.info(
            "Promoted %d callback-reported vulnerability result(s) after Agent "
            "upgrade: agent_key=%s scan_id=%s",
            len(promoted_indexes),
            agent.agent_key,
            scan_id,
        )
    return recoverable_scan_ids, promoted_by_scan


async def _resume_final_callback_downstream(
    agent: AgentInfo,
    scan_ids: list[str],
    promoted_by_scan: dict[str, list[int]],
    *,
    server_url: str,
) -> None:
    """Resume unresolved FP review and validation after the upgraded handshake."""
    if not scan_ids:
        return
    from backend.scans.fp_review_policy import _scan_fp_review_settings
    from backend.scans.fp_review import _start_fp_review
    from backend.scans.validation import _trigger_vulnerability_validation

    store = get_scan_store()
    for scan_id in scan_ids:
        loaded = await run_store_call(store, "load_scan", scan_id)
        if loaded is None:
            continue
        scan, meta = loaded
        if not agent.agent_key or meta.agent_key != agent.agent_key:
            continue
        explicitly_stopped = (
            scan.status == ScanItemStatus.CANCELLED
            and not _is_infrastructure_interruption(
                scan.status,
                scan.error_message,
            )
        )
        if explicitly_stopped:
            continue

        auto_fp_review, _method = _scan_fp_review_settings(scan_id, scan)
        if auto_fp_review:
            try:
                await _start_fp_review(
                    scan_id,
                    server_url,
                    raise_on_error=False,
                    require_unresolved=True,
                    allow_cancelled=False,
                )
            except Exception as exc:
                logger.warning(
                    "Unable to resume automatic FP review after Agent upgrade "
                    "for scan %s: %s",
                    scan_id,
                    exc,
                )

        validation_config = meta.vulnerability_validation
        if (
            validation_config is None
            or not validation_config.enabled
            or not meta.runtime_product
        ):
            continue
        existing_validation_indexes = {
            item.vuln_index for item in scan.validations
        }
        for vuln_index in promoted_by_scan.get(scan_id, []):
            if vuln_index in existing_validation_indexes:
                continue
            if vuln_index < 0 or vuln_index >= len(scan.vulnerabilities):
                continue
            vulnerability = scan.vulnerabilities[vuln_index]
            if not (
                vulnerability.confirmed
                or vulnerability.ai_verdict == "confirmed"
            ):
                continue
            try:
                await _trigger_vulnerability_validation(
                    scan_id,
                    vuln_index,
                    server_url,
                )
            except Exception as exc:
                logger.warning(
                    "Unable to resume vulnerability validation after Agent "
                    "upgrade for scan %s index %d: %s",
                    scan_id,
                    vuln_index,
                    exc,
                )


async def _mark_agent_scans_cancelled_async(agent_id: str) -> None:
    """Mark all running scans belonging to this agent as CANCELLED.

    Called when an agent disconnects so the frontend shows the correct state.
    """
    store = get_scan_store()
    cancelled_scan_ids = set(
        await run_store_call(
            store,
            "mark_agent_scans_cancelled",
            agent_id,
            AGENT_DISCONNECT_ERROR,
        )
    )
    fp_review_count = await run_store_call(
        store,
        "mark_fp_reviews_for_agent_error",
        agent_id,
        AGENT_DISCONNECT_ERROR,
    )

    stale_local_scan_ids: set[str] = set()
    for scan_id in list(get_runtime().scans.running_scans):
        meta = await run_store_call(store, "get_scan_meta", scan_id)
        if meta is None:
            continue
        if meta.agent_id != agent_id:
            continue
        if scan_id in cancelled_scan_ids:
            scan = get_runtime().scans.running_scans.get(scan_id)
            if scan is not None:
                scan.status = ScanItemStatus.CANCELLED
                scan.error_message = AGENT_DISCONNECT_ERROR
                scan.current_candidate = None
                scan.opencode_pool = _terminal_opencode_pool_status(
                    scan.opencode_pool,
                )
            continue
        loaded = await run_store_call(store, "load_scan_runtime", scan_id)
        if loaded is not None and loaded[0].status not in _RUNNING_SCAN_STATUSES:
            stale_local_scan_ids.add(scan_id)

    for scan_id in cancelled_scan_ids | stale_local_scan_ids:
        get_runtime().scans.running_scans.pop(scan_id, None)
        get_runtime().scans.scan_owners.pop(scan_id, None)

    if cancelled_scan_ids:
        from backend.application import publish

        refreshed = await asyncio.gather(*(
            run_store_call(store, "load_scan_runtime", scan_id)
            for scan_id in sorted(cancelled_scan_ids)
        ))
        for scan_id, loaded in zip(sorted(cancelled_scan_ids), refreshed):
            persisted = loaded[0] if loaded is not None else None
            publish(scan_id, "scan_status", {
                "execution_revision": persisted.execution_revision if persisted else 0,
                "status": ScanItemStatus.CANCELLED,
                "error_message": AGENT_DISCONNECT_ERROR,
                "opencode_pool": (
                    persisted.opencode_pool.model_dump(mode="json")
                    if persisted is not None and persisted.opencode_pool is not None
                    else None
                ),
            })

    if cancelled_scan_ids or fp_review_count:
        logger.info(
            "Agent %s disconnect cancelled %d scan(s) and %d FP review job(s)",
            agent_id,
            len(cancelled_scan_ids),
            fp_review_count,
        )


def _mark_agent_scans_cancelled(agent_id: str) -> None:
    return _run_reconnect_helper(_mark_agent_scans_cancelled_async(agent_id))
