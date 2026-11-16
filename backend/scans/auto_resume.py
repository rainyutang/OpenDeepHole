"""Durable, bounded continuation of a scan and its false-positive reviews.

Callbacks only enqueue an evaluation. Dispatch runs outside the reporting
request, so waiting for the old Agent execution to exit cannot deadlock its
final HTTP report. Database reservations also cover review-only continuations.
"""

from __future__ import annotations

import asyncio
import time

from backend.application import ApplicationError, get_runtime, get_scan_store, publish, run_store_call
from backend.logger import get_logger
from backend.models import ScanItemStatus, User
from backend.scan_metrics import latest_fp_review_result_map
from backend.scans.fp_review_policy import _automatic_fp_review_resume_state
from backend.scans.resume_policy import build_resume_plan

logger = get_logger(__name__)
AUTO_RESUME_LIMIT = 3
AUTO_RESUME_RECHECK_SECONDS = 30
_ACTIVE = {ScanItemStatus.PENDING, ScanItemStatus.ANALYZING, ScanItemStatus.AUDITING}


async def publish_auto_resume(scan_id: str) -> None:
    record = await run_store_call(get_scan_store(), "get_scan_auto_resume", scan_id)
    if record is None:
        return
    fields = {key: record[key] for key in (
        "auto_resume_enabled", "auto_resume_count", "auto_resume_state", "auto_resume_reason",
    )}
    fields["auto_resume_enabled"] = bool(fields["auto_resume_enabled"])
    live = get_runtime().scans.running_scans.get(scan_id)
    if live is not None:
        for key, value in fields.items():
            setattr(live, key, value)
    publish(scan_id, "scan_status", {
        "execution_revision": record["execution_revision"], **fields,
    })


async def notify_auto_resume(scan_id: str, server_url: str = "") -> None:
    """Persist the callback's intent; paused/deleted scans cannot be revived."""
    store = get_scan_store()
    if not hasattr(store, "schedule_scan_auto_resume"):
        return
    if not await run_store_call(store, "schedule_scan_auto_resume", scan_id, server_url=server_url):
        return
    await publish_auto_resume(scan_id)
    get_runtime().scans.auto_resume_wakeup.set()


async def _renew_reservation(scan_id: str, token: str) -> None:
    while True:
        await asyncio.sleep(AUTO_RESUME_RECHECK_SECONDS)
        if not await run_store_call(get_scan_store(), "renew_scan_resume_reservation", scan_id, token):
            return


async def acquire_resume_dispatch(
    scan_id: str, *, automatic: bool, expected_revision: int,
    server_url: str, expected_fp_revisions=None,
) -> str:
    """Called after read-only preflights, before mutating either execution."""
    await run_store_call(get_scan_store(), "recover_scan_resume_reservation", scan_id)
    token = await run_store_call(
        get_scan_store(), "reserve_scan_resume", scan_id,
        expected_revision=expected_revision, automatic=automatic,
        server_url=server_url, expected_fp_revisions=expected_fp_revisions,
    )
    if not token:
        raise ApplicationError(409, "扫描已在续扫、被停止或自动续扫次数已用尽")
    get_runtime().scans.resume_heartbeats[token] = asyncio.create_task(_renew_reservation(scan_id, token))
    await publish_auto_resume(scan_id)
    return token


async def verify_resume_dispatch(scan_id: str, token: str) -> None:
    if not await run_store_call(get_scan_store(), "check_scan_resume_reservation", scan_id, token):
        raise ApplicationError(409, "续扫已被停止或轮次已过期")


async def finish_resume_dispatch(
    scan_id: str, token: str, *, failed: bool = False, reason: str = "",
) -> None:
    heartbeat = get_runtime().scans.resume_heartbeats.pop(token, None)
    if heartbeat is not None:
        heartbeat.cancel()
        await asyncio.gather(heartbeat, return_exceptions=True)
    await run_store_call(
        get_scan_store(), "finish_scan_resume_reservation", scan_id, token,
        state="waiting" if failed else "running", reason=reason,
    )
    await publish_auto_resume(scan_id)
    # Failures need no Agent callback. The periodic sweep will retry them;
    # don't immediately spin through the remaining budget on dispatch errors.


async def pause_auto_resume(scan_id: str) -> None:
    await run_store_call(get_scan_store(), "pause_scan_auto_resume", scan_id)
    await publish_auto_resume(scan_id)


async def _set_state(scan_id: str, state: str, reason: str = "", *, round_id=None) -> None:
    await run_store_call(
        get_scan_store(), "set_scan_auto_resume_state", scan_id, state,
        reason=reason, round_id=round_id,
    )
    await publish_auto_resume(scan_id)


async def _start_initial_review(scan_id: str, meta, server_url: str) -> None:
    """Complete a fast scan's first-review handoff without charging a retry.

    The normal finish callback starts this review. If a very fast resumed scan
    finishes while its resume dispatcher still owns the handoff, that callback
    defers review creation. Reuse its durable finish fence to close that gap,
    and only use this path when no review job exists yet.
    """
    store = get_scan_store()
    token = await run_store_call(
        store, "acquire_scan_finish", scan_id,
        agent_session_id=meta.execution_agent_session_id, execution_revision=meta.execution_revision,
    )
    if token is None:
        return
    owner = asyncio.current_task()

    async def renew():
        while True:
            await asyncio.sleep(AUTO_RESUME_RECHECK_SECONDS)
            if not await run_store_call(store, "renew_scan_finish", scan_id, token):
                if owner is not None:
                    owner.cancel()
                return

    heartbeat = asyncio.create_task(renew())
    try:
        if await run_store_call(store, "get_fp_review_by_scan", scan_id) is not None:
            return
        from backend.scans.fp_review import _start_fp_review
        await _start_fp_review(scan_id, server_url, require_unresolved=True, allow_cancelled=False)
    except ApplicationError as exc:
        await _set_state(scan_id, "waiting", str(exc.detail))
    except Exception:
        logger.exception("Unable to start initial FP review for scan %s", scan_id)
        await _set_state(scan_id, "waiting", "首次去误报暂未启动，将稍后重试")
    finally:
        heartbeat.cancel()
        await asyncio.gather(heartbeat, return_exceptions=True)
        await run_store_call(store, "release_scan_finish", scan_id, token)


async def process_auto_resume(scan_id: str, server_url: str = "") -> None:
    """Evaluate one durable entry against current results, never pool history."""
    store = get_scan_store()
    await run_store_call(store, "recover_scan_resume_reservation", scan_id)
    record = await run_store_call(store, "get_scan_auto_resume", scan_id)
    if not record or not record["auto_resume_enabled"] or record["auto_resume_state"] in {"paused", "exhausted"}:
        return
    if record.get("lease_until", 0) > time.time() or record.get("finish_until", 0) > time.time():
        return
    server_url = server_url or record.get("server_url", "")
    if not server_url:
        return
    # Avoid materializing every result while any primary execution is active.
    if record["status"] in _ACTIVE:
        return
    states_by_scan = await run_store_call(store, "list_fp_review_states_by_scans", [scan_id])
    states = states_by_scan.get(scan_id, [])
    if any(status in {"pending", "running"} for _, status in states):
        return
    loaded = await run_store_call(store, "load_scan", scan_id)
    if loaded is None:
        return
    scan, meta = loaded
    if scan.status in _ACTIVE:
        return
    # Explicit stops are never interpreted as failed work. Infrastructure
    # interruption/recovery retains ownership of its existing execution.
    if scan.status == ScanItemStatus.CANCELLED:
        if scan.error_message == "用户手动停止":
            await pause_auto_resume(scan_id)
        return
    processed, verdicts = await asyncio.gather(
        run_store_call(store, "get_processed_keys", scan_id),
        run_store_call(store, "list_fp_review_verdicts_by_scans", [scan_id]),
    )
    plan = build_resume_plan(scan, meta, processed)
    active, fp_count = _automatic_fp_review_resume_state(
        scan, latest_fp_review_result_map(verdicts.get(scan_id, [])), states,
    )
    if active:
        return
    if not plan.resume_main_scan and not fp_count:
        await _set_state(scan_id, "idle", round_id=record.get("round_id"))
        return
    if scan.status == ScanItemStatus.COMPLETE and scan.auto_fp_review and not states and fp_count:
        await _start_initial_review(scan_id, meta, server_url)
        return
    recovering_unsent = bool(
        record.get("automatic") and record.get("lease_until", 0) > 0
        and record["lease_until"] <= time.time() and not record.get("dispatch_started")
        and record.get("source_revision") == meta.execution_revision
    )
    if int(record["auto_resume_count"]) >= AUTO_RESUME_LIMIT and not recovering_unsent:
        await _set_state(scan_id, "exhausted", "已达自动续扫上限，可手动续扫", round_id=record.get("round_id"))
        return
    from backend.scans.continuation import _continue_scan
    try:
        await _continue_scan(
            scan_id, server_url,
            User(user_id=meta.user_id, username="auto-resume", role="user"),
            skip_owner_check=True, auto_resume_round="auto",
            auto_resume_expected_revision=meta.execution_revision,
        )
    except ApplicationError as exc:
        await _set_state(scan_id, "waiting", str(exc.detail), round_id=record.get("round_id"))
        logger.info("Auto resume deferred scan=%s: %s", scan_id, exc.detail)
    except Exception as exc:
        logger.exception("Auto resume failed scan=%s", scan_id)
        await _set_state(scan_id, "waiting", "自动续扫暂未启动，将稍后重试", round_id=record.get("round_id"))


async def run_auto_resume_scheduler() -> None:
    """Wake on callbacks and recover pending work without loading old scans."""
    wakeup = get_runtime().scans.auto_resume_wakeup
    tasks: dict[str, asyncio.Task] = {}
    semaphore = asyncio.Semaphore(4)

    async def process(record):
        async with semaphore:
            await process_auto_resume(record["scan_id"], record.get("server_url", ""))

    try:
        while True:
            wakeup.clear()
            try:
                records = await run_store_call(get_scan_store(), "list_scan_auto_resume_pending")
                for record in records:
                    scan_id = record["scan_id"]
                    previous = tasks.get(scan_id)
                    if previous is not None and not previous.done():
                        continue
                    if previous is not None:
                        # Consume exceptions so an isolated scan cannot stop the scheduler.
                        await asyncio.gather(previous, return_exceptions=True)
                    tasks[scan_id] = asyncio.create_task(process(record))
                for scan_id, task in list(tasks.items()):
                    if task.done():
                        await asyncio.gather(task, return_exceptions=True)
                        tasks.pop(scan_id, None)
            except Exception:
                logger.exception("Unable to sweep pending automatic scan continuations")
            try:
                await asyncio.wait_for(wakeup.wait(), timeout=AUTO_RESUME_RECHECK_SECONDS)
                # Give the notifying final-report HTTP request time to return.
                await asyncio.sleep(1)
            except asyncio.TimeoutError:
                pass
    finally:
        for task in tasks.values():
            task.cancel()
        await asyncio.gather(*tasks.values(), return_exceptions=True)
