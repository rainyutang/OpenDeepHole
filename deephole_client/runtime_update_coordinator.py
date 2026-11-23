"""Drain active Agent work before applying a server runtime update and restarting.

Mirrors ``task_agent.config_reload.ConfigReloadCoordinator``:
- Admission closes synchronously before yielding so no new OpenCode sessions start.
- The update archive is downloaded and verified immediately while its one-time
  download token is fresh.
- Admitted OpenCode tasks, in-flight non-OpenCode phases, and post-lease result
  settlement run to completion; buffered reports and SQLite outbox rows flush
  before OpenCode Serve shuts down and ``os.execv`` replaces the process.
- Running scans, FP reviews, and validations are never sent synthetic
  ``cancelled`` terminal reports so the backend automatically resumes them from
  their latest checkpoints once the updated Agent reconnects.
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
import time
from collections.abc import Awaitable, Callable
from typing import Any

from task_agent.output_format import with_local_timestamp


RUNTIME_UPDATE_HOLD_ID = "runtime_update"
StatusSender = Callable[[dict[str, Any]], Awaitable[None]]


class RuntimeUpdateCoordinator:
    def __init__(
        self,
        *,
        quiescence_seconds: float = 0.3,
        flush_timeout_seconds: float = 30.0,
    ) -> None:
        self._state = "idle"
        self._target_hash = ""
        self._error = ""
        self._generation = 0
        self._pending_update: dict[str, Any] | None = None
        self._fallback_server_url = ""
        self._staged: Any = None
        self._worker: asyncio.Task[None] | None = None
        self._wakeup = asyncio.Event()
        self._status_sender: StatusSender | None = None
        self._reporter: Any = None
        self._config: Any = None
        self._task_manager: Any = None
        self._notified_drain_scans: set[str] = set()
        self._quiescence_seconds = max(0.0, float(quiescence_seconds))
        self._flush_timeout_seconds = max(0.5, float(flush_timeout_seconds))

    def bind_connection(
        self,
        *,
        send_status: StatusSender | None,
        reporter: Any = None,
        config: Any = None,
        task_manager: Any = None,
    ) -> None:
        self._status_sender = send_status
        if reporter is not None:
            self._reporter = reporter
        if config is not None:
            self._config = config
        if task_manager is not None:
            self._task_manager = task_manager

    def unbind_connection(self, send_status: StatusSender | None = None) -> None:
        if send_status is None or self._status_sender is send_status:
            self._status_sender = None

    def _active_counts(self) -> tuple[int, int]:
        from task_agent.config_reload import get_config_reload_coordinator

        reload_coordinator = get_config_reload_coordinator()
        return (
            reload_coordinator.active_task_count(),
            reload_coordinator.active_local_work_count(),
        )

    def status(self) -> dict[str, Any]:
        opencode_tasks, local_work = self._active_counts()
        return {
            "state": self._state,
            "target_hash": self._target_hash,
            "active_tasks": opencode_tasks + local_work,
            "active_opencode_tasks": opencode_tasks,
            "active_local_work": local_work,
            "error": self._error,
        }

    def is_draining_or_updating(self) -> bool:
        return self._state in {"staging", "draining", "updating"}

    def _cleanup_staged(self) -> None:
        staged = self._staged
        self._staged = None
        if staged is not None:
            with contextlib.suppress(Exception):
                staged.cleanup()

    def _release_hold_and_wake(self) -> None:
        from task_agent.config_reload import get_config_reload_coordinator

        get_config_reload_coordinator().release_admission_hold(RUNTIME_UPDATE_HOLD_ID)
        with contextlib.suppress(Exception):
            from deephole_client.server import (
                refresh_fp_review_scheduling,
                refresh_validation_scheduling,
            )

            refresh_fp_review_scheduling()
            refresh_validation_scheduling()

    async def _notify_model_pool(self) -> None:
        from task_agent.model_pool import notify_model_pool_config_changed

        await notify_model_pool_config_changed()

    async def _send_status(
        self,
        *,
        state: str,
        target_hash: str,
        active_tasks: int | None = None,
        error: str = "",
    ) -> None:
        sender = self._status_sender
        if sender is None:
            return
        if active_tasks is None:
            opencode_tasks, local_work = self._active_counts()
            active_tasks = opencode_tasks + local_work
        payload = {
            "type": "runtime_update_status",
            "state": state,
            "target_hash": target_hash,
            "active_tasks": max(0, int(active_tasks)),
            "error": str(error or ""),
        }
        try:
            await sender(payload)
        except Exception:
            pass

    async def _emit_scan_notice(self, message: str, *, once_per_scan: bool = False) -> None:
        reporter = self._reporter
        task_manager = self._task_manager
        if reporter is None or task_manager is None or not hasattr(reporter, "send_event"):
            return
        try:
            from backend.models import ScanEvent

            snapshots = task_manager.active_snapshots()
        except Exception:
            return
        for snapshot in snapshots:
            scan_id = str(snapshot.get("scan_id") or "")
            if not scan_id:
                continue
            if once_per_scan and scan_id in self._notified_drain_scans:
                continue
            if once_per_scan:
                self._notified_drain_scans.add(scan_id)
            with contextlib.suppress(Exception):
                await reporter.send_event(
                    scan_id,
                    ScanEvent.create("agent_update", message),
                )

    def stage_update(
        self,
        update: dict[str, Any] | None,
        *,
        server_url: str = "",
    ) -> bool:
        """Close new-session admission immediately and schedule drain + update."""
        if not isinstance(update, dict):
            return False
        target_hash = str(update.get("hash") or "").strip()
        if not target_hash:
            return False

        from deephole_client.updater import compute_runtime_hash

        local_hash = compute_runtime_hash()
        if target_hash == local_hash:
            self.abort_if_matching(local_hash)
            return False

        if self._state == "updating":
            return False
        if (
            self._state in {"staging", "draining"}
            and self._target_hash == target_hash
        ):
            return True

        from task_agent.config_reload import get_config_reload_coordinator

        get_config_reload_coordinator().hold_admission(RUNTIME_UPDATE_HOLD_ID)
        self._generation += 1
        self._pending_update = copy.deepcopy(update)
        if server_url:
            self._fallback_server_url = str(server_url).strip()
        self._target_hash = target_hash
        self._error = ""
        self._state = "staging"
        self._wakeup.set()
        self._start_worker()
        return True

    def handle_server_runtime_hash(self, server_hash: str) -> None:
        normalized = str(server_hash or "").strip()
        if not normalized:
            return
        from deephole_client.updater import compute_runtime_hash

        if normalized == compute_runtime_hash():
            self.abort_if_matching(normalized)

    def abort_if_matching(self, local_hash: str) -> None:
        """Cancel an outstanding drain when the server matches local runtime again."""
        if self._state in {"idle", "updating"}:
            return
        self._generation += 1
        self._pending_update = None
        self._target_hash = ""
        self._error = ""
        self._state = "idle"
        self._notified_drain_scans.clear()
        self._cleanup_staged()
        self._release_hold_and_wake()
        self._wakeup.set()
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._notify_aborted_up_to_date(local_hash))
        except RuntimeError:
            pass

    async def _notify_aborted_up_to_date(self, local_hash: str) -> None:
        with contextlib.suppress(Exception):
            await self._notify_model_pool()
        await self._send_status(state="up_to_date", target_hash=local_hash, active_tasks=0)

    def _start_worker(self) -> None:
        if self._worker is None or self._worker.done():
            self._worker = asyncio.create_task(
                self._run(),
                name="agent-runtime-update-drain",
            )

    async def _shutdown_opencode(self) -> None:
        try:
            from task_agent import shutdown_opencode

            await shutdown_opencode()
        except Exception as exc:
            print(with_local_timestamp(
                f"SERVE_SHUTDOWN_WARNING error={type(exc).__name__}: {exc}",
                prefix="[agent_update]",
            ), flush=True)

    async def _wait_for_drain(self, generation: int, target_hash: str) -> bool:
        """Wait until all active OpenCode tasks and local work units settle.

        Returns False if superseded by a newer update generation or aborted.
        """
        from task_agent.config_reload import get_config_reload_coordinator

        reload_coordinator = get_config_reload_coordinator()
        last_reported_active: int | None = None

        while True:
            if generation != self._generation or self._state == "idle":
                return False

            opencode_tasks, local_work = self._active_counts()
            active_total = opencode_tasks + local_work
            if active_total != last_reported_active:
                last_reported_active = active_total
                print(with_local_timestamp(
                    f"DRAINING target={target_hash[:12]} "
                    f"active_opencode={opencode_tasks} active_local={local_work}",
                    prefix="[agent_update]",
                ), flush=True)
                await self._send_status(
                    state="draining",
                    target_hash=target_hash,
                    active_tasks=active_total,
                )

            if reload_coordinator.has_pending_work():
                self._wakeup.clear()
                change_wait = asyncio.create_task(reload_coordinator.wait_for_change(timeout=0.25))
                wake_wait = asyncio.create_task(self._wakeup.wait())
                try:
                    await asyncio.wait(
                        {change_wait, wake_wait},
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                finally:
                    for waiter in (change_wait, wake_wait):
                        if not waiter.done():
                            waiter.cancel()
                    await asyncio.gather(change_wait, wake_wait, return_exceptions=True)
                continue

            # Brief quiescence check so coroutines just waking from run_opencode_task
            # can enter track_local_work("post_lease_settlement") before restart.
            if self._quiescence_seconds > 0:
                deadline = time.monotonic() + self._quiescence_seconds
                reentered_work = False
                while time.monotonic() < deadline:
                    await asyncio.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
                    if generation != self._generation or self._state == "idle":
                        return False
                    if reload_coordinator.has_pending_work():
                        reentered_work = True
                        break
                if reentered_work:
                    continue
            else:
                await asyncio.sleep(0)
                if generation != self._generation or self._state == "idle":
                    return False
                if reload_coordinator.has_pending_work():
                    continue
            return True

    async def _run(self) -> None:
        from deephole_client.updater import (
            _restart_process,
            install_staged_runtime_update,
            stage_runtime_update,
        )
        from task_agent.config_reload import get_config_reload_coordinator

        try:
            await self._notify_model_pool()
            await self._emit_scan_notice(
                "检测到服务端已更新，已暂停创建新会话，等待当前在途任务完成后自动更新 Agent 并继续扫描",
                once_per_scan=True,
            )

            while True:
                if self._state == "idle":
                    return
                generation = self._generation
                update = copy.deepcopy(self._pending_update)
                target_hash = self._target_hash
                if not update or not target_hash:
                    return

                if self._staged is None or self._staged.target_hash != target_hash:
                    self._state = "staging"
                    print(with_local_timestamp(
                        f"STAGING target={target_hash[:12]}",
                        prefix="[agent_update]",
                    ), flush=True)
                    try:
                        staged = await stage_runtime_update(
                            update,
                            fallback_server_url=self._fallback_server_url,
                        )
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        if generation != self._generation:
                            continue
                        self._error = f"Agent 更新包下载或校验失败：{exc}"
                        self._state = "failed"
                        print(with_local_timestamp(
                            f"STAGING_FAILED target={target_hash[:12]} error={exc}",
                            prefix="[agent_update]",
                        ), flush=True)
                        self._cleanup_staged()
                        self._notified_drain_scans.clear()
                        self._release_hold_and_wake()
                        await self._notify_model_pool()
                        await self._send_status(
                            state="failed",
                            target_hash=target_hash,
                            error=self._error,
                        )
                        return

                    if generation != self._generation:
                        if staged is not None:
                            with contextlib.suppress(Exception):
                                staged.cleanup()
                        continue

                    if staged is None:
                        self._state = "idle"
                        self._target_hash = ""
                        self._error = ""
                        self._notified_drain_scans.clear()
                        self._cleanup_staged()
                        self._release_hold_and_wake()
                        await self._notify_model_pool()
                        await self._send_status(
                            state="up_to_date",
                            target_hash=target_hash,
                            active_tasks=0,
                        )
                        return

                    self._cleanup_staged()
                    self._staged = staged

                self._state = "draining"
                drained = await self._wait_for_drain(generation, target_hash)
                if not drained:
                    continue

                if generation != self._generation or self._staged is None:
                    continue

                self._state = "updating"
                print(with_local_timestamp(
                    f"APPLYING target={target_hash[:12]}",
                    prefix="[agent_update]",
                ), flush=True)
                await self._emit_scan_notice(
                    "当前在途任务已全部完成，正在更新 Agent 并将在重启重连后自动继续扫描",
                )
                await self._send_status(
                    state="updating",
                    target_hash=target_hash,
                    active_tasks=0,
                )

                try:
                    reporter = self._reporter
                    if reporter is not None and hasattr(reporter, "flush_for_restart"):
                        await reporter.flush_for_restart(
                            timeout=self._flush_timeout_seconds,
                        )
                    await get_config_reload_coordinator().shutdown()
                    await self._shutdown_opencode()

                    staged = self._staged
                    self._staged = None
                    assert staged is not None
                    await asyncio.to_thread(install_staged_runtime_update, staged)
                    if reporter is not None and hasattr(reporter, "close"):
                        await reporter.close()
                    _restart_process(reason="runtime_update")
                    return
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    self._error = f"Agent 更新安装失败：{exc}"
                    self._state = "failed"
                    print(with_local_timestamp(
                        f"APPLY_FAILED target={target_hash[:12]} error={exc}",
                        prefix="[agent_update]",
                    ), flush=True)
                    self._cleanup_staged()
                    self._notified_drain_scans.clear()
                    self._release_hold_and_wake()
                    with contextlib.suppress(Exception):
                        await self._notify_model_pool()
                    await self._send_status(
                        state="failed",
                        target_hash=target_hash,
                        error=self._error,
                    )
                    return
        finally:
            self._worker = None

    async def shutdown(self) -> None:
        worker = self._worker
        if worker is not None:
            worker.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await worker
        self._cleanup_staged()
        self._notified_drain_scans.clear()
        self._release_hold_and_wake()


_coordinator: RuntimeUpdateCoordinator | None = None


def get_runtime_update_coordinator() -> RuntimeUpdateCoordinator:
    global _coordinator
    if _coordinator is None:
        _coordinator = RuntimeUpdateCoordinator()
    return _coordinator


def reset_runtime_update_coordinator(
    coordinator: RuntimeUpdateCoordinator | None = None,
) -> RuntimeUpdateCoordinator:
    """Test helper to swap or reset the module singleton."""
    global _coordinator
    _coordinator = coordinator if coordinator is not None else RuntimeUpdateCoordinator()
    return _coordinator
