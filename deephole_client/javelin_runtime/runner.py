"""Standalone client runner for Java + Javelin scans with guaranteed /finish convergence."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Callable

from backend.models import JAVELIN_ENGINE_ID, has_javelin_engine
from deephole_client.javelin_runtime.manager import (
    default_javelin_data_root,
    get_javelin_service_manager,
)
from deephole_client.javelin_runtime.observer import (
    DEBOUNCE_SECONDS,
    FALLBACK_POLL_SECONDS,
    JavelinAuditObserver,
)

logger = logging.getLogger(__name__)

_TERMINAL_JAVELIN_STATUSES = frozenset({"completed", "failed", "cancelled", "interrupted"})
_TESTING_SERVICE_FACTORY: Callable[[], Any] | None = None
_ACTIVE_OBSERVERS: dict[str, JavelinAuditObserver] = {}


def set_javelin_service_factory_for_testing(factory: Callable[[], Any] | None) -> None:
    global _TESTING_SERVICE_FACTORY
    _TESTING_SERVICE_FACTORY = factory


def _resolve_service() -> Any:
    if _TESTING_SERVICE_FACTORY is not None:
        return _TESTING_SERVICE_FACTORY()
    return get_javelin_service_manager()


def is_javelin_task(task: Any) -> bool:
    """Return True when ScanTask or command dict targets the Javelin Java pipeline."""
    lang = (
        task.get("language")
        if isinstance(task, dict)
        else getattr(task, "language", "c_cpp")
    )
    if str(lang or "").strip().lower() == "java":
        return True
    engines = (
        task.get("mining_engines")
        if isinstance(task, dict)
        else getattr(task, "mining_engines", None)
    )
    return has_javelin_engine(engines)


def has_active_javelin_work() -> bool:
    if _ACTIVE_OBSERVERS:
        return True
    mgr = _TESTING_SERVICE_FACTORY() if _TESTING_SERVICE_FACTORY is not None else _GLOBAL_MGR_IF_ANY()
    return bool(mgr and hasattr(mgr, "has_active_work") and mgr.has_active_work())


def _GLOBAL_MGR_IF_ANY() -> Any:
    from deephole_client.javelin_runtime import manager

    return manager._GLOBAL_JAVELIN_MANAGER


def _map_javelin_terminal_to_deephole_status(j_status: str, error_msg: str) -> tuple[str, str | None]:
    norm = str(j_status or "").strip().lower()
    if norm == "completed":
        return "complete", None
    if norm == "cancelled":
        return "cancelled", error_msg or "用户取消 Javelin 扫描"
    if norm == "interrupted":
        return "error", error_msg or "Javelin 执行中断（可断点恢复）"
    return "error", error_msg or "Javelin 扫描执行失败"


async def run_javelin_scan(
    *,
    config: Any,
    task: Any,
    reporter: Any,
    action: str = "start",
) -> None:
    """Execute a full Javelin Java scan or breakpoint recovery and ALWAYS converge via /finish."""
    scan_id = str(task.scan_id)
    execution_revision = max(1, int(getattr(task, "execution_revision", 1) or 1))
    audit_id = str(getattr(task, "javelin_audit_id", "") or f"dh-{scan_id}")
    project_path = Path(task.project_path)
    javelin_cfg = dict(getattr(task, "javelin_config", None) or {})
    has_secret = bool(getattr(task, "has_secret_context", False))

    service = _resolve_service()
    if hasattr(service, "mark_scan_active"):
        service.mark_scan_active(scan_id)

    secret_env = ""
    secret_acked = not has_secret
    final_deephole_status = "error"
    final_error_message: str | None = "Javelin 扫描异常退出"
    total_tasks = 0
    reported_tasks = 0

    observer = JavelinAuditObserver(
        scan_id=scan_id,
        audit_id=audit_id,
        execution_revision=execution_revision,
        service=service,
        reporter=reporter,
        cursor_dir=default_javelin_data_root() / "cursors",
    )
    _ACTIVE_OBSERVERS[scan_id] = observer
    sse_task: asyncio.Task | None = None

    try:
        if has_secret and reporter is not None:
            secret_data = await reporter.fetch_javelin_secret_context(
                scan_id,
                execution_revision=execution_revision,
            )
            if isinstance(secret_data, dict):
                ctx = secret_data.get("secret_context")
                if isinstance(ctx, dict):
                    secret_env = str(ctx.get("test_environment_context") or "")

        if action == "recover":
            await service.ensure_started(config, target_project_path=project_path)
            await service.dispatch_action(audit_id, "recover", action_id=f"recover-{scan_id}-r{execution_revision}")
        else:
            await service.create_and_start_audit(
                config=config,
                scan_id=scan_id,
                audit_id=audit_id,
                scan_name=str(task.scan_name or project_path.name),
                project_path=project_path,
                product_name=str(task.product or "DeepHole"),
                javelin_config=javelin_cfg,
                secret_test_env=secret_env,
            )
        # Immediately wipe secret from local Python frame after handing off to runner
        secret_env = ""

        sse_task = asyncio.create_task(observer.run_sse_listener())

        while True:
            if getattr(task, "cancel_event", None) is not None and task.cancel_event.is_set():
                try:
                    await service.dispatch_action(audit_id, "cancel", action_id=f"local-cancel-{scan_id}")
                except Exception:
                    pass

            audit = await observer.sync_once(force=False)
            j_status = str(audit.get("status") or "")

            if not secret_acked and j_status in {"running", "completed", "failed", "cancelled"}:
                secret_acked = True
                if reporter is not None:
                    try:
                        await reporter.ack_javelin_secret_context(
                            scan_id,
                            execution_revision=execution_revision,
                        )
                    except Exception:
                        pass

            board_meta = audit.get("task_board") if isinstance(audit.get("task_board"), dict) else {}
            total_tasks = int(board_meta.get("total") or total_tasks)
            reported_tasks = int(board_meta.get("reported") or reported_tasks)

            if j_status in _TERMINAL_JAVELIN_STATUSES:
                # Final forced sync of all 5 channels before /finish!
                final_audit = await observer.sync_once(force=True)
                final_board = final_audit.get("task_board") if isinstance(final_audit.get("task_board"), dict) else {}
                total_tasks = int(final_board.get("total") or total_tasks)
                reported_tasks = int(final_board.get("reported") or reported_tasks)
                final_deephole_status, final_error_message = _map_javelin_terminal_to_deephole_status(
                    str(final_audit.get("status") or j_status),
                    str(final_audit.get("error") or ""),
                )
                break

            observer._wakeup.clear()
            try:
                await asyncio.wait_for(observer._wakeup.wait(), timeout=FALLBACK_POLL_SECONDS)
                await asyncio.sleep(DEBOUNCE_SECONDS)
            except asyncio.TimeoutError:
                pass

    except Exception as exc:
        logger.exception("Javelin scan %s (rev=%d) failed: %s", scan_id, execution_revision, exc)
        final_deephole_status = "error"
        final_error_message = f"Javelin 执行异常：{exc}"
        if reporter is not None:
            try:
                await reporter.report_javelin_state(
                    scan_id,
                    execution_revision=execution_revision,
                    state={
                        "audit_id": audit_id,
                        "status": "failed",
                        "resumable": True,
                        "error_message": final_error_message,
                    },
                    wait_for_delivery=True,
                )
            except Exception:
                pass
    finally:
        secret_env = ""
        observer.stop()
        _ACTIVE_OBSERVERS.pop(scan_id, None)
        if sse_task is not None:
            sse_task.cancel()
            await asyncio.gather(sse_task, return_exceptions=True)
        if hasattr(service, "mark_scan_finished"):
            service.mark_scan_finished(scan_id)

        suppress = bool(
            getattr(getattr(task, "cancel_event", None), "suppress_terminal_report", False)
        )
        if reporter is not None and not suppress:
            try:
                await reporter.flush_javelin_streams(scan_id, timeout=20.0)
            except Exception as exc:
                logger.warning("Javelin stream flush warning for %s: %s", scan_id, exc)
            # P0 #5: ALWAYS converge scans.status via /api/agent/v2/scan/{scan_id}/finish!
            await reporter.finish_scan(
                scan_id=scan_id,
                vulnerabilities=[],
                status=final_deephole_status,
                total_candidates=total_tasks,
                processed_candidates=reported_tasks,
                error_message=final_error_message,
            )


async def handle_javelin_action_command(
    msg: dict[str, Any],
    *,
    config: Any,
    task_manager: Any,
    reporter: Any,
) -> dict[str, Any]:
    """Handle server WS 'javelin_action' (pause, resume, cancel, dispatch, recover)."""
    scan_id = str(msg.get("scan_id") or "")
    audit_id = str(msg.get("audit_id") or f"dh-{scan_id}")
    action = str(msg.get("action") or "").strip().lower()
    action_id = str(msg.get("action_id") or "")
    execution_revision = max(1, int(msg.get("execution_revision") or 1))

    if action == "recover":
        if reporter is not None:
            reporter.set_scan_execution(scan_id, execution_revision)
        existing = task_manager.get(scan_id) if task_manager is not None else None
        if existing is not None:
            existing.cancel_event.suppress_terminal_report = True
            existing.cancel_event.set()
            task_manager.remove(scan_id, existing)
        project_path = str(msg.get("project_path") or "")
        task = task_manager.create(
            scan_id=scan_id,
            project_path=project_path,
            code_scan_path=project_path,
            checkers=[],
            scan_name=str(msg.get("scan_name") or ""),
            product=str(msg.get("product") or ""),
            mining_engines=[{"engine_id": JAVELIN_ENGINE_ID, "enabled": True}],
            execution_revision=execution_revision,
            language="java",
            javelin_audit_id=audit_id,
            javelin_config=msg.get("javelin_config") if isinstance(msg.get("javelin_config"), dict) else {},
        )
        from deephole_client.reporter import scan_execution_context

        async def _run_recover() -> None:
            with scan_execution_context(scan_id, execution_revision):
                try:
                    await run_javelin_scan(
                        config=config,
                        task=task,
                        reporter=reporter,
                        action="recover",
                    )
                finally:
                    task_manager.remove(scan_id, task)

        task.asyncio_task = asyncio.create_task(_run_recover())
        return {"ok": True, "action": "recover", "execution_revision": execution_revision}

    service = _resolve_service()
    await service.ensure_started(config)
    result = await service.dispatch_action(audit_id, action, action_id=action_id)
    obs = _ACTIVE_OBSERVERS.get(scan_id)
    if obs is not None:
        obs.notify()
    return {"ok": True, "action": action, "audit_status": result.get("status")}
