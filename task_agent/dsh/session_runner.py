"""Subprocess lifecycle, cancellation, timeout watchdog, and SDK runner for DSH."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from ..serve_client import OpenCodeFileWrite, OpenCodePromptResult
from ..token_usage import OpenCodeTokenUsage
from .approval_policy import DshApprovalArbitrator
from .error_mapping import map_dsh_failure
from .event_bridge import (
    DshEventBridge,
    normalize_dsh_finish_reason,
    verify_required_bash_commands,
)
from .model_catalog import ResolvedDshModel, resolve_dsh_binary
from .patch_composer import ComposedDshPatch

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ActiveDshRunHandle:
    """Handle tracked by ``DeepSeekHarnessManager`` for shutdown/cancellation."""

    run_id: str
    session_id: str
    abort: Callable[[], None]


def _force_kill_harness_process(harness: Any) -> None:
    """Terminate the underlying ``dsh`` subprocess tree immediately on cancel/timeout."""
    client = getattr(harness, "client", None)
    proc = getattr(client, "_proc", None) if client is not None else None
    if proc is not None and proc.poll() is None:
        try:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=3.0,
                    check=False,
                )
            else:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    proc.kill()
        except Exception:
            with contextlib.suppress(Exception):
                proc.kill()
    with contextlib.suppress(Exception):
        harness.close()


def find_persisted_session_jsonl(dsh_home: Path, session_id: str) -> Path | None:
    """Locate the persisted JSONL file for ``session_id`` under ``dsh_home/sessions``.

    Supports both the current DeepSeek Harness v4 layout
    (``sessions/<encoded-cwd>/<session_id>/session.v4.jsonl``) and flat/unbucketed
    layouts (``sessions/<session_id>.jsonl`` or ``sessions/<session_id>/session*.jsonl``).
    """
    sid = str(session_id or "").strip()
    if not sid or "/" in sid or "\\" in sid or sid in {".", ".."} or ".." in sid:
        return None
    sessions_dir = dsh_home / "sessions"
    if not sessions_dir.is_dir():
        return None

    direct = sessions_dir / f"{sid}.jsonl"
    if direct.is_file():
        return direct

    def _pick_jsonl_in_dir(session_dir: Path) -> Path | None:
        if not session_dir.is_dir():
            return None
        v4 = session_dir / "session.v4.jsonl"
        if v4.is_file():
            return v4
        candidates = sorted(
            (p for p in session_dir.glob("*.jsonl") if p.is_file()),
            reverse=True,
        )
        return candidates[0] if candidates else None

    unbucketed = _pick_jsonl_in_dir(sessions_dir / sid)
    if unbucketed is not None:
        return unbucketed

    try:
        children = list(sessions_dir.iterdir())
    except OSError:
        return None
    for child in children:
        if not child.is_dir():
            continue
        found = _pick_jsonl_in_dir(child / sid)
        if found is not None:
            return found
    return None


def _persisted_session_exists(dsh_home: Path, session_id: str) -> bool:
    return find_persisted_session_jsonl(dsh_home, session_id) is not None


def _schedule_callback(
    loop: asyncio.AbstractEventLoop,
    callback: Callable[..., Any] | None,
    *args: Any,
    pending_tasks: set[asyncio.Task[Any]],
) -> None:
    if callback is None:
        return

    def _invoke() -> None:
        try:
            outcome = callback(*args)
            if inspect.isawaitable(outcome):
                task = loop.create_task(outcome)
                pending_tasks.add(task)
                task.add_done_callback(pending_tasks.discard)
        except Exception:
            logger.debug("Ignoring DSH callback error", exc_info=True)

    with contextlib.suppress(RuntimeError):
        loop.call_soon_threadsafe(_invoke)


async def run_dsh_turn(
    *,
    prompt: str,
    directory: Path,
    dsh_home: Path,
    dsh_executable: str,
    dsh_profile: str,
    resolved_model: ResolvedDshModel,
    composed_patch: ComposedDshPatch,
    arbitrator: DshApprovalArbitrator,
    session_id: str | None = None,
    timeout: float | None = None,
    idle_timeout: float | None = None,
    cancel_event: Any = None,
    log_stage: str = "opencode",
    llm_providers: dict[str, Any] | None = None,
    required_bash_commands: tuple[str, ...] = (),
    required_bash_success_markers: tuple[tuple[str, str], ...] = (),
    on_line: Callable[[str], Any] | None = None,
    on_session_id: Callable[[str], Any] | None = None,
    on_model_request_failure: Callable[[str], Any] | None = None,
    on_response_model: Callable[[str], Any] | None = None,
    on_token_usage: Callable[[OpenCodeTokenUsage], Any] | None = None,
    on_file_write: Callable[[OpenCodeFileWrite], Any] | None = None,
    on_model_progress: Callable[[], Any] | None = None,
    on_register_active: Callable[[ActiveDshRunHandle], None] | None = None,
    on_unregister_active: Callable[[str], None] | None = None,
    harness_factory: Callable[[Any], Any] | None = None,
) -> OpenCodePromptResult:
    """Execute one prompt turn against DeepSeek Harness with full lifecycle guards."""
    loop = asyncio.get_running_loop()
    pending_callbacks: set[asyncio.Task[Any]] = set()
    active_session_id = str(session_id or "").strip() or f"dsh-{uuid4().hex}"
    resuming = bool(session_id and _persisted_session_exists(dsh_home, active_session_id))
    run_id = uuid4().hex

    if on_session_id is not None:
        outcome = on_session_id(active_session_id)
        if inspect.isawaitable(outcome):
            await outcome

    bridge = DshEventBridge(
        session_id=active_session_id,
        model_label=resolved_model.full_id,
        log_stage=log_stage,
        arbitrator=arbitrator,
        emit_line=lambda line: _schedule_callback(loop, on_line, line, pending_tasks=pending_callbacks),
        emit_token_usage=lambda usage: _schedule_callback(loop, on_token_usage, usage, pending_tasks=pending_callbacks),
        emit_response_model=lambda m: _schedule_callback(loop, on_response_model, m, pending_tasks=pending_callbacks),
        emit_file_write=lambda fw: _schedule_callback(loop, on_file_write, fw, pending_tasks=pending_callbacks),
        emit_model_progress=lambda: _schedule_callback(loop, on_model_progress, pending_tasks=pending_callbacks),
    )

    abort_lock = threading.Lock()
    state: dict[str, Any] = {
        "harness": None,
        "aborted": False,
        "abort_reason": "",
        "startup_completed": False,
    }

    def trigger_abort(reason: str) -> None:
        with abort_lock:
            if state["aborted"]:
                return
            state["aborted"] = True
            state["abort_reason"] = reason
            harness = state["harness"]
        if harness is not None:
            _force_kill_harness_process(harness)

    handle = ActiveDshRunHandle(
        run_id=run_id,
        session_id=active_session_id,
        abort=lambda: trigger_abort("shutdown"),
    )
    if on_register_active is not None:
        on_register_active(handle)

    def _run_sync() -> Any:
        try:
            from deepseek_harness import DeepSeekHarness, DeepSeekHarnessConfig
        except ImportError as exc:
            mapped, kind = map_dsh_failure(
                error=exc,
                model=resolved_model.full_id,
                llm_providers=llm_providers,
                startup_phase=True,
            )
            raise mapped from exc

        dsh_bin = resolve_dsh_binary(dsh_executable) if harness_factory is None else (dsh_executable or None)
        dsh_home.mkdir(parents=True, exist_ok=True)
        init_timeout = 30.0
        if timeout is not None and timeout > 0:
            init_timeout = min(init_timeout, max(5.0, float(timeout)))

        cfg = DeepSeekHarnessConfig(
            provider=resolved_model.provider_id,
            model=resolved_model.model_id,
            cwd=str(directory.resolve()),
            dsh_bin=dsh_bin,
            profile=dsh_profile or "sdk-minimal",
            patches=(str(composed_patch.patch_path),),
            dsh_home=str(dsh_home.resolve()),
            env=dict(composed_patch.env),
            initialize_timeout_seconds=init_timeout,
            shutdown_timeout_seconds=1.0,
            approval_requests=True,
        )
        harness = harness_factory(cfg) if harness_factory is not None else DeepSeekHarness(cfg)
        with abort_lock:
            state["harness"] = harness
            already_aborted = state["aborted"]
        if already_aborted:
            _force_kill_harness_process(harness)
            raise asyncio.CancelledError("DeepSeek Harness turn cancelled before start")

        stop_approvals = threading.Event()

        def approval_worker() -> None:
            while not stop_approvals.is_set():
                try:
                    req = harness.client.next_request()
                except Exception:
                    break
                if stop_approvals.is_set():
                    break
                try:
                    if req.method == "approval/request":
                        decision, _detail = arbitrator.decide(req.payload)
                        harness.client.respond(req.id, {"outcome": decision})
                    else:
                        harness.client.respond_error(
                            req.id,
                            code=-32601,
                            message=f"Unsupported host callback method: {req.method}",
                        )
                except Exception:
                    break

        approval_thread = threading.Thread(
            target=approval_worker,
            name=f"dsh-approval-{run_id[:8]}",
            daemon=True,
        )
        try:
            harness.start()
            state["startup_completed"] = True
            approval_thread.start()
            if resuming:
                session = harness.resume_session(active_session_id)
            else:
                session = harness.start_session(active_session_id)
            return session.run(prompt, on_notification=bridge.handle_notification)
        finally:
            stop_approvals.set()
            with contextlib.suppress(Exception):
                harness.close()
            approval_thread.join(timeout=0.5)

    worker_task = asyncio.create_task(asyncio.to_thread(_run_sync))
    started_at = time.monotonic()

    async def watchdog() -> str:
        while not worker_task.done():
            if cancel_event is not None and cancel_event.is_set():
                trigger_abort("cancelled")
                return "cancelled"
            now = time.monotonic()
            if timeout is not None and timeout > 0 and (now - started_at) >= timeout:
                trigger_abort("timeout")
                return "timeout"
            if (
                idle_timeout is not None
                and idle_timeout > 0
                and bridge.seconds_since_activity() >= idle_timeout
            ):
                trigger_abort("idle_timeout")
                return "idle_timeout"
            await asyncio.sleep(0.1)
        return ""

    watchdog_task = asyncio.create_task(watchdog())

    try:
        done, _ = await asyncio.wait(
            {worker_task, watchdog_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        abort_kind = ""
        if watchdog_task in done:
            abort_kind = watchdog_task.result()
        else:
            watchdog_task.cancel()
            with contextlib.suppress(BaseException):
                await watchdog_task

        if abort_kind == "cancelled":
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(worker_task, timeout=3.0)
            raise asyncio.CancelledError("DeepSeek Harness task cancelled")

        if abort_kind in {"timeout", "idle_timeout"}:
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(worker_task, timeout=3.0)
            if on_model_request_failure is not None:
                on_model_request_failure("timeout")
            label = "无新内容空闲超时" if abort_kind == "idle_timeout" else "执行超时"
            raise asyncio.TimeoutError(
                f"DeepSeek Harness {label}（session={active_session_id}）"
            )

        run_result = await worker_task
    except asyncio.CancelledError:
        trigger_abort("cancelled")
        watchdog_task.cancel()
        with contextlib.suppress(BaseException):
            await watchdog_task
        with contextlib.suppress(BaseException):
            await asyncio.wait_for(worker_task, timeout=3.0)
        raise
    except asyncio.TimeoutError:
        raise
    except BaseException as exc:
        if state["abort_reason"] == "cancelled":
            raise asyncio.CancelledError("DeepSeek Harness task cancelled") from exc
        if state["abort_reason"] in {"timeout", "idle_timeout"}:
            if on_model_request_failure is not None:
                on_model_request_failure("timeout")
            raise asyncio.TimeoutError("DeepSeek Harness execution timed out") from exc
        mapped, failure_kind = map_dsh_failure(
            error=exc,
            failure=bridge.turn_error,
            model=resolved_model.full_id,
            llm_providers=llm_providers,
            startup_phase=not state["startup_completed"],
        )
        if on_model_request_failure is not None:
            on_model_request_failure(failure_kind)
        raise mapped from exc
    finally:
        if not watchdog_task.done():
            watchdog_task.cancel()
            with contextlib.suppress(BaseException):
                await watchdog_task
        if pending_callbacks:
            await asyncio.gather(*list(pending_callbacks), return_exceptions=True)
        if on_unregister_active is not None:
            on_unregister_active(run_id)
        with contextlib.suppress(OSError):
            composed_patch.patch_path.unlink(missing_ok=True)

    # Post-turn terminal state inspection
    raw_finish = str(getattr(run_result, "finish_reason", "") or bridge.finish_reason_raw or "").strip()
    if raw_finish.lower() == "error" or bridge.turn_error is not None:
        mapped, failure_kind = map_dsh_failure(
            failure=bridge.turn_error or {"message": str(getattr(run_result, "final_response", "") or "turn failed")},
            model=resolved_model.full_id,
            llm_providers=llm_providers,
            startup_phase=False,
        )
        if on_model_request_failure is not None:
            on_model_request_failure(failure_kind)
        raise mapped

    if raw_finish.lower() == "aborted":
        raise asyncio.CancelledError("DeepSeek Harness turn aborted")

    # Enforce required bash command audit before returning success
    verify_required_bash_commands(
        required_commands=required_bash_commands,
        success_markers=required_bash_success_markers,
        audits=bridge.bash_audits,
    )

    final_text = str(getattr(run_result, "final_response", "") or "")
    normalized_finish = normalize_dsh_finish_reason(raw_finish)
    return OpenCodePromptResult(
        session_id=active_session_id,
        message_id=bridge.last_message_id or f"dsh-msg-{uuid4().hex[:12]}",
        lines=list(bridge.lines),
        text=final_text,
        model=resolved_model.full_id,
        token_usage=bridge.accumulated_token_usage(),
        raw=run_result,
        finish_reason=normalized_finish,
        output_tokens=bridge.last_output_tokens,
    )
