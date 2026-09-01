"""The single public OpenCode task interface used by DeepHole 2.0 components."""

from __future__ import annotations

import asyncio
import concurrent.futures
import inspect
import threading
from collections.abc import Sequence
from contextlib import contextmanager
from contextvars import ContextVar, copy_context
from dataclasses import dataclass, field
from os import PathLike, fspath
from pathlib import Path
from typing import Any, Callable, Literal


_SUPPORTED_TASK_TYPES = frozenset({
    "vulnerability_mining",
    "threat_analysis",
    "fp_review",
    "vulnerability_validation",
    "git_history",
    "variant_hunt",
    "memory_api_discovery",
    "skill_create",
})
_UNSET = object()
_PathValue = str | PathLike[str]
_PathValues = _PathValue | Sequence[_PathValue]
_COMPONENT_OWNER_LOOP: ContextVar[asyncio.AbstractEventLoop | None] = ContextVar(
    "task_agent_component_owner_loop",
    default=None,
)


def _standalone_console_output() -> Callable[[str], None]:
    def emit(line: str) -> None:
        text = str(line or "")
        if text:
            print(text, flush=True)

    return emit


@dataclass(frozen=True)
class OpenCodeResult:
    session_id: str
    status: Literal["success", "failure", "timeout"]
    text: str
    structured: Any
    model: str
    output_source: dict[str, Any] = field(default_factory=dict)
    token_usage: dict[str, Any] | None = None


def _normalize_path_values(
    value: _PathValues | None,
    *,
    parameter: str,
) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, bytes):
        raise TypeError(
            f"OpenCode {parameter} must be a path, a sequence of paths, or None"
        )
    if isinstance(value, (str, PathLike)):
        entries = (value,)
    elif isinstance(value, Sequence):
        entries = value
    else:
        raise TypeError(
            f"OpenCode {parameter} must be a path, a sequence of paths, or None"
        )
    normalized: list[str] = []
    for item in entries:
        if isinstance(item, bytes) or not isinstance(item, (str, PathLike)):
            raise TypeError(
                f"OpenCode {parameter} entries must be strings or PathLike values"
            )
        raw = fspath(item)
        if not isinstance(raw, str):
            raise TypeError(
                f"OpenCode {parameter} entries must resolve to string paths"
            )
        if not raw.strip():
            raise ValueError(f"OpenCode {parameter} entries cannot be empty")
        if "*" in raw or "?" in raw:
            raise ValueError(
                f"OpenCode {parameter} entries cannot contain wildcard characters"
            )
        normalized.append(raw)
    return tuple(normalized)


def _normalize_file_write_allowlist(
    value: _PathValues | None,
) -> tuple[str, ...]:
    return _normalize_path_values(value, parameter="file_write_allowlist")


def _normalize_writable_paths(
    value: _PathValues | None,
) -> tuple[str, ...]:
    return _normalize_path_values(value, parameter="writable_paths")


def _normalize_readable_paths(
    value: _PathValues | None,
) -> tuple[str, ...]:
    return _normalize_path_values(value, parameter="readable_paths")


def _normalize_required_bash_commands(
    value: str | Sequence[str] | None,
) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        entries = (value,)
    elif isinstance(value, Sequence) and not isinstance(value, bytes):
        entries = value
    else:
        raise TypeError(
            "OpenCode required_bash_commands must be a string, "
            "a sequence of strings, or None"
        )
    normalized: list[str] = []
    for item in entries:
        if not isinstance(item, str):
            raise TypeError(
                "OpenCode required_bash_commands entries must be strings"
            )
        command = item.strip()
        if not command:
            raise ValueError(
                "OpenCode required_bash_commands entries cannot be empty"
            )
        if "\n" in item or "\r" in item:
            raise ValueError(
                "OpenCode required_bash_commands entries cannot contain newlines"
            )
        if "*" in command or "?" in command:
            raise ValueError(
                "OpenCode required_bash_commands entries cannot contain wildcard characters"
            )
        if command not in normalized:
            normalized.append(command)
    return tuple(normalized)


async def run_opencode_task(
    *,
    task_name: str,
    task_type: str,
    prompt: str,
    required_capability: Literal["low", "high"],
    output_schema: dict[str, Any] | None = None,
    invalid_json_retry_count: int = 2,
    invalid_json_retry_prompt: str | None = None,
    file_write_allowlist: str | PathLike[str] | Sequence[str | PathLike[str]] | None = None,
    writable_paths: str | PathLike[str] | Sequence[str | PathLike[str]] | None = None,
    readable_paths: str | PathLike[str] | Sequence[str | PathLike[str]] | None = None,
    required_bash_commands: str | Sequence[str] | None = None,
    session_id: str | None = None,
    config_path: str | PathLike[str] | None = None,
    output: Callable[[str], Any] | None | object = _UNSET,
    cancel_event: Any = _UNSET,
) -> OpenCodeResult:
    """Run one task, dispatching worker-thread calls to the owning event loop."""
    owner_loop = _COMPONENT_OWNER_LOOP.get()
    current_loop = asyncio.get_running_loop()
    coroutine = _run_opencode_task_local(
        task_name=task_name,
        task_type=task_type,
        prompt=prompt,
        required_capability=required_capability,
        output_schema=output_schema,
        invalid_json_retry_count=invalid_json_retry_count,
        invalid_json_retry_prompt=invalid_json_retry_prompt,
        file_write_allowlist=file_write_allowlist,
        writable_paths=writable_paths,
        readable_paths=readable_paths,
        required_bash_commands=required_bash_commands,
        session_id=session_id,
        config_path=config_path,
        output=output,
        cancel_event=cancel_event,
    )
    if owner_loop is None or owner_loop is current_loop:
        return await coroutine
    concurrent_future = asyncio.run_coroutine_threadsafe(coroutine, owner_loop)
    try:
        while not concurrent_future.done():
            await asyncio.sleep(0.01)
        return concurrent_future.result()
    except concurrent.futures.CancelledError as exc:
        raise asyncio.CancelledError from exc
    except BaseException:
        concurrent_future.cancel()
        raise


async def _run_opencode_task_local(
    *,
    task_name: str,
    task_type: str,
    prompt: str,
    required_capability: Literal["low", "high"],
    output_schema: dict[str, Any] | None = None,
    invalid_json_retry_count: int = 2,
    invalid_json_retry_prompt: str | None = None,
    file_write_allowlist: _PathValues | None = None,
    writable_paths: _PathValues | None = None,
    readable_paths: _PathValues | None = None,
    required_bash_commands: str | Sequence[str] | None = None,
    session_id: str | None = None,
    config_path: str | PathLike[str] | None = None,
    output: Callable[[str], Any] | None | object = _UNSET,
    cancel_event: Any = _UNSET,
) -> OpenCodeResult:
    """Run one OpenCode task using host-bound or standalone file configuration."""
    normalized_name = str(task_name or "").strip()
    normalized_prompt = str(prompt or "")
    if not normalized_name:
        raise ValueError("OpenCode task_name is required")
    if not normalized_prompt.strip():
        raise ValueError("OpenCode prompt is required")
    normalized_task_type = task_type.strip() if isinstance(task_type, str) else ""
    if normalized_task_type not in _SUPPORTED_TASK_TYPES:
        raise ValueError(f"Unsupported OpenCode task_type: {task_type!r}")
    capability = str(required_capability or "").strip().lower()
    if capability not in {"low", "high"}:
        raise ValueError("OpenCode required_capability must be 'low' or 'high'")
    if output_schema is not None and not isinstance(output_schema, dict):
        raise TypeError("OpenCode output_schema must be a dict or None")
    retry_count = int(invalid_json_retry_count)
    if retry_count < 0:
        raise ValueError("OpenCode invalid_json_retry_count cannot be negative")
    if invalid_json_retry_prompt is not None:
        if not isinstance(invalid_json_retry_prompt, str):
            raise TypeError(
                "OpenCode invalid_json_retry_prompt must be a string or None"
            )
        if not invalid_json_retry_prompt.strip():
            raise ValueError("OpenCode invalid_json_retry_prompt cannot be empty")
    normalized_file_write_allowlist = _normalize_file_write_allowlist(
        file_write_allowlist
    )
    normalized_writable_paths = _normalize_writable_paths(writable_paths)
    normalized_readable_paths = _normalize_readable_paths(readable_paths)
    normalized_required_bash_commands = _normalize_required_bash_commands(
        required_bash_commands
    )
    if output is not _UNSET and output is not None and not callable(output):
        raise TypeError("OpenCode output must be callable or None")

    from .standalone import ensure_opencode_configuration
    from .task_service import (
        _run_component_task,
        bind_opencode_execution_context,
        get_opencode_execution_context,
    )

    bound_context = get_opencode_execution_context()
    effective_config_path = config_path or bound_context.config_path
    standalone = ensure_opencode_configuration(effective_config_path)

    async def run() -> OpenCodeResult:
        return await _run_component_task(
            task_name=normalized_name,
            task_type=normalized_task_type,
            prompt=normalized_prompt,
            required_capability=capability,
            output_schema=output_schema,
            invalid_json_retry_count=retry_count,
            invalid_json_retry_prompt=invalid_json_retry_prompt,
            file_write_allowlist=normalized_file_write_allowlist,
            writable_paths=normalized_writable_paths,
            readable_paths=normalized_readable_paths,
            required_bash_commands=normalized_required_bash_commands,
            session_id=str(session_id or "").strip() or None,
        )

    async def run_with_overrides() -> OpenCodeResult:
        overrides: dict[str, Any] = {}
        if output is not _UNSET:
            overrides["on_output"] = output
        if cancel_event is not _UNSET:
            overrides["cancel_event"] = cancel_event
        if not overrides:
            return await run()
        with bind_opencode_execution_context(**overrides):
            return await run()

    if standalone is None:
        return await run_with_overrides()
    standalone_output = _standalone_console_output() if output is _UNSET else output
    standalone_cancel_event = None if cancel_event is _UNSET else cancel_event
    with bind_opencode_execution_context(
        project_dir=bound_context.project_dir or standalone.project_dir,
        work_dir=bound_context.work_dir or standalone.work_dir,
        task_metadata={"standalone_console": True},
        on_output=standalone_output,
        cancel_event=standalone_cancel_event,
    ):
        return await run()


async def run_sync_component(
    function: Callable[..., Any],
    /,
    *args: Any,
    **kwargs: Any,
) -> Any:
    """Run a synchronous component without moving Task Agent work off-loop."""
    if inspect.iscoroutinefunction(function):
        return await function(*args, **kwargs)
    owner_loop = asyncio.get_running_loop()
    token = _COMPONENT_OWNER_LOOP.set(owner_loop)
    outcome: concurrent.futures.Future[Any] = concurrent.futures.Future()
    context = copy_context()

    def invoke() -> None:
        try:
            outcome.set_result(context.run(function, *args, **kwargs))
        except BaseException as exc:
            outcome.set_exception(exc)

    worker = threading.Thread(
        target=invoke,
        name=f"task-agent-component-{getattr(function, '__name__', 'sync')}",
        daemon=True,
    )
    try:
        worker.start()
        while not outcome.done():
            await asyncio.sleep(0.01)
        result = outcome.result()
        if inspect.isawaitable(result):
            return await result
        return result
    finally:
        _COMPONENT_OWNER_LOOP.reset(token)


@contextmanager
def opencode_task_context(
    *,
    project_dir: str | PathLike[str],
    work_dir: str | PathLike[str],
    scan_id: str | None = None,
    feedback_entries: list[dict[str, Any]] | None = None,
    code_graph_mcp: dict[str, Any] | None | object = _UNSET,
    knowledge_base_mcp: dict[str, Any] | None | object = _UNSET,
    config_path: str | PathLike[str] | None = None,
    skill_paths: list[str | PathLike[str]] | None = None,
    task_metadata: dict[str, Any] | None = None,
    output: Callable[[str], Any] | None | object = _UNSET,
    cancel_event: Any = None,
):
    """Bind host context; omitted output inherits and explicit None disables it."""
    from .task_service import bind_opencode_execution_context

    context_kwargs: dict[str, Any] = {
        "project_dir": Path(project_dir).expanduser().resolve(),
        "work_dir": Path(work_dir).expanduser().resolve(),
        "config_path": (
            Path(config_path).expanduser().resolve()
            if config_path is not None
            else None
        ),
        "skill_paths": list(skill_paths or []),
        "scan_id": None if scan_id is None else str(scan_id or ""),
        "feedback_entries": list(feedback_entries or []),
        "task_metadata": dict(task_metadata or {}),
        "cancel_event": cancel_event,
    }
    if code_graph_mcp is not _UNSET:
        context_kwargs["code_graph_mcp"] = code_graph_mcp
    if knowledge_base_mcp is not _UNSET:
        context_kwargs["knowledge_base_mcp"] = knowledge_base_mcp
    if output is not _UNSET:
        context_kwargs["on_output"] = output

    with bind_opencode_execution_context(
        **context_kwargs,
    ):
        yield
