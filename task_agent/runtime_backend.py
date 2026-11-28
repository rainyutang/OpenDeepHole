"""Minimal runtime backend registry for Task Agent execution engines.

OpenCode remains the default backend. Additional execution runtimes such as
DeepSeek Harness register behind this small facade so existing scheduling,
model-pool, retry, and structured-output flows stay backend-agnostic without
invasive edits to OpenCode's Serve implementation.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from ._opencode_v2 import normalize_opencode_version

TOOL_OPENCODE = "opencode"
TOOL_DEEPSEEK_HARNESS = "deepseek_harness"
SUPPORTED_RUNTIME_TOOLS = frozenset({TOOL_OPENCODE, TOOL_DEEPSEEK_HARNESS})
DEFAULT_DSH_PROFILE = "sdk-minimal"


def normalize_runtime_tool(
    value: object,
    *,
    default: str = TOOL_OPENCODE,
    strict: bool = False,
) -> str:
    """Normalize a runtime tool identifier to a canonical backend name."""
    raw = str(value or "").strip().lower()
    if not raw:
        return default
    if raw in SUPPORTED_RUNTIME_TOOLS:
        return raw
    if strict:
        supported = ", ".join(sorted(SUPPORTED_RUNTIME_TOOLS))
        raise ValueError(f"Unsupported runtime tool {raw!r}; expected one of: {supported}")
    return default


def is_supported_runtime_tool(value: object) -> bool:
    return str(value or "").strip().lower() in SUPPORTED_RUNTIME_TOOLS


def resolve_cli_runtime_identity(cli_config: Any) -> tuple[str, str]:
    """Return ``(tool, executable)`` for model-pool option & health identity."""
    tool = normalize_runtime_tool(getattr(cli_config, "tool", TOOL_OPENCODE))
    if tool == TOOL_DEEPSEEK_HARNESS:
        executable = str(
            getattr(cli_config, "dsh_executable", "")
            or getattr(cli_config, "executable", "")
            or ""
        ).strip()
        return TOOL_DEEPSEEK_HARNESS, executable or "dsh"
    opencode_version = normalize_opencode_version(
        getattr(cli_config, "opencode_version", "1")
    )
    if opencode_version == "2":
        v2_exec = str(getattr(cli_config, "executable_v2", "") or "").strip()
        if v2_exec:
            return TOOL_OPENCODE, v2_exec
    executable = str(getattr(cli_config, "executable", "") or "").strip()
    return TOOL_OPENCODE, executable or TOOL_OPENCODE


def active_runtime_tool(config: Any = None) -> str:
    """Extract the active runtime tool from an AgentConfig or CLI config."""
    if config is None:
        return TOOL_OPENCODE
    cli = getattr(config, "opencode", None)
    if cli is not None:
        return normalize_runtime_tool(getattr(cli, "tool", TOOL_OPENCODE))
    base = getattr(config, "base", None)
    if base is not None:
        return normalize_runtime_tool(getattr(base, "tool", TOOL_OPENCODE))
    return normalize_runtime_tool(getattr(config, "tool", TOOL_OPENCODE))


@runtime_checkable
class RuntimeBackendManager(Protocol):
    """Structural contract shared by OpenCodeServeManager and DeepSeekHarnessManager."""

    def is_ready_for_prompt(self) -> bool: ...

    def is_preparing(self) -> bool: ...

    def config_runtime_status(self) -> dict[str, int | str]: ...

    def mark_dirty(self) -> None: ...

    def update_managed_mcp_configs(self, specs: dict[str, dict[str, Any]]) -> None: ...

    async def update_skill_catalog(
        self,
        needed: Callable[[], bool],
        publish: Callable[[], None],
        *,
        cancel_event: Any = None,
    ) -> None: ...

    async def reload_runtime(self, **kwargs: Any) -> Any: ...

    async def list_models(self, **kwargs: Any) -> Any: ...

    async def run_prompt(self, **kwargs: Any) -> Any: ...

    async def get_session(self, session_id: str, **kwargs: Any) -> Any: ...

    async def get_session_messages(self, session_id: str, **kwargs: Any) -> list[dict[str, Any]]: ...

    async def delete_session(self, session_id: str, **kwargs: Any) -> Any: ...

    async def shutdown(self) -> None: ...


BackendFactory = Callable[[], Any]
BackendShutdown = Callable[[], Awaitable[None]]

_FACTORIES: dict[str, BackendFactory] = {}
_SHUTDOWNS: dict[str, BackendShutdown] = {}


def _get_opencode_manager() -> Any:
    from .serve_client import get_serve_manager

    return get_serve_manager()


async def _shutdown_opencode_manager() -> None:
    from .serve_client import shutdown_serve_manager

    await shutdown_serve_manager()


def _get_dsh_manager() -> Any:
    from .dsh.manager import get_dsh_manager

    return get_dsh_manager()


async def _shutdown_dsh_manager() -> None:
    from .dsh.manager import shutdown_dsh_manager

    await shutdown_dsh_manager()


def _ensure_builtin_backends() -> None:
    if TOOL_OPENCODE not in _FACTORIES:
        _FACTORIES[TOOL_OPENCODE] = _get_opencode_manager
        _SHUTDOWNS[TOOL_OPENCODE] = _shutdown_opencode_manager
    if TOOL_DEEPSEEK_HARNESS not in _FACTORIES:
        _FACTORIES[TOOL_DEEPSEEK_HARNESS] = _get_dsh_manager
        _SHUTDOWNS[TOOL_DEEPSEEK_HARNESS] = _shutdown_dsh_manager


def register_runtime_backend(
    tool: str,
    factory: BackendFactory,
    shutdown: BackendShutdown | None = None,
) -> None:
    """Register or replace a runtime backend factory (useful for extensions/tests)."""
    _ensure_builtin_backends()
    normalized = str(tool or "").strip().lower()
    if not normalized:
        raise ValueError("Runtime backend tool name cannot be empty")
    _FACTORIES[normalized] = factory
    if shutdown is not None:
        _SHUTDOWNS[normalized] = shutdown


def get_runtime_manager(tool: object = None) -> Any:
    """Return the singleton manager for *tool* (or a runtime object with ``.tool``)."""
    _ensure_builtin_backends()
    raw_tool = getattr(tool, "tool", tool) if tool is not None else TOOL_OPENCODE
    normalized = normalize_runtime_tool(raw_tool, strict=True)
    factory = _FACTORIES.get(normalized)
    if factory is None:
        raise ValueError(f"No runtime backend registered for tool {normalized!r}")
    return factory()


async def shutdown_runtime_backend(tool: object) -> None:
    """Stop the runtime backend identified by *tool*, if registered."""
    _ensure_builtin_backends()
    raw_tool = getattr(tool, "tool", tool)
    normalized = normalize_runtime_tool(raw_tool, default="")
    if not normalized:
        return
    shutdown_fn = _SHUTDOWNS.get(normalized)
    if shutdown_fn is None:
        return
    outcome = shutdown_fn()
    if inspect.isawaitable(outcome):
        await outcome


async def shutdown_all_runtime_backends() -> None:
    """Stop every registered runtime backend cleanly."""
    _ensure_builtin_backends()
    first_error: BaseException | None = None
    for tool_name in list(_SHUTDOWNS):
        try:
            await shutdown_runtime_backend(tool_name)
        except BaseException as exc:  # pragma: no cover - defensive teardown
            if first_error is None:
                first_error = exc
    if first_error is not None:
        raise first_error


def runtime_has_tool_directory_compat(directory: Path | None) -> Path:
    return Path(directory or Path.cwd()).resolve()
