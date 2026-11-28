"""Self-contained Task Agent framework backed by OpenCode-compatible Serve."""

from .api import (
    OpenCodeResult,
    cancel_opencode_execution,
    opencode_task_context,
    run_opencode_task,
    run_sync_component,
)
from .host import OpenCodeHostBindings, OpenCodeSessionRuntime, configure_opencode


async def shutdown_opencode() -> None:
    """Stop all managed runtime backends and reset lazy component singletons."""
    from .host import _reset_standalone_opencode_configuration
    from .runtime_backend import shutdown_all_runtime_backends
    from .task_service import reset_opencode_task_service

    await shutdown_all_runtime_backends()
    reset_opencode_task_service()
    _reset_standalone_opencode_configuration()


__all__ = [
    "OpenCodeHostBindings",
    "OpenCodeResult",
    "OpenCodeSessionRuntime",
    "cancel_opencode_execution",
    "configure_opencode",
    "opencode_task_context",
    "run_opencode_task",
    "run_sync_component",
    "shutdown_opencode",
]
