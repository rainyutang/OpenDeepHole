"""Stage Agent API changes without changing the runtime of admitted tasks."""

from __future__ import annotations

import copy
from pathlib import Path

from .config import AgentConfig

_source: AgentConfig | None = None
_active: AgentConfig | None = None


def active_config(config: AgentConfig | None = None) -> AgentConfig | None:
    """Resolve even copied scan configs through the Agent's applied snapshot."""
    return _active if _active is not None else config


def active_providers() -> dict:
    return copy.deepcopy(_active.llm_providers) if _active is not None else {}


def initialize(config: AgentConfig) -> None:
    global _source, _active
    if _source is config:
        return
    from task_agent.config_reload import get_config_reload_coordinator
    from task_agent.llm_config import llm_provider_revision

    _source = config
    _active = copy.deepcopy(config)
    # A saved Provider is only applied after Serve has actually loaded it.
    get_config_reload_coordinator().initialize(
        "" if config.llm_providers else llm_provider_revision({}),
    )


async def update(config: AgentConfig) -> None:
    """Queue changed Providers; refresh ordinary settings without a restart."""
    global _active
    from task_agent.config_reload import get_config_reload_coordinator
    from task_agent.llm_config import llm_provider_revision
    from task_agent.runtime_backend import (
        active_runtime_tool,
        shutdown_runtime_backend,
    )
    from .dsh_integration import dsh_runtime_change_key

    initialize(config)
    coordinator = get_config_reload_coordinator()
    revision = llm_provider_revision(config.llm_providers)
    status = coordinator.status()
    if revision != status["applied_revision"] or status["state"] != "active":
        coordinator.stage(revision, copy.deepcopy(config), _apply)
        return
    previous = _active
    changed_runtime = previous is not None and (
        dsh_runtime_change_key(previous) != dsh_runtime_change_key(config)
    )
    if previous is not None and active_runtime_tool(previous) != active_runtime_tool(config):
        await shutdown_runtime_backend(active_runtime_tool(previous))
    _active = copy.deepcopy(config)
    from .main import _refresh_live_runtime
    await _refresh_live_runtime(config, mark_dirty=changed_runtime)


async def _apply(candidate: AgentConfig, revision: str) -> None:
    global _active
    previous = _active
    from task_agent.runtime_backend import (
        TOOL_OPENCODE,
        active_runtime_tool,
        get_runtime_manager,
        shutdown_runtime_backend,
    )
    from task_agent.serve_client import get_serve_manager
    from .dsh_integration import dsh_runtime_change_key
    from .opencode_integration import (
        build_opencode_session_runtime,
        configure_opencode_component,
        refresh_global_opencode_config,
    )

    candidate_tool = active_runtime_tool(candidate)
    previous_tool = active_runtime_tool(previous) if previous is not None else candidate_tool
    backend_manager = (
        get_serve_manager()
        if candidate_tool == TOOL_OPENCODE
        else get_runtime_manager(candidate_tool)
    )

    try:
        from task_agent.config_reload import get_config_reload_coordinator
        from .main import _refresh_live_runtime
        # A pool-only save may arrive during an earlier Provider startup. Once
        # that same revision is loaded, apply the latest pool without restarting
        # the process a second time.
        if (
            previous is not None
            and get_config_reload_coordinator().status()["applied_revision"] == revision
            and (
                *dsh_runtime_change_key(previous),
                previous.opencode.config_paths,
            )
            == (
                *dsh_runtime_change_key(candidate),
                candidate.opencode.config_paths,
            )
            and backend_manager.config_runtime_status()["runtime_state"] == "active"
        ):
            _active = copy.deepcopy(candidate)
            await _refresh_live_runtime(_active, mark_dirty=False)
            return
        if previous is not None and previous_tool != candidate_tool:
            await shutdown_runtime_backend(previous_tool)
        configure_opencode_component()
        refresh_global_opencode_config(providers=candidate.llm_providers)
        runtime = build_opencode_session_runtime(candidate.opencode, directory=Path.cwd())
        result = await backend_manager.reload_runtime(**runtime.kwargs_for_backend())
        visible = {f"{model.provider_id}/{model.model_id}" for model in result.models}
        expected = {
            f"{provider_id}/{model_id}"
            for provider_id, provider in candidate.llm_providers.items()
            for model_id in provider["models"]
        }
        if expected - visible:
            raise RuntimeError("运行时未加载全部配置的模型，请检查 API 模型配置")
        _active = copy.deepcopy(candidate)
        await _refresh_live_runtime(_active, mark_dirty=False)
    except BaseException:
        # Keep the private source consistent with the last applied generation;
        # admission remains closed until a successful retry.
        _active = previous
        refresh_global_opencode_config(providers=active_providers())
        if previous is not None:
            from .platform_runtime import refresh_platform_runtime_config
            refresh_platform_runtime_config(previous)
        raise


def status() -> dict:
    from task_agent.config_reload import get_config_reload_coordinator
    from task_agent.llm_config import redact_llm_error
    result = get_config_reload_coordinator().status()
    if result.get("error"):
        # Runtime diagnostics can originate in a Provider's HTTP response.
        result["error"] = redact_llm_error(
            result["error"], _source.llm_providers if _source else {},
        )
    return result


def retry() -> bool:
    from task_agent.config_reload import get_config_reload_coordinator
    return get_config_reload_coordinator().retry()
