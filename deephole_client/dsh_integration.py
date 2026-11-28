"""DeepHole 2.0 host integration for the DeepSeek Harness (`sdk-minimal`) runtime."""

from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path
from typing import Any

from backend.config import get_config
from task_agent.config_discovery import merge_discovered_opencode_config
from task_agent.host import OpenCodeSessionRuntime
from task_agent.runtime_backend import (
    DEFAULT_DSH_PROFILE,
    TOOL_DEEPSEEK_HARNESS,
    normalize_runtime_tool,
)

from .config import _merged_no_proxy_environment

_GLOBAL_DSH_HOME = Path.home() / ".opendeephole" / "dsh_home"


def _config_value(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def get_global_dsh_home() -> Path:
    """Return and initialize the Agent-wide DeepSeek Harness home directory."""
    home = _GLOBAL_DSH_HOME.expanduser().resolve()
    home.mkdir(parents=True, exist_ok=True)
    return home


def _discovered_opencode_providers(
    *,
    directory: Path,
    config_paths: Any = None,
) -> dict[str, Any]:
    """Read local OpenAI-compatible providers from discovered opencode.json as fallback."""
    try:
        merged, _loaded = merge_discovered_opencode_config(
            executable="opencode",
            project_dir=directory,
            configured_paths=config_paths,
            env=dict(os.environ),
            platform=sys.platform,
        )
    except Exception:
        return {}
    raw_providers = merged.get("provider")
    if not isinstance(raw_providers, dict):
        return {}
    result: dict[str, Any] = {}
    for provider_id, entry in raw_providers.items():
        if not isinstance(entry, dict):
            continue
        options = entry.get("options")
        models = entry.get("models")
        if (
            isinstance(options, dict)
            and str(options.get("baseURL") or "").strip()
            and isinstance(models, dict)
            and models
        ):
            result[str(provider_id)] = copy.deepcopy(entry)
    return result


def _resolved_llm_providers(
    *,
    directory: Path | None = None,
    config_paths: Any = None,
) -> dict[str, Any]:
    from .llm_runtime import effective_providers

    merged: dict[str, Any] = {}
    if directory is not None:
        merged.update(
            _discovered_opencode_providers(
                directory=directory,
                config_paths=config_paths,
            )
        )
    providers = effective_providers()
    if providers:
        merged.update(providers)
        return merged
    try:
        cfg = get_config()
        raw = getattr(cfg, "llm_providers", None)
        if isinstance(raw, dict):
            merged.update(copy.deepcopy(raw))
    except Exception:
        pass
    return merged


def build_dsh_session_runtime(
    cli_config: Any,
    model_option: Any,
    directory: Path,
) -> OpenCodeSessionRuntime:
    """Construct a DeepSeek Harness ``OpenCodeSessionRuntime`` for DeepHole 2.0."""
    from .opencode_integration import get_global_opencode_workspace

    use_default_model = bool(_config_value(model_option, "use_default_model", False))
    override_model = _config_value(model_option, "model", None)
    model = (
        ""
        if use_default_model
        else str(
            override_model
            if override_model not in (None, "")
            else _config_value(cli_config, "model", "")
            or ""
        ).strip()
    )
    dsh_executable = str(_config_value(cli_config, "dsh_executable", "") or "").strip()
    dsh_profile = (
        str(_config_value(cli_config, "dsh_profile", DEFAULT_DSH_PROFILE) or DEFAULT_DSH_PROFILE).strip()
        or DEFAULT_DSH_PROFILE
    )
    no_proxy = str(_config_value(cli_config, "no_proxy", "") or "")
    env_overrides: dict[str, str] = {"NODE_TLS_REJECT_UNAUTHORIZED": "0"}
    env_overrides.update(_merged_no_proxy_environment(no_proxy))

    workspace = get_global_opencode_workspace()
    skills_dir = (workspace / ".opencode" / "skills").resolve()
    dsh_home = get_global_dsh_home()
    resolved_dir = Path(directory).resolve()
    providers = _resolved_llm_providers(
        directory=resolved_dir,
        config_paths=_config_value(cli_config, "config_paths", None),
    )
    # Keep OpenCode-compatible provider JSON in config_content so Codex threat
    # analysis (`codex_runtime.py`) and configured limit extraction stay seamless.
    config_content = json.dumps(
        {"provider": providers} if providers else {},
        ensure_ascii=False,
    )
    return OpenCodeSessionRuntime(
        directory=resolved_dir,
        tool=TOOL_DEEPSEEK_HARNESS,
        executable=dsh_executable or "dsh",
        opencode_version="1",
        model=model,
        config_workspace=workspace,
        config_content=config_content,
        env_overrides=env_overrides,
        serve_port_auto=False,
        backend_options={
            "dsh_home": str(dsh_home),
            "dsh_executable": dsh_executable,
            "dsh_profile": dsh_profile,
            "llm_providers": providers,
            "skill_roots": [str(skills_dir)] if skills_dir.is_dir() else [],
        },
    )


def dsh_runtime_change_key(config: Any) -> tuple[Any, ...]:
    """Return a comparable runtime-fingerprint tuple covering both backends."""
    oc = getattr(config, "opencode", None)
    tool = normalize_runtime_tool(getattr(oc, "tool", "opencode"))
    return (
        tool,
        getattr(oc, "opencode_version", "1"),
        getattr(oc, "executable", "opencode"),
        getattr(oc, "executable_v2", "opencode"),
        getattr(oc, "dsh_executable", ""),
        getattr(oc, "dsh_profile", DEFAULT_DSH_PROFILE),
        getattr(oc, "serve_port", None),
        getattr(config, "no_proxy", ""),
    )
