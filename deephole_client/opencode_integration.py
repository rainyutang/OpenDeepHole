"""DeepHole 2.0 integration for the self-contained Task Agent component."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

from backend.config import get_config
from backend.logger import get_logger
from task_agent.config_discovery import (
    config_home_candidates,
    deep_merge_opencode_config,
    merge_discovered_opencode_config,
    opencode_executable_alias,
    read_opencode_config,
    runtime_config_candidates,
)

from .config import _merged_no_proxy_environment

logger = get_logger(__name__)

_GLOBAL_WORKSPACE = Path.home() / ".opendeephole" / "opencode_workspace"
_MANAGED_CONFIG_FILENAME = ".opendeephole-managed-opencode.json"
_GLOBAL_OPENCODE_EXTERNAL_ROOT = "~/.opendeephole/opencode_workspace/.opencode"
_AGENT_WRITABLE_EXTERNAL_ROOTS = (
    "~/.opendeephole/scans",
    "~/.opendeephole/fp_reviews",
    "~/.opendeephole/vulnerability_validation",
    "~/.opendeephole/skill_create",
)
_LEGACY_MANAGED_THREAT_ANALYSIS_SKILLS = (
    "value-asset-map",
    "high-risk-module-map",
    "high-risk-module-merge",
    "attack-tree-by-asset",
)
_workspace_locks: dict[str, threading.RLock] = {}
_workspace_locks_guard = threading.Lock()
@dataclass(frozen=True)
class _ResolvedServePort:
    port: int
    auto_selected: bool


def _config_value(value, name: str, default=None):
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def _disabled_source_mcp_tools(directory: Path) -> tuple[str, ...]:
    """Legacy host hook; scan contexts now select their source MCP explicitly."""
    return ()


def _build_session_runtime(cli_config, model_option, directory: Path):
    """Resolve the existing DeepHole 2.0 Serve configuration for the component."""
    from task_agent import OpenCodeSessionRuntime
    effective = _effective_model_config(cli_config, model_option)
    tool = str(effective["tool"] or "opencode").strip().lower()
    if tool != "opencode":
        raise ValueError(f"Unsupported OpenCode serve tool: {tool}")
    executable = str(effective["executable"] or tool).strip()
    resolved_executable = shutil.which(executable)
    if resolved_executable:
        executable = resolved_executable
    model = str(effective["model"] or "")
    workspace = get_global_opencode_workspace()
    serve_env = _runtime_environment(effective)
    resolved_port = _resolve_serve_port(effective.get("serve_port"))
    # Automatic ports are allocated by OpenCodeServeManager immediately before
    # it launches Serve.  Publishing a sampled-and-released ephemeral port here
    # leaves a much larger window in which Windows or another process can claim
    # it before Popen reaches the actual listener bind.
    if not resolved_port.auto_selected:
        serve_env["OPENCODE_SERVE_PORT"] = str(resolved_port.port)
    config_content = _runtime_config_content(
        workspace,
        effective,
        Path(directory).resolve(),
    )
    return OpenCodeSessionRuntime(
        directory=Path(directory).resolve(),
        tool=tool,
        executable=executable,
        model=model,
        config_workspace=workspace,
        config_content=config_content,
        serve_port_auto=resolved_port.auto_selected,
        env_overrides={
            key: serve_env[key]
            for key in (
                "NO_PROXY",
                "no_proxy",
                "NODE_TLS_REJECT_UNAUTHORIZED",
                "OPENCODE_SERVE_PORT",
            )
            if key in serve_env
        },
    )


def build_opencode_session_runtime(
    cli_config,
    model_option=None,
    directory: Path | None = None,
):
    """Build the generic Serve runtime used by task scheduling and model listing."""
    return _build_session_runtime(
        cli_config,
        model_option,
        Path(directory or Path.cwd()).resolve(),
    )


def _effective_model_config(cli_config, model_option) -> dict:
    def choose(name: str, default=None):
        override = _config_value(model_option, name, None)
        return override if override not in (None, "") else _config_value(
            cli_config,
            name,
            default,
        )

    use_default_model = bool(_config_value(model_option, "use_default_model", False))
    return {
        "tool": "opencode",
        "executable": _config_value(cli_config, "executable", "opencode") or "opencode",
        "model": "" if use_default_model else choose("model", ""),
        "config_paths": _config_value(cli_config, "config_paths", []) or [],
        "proxy_url": str(_config_value(cli_config, "proxy_url", "") or ""),
        "no_proxy": str(_config_value(cli_config, "no_proxy", "") or ""),
        "serve_port": _config_value(cli_config, "serve_port", None),
    }


def _resolve_serve_port(configured_port: object = None) -> _ResolvedServePort:
    """Resolve a fixed port or return the sentinel for launch-time allocation."""
    raw = configured_port
    if raw in (None, ""):
        raw = os.environ.get("OPENCODE_SERVE_PORT", "")
    if raw not in (None, ""):
        try:
            port = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"OPENCODE_SERVE_PORT must be an integer port: {raw!r}"
            ) from exc
        if not 1 <= port <= 65535:
            raise ValueError(
                f"OPENCODE_SERVE_PORT must be between 1 and 65535: {raw!r}"
            )
        return _ResolvedServePort(port=port, auto_selected=False)

    return _ResolvedServePort(port=0, auto_selected=True)


def _resolved_serve_port(configured_port: object = None) -> int:
    """Compatibility helper; zero means allocate automatically at launch."""
    return _resolve_serve_port(configured_port).port


def _deep_merge(base: dict, override: dict) -> dict:
    return deep_merge_opencode_config(base, override)


def _read_runtime_config(path: Path) -> dict:
    def warn_invalid(invalid_path: Path, exc: Exception) -> None:
        logger.warning("Ignoring invalid OpenCode config %s: %s", invalid_path, exc)

    return read_opencode_config(path, on_invalid=warn_invalid)


def _config_home_candidates(env: dict[str, str]) -> list[Path]:
    return config_home_candidates(env, platform=sys.platform)


def _runtime_config_candidates(
    effective: dict,
    project_dir: Path,
    env: dict[str, str],
) -> list[tuple[str, Path]]:
    return runtime_config_candidates(
        executable=effective.get("executable"),
        project_dir=project_dir,
        configured_paths=effective.get("config_paths"),
        env=env,
        platform=sys.platform,
    )


def _opencode_executable_alias(value: object) -> str:
    """Return a known compatibility executable name for config discovery."""
    return opencode_executable_alias(value)


def _merge_managed_runtime_config(base: dict, managed: dict) -> dict:
    merged = _deep_merge(base, managed)
    for key in ("$schema", "skills", "permission"):
        if key in managed:
            merged[key] = json.loads(json.dumps(managed[key]))
    for section_name in ("mcp", "agent"):
        managed_section = managed.get(section_name)
        if not isinstance(managed_section, dict):
            continue
        merged_section = merged.setdefault(section_name, {})
        if not isinstance(merged_section, dict):
            merged_section = {}
            merged[section_name] = merged_section
        for name, value in managed_section.items():
            merged_section[name] = json.loads(json.dumps(value))
    return merged


def _runtime_config_content(
    workspace: Path,
    effective: dict,
    project_dir: Path,
) -> str:
    from task_agent.config_json import dump_opencode_config

    def warn_invalid(path: Path, exc: Exception) -> None:
        logger.warning("Ignoring invalid OpenCode config %s: %s", path, exc)

    merged, loaded = merge_discovered_opencode_config(
        executable=effective.get("executable"),
        project_dir=project_dir,
        configured_paths=effective.get("config_paths"),
        env=dict(os.environ),
        platform=sys.platform,
        on_invalid=warn_invalid,
    )
    managed = _read_runtime_config(managed_opencode_config_path(workspace))
    merged = _merge_managed_runtime_config(merged, managed)
    logger.info(
        "OpenCode runtime config discovery: project_dir=%s loaded=%s merged_top_keys=%s",
        project_dir,
        loaded,
        sorted(str(key) for key in merged),
    )
    return dump_opencode_config(merged)


def _runtime_environment(effective: dict) -> dict[str, str]:
    env = {"NODE_TLS_REJECT_UNAUTHORIZED": "0"}
    env.update(_merged_no_proxy_environment(effective.get("no_proxy")))
    return env


def configure_opencode_component() -> None:
    """Register DeepHole 2.0 host bindings without starting OpenCode Serve."""
    from task_agent import OpenCodeHostBindings, configure_opencode

    configure_opencode(OpenCodeHostBindings(
        get_config=get_config,
        get_workspace=get_global_opencode_workspace,
        build_session_runtime=_build_session_runtime,
        disabled_source_mcp_tools=_disabled_source_mcp_tools,
        writable_roots=_agent_writable_roots,
    ))


def _agent_writable_roots() -> tuple[Path, ...]:
    """Return stable Agent-owned roots made writable in global config."""
    root = Path.home() / ".opendeephole"
    return tuple(
        (root / name).resolve()
        for name in (
            "scans",
            "fp_reviews",
            "vulnerability_validation",
            "skill_create",
        )
    )


def get_workspace_lock(workspace: Path) -> threading.RLock:
    """Return a process-local lock for opencode files in one workspace."""
    key = str(workspace.resolve())
    with _workspace_locks_guard:
        lock = _workspace_locks.get(key)
        if lock is None:
            lock = threading.RLock()
            _workspace_locks[key] = lock
        return lock


def managed_opencode_config_path(workspace: Path) -> Path:
    """Return the private DeepHole 2.0-owned config layer for one workspace."""
    return workspace / _MANAGED_CONFIG_FILENAME


def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)


def _remove_legacy_managed_threat_analysis_skills(workspace: Path) -> Path:
    """Remove globally injected Skills now supplied by each selected method."""
    skills_dir = workspace / ".opencode" / "skills"
    skills_dir.mkdir(parents=True, exist_ok=True)
    for name in _LEGACY_MANAGED_THREAT_ANALYSIS_SKILLS:
        _remove_path(skills_dir / name)
    return skills_dir


def get_global_opencode_workspace() -> Path:
    """Return and initialize the single Agent-wide OpenCode workspace.

    The workspace contains stable MCP/Skill configuration, an explicit
    read-only grant for ``.opencode``, and writable grants for the Agent-owned
    task stores. Scan-specific state (scope and selected feedback) is attached
    to each task by :mod:`task_agent.task_service`.
    """
    workspace = _GLOBAL_WORKSPACE
    workspace.mkdir(parents=True, exist_ok=True)
    with get_workspace_lock(workspace):
        _remove_legacy_managed_threat_analysis_skills(workspace)
        config_path = managed_opencode_config_path(workspace)
        config_missing = not config_path.is_file()
        permissions_stale = (
            not config_missing
            and not _has_managed_permissions(config_path, workspace)
        )
        builtin_mcp_stale = (
            not config_missing
            and _has_obsolete_builtin_mcp(config_path)
        )
        if config_missing or permissions_stale or builtin_mcp_stale:
            _write_opencode_config(workspace)
    return workspace


def refresh_global_opencode_config() -> Path:
    """Rewrite the Agent-owned OpenCode configuration and managed MCP entries."""
    workspace = get_global_opencode_workspace()
    config_path = managed_opencode_config_path(workspace)
    skills_dir = (workspace / ".opencode" / "skills").resolve()
    with get_workspace_lock(workspace):
        _write_text_atomic(
            config_path,
            json.dumps(build_opencode_config(
                skills_paths=[str(skills_dir)],
                readable_paths=[str(workspace / ".opencode")],
            ), indent=2),
            mode=0o600,
        )
    return workspace


def _write_text_atomic(path: Path, content: str, *, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    if mode is not None:
        temporary.chmod(mode)
    os.replace(temporary, path)
    if mode is not None:
        path.chmod(mode)


def writable_edit_patterns(path: str | os.PathLike[str]) -> list[str]:
    normalized = str(path)
    variants = [normalized]
    slash_normalized = normalized.replace("\\", "/")
    if slash_normalized not in variants:
        variants.append(slash_normalized)
    backslash_normalized = normalized.replace("/", "\\")
    if backslash_normalized not in variants:
        variants.append(backslash_normalized)

    patterns: list[str] = []
    for variant in variants:
        separator = "\\" if "\\" in variant and "/" not in variant else "/"
        descendant = (
            f"{variant}**"
            if variant.endswith(("/", "\\"))
            else f"{variant}{separator}**"
        )
        for pattern in (variant, descendant):
            if pattern not in patterns:
                patterns.append(pattern)
    return patterns


def build_opencode_config(
    skills_paths: list[str] | None = None,
    writable_paths: list[str] | None = None,
    readable_paths: list[str] | None = None,
) -> dict:
    """Build the canonical opencode.json content for DeepHole 2.0 workspaces."""
    read_permissions = {"*": "allow"}
    external_permissions = {"*": "deny"}
    edit_permissions = {"*": "deny"}

    def add_path_rules(
        paths: list[str | os.PathLike[str]],
        *,
        writable: bool,
    ) -> None:
        for path in paths:
            normalized = str(Path(path).expanduser().resolve())
            patterns = (
                writable_edit_patterns(path)
                + writable_edit_patterns(normalized)
            )
            for pattern in patterns:
                read_permissions[pattern] = "allow"
                external_permissions[pattern] = "allow"
                if writable:
                    edit_permissions[pattern] = "allow"

    stable_writable_paths: list[str | os.PathLike[str]] = [
        *_AGENT_WRITABLE_EXTERNAL_ROOTS,
        *_agent_writable_roots(),
        *(writable_paths or []),
    ]
    stable_readable_paths: list[str | os.PathLike[str]] = [
        _GLOBAL_OPENCODE_EXTERNAL_ROOT,
        _GLOBAL_WORKSPACE / ".opencode",
        *(skills_paths or []),
        *(readable_paths or []),
    ]
    add_path_rules(stable_readable_paths, writable=False)
    add_path_rules(stable_writable_paths, writable=True)

    data = {
        "$schema": "https://opencode.ai/config.json",
        "mcp": {},
        "permission": {
            "read": read_permissions,
            "list": {"*": "allow"},
            "glob": {"*": "allow"},
            "grep": {"*": "allow"},
            "external_directory": external_permissions,
            "edit": edit_permissions,
            "bash": {"*": "deny"},
            "skill": {"*": "allow"},
        },
    }
    for spec in build_managed_mcp_runtime_specs(get_config()).values():
        entry = spec.get("config")
        if spec.get("enabled") and isinstance(entry, dict) and not spec.get("error"):
            data["mcp"][str(spec["name"])] = entry
    if skills_paths:
        data["skills"] = {"paths": skills_paths}
    return data


def _has_managed_permissions(config_path: Path, workspace: Path) -> bool:
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
        permission = data.get("permission", {})
        read = permission.get("read", {})
        external = permission.get("external_directory", {})
        edit = permission.get("edit", {})
        readable_patterns: list[str] = []
        for path in (
            _GLOBAL_OPENCODE_EXTERNAL_ROOT,
            workspace / ".opencode",
            workspace / ".opencode" / "skills",
        ):
            readable_patterns.extend(writable_edit_patterns(path))
            readable_patterns.extend(writable_edit_patterns(
                Path(path).expanduser().resolve()
            ))
        writable_patterns: list[str] = []
        for path in (*_AGENT_WRITABLE_EXTERNAL_ROOTS, *_agent_writable_roots()):
            writable_patterns.extend(writable_edit_patterns(path))
            writable_patterns.extend(writable_edit_patterns(
                Path(path).expanduser().resolve()
            ))
        return (
            read.get("*") == "allow"
            and all(
                permission.get(name, {}).get("*") == "allow"
                for name in ("list", "glob", "grep")
            )
            and external.get("*") == "deny"
            and edit.get("*") == "deny"
            and permission.get("bash", {}).get("*") == "deny"
            and permission.get("skill", {}).get("*") == "allow"
            and all(
                read.get(pattern) == "allow"
                and external.get(pattern) == "allow"
                and edit.get(pattern) != "allow"
                for pattern in dict.fromkeys(readable_patterns)
            )
            and all(
                read.get(pattern) == "allow"
                and external.get(pattern) == "allow"
                and edit.get(pattern) == "allow"
                for pattern in dict.fromkeys(writable_patterns)
            )
        )
    except Exception:
        return False


def _has_obsolete_builtin_mcp(config_path: Path) -> bool:
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
        mcp = data.get("mcp", {})
        return isinstance(mcp, dict) and "deephole-code" in mcp
    except Exception:
        return False


def _managed_mcp_value(value, name: str, default=None):
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def normalized_managed_mcp_config(managed) -> dict:
    """Return one stable managed-MCP payload for hashing and runtime sync."""
    local = _managed_mcp_value(managed, "local", {}) or {}
    remote = _managed_mcp_value(managed, "remote", {}) or {}
    return {
        "enabled": bool(_managed_mcp_value(managed, "enabled", False)),
        "name": str(_managed_mcp_value(managed, "name", "") or "").strip(),
        "transport": str(_managed_mcp_value(managed, "transport", "local") or "local"),
        "timeout_seconds": max(1, int(_managed_mcp_value(managed, "timeout_seconds", 300) or 300)),
        "local": {
            "executable": str(_managed_mcp_value(local, "executable", "") or "").strip(),
            "args": [str(item) for item in (_managed_mcp_value(local, "args", []) or [])],
            "environment": {
                str(key): str(value)
                for key, value in dict(_managed_mcp_value(local, "environment", {}) or {}).items()
            },
        },
        "remote": {
            "url": str(_managed_mcp_value(remote, "url", "") or "").strip(),
            "headers": {
                str(key): str(value)
                for key, value in dict(_managed_mcp_value(remote, "headers", {}) or {}).items()
            },
        },
    }


def managed_mcp_config_fingerprint(managed) -> str:
    payload = json.dumps(
        normalized_managed_mcp_config(managed),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_managed_mcp_runtime_specs(runtime_config=None) -> dict[str, dict]:
    """Return Agent-wide MCP entries.

    Product knowledge and source graphs are scan-owned from v5 onward. An
    empty result also disconnects a previously hot-loaded v4 product MCP.
    """
    del runtime_config
    return {}


def _write_opencode_config(workspace: Path) -> None:
    """Generate the private DeepHole 2.0-owned runtime configuration layer."""
    config_path = managed_opencode_config_path(workspace)
    skills_dir = (workspace / ".opencode" / "skills").resolve()
    _write_text_atomic(
        config_path,
        json.dumps(build_opencode_config(
            skills_paths=[str(skills_dir)],
            readable_paths=[str(workspace / ".opencode")],
        ), indent=2),
        mode=0o600,
    )
