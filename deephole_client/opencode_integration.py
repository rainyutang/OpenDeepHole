"""OpenDeepHole integration for the self-contained Task Agent component."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import threading
from pathlib import Path

from backend.config import get_config
from backend.logger import get_logger

logger = get_logger(__name__)

_GLOBAL_WORKSPACE = Path.home() / ".opendeephole" / "opencode_workspace"
_MANAGED_CONFIG_FILENAME = ".opendeephole-managed-opencode.json"
_SCANS_EXTERNAL_ROOT = "~/.opendeephole/scans"
_SCANS_EXTERNAL_PATTERNS = (
    _SCANS_EXTERNAL_ROOT,
    f"{_SCANS_EXTERNAL_ROOT}/**",
)

_workspace_locks: dict[str, threading.RLock] = {}
_workspace_locks_guard = threading.Lock()
_auto_serve_port: int | None = None
_auto_serve_port_guard = threading.Lock()


def _config_value(value, name: str, default=None):
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def _disabled_source_mcp_tools(directory: Path) -> tuple[str, ...]:
    """Choose the source MCP disabled for one project using Agent state."""
    config = get_config()
    code_graph = getattr(config, "code_graph", None)
    name = str(_config_value(code_graph, "name", "codegraph") or "codegraph")
    if not bool(_config_value(code_graph, "enabled", False)):
        return (name,)
    try:
        from deephole_client.codegraph import is_codegraph_mcp_available, is_codegraph_ready

        if is_codegraph_mcp_available(config) and is_codegraph_ready(directory):
            return ("deephole-code",)
    except Exception:
        pass
    return (name,)


def _build_session_runtime(cli_config, model_option, directory: Path):
    """Resolve the existing OpenDeepHole Serve configuration for the component."""
    from task_agent import OpenCodeSessionRuntime
    effective = _effective_model_config(cli_config, model_option)
    tool = str(effective["tool"] or "opencode").strip().lower()
    if tool not in {"opencode", "nga"}:
        raise ValueError(f"Unsupported OpenCode serve tool: {tool}")
    executable = str(effective["executable"] or tool).strip()
    resolved_executable = shutil.which(executable)
    if resolved_executable:
        executable = resolved_executable
    model = str(effective["model"] or "")
    workspace = get_global_opencode_workspace()
    serve_env = _runtime_environment(effective)
    serve_env["OPENCODE_SERVE_PORT"] = str(
        _resolved_serve_port(effective.get("serve_port"))
    )
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
        env_overrides={
            key: serve_env[key]
            for key in (
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "http_proxy",
                "https_proxy",
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
        "tool": choose("tool", "opencode"),
        "executable": choose("executable", ""),
        "model": "" if use_default_model else choose("model", ""),
        "config_paths": _config_value(cli_config, "config_paths", []) or [],
        "config_jsonc": str(_config_value(cli_config, "config_jsonc", "{}") or "{}"),
        "proxy_url": str(_config_value(cli_config, "proxy_url", "") or ""),
        "no_proxy": str(_config_value(cli_config, "no_proxy", "") or ""),
        "serve_port": _config_value(cli_config, "serve_port", None),
    }


def _resolved_serve_port(configured_port: object = None) -> int:
    """Resolve one Agent-wide Serve port, choosing an auto port once per process."""
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
        return port

    global _auto_serve_port
    with _auto_serve_port_guard:
        if _auto_serve_port is None:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", 0))
                _auto_serve_port = int(sock.getsockname()[1])
        return _auto_serve_port


def _deep_merge(base: dict, override: dict) -> dict:
    merged = json.loads(json.dumps(base))
    for key, value in override.items():
        if isinstance(merged.get(key), dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = json.loads(json.dumps(value))
    return merged


def _read_runtime_config(path: Path) -> dict:
    if not path.is_file():
        return {}
    from task_agent.config_json import parse_opencode_jsonc

    try:
        value = parse_opencode_jsonc(
            path.read_text(encoding="utf-8"),
            source=str(path),
        )
    except Exception as exc:
        logger.warning("Ignoring invalid OpenCode config %s: %s", path, exc)
        return {}
    return value if isinstance(value, dict) else {}


def _runtime_config_content(
    workspace: Path,
    effective: dict,
    project_dir: Path,
) -> str:
    from task_agent.config_json import dump_opencode_config, parse_opencode_jsonc

    merged: dict = {}
    raw_paths = effective.get("config_paths") or []
    if isinstance(raw_paths, str):
        raw_paths = [raw_paths]
    for raw_path in raw_paths:
        path = Path(str(raw_path)).expanduser()
        candidates = (
            [path / "opencode.json", path / "opencode.jsonc"]
            if path.is_dir()
            else [path]
        )
        for candidate in candidates:
            merged = _deep_merge(merged, _read_runtime_config(candidate))
    for candidate in (
        project_dir / "opencode.json",
        project_dir / "opencode.jsonc",
        project_dir / ".opencode" / "opencode.json",
        project_dir / ".opencode" / "opencode.jsonc",
    ):
        merged = _deep_merge(merged, _read_runtime_config(candidate))
    web_config = parse_opencode_jsonc(
        str(effective.get("config_jsonc") or "{}"),
        source="Agent OpenCode config",
    )
    if isinstance(web_config, dict):
        merged = _deep_merge(merged, web_config)
    merged = _deep_merge(
        merged,
        _read_runtime_config(managed_opencode_config_path(workspace)),
    )
    return dump_opencode_config(merged)


def _runtime_environment(effective: dict) -> dict[str, str]:
    env = dict(os.environ)
    env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
    proxy = str(effective.get("proxy_url") or "").strip()
    if proxy and "://" not in proxy:
        proxy = f"http://{proxy}"
    if proxy:
        no_proxy = str(effective.get("no_proxy") or "").strip()
        env.update({
            "HTTP_PROXY": proxy,
            "HTTPS_PROXY": proxy,
            "http_proxy": proxy,
            "https_proxy": proxy,
            "NO_PROXY": no_proxy,
            "no_proxy": no_proxy,
        })
    return env


def configure_opencode_component() -> None:
    """Register OpenDeepHole host bindings without starting OpenCode Serve."""
    from task_agent import OpenCodeHostBindings, configure_opencode

    configure_opencode(OpenCodeHostBindings(
        get_config=get_config,
        get_workspace=get_global_opencode_workspace,
        build_session_runtime=_build_session_runtime,
        disabled_source_mcp_tools=_disabled_source_mcp_tools,
    ))


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
    """Return the private OpenDeepHole-owned config layer for one workspace."""
    return workspace / _MANAGED_CONFIG_FILENAME


def opencode_runtime_config_path() -> Path:
    """Return the Agent-wide resolved Serve config path without initializing it."""
    return _GLOBAL_WORKSPACE / "opencode.json"


def get_global_opencode_workspace(*, mcp_port: int | None = None) -> Path:
    """Return and initialize the single Agent-wide OpenCode workspace.

    The workspace contains stable MCP/skill configuration and a read-only
    external-directory grant for the Agent scan store. Scan-specific state
    (scope, selected feedback and writable roots) is attached to each task by
    :mod:`task_agent.task_service` and is never written here.
    """
    workspace = _GLOBAL_WORKSPACE
    workspace.mkdir(parents=True, exist_ok=True)
    with get_workspace_lock(workspace):
        # A caller that owns/has just joined the Agent-wide MCP gateway provides
        # its actual port. Stale managed permissions are migrated before the
        # next Serve acquisition; without an explicit port, the writer keeps
        # the current gateway URL instead of replacing a dynamically allocated
        # port with the configured fallback.
        config_path = managed_opencode_config_path(workspace)
        config_missing = not config_path.is_file()
        permissions_stale = (
            not config_missing
            and not _has_managed_scan_permissions(config_path)
        )
        if mcp_port is not None or config_missing or permissions_stale:
            _write_opencode_config(workspace, mcp_port=mcp_port)
    return workspace


def refresh_global_opencode_config() -> Path:
    """Rewrite managed MCP entries while preserving the active code gateway URL."""
    workspace = get_global_opencode_workspace()
    config_path = managed_opencode_config_path(workspace)
    current_url = _current_deephole_code_url(config_path)
    mcp_url = current_url or (
        f"http://127.0.0.1:{get_config().mcp_server.port}/mcp"
    )
    skills_dir = (workspace / ".opencode" / "skills").resolve()
    with get_workspace_lock(workspace):
        _write_text_atomic(
            config_path,
            json.dumps(build_opencode_config(mcp_url, [str(skills_dir)]), indent=2),
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
    mcp_url: str,
    skills_paths: list[str] | None = None,
    writable_paths: list[str] | None = None,
) -> dict:
    """Build the canonical opencode.json content for OpenDeepHole workspaces."""
    external_permissions = {"*": "deny"}
    edit_permissions = {"*": "deny"}
    for pattern in _SCANS_EXTERNAL_PATTERNS:
        external_permissions[pattern] = "allow"
        # OpenCode external roots inherit normal workspace permissions. Keep
        # the stable scan-store grant read-only; the current task work_dir is
        # allowed later by its Session permission rules.
        edit_permissions[pattern] = "deny"
    for path in writable_paths or []:
        normalized = str(Path(path).resolve())
        patterns = (
            writable_edit_patterns(path)
            + writable_edit_patterns(normalized)
        )
        for pattern in patterns:
            edit_permissions[pattern] = "allow"
    data = {
        "$schema": "https://opencode.ai/config.json",
        "mcp": {
            "deephole-code": {
                "type": "remote",
                "url": mcp_url,
                "enabled": True,
            }
        },
        "permission": {
            "read": {"*": "allow"},
            "list": {"*": "allow"},
            "glob": {"*": "allow"},
            "grep": {"*": "allow"},
            "external_directory": external_permissions,
            "edit": edit_permissions,
            "bash": {"*": "deny"},
        },
    }
    for spec in build_managed_mcp_runtime_specs(get_config()).values():
        entry = spec.get("config")
        if spec.get("enabled") and isinstance(entry, dict) and not spec.get("error"):
            data["mcp"][str(spec["name"])] = entry
    if skills_paths:
        data["skills"] = {"paths": skills_paths}
    return data


def _has_managed_scan_permissions(config_path: Path) -> bool:
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
        permission = data.get("permission", {})
        external = permission.get("external_directory", {})
        edit = permission.get("edit", {})
        return (
            external.get("*") == "deny"
            and edit.get("*") == "deny"
            and all(
                external.get(pattern) == "allow"
                and edit.get(pattern) == "deny"
                for pattern in _SCANS_EXTERNAL_PATTERNS
            )
        )
    except Exception:
        return False


def _current_deephole_code_url(config_path: Path) -> str | None:
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
        value = data.get("mcp", {}).get("deephole-code", {}).get("url")
        if value is None:
            return None
        return str(value).strip() or None
    except Exception:
        return None


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
    """Build the two server-managed MCP entries used by config and hot reload."""
    runtime_config = runtime_config or get_config()
    result: dict[str, dict] = {}
    for target, managed in (
        ("code_graph", getattr(runtime_config, "code_graph", None)),
        ("product_info", getattr(runtime_config, "product_info", None)),
    ):
        normalized = normalized_managed_mcp_config(managed or {})
        enabled = normalized["enabled"]
        name = normalized["name"]
        transport = normalized["transport"]
        error = ""
        entry: dict | None = None
        if enabled and (not name or name == "deephole-code"):
            error = "MCP name is empty or reserved"
        elif enabled and transport == "remote":
            url = normalized["remote"]["url"]
            if not url:
                error = "Remote MCP URL is empty"
            else:
                entry = {
                    "type": "remote",
                    "url": url,
                    "enabled": True,
                    "timeout": normalized["timeout_seconds"] * 1000,
                    # OpenDeepHole currently supports static request-header auth.
                    # Disable OpenCode's interactive OAuth auto-discovery so a bad
                    # Bearer token is reported as a connection failure instead.
                    "oauth": False,
                }
                if normalized["remote"]["headers"]:
                    entry["headers"] = dict(normalized["remote"]["headers"])
        elif enabled and transport == "local":
            executable = normalized["local"]["executable"]
            if not executable:
                error = "Local MCP executable is empty"
            elif target == "code_graph" and not (
                shutil.which(executable) or Path(executable).is_file()
            ):
                error = f"CodeGraph executable not found: {executable}"
            else:
                entry = {
                    "type": "local",
                    "command": [executable, *normalized["local"]["args"]],
                    "enabled": True,
                    "timeout": normalized["timeout_seconds"] * 1000,
                }
                if normalized["local"]["environment"]:
                    entry["environment"] = dict(normalized["local"]["environment"])
        elif enabled:
            error = f"Unsupported MCP transport: {transport}"
        result[target] = {
            "target": target,
            "enabled": enabled,
            "name": name,
            "fingerprint": managed_mcp_config_fingerprint(normalized),
            "config": entry,
            "error": error,
        }
    return result


def _write_opencode_config(workspace: Path, mcp_port: int | None = None) -> None:
    """Generate the private OpenDeepHole-owned runtime configuration layer."""
    config = get_config()
    port = mcp_port if mcp_port is not None else config.mcp_server.port
    config_path = managed_opencode_config_path(workspace)
    mcp_url = f"http://127.0.0.1:{port}/mcp"
    if mcp_port is None:
        mcp_url = _current_deephole_code_url(config_path) or mcp_url
    skills_dir = (workspace / ".opencode" / "skills").resolve()
    _write_text_atomic(
        config_path,
        json.dumps(build_opencode_config(mcp_url, [str(skills_dir)]), indent=2),
        mode=0o600,
    )
