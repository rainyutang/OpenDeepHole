"""Scan-local Codex trust and CodeGraph MCP configuration."""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 Agent compatibility.
    import tomli as tomllib

from .codex_profiles import sync_codex_trusted_projects


_SCAN_CONFIG_MARKER = (
    "# Managed by OpenDeepHole scan Codex configuration. Do not edit."
)
_SCAN_WORKSPACE_NAME = "threat_analysis"
_MCP_NAME = "codegraph"


@dataclass(frozen=True)
class ScanCodexConfigResult:
    """Outcome of one scan-level Codex configuration operation."""

    trusted_paths: tuple[str, ...] = ()
    mcp_configured: bool = False
    warnings: tuple[str, ...] = ()
    error: str = ""


def scan_codex_workspace(scan_dir: str | Path) -> Path:
    """Return the exact cwd used by the Codex Goal app-server."""
    return Path(scan_dir).expanduser().resolve() / _SCAN_WORKSPACE_NAME


def codex_runtime_reference_root() -> Path:
    """Return the references and validator directory read by the Codex Goal."""
    return (
        Path(__file__).resolve().parent
        / "threat_analysis"
        / "methods"
        / "codex_goal_threat_analysis"
    )


def _opendeephole_home(scan_dir: Path) -> Path:
    # Scan storage is ~/.opendeephole/scans/<scan_id>. Deriving the root from
    # the actual scan path keeps trust aligned with the Agent's chosen home on
    # both Linux and Windows.
    if len(scan_dir.parents) < 2:
        raise ValueError(f"scan directory has no OpenDeepHole root: {scan_dir}")
    return scan_dir.parent.parent


def prepare_scan_codex_access(
    *,
    project_path: str | Path,
    scan_dir: str | Path,
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    codex_home: Path | None = None,
) -> ScanCodexConfigResult:
    """Trust every absolute path the scan's Codex process must read."""
    project = Path(project_path).expanduser().resolve()
    scan_root = Path(scan_dir).expanduser().resolve()
    workspace = scan_codex_workspace(scan_root)
    try:
        if workspace.is_symlink():
            raise OSError(f"refused to use symlinked Codex workspace {workspace}")
        workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not workspace.is_dir():
            raise NotADirectoryError(str(workspace))
        if os.name != "nt":
            os.chmod(workspace, 0o700)
    except OSError as exc:
        return ScanCodexConfigResult(
            error=(
                f"could not prepare scan Codex workspace {workspace} "
                f"({type(exc).__name__})"
            ),
        )

    required_paths = (
        project,
        _opendeephole_home(scan_root),
        workspace,
        codex_runtime_reference_root(),
    )
    result = sync_codex_trusted_projects(
        required_paths,
        env=env,
        platform=platform,
        codex_home=codex_home,
    )
    return ScanCodexConfigResult(
        trusted_paths=result.trusted_paths,
        warnings=result.warnings,
        error=result.error,
    )


def _toml_string(value: object) -> str:
    return json.dumps(str(value), ensure_ascii=True)


def _timeout_seconds(raw: object) -> int:
    if isinstance(raw, bool):
        raise ValueError("CodeGraph MCP timeout must be a positive integer")
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "CodeGraph MCP timeout must be a positive integer"
        ) from exc
    if value < 1:
        raise ValueError("CodeGraph MCP timeout must be a positive integer")
    return value


def _string_mapping(raw: object, *, label: str) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise ValueError(f"CodeGraph MCP {label} must be an object")
    return {str(key): str(value) for key, value in raw.items()}


def _local_command(
    executable: str,
    args: Sequence[object],
    *,
    env: Mapping[str, str],
    platform: str,
) -> tuple[str, tuple[str, ...]]:
    resolved = shutil.which(executable)
    if resolved is None:
        candidate = Path(executable).expanduser()
        if candidate.is_file():
            resolved = str(candidate.resolve())
    command = str(resolved or executable)
    rendered_args = tuple(str(item) for item in args)
    if platform == "win32" and Path(command).suffix.lower() in {".bat", ".cmd"}:
        return (
            str(env.get("COMSPEC") or os.environ.get("COMSPEC") or "cmd.exe"),
            ("/d", "/c", "call", command, *rendered_args),
        )
    return command, rendered_args


def _render_mapping_table(
    lines: list[str],
    table: str,
    values: Mapping[str, str],
) -> None:
    if not values:
        return
    lines.extend(("", f"[{table}]"))
    for key in sorted(values, key=lambda item: (item.casefold(), item)):
        lines.append(f"{_toml_string(key)} = {_toml_string(values[key])}")


def _render_codegraph_mcp(
    config: Mapping[str, Any],
    *,
    project_path: Path,
    env: Mapping[str, str],
    platform: str,
) -> bytes:
    if not bool(config.get("enabled")):
        raise ValueError("CodeGraph MCP is disabled")
    transport = str(config.get("transport") or "local").strip().lower()
    timeout = _timeout_seconds(config.get("timeout_seconds", 300))
    lines = [
        _SCAN_CONFIG_MARKER,
        f"[mcp_servers.{_MCP_NAME}]",
    ]
    if transport == "local":
        local = config.get("local")
        if not isinstance(local, Mapping):
            raise ValueError("CodeGraph MCP local config must be an object")
        executable = str(local.get("executable") or "").strip()
        if not executable:
            raise ValueError("CodeGraph MCP executable is empty")
        raw_args = local.get("args", ())
        if not isinstance(raw_args, (list, tuple)):
            raise ValueError("CodeGraph MCP args must be an array")
        command, args = _local_command(
            executable,
            raw_args,
            env=env,
            platform=platform,
        )
        lines.extend((
            f"command = {_toml_string(command)}",
            "args = [" + ", ".join(_toml_string(item) for item in args) + "]",
            f"cwd = {_toml_string(project_path)}",
        ))
        environment = _string_mapping(
            local.get("environment"),
            label="environment",
        )
    elif transport == "remote":
        remote = config.get("remote")
        if not isinstance(remote, Mapping):
            raise ValueError("CodeGraph MCP remote config must be an object")
        url = str(remote.get("url") or "").strip()
        if not url:
            raise ValueError("CodeGraph MCP remote URL is empty")
        lines.append(f"url = {_toml_string(url)}")
        headers = _string_mapping(remote.get("headers"), label="headers")
        environment = {}
    else:
        raise ValueError(
            f"unsupported CodeGraph MCP transport: {transport or '(empty)'}"
        )

    lines.extend((
        "enabled = true",
        "required = false",
        f"startup_timeout_sec = {timeout}",
        f"tool_timeout_sec = {timeout}",
    ))
    if transport == "local":
        _render_mapping_table(
            lines,
            f"mcp_servers.{_MCP_NAME}.env",
            environment,
        )
    else:
        _render_mapping_table(
            lines,
            f"mcp_servers.{_MCP_NAME}.http_headers",
            headers,
        )
    lines.append("")
    rendered = "\n".join(lines)
    tomllib.loads(rendered)
    return rendered.encode("utf-8")


def _owned_scan_config(path: Path, content: bytes | None = None) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    try:
        raw = path.read_bytes() if content is None else content
        first_line = raw.decode("utf-8").splitlines()[0]
    except (OSError, UnicodeError, IndexError):
        return False
    return first_line == _SCAN_CONFIG_MARKER


def _stage_file(path: Path, content: bytes, *, mode: int) -> Path:
    temporary = path.parent / (
        f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        return temporary
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _unchanged(
    path: Path,
    original: bytes | None,
    original_mode: int,
) -> bool:
    try:
        if path.is_symlink():
            return False
        if original is None:
            return not path.exists()
        return (
            path.is_file()
            and path.read_bytes() == original
            and stat.S_IMODE(path.stat().st_mode) == original_mode
        )
    except OSError:
        return False


def sync_scan_codex_mcp(
    *,
    scan_dir: str | Path,
    project_path: str | Path,
    code_graph_mcp: Mapping[str, Any] | None,
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
) -> ScanCodexConfigResult:
    """Reconcile the owned CodeGraph MCP file for one scan workspace."""
    effective_env = dict(os.environ) if env is None else dict(env)
    active_platform = platform or sys.platform
    workspace = scan_codex_workspace(scan_dir)
    config_dir = workspace / ".codex"
    config_path = config_dir / "config.toml"
    enabled = bool(
        isinstance(code_graph_mcp, Mapping)
        and code_graph_mcp.get("enabled")
    )
    try:
        desired = (
            _render_codegraph_mcp(
                code_graph_mcp,
                project_path=Path(project_path).expanduser().resolve(),
                env=effective_env,
                platform=active_platform,
            )
            if enabled and code_graph_mcp is not None
            else None
        )
    except Exception as exc:
        return ScanCodexConfigResult(
            error=(
                "could not render scan CodeGraph MCP configuration "
                f"({type(exc).__name__}: {exc})"
            ),
        )

    try:
        if workspace.is_symlink():
            return ScanCodexConfigResult(
                error=f"refused to modify symlinked Codex workspace {workspace}",
            )
        if workspace.exists() and not workspace.is_dir():
            return ScanCodexConfigResult(
                error=f"refused to modify non-directory Codex workspace {workspace}",
            )
        if config_dir.is_symlink():
            return ScanCodexConfigResult(
                error=f"refused to modify symlinked scan Codex directory {config_dir}",
            )
        if config_dir.exists() and not config_dir.is_dir():
            return ScanCodexConfigResult(
                error=f"refused to modify non-directory scan Codex path {config_dir}",
            )
        if config_path.is_symlink():
            return ScanCodexConfigResult(
                error=f"refused to modify symlinked scan Codex config {config_path}",
            )
        exists = config_path.exists()
        if exists and not config_path.is_file():
            return ScanCodexConfigResult(
                error=f"refused to modify non-file scan Codex config {config_path}",
            )
        original = config_path.read_bytes() if exists else None
        original_mode = (
            stat.S_IMODE(config_path.stat().st_mode)
            if exists
            else 0o600
        )
    except OSError as exc:
        return ScanCodexConfigResult(
            error=(
                f"could not inspect scan Codex config {config_path} "
                f"({type(exc).__name__})"
            ),
        )

    if original is not None and not _owned_scan_config(config_path, original):
        return ScanCodexConfigResult(
            error=(
                f"refused to overwrite foreign scan Codex config {config_path}"
            ),
        )
    if desired is None:
        if original is None:
            return ScanCodexConfigResult()
        try:
            if not _unchanged(config_path, original, original_mode):
                raise OSError("scan Codex config changed during cleanup")
            config_path.unlink()
        except OSError as exc:
            return ScanCodexConfigResult(
                error=(
                    "could not remove disabled scan CodeGraph MCP config "
                    f"({type(exc).__name__})"
                ),
            )
        return ScanCodexConfigResult()

    if original == desired and original_mode == 0o600:
        return ScanCodexConfigResult(mcp_configured=True)

    staged: Path | None = None
    try:
        workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            os.chmod(workspace, 0o700)
            os.chmod(config_dir, 0o700)
        staged = _stage_file(config_path, desired, mode=0o600)
        if not _unchanged(config_path, original, original_mode):
            raise OSError("scan Codex config changed during synchronization")
        os.replace(staged, config_path)
        staged = None
    except OSError as exc:
        if staged is not None:
            try:
                staged.unlink()
            except OSError:
                pass
        return ScanCodexConfigResult(
            error=(
                "could not atomically write scan CodeGraph MCP config "
                f"({type(exc).__name__})"
            ),
        )
    return ScanCodexConfigResult(mcp_configured=True)


__all__ = [
    "ScanCodexConfigResult",
    "codex_runtime_reference_root",
    "prepare_scan_codex_access",
    "scan_codex_workspace",
    "sync_scan_codex_mcp",
]
