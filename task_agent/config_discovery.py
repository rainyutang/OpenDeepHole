"""Controlled discovery and merging for OpenCode runtime configuration."""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path, PureWindowsPath
from typing import Callable, Mapping

from .config_json import parse_opencode_jsonc


GLOBAL_CONFIG_FILENAMES = (
    "config.json",
    "opencode.json",
    "opencode.jsonc",
)
NAMED_CONFIG_FILENAMES = (
    "opencode.json",
    "opencode.jsonc",
)
EXPLICIT_CONFIG_ENV_NAMES = (
    "OPENCODE_CONFIG_PATH",
    "OPENCODE_CONFIG",
    "OPENCODE_CONFIG_DIR",
)

InvalidConfigHandler = Callable[[Path, Exception], None]


def _json_clone(value):
    return json.loads(json.dumps(value))


def deep_merge_opencode_config(base: dict, override: dict) -> dict:
    """Recursively merge JSON objects, with the later layer taking precedence."""
    merged = _json_clone(base)
    for key, value in override.items():
        if isinstance(merged.get(key), dict) and isinstance(value, dict):
            merged[key] = deep_merge_opencode_config(merged[key], value)
        else:
            merged[key] = _json_clone(value)
    return merged


def config_home_candidates(
    env: Mapping[str, str],
    *,
    platform: str | None = None,
) -> list[Path]:
    """Return user-level OpenCode configuration roots in precedence order."""
    active_platform = platform or sys.platform
    candidates: list[Path] = []
    xdg_config_home = str(env.get("XDG_CONFIG_HOME") or "").strip()
    if xdg_config_home:
        candidates.append(Path(os.path.expandvars(xdg_config_home)).expanduser())

    home = str(env.get("HOME") or "").strip()
    if not home and active_platform == "win32":
        home = str(env.get("USERPROFILE") or "").strip()
    if home:
        candidates.append(
            Path(os.path.expandvars(home)).expanduser() / ".config"
        )
    else:
        candidates.append(Path.home() / ".config")

    if active_platform == "win32":
        appdata = str(env.get("APPDATA") or "").strip()
        if appdata:
            candidates.append(
                Path(os.path.expandvars(appdata)).expanduser()
            )

    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = _path_key(candidate)
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return unique


def opencode_executable_alias(value: object) -> str:
    """Return a known compatibility executable name for config discovery."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    names = {Path(raw).name, PureWindowsPath(raw).name}
    for name in names:
        normalized = name.strip().lower()
        for suffix in (".exe", ".cmd", ".bat"):
            if normalized.endswith(suffix):
                normalized = normalized[: -len(suffix)]
                break
        if normalized in {"opencode", "nga"}:
            return normalized
    return ""


def _split_config_path_value(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    if not text:
        return []
    result: list[str] = []
    for line in text.splitlines():
        for item in line.split(os.pathsep):
            item = item.strip()
            if item:
                result.append(item)
    return result


def _expand_config_path(raw_path: str) -> list[Path]:
    path = Path(os.path.expandvars(raw_path)).expanduser()
    if path.is_dir():
        return [path / name for name in GLOBAL_CONFIG_FILENAMES]
    return [path]


def runtime_config_candidates(
    *,
    executable: object,
    project_dir: Path,
    configured_paths: object = (),
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
) -> list[tuple[str, Path]]:
    """Discover ambient OpenCode config layers from low to high precedence."""
    effective_env = dict(os.environ) if env is None else dict(env)
    candidates: list[tuple[str, Path]] = []
    config_dir_names = ["opencode"]
    if opencode_executable_alias(executable) == "nga":
        config_dir_names.append("nga")
    for config_home in config_home_candidates(
        effective_env,
        platform=platform,
    ):
        for config_dir_name in config_dir_names:
            config_dir = config_home / config_dir_name
            candidates.extend(
                ("global", config_dir / filename)
                for filename in GLOBAL_CONFIG_FILENAMES
            )

    executable_text = str(executable or "opencode").strip()
    if executable_text:
        resolved_executable = shutil.which(executable_text) or executable_text
        executable_parent = Path(resolved_executable).expanduser().parent
        if str(executable_parent) not in {"", "."}:
            candidates.extend(
                ("executable", executable_parent / filename)
                for filename in NAMED_CONFIG_FILENAMES
            )
            candidates.extend(
                ("executable", executable_parent / ".opencode" / filename)
                for filename in NAMED_CONFIG_FILENAMES
            )

    candidates.extend(
        ("project", project_dir / filename)
        for filename in NAMED_CONFIG_FILENAMES
    )
    candidates.extend(
        ("project", project_dir / ".opencode" / filename)
        for filename in NAMED_CONFIG_FILENAMES
    )

    for raw_path in _split_config_path_value(configured_paths):
        candidates.extend(
            ("configured", path) for path in _expand_config_path(raw_path)
        )
    for env_name in EXPLICIT_CONFIG_ENV_NAMES:
        for raw_path in _split_config_path_value(effective_env.get(env_name)):
            candidates.extend(
                (env_name, path) for path in _expand_config_path(raw_path)
            )
    return candidates


def read_opencode_config(
    path: Path,
    *,
    on_invalid: InvalidConfigHandler | None = None,
) -> dict:
    """Read one JSON/JSONC object, ignoring a missing or invalid layer."""
    if not path.is_file():
        return {}
    try:
        return parse_opencode_jsonc(
            path.read_text(encoding="utf-8"),
            source=str(path),
        )
    except Exception as exc:
        if on_invalid is not None:
            on_invalid(path, exc)
        return {}


def merge_discovered_opencode_config(
    *,
    executable: object,
    project_dir: Path,
    configured_paths: object = (),
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    excluded_paths: tuple[Path, ...] = (),
    on_invalid: InvalidConfigHandler | None = None,
) -> tuple[dict, list[dict[str, object]]]:
    """Load and merge discovered config layers while reporting safe metadata."""
    excluded = {_path_key(path) for path in excluded_paths}
    merged: dict = {}
    loaded: list[dict[str, object]] = []
    seen: set[str] = set()
    for source, candidate in runtime_config_candidates(
        executable=executable,
        project_dir=project_dir,
        configured_paths=configured_paths,
        env=env,
        platform=platform,
    ):
        key = _path_key(candidate)
        if key in seen or key in excluded:
            continue
        seen.add(key)
        config = read_opencode_config(candidate, on_invalid=on_invalid)
        if not config:
            continue
        merged = deep_merge_opencode_config(merged, config)
        loaded.append({
            "source": source,
            "path": str(candidate),
            "keys": sorted(str(item) for item in config),
        })
    return merged, loaded


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))
