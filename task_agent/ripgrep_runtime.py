"""Runtime detection and provisioning for OpenCode's ripgrep dependency."""

from __future__ import annotations

import os
import re
import secrets
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, MutableMapping

from .config_discovery import opencode_executable_alias


BUNDLED_RIPGREP_DIRNAME = "ripgrep-x86_64-pc-windows-msvc"
BUNDLED_RIPGREP_WINDOWS_EXE = "rg.exe"
_WINDOWS_DRIVE_PREFIX_RE = re.compile(r"[A-Za-z]:[\\/]")
_ORIGINAL_POPEN = subprocess.Popen
_PROBE_CACHE: dict[tuple[str, int, int], bool] = {}


@dataclass(frozen=True)
class RipgrepEnsureResult:
    """Summary of ripgrep availability and startup provisioning actions."""

    available: bool
    executable: str = ""
    source: str = ""
    copied_targets: tuple[str, ...] = ()
    reused_targets: tuple[str, ...] = ()
    prepended_path_dir: str = ""
    warnings: tuple[str, ...] = ()


def default_repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def bundled_ripgrep_dir(root: Path | None = None) -> Path:
    base = root if root is not None else default_repo_root()
    return base / BUNDLED_RIPGREP_DIRNAME


def bundled_ripgrep_executable(root: Path | None = None) -> Path | None:
    candidate = bundled_ripgrep_dir(root) / BUNDLED_RIPGREP_WINDOWS_EXE
    try:
        if candidate.is_file() and candidate.stat().st_size > 0:
            return candidate
    except OSError:
        return None
    return None


def _path_key(path: Path | str, *, platform: str) -> str:
    raw = str(path).strip()
    if platform == "win32":
        normalized = raw.replace("/", "\\").rstrip("\\")
        return normalized.lower()
    try:
        return str(Path(raw).resolve())
    except OSError:
        return os.path.abspath(raw)


def _path_delimiter(raw_path: str, *, platform: str) -> str:
    if platform == "win32":
        if ";" in raw_path or sys.platform == "win32" or _WINDOWS_DRIVE_PREFIX_RE.search(raw_path):
            return ";"
    return os.pathsep


def _get_env_path(env: Mapping[str, str]) -> str:
    if "PATH" in env:
        return str(env.get("PATH") or "")
    for key, value in env.items():
        if key.lower() == "path":
            return str(value or "")
    return ""


def prepend_dir_to_env_path(
    env: MutableMapping[str, str],
    directory: Path | str,
    *,
    platform: str | None = None,
) -> str:
    """Prepend *directory* to ``env['PATH']`` without leaving duplicate-case keys."""
    active_platform = platform or sys.platform
    dir_text = str(directory).strip()
    if not dir_text:
        return _get_env_path(env)

    existing_raw = _get_env_path(env)
    delimiter = ";" if (active_platform == "win32" and (";" in existing_raw or sys.platform == "win32" or _WINDOWS_DRIVE_PREFIX_RE.search(dir_text))) else _path_delimiter(existing_raw, platform=active_platform)
    entries = [item.strip() for item in existing_raw.split(delimiter) if item.strip()] if existing_raw else []
    target_key = _path_key(dir_text, platform=active_platform)
    retained = [item for item in entries if _path_key(item, platform=active_platform) != target_key]
    updated = delimiter.join([dir_text, *retained])

    if env is not os.environ:
        for key in [k for k in list(env.keys()) if k.lower() == "path" and k != "PATH"]:
            env.pop(key, None)
    env["PATH"] = updated
    return updated


def is_working_ripgrep(
    executable_path: Path | str,
    *,
    timeout_seconds: float = 5.0,
) -> bool:
    """Return True when *executable_path* executes ``--version`` as ripgrep."""
    path = Path(executable_path)
    try:
        stat_result = path.stat()
        if not path.is_file() or stat_result.st_size <= 0:
            return False
        cache_key = (str(path.resolve()), stat_result.st_mtime_ns, stat_result.st_size)
    except OSError:
        return False

    cached = _PROBE_CACHE.get(cache_key)
    if cached is not None:
        return cached

    proc = None
    try:
        proc = _ORIGINAL_POPEN(
            [str(path), "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, _stderr = proc.communicate(timeout=timeout_seconds)
        returncode = proc.returncode
    except Exception:
        if proc is not None:
            try:
                proc.kill()
                proc.communicate(timeout=1.0)
            except Exception:
                pass
        return False

    ok = returncode == 0 and "ripgrep" in (stdout or b"").decode("utf-8", errors="replace").lower()
    if len(_PROBE_CACHE) >= 256:
        _PROBE_CACHE.clear()
    _PROBE_CACHE[cache_key] = ok
    return ok


def find_system_ripgrep(
    env: Mapping[str, str] | None = None,
    *,
    root: Path | None = None,
    platform: str | None = None,
    probe_fn: Callable[[Path], bool] = is_working_ripgrep,
) -> Path | None:
    """Locate a working ``rg`` on ``PATH``, ignoring the bundled Windows tool dir."""
    active_platform = platform or sys.platform
    effective_env = os.environ if env is None else env
    raw_path = _get_env_path(effective_env)
    if not raw_path:
        return None

    delimiter = _path_delimiter(raw_path, platform=active_platform)
    bundled_key = _path_key(bundled_ripgrep_dir(root), platform=active_platform)
    candidate_names = (
        ("rg.exe", "rg.cmd", "rg.bat", "rg")
        if active_platform == "win32"
        else ("rg",)
    )

    seen_dirs: set[str] = set()
    for raw_entry in raw_path.split(delimiter):
        entry_text = raw_entry.strip().strip('"')
        if not entry_text:
            continue
        entry_key = _path_key(entry_text, platform=active_platform)
        if entry_key == bundled_key or entry_key in seen_dirs:
            continue
        seen_dirs.add(entry_key)
        entry_dir = Path(entry_text)
        for name in candidate_names:
            candidate = entry_dir / name
            if probe_fn(candidate):
                return candidate
    return None


def _resolve_user_home(
    env: Mapping[str, str],
    *,
    platform: str,
) -> Path:
    if platform == "win32":
        for key in ("USERPROFILE", "HOME"):
            raw = str(env.get(key) or "").strip()
            if raw:
                return Path(os.path.expandvars(raw)).expanduser()
    else:
        raw = str(env.get("HOME") or "").strip()
        if raw:
            return Path(os.path.expandvars(raw)).expanduser()
    return Path.home()


def opencode_ripgrep_bin_targets(
    *,
    env: Mapping[str, str] | None = None,
    executable: object = "opencode",
    isolated_data_home: Path | None = None,
    platform: str | None = None,
) -> list[Path]:
    """Return OpenCode ``Global.Path.bin`` ripgrep file paths in precedence order."""
    active_platform = platform or sys.platform
    effective_env = os.environ if env is None else env
    exe_name = BUNDLED_RIPGREP_WINDOWS_EXE if active_platform == "win32" else "rg"
    alias = opencode_executable_alias(executable)

    data_roots: list[Path] = []
    user_home = _resolve_user_home(effective_env, platform=active_platform)
    data_roots.append(user_home / ".local" / "share")

    xdg_data_home = str(effective_env.get("XDG_DATA_HOME") or "").strip()
    if xdg_data_home:
        data_roots.append(Path(os.path.expandvars(xdg_data_home)).expanduser())
    if env is not None and env is not os.environ:
        ambient_xdg_data_home = str(os.environ.get("XDG_DATA_HOME") or "").strip()
        if ambient_xdg_data_home and ambient_xdg_data_home != xdg_data_home:
            data_roots.append(
                Path(os.path.expandvars(ambient_xdg_data_home)).expanduser()
            )

    app_names = ["opencode"]
    if alias == "nga":
        app_names.append("nga")

    targets: list[Path] = []
    seen: set[str] = set()

    def _add_target(target: Path) -> None:
        key = _path_key(target, platform=active_platform)
        if key not in seen:
            seen.add(key)
            targets.append(target)

    for data_root in data_roots:
        for app_name in app_names:
            _add_target(data_root / app_name / "bin" / exe_name)
        if "nga" not in app_names and (data_root / "nga").is_dir():
            _add_target(data_root / "nga" / "bin" / exe_name)

    if isolated_data_home is not None:
        for app_name in app_names:
            _add_target(isolated_data_home / app_name / "bin" / exe_name)

    return targets


def _atomic_copy_executable(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp_name = f".{dest.name}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
    tmp_path = dest.parent / tmp_name
    try:
        shutil.copy2(src, tmp_path)
        if os.name != "nt":
            try:
                tmp_path.chmod(tmp_path.stat().st_mode | 0o111)
            except OSError:
                pass
        os.replace(tmp_path, dest)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def ensure_ripgrep_ready(
    *,
    env: MutableMapping[str, str] | None = None,
    executable: object = "opencode",
    isolated_data_home: Path | None = None,
    root: Path | None = None,
    platform: str | None = None,
    probe_fn: Callable[[Path], bool] | None = None,
) -> RipgrepEnsureResult:
    """Ensure OpenCode can locate a working ``rg`` binary via ``PATH`` and ``bin``."""
    active_platform = platform or sys.platform
    target_env: MutableMapping[str, str] = os.environ if env is None else env
    effective_probe = probe_fn or is_working_ripgrep
    warnings: list[str] = []

    system_rg = find_system_ripgrep(
        target_env,
        root=root,
        platform=active_platform,
        probe_fn=effective_probe,
    )
    targets = opencode_ripgrep_bin_targets(
        env=target_env,
        executable=executable,
        isolated_data_home=isolated_data_home,
        platform=active_platform,
    )

    if active_platform != "win32":
        if system_rg is not None:
            return RipgrepEnsureResult(
                available=True,
                executable=str(system_rg),
                source="system_path",
            )
        for target in targets:
            if effective_probe(target):
                prepended_dir = str(target.parent)
                prepend_dir_to_env_path(target_env, prepended_dir, platform=active_platform)
                return RipgrepEnsureResult(
                    available=True,
                    executable=str(target),
                    source="opencode_bin",
                    reused_targets=(str(target),),
                    prepended_path_dir=prepended_dir,
                )
        warnings.append(
            "ripgrep (rg) was not found in PATH or OpenCode data bin; "
            "install ripgrep so OpenCode grep/glob/skill tools can run offline."
        )
        return RipgrepEnsureResult(
            available=False,
            warnings=tuple(warnings),
        )

    bundled_rg = bundled_ripgrep_executable(root)
    usable_bundled_rg: Path | None = None
    if bundled_rg is not None:
        if probe_fn is not None or sys.platform == "win32":
            if effective_probe(bundled_rg):
                usable_bundled_rg = bundled_rg
            else:
                warnings.append(f"Bundled ripgrep failed health probe: {bundled_rg}")
        else:
            usable_bundled_rg = bundled_rg

    copy_source = usable_bundled_rg or system_rg
    copied: list[str] = []
    reused: list[str] = []

    for target in targets:
        target_exists = False
        try:
            target_exists = target.exists()
        except OSError:
            target_exists = False

        if target_exists and effective_probe(target):
            reused.append(str(target))
            continue

        # Copy when system ripgrep is missing, when repairing a broken cached
        # rg.exe, or when seeding OpenCode 2.x's isolated XDG data directory.
        is_isolated_target = (
            isolated_data_home is not None
            and _path_key(target.parent.parent.parent, platform=active_platform)
            == _path_key(isolated_data_home, platform=active_platform)
        )
        should_copy = (
            copy_source is not None
            and (system_rg is None or target_exists or is_isolated_target)
        )
        if not should_copy:
            continue

        try:
            _atomic_copy_executable(copy_source, target)
            copied.append(str(target))
        except OSError as exc:
            warnings.append(f"Failed to copy ripgrep to {target}: {exc}")

    prepended_dir = ""
    if usable_bundled_rg is not None:
        prepended_dir = str(usable_bundled_rg.parent)
        prepend_dir_to_env_path(target_env, prepended_dir, platform=active_platform)
    elif copied:
        prepended_dir = str(Path(copied[0]).parent)
        prepend_dir_to_env_path(target_env, prepended_dir, platform=active_platform)
    elif reused and system_rg is None:
        prepended_dir = str(Path(reused[0]).parent)
        prepend_dir_to_env_path(target_env, prepended_dir, platform=active_platform)

    if system_rg is not None:
        return RipgrepEnsureResult(
            available=True,
            executable=str(system_rg),
            source="system_path",
            copied_targets=tuple(copied),
            reused_targets=tuple(reused),
            prepended_path_dir=prepended_dir,
            warnings=tuple(warnings),
        )
    if usable_bundled_rg is not None:
        return RipgrepEnsureResult(
            available=True,
            executable=str(usable_bundled_rg),
            source="bundled",
            copied_targets=tuple(copied),
            reused_targets=tuple(reused),
            prepended_path_dir=prepended_dir,
            warnings=tuple(warnings),
        )
    if copied or reused:
        chosen = copied[0] if copied else reused[0]
        return RipgrepEnsureResult(
            available=True,
            executable=chosen,
            source="opencode_bin",
            copied_targets=tuple(copied),
            reused_targets=tuple(reused),
            prepended_path_dir=prepended_dir,
            warnings=tuple(warnings),
        )

    warnings.append(
        f"ripgrep (rg.exe) is missing and bundled {BUNDLED_RIPGREP_DIRNAME}/rg.exe is unavailable."
    )
    return RipgrepEnsureResult(
        available=False,
        warnings=tuple(warnings),
    )
