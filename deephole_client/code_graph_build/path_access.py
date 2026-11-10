"""Keep Windows extended paths at the filesystem boundary, not in index keys."""

from __future__ import annotations

import ntpath
import os
from pathlib import Path


def is_windows() -> bool:
    return os.name == "nt"


def _extended_windows_path(value: str) -> str:
    value = ntpath.normpath(value)
    if value.startswith(("\\\\?\\", "\\\\.\\")):
        return value
    value = ntpath.abspath(value)
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _display_path(value: str) -> str:
    if value[:8].casefold() == "\\\\?\\unc\\":
        return "\\\\" + value[8:]
    if value.startswith("\\\\?\\"):
        return value[4:]
    return value


def io_path(path: str | Path) -> Path:
    """Return an absolute extended Windows path for filesystem operations."""
    return Path(_extended_windows_path(str(path))) if is_windows() else Path(path)


def display_path(path: str | Path) -> Path:
    return Path(_display_path(str(path)))


def resolved_path(path: str | Path) -> Path:
    return display_path(io_path(path).resolve())


def needs_short_tool_path(path: str | Path) -> bool:
    """External Windows tools may still use MAX_PATH-limited file APIs."""
    if not is_windows():
        return False
    absolute = _display_path(ntpath.abspath(str(path)))
    return len(absolute.encode("utf-16-le", errors="surrogatepass")) // 2 >= 260
