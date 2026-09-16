"""Trusted command identities for opt-in Python script canonicalization."""

from __future__ import annotations

import ntpath
import posixpath
import sys
from pathlib import PurePosixPath, PureWindowsPath
from typing import Iterable


_PYTHON_NAMES = frozenset({"python", "python3", "python.exe", "python3.exe"})


def _literal_command_args(command: str, *, windows: bool) -> tuple[str, ...] | None:
    """Read literal words only; never evaluate shell syntax or expansions.

    Keep this grammar aligned with literalCommandArgs in the managed Hook.
    Windows accepts either quoting style for recognition, retaining backslashes;
    only the trusted, generated command is ever passed to the actual shell.
    """
    if any(ord(char) < 32 and char != "\t" for char in command):
        return None
    words: list[str] = []
    word: list[str] = []
    quote = ""
    active = False
    index = 0
    while index < len(command):
        char = command[index]
        if windows and char in "$`%!":
            return None
        if quote:
            if char == quote:
                quote = ""
            elif quote == '"' and not windows and char == "\\":
                if index + 1 < len(command) and command[index + 1] in '\\"$`':
                    index += 1
                    word.append(command[index])
                else:
                    word.append(char)
            elif quote == '"' and char in "$`":
                return None
            else:
                word.append(char)
        elif char in " \t":
            if active:
                words.append("".join(word))
                word = []
                active = False
        elif char in "\"'":
            quote = char
            active = True
        elif char == "\\" and not windows:
            index += 1
            if index == len(command):
                return None
            word.append(command[index])
            active = True
        elif char in "|&;<>(){}[]*?~$`#":
            return None
        else:
            word.append(char)
            active = True
        index += 1
    if quote:
        return None
    if active:
        words.append("".join(word))
    return tuple(words)


def _absolute_command_path(value: str, *, windows: bool) -> str:
    if windows:
        if not PureWindowsPath(value).is_absolute():
            return ""
        return ntpath.normpath(value).lower()
    if not PurePosixPath(value).is_absolute():
        return ""
    # Node's path.posix.normalize collapses a double leading slash too.
    return "/" + posixpath.normpath(value).lstrip("/")


def command_binding_metadata(
    commands: Iterable[str],
    *,
    match_mode: str = "exact",
    platform: str | None = None,
    python_executable: str | None = None,
) -> dict[str, object]:
    """Validate the opt-in policy and produce additive v2 binding metadata."""
    if match_mode not in ("exact", "bound_python_script"):
        raise ValueError(
            "OpenCode bash_command_match_mode must be 'exact' or 'bound_python_script'"
        )
    if match_mode == "exact":
        return {}
    windows = (platform or sys.platform) == "win32"
    executable = python_executable or sys.executable
    host_python = _absolute_command_path(executable, windows=windows)
    scripts: dict[str, str] = {}
    for command in commands:
        argv = _literal_command_args(command, windows=windows)
        if (
            not argv
            or len(argv) < 2
            or not (
                argv[0] in _PYTHON_NAMES
                or (
                    host_python
                    and _absolute_command_path(argv[0], windows=windows) == host_python
                )
            )
        ):
            raise ValueError(
                "OpenCode bound_python_script requires a direct literal Python script command"
            )
        script = _absolute_command_path(argv[1], windows=windows)
        if not script or not script.lower().endswith(".py"):
            raise ValueError(
                "OpenCode bound_python_script requires an absolute Python script path"
            )
        if script in scripts and scripts[script] != command:
            raise ValueError(
                "OpenCode bound_python_script cannot bind multiple commands to the same script"
            )
        scripts[script] = command
    if not scripts:
        raise ValueError("OpenCode bound_python_script requires bound bash commands")
    return {
        "bash_command_match_mode": match_mode,
        "command_platform": "win32" if windows else "posix",
        "python_executable": executable,
        "python_script_commands": scripts,
    }
