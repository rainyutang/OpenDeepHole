"""Shared file reading and cancellable execution for compact artifact validators."""

from __future__ import annotations

import asyncio
import contextlib
import json
import shlex
import sys
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{path}: JSON 第 {exc.lineno} 行第 {exc.colno} 列：{exc.msg}"
        ) from exc
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"{path}: cannot read UTF-8 JSON: {exc}") from exc


def command_for_argv(argv: Sequence[str]) -> str:
    if sys.platform != "win32":
        return shlex.join(argv)
    # A bound Session prepends the host interpreter directory on Windows.
    if any('"' in value for value in argv[1:]):
        raise ValueError("Windows validation command arguments cannot contain quotes")
    return "python " + " ".join(f'"{value}"' for value in argv[1:])


async def run_validator(
    argv: Sequence[str], *, output_path: str | Path, label: str,
    timeout_seconds: float = 60.0, stop_timeout_seconds: float = 2.0,
) -> None:
    """Run a Python validator without blocking heartbeats or retaining huge logs."""
    # The standalone CLIs need no Task Agent installation.
    from task_agent.deadline import OperationDeadline, retire_task

    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = await asyncio.create_subprocess_exec(*argv, stdout=stdout, stderr=stderr)
        deadline = OperationDeadline(timeout_seconds)
        try:
            returncode = await deadline.wait(process.wait(), phase="artifact_validation")
        except BaseException as exc:
            stop_expires = time.monotonic() + stop_timeout_seconds
            if process.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    process.terminate()
                waiter = asyncio.create_task(process.wait())
                await asyncio.wait({waiter}, timeout=min(0.5, stop_timeout_seconds / 2))
                if process.returncode is None:
                    with contextlib.suppress(ProcessLookupError):
                        process.kill()
                await asyncio.wait({waiter}, timeout=max(0.0, stop_expires - time.monotonic()))
                retire_task(waiter)
            if isinstance(exc, asyncio.TimeoutError):
                raise ValueError(
                    f"{output_path}: {label.lower()} timed out after {timeout_seconds:g}s"
                ) from exc
            raise
        if returncode != 0:
            def tail(stream) -> str:
                stream.seek(0, 2)
                stream.seek(max(0, stream.tell() - 16 * 1024))
                return stream.read().decode("utf-8", errors="replace").strip()

            detail = tail(stderr) or tail(stdout) or f"exit={returncode}"
            raise ValueError(f"{label} failed: {detail}")
