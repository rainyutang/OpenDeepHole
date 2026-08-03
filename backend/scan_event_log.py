"""Shared filtering and retention rules for scan event logs."""

from __future__ import annotations

import re


SCAN_EVENT_RETENTION_LIMIT = 200

_TASK_OUTPUT_CATEGORIES = ("task", "session", "tool", "skill", "step")
_TASK_OUTPUT_HEADER_RE = re.compile(
    r"^(?:\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s+)?"
    r"\[[^\]\r\n]+\]\[[^\]\r\n]+\]"
    r"\[(?:task|session|tool|skill|step)\](?:\s|$)"
)


def is_agent_local_task_output(message: object) -> bool:
    """Return whether a scan-event message is Agent-local Task Agent output."""
    return bool(_TASK_OUTPUT_HEADER_RE.match(str(message or "")))


def task_output_glob_patterns() -> tuple[str, ...]:
    """Return SQLite GLOB patterns for current and legacy Task Agent headers."""
    patterns: list[str] = []
    for category in _TASK_OUTPUT_CATEGORIES:
        header = f"[[]*[]][[]*[]][[]{category}[]]"
        timestamped_header = (
            "[[]????-??-?? ??:??:??[]] " + header
        )
        patterns.extend((
            header,
            f"{header} *",
            timestamped_header,
            f"{timestamped_header} *",
        ))
    return tuple(patterns)


__all__ = [
    "SCAN_EVENT_RETENTION_LIMIT",
    "is_agent_local_task_output",
    "task_output_glob_patterns",
]
