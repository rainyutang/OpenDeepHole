"""Compatibility helpers for Markdown vulnerability call chains."""

from __future__ import annotations

import json
import re
from typing import Any


_ENTRY_LINE_RE = re.compile(
    r"^\s*(?:[-*]\s*)?(?:\*\*)?Entry(?:\*\*)?\s*:\s*(.+?)\s*$",
    flags=re.IGNORECASE | re.MULTILINE,
)
_STACK_HEADING_RE = re.compile(
    r"^\s*(?:[-*]\s*)?(?:\*\*)?Call Stack(?:\*\*)?\s*:\s*$",
    flags=re.IGNORECASE,
)
_STACK_END_RE = re.compile(
    r"^\s*(?:[-*]\s*)?(?:\*\*)?"
    r"(?:Vulnerable Frame|Source To Sink Stack)(?:\*\*)?\s*:",
    flags=re.IGNORECASE,
)
_STACK_FRAME_RE = re.compile(
    r"^(?P<function>.+?)\s+\((?P<file>.+):(?P<line>\d+)\)"
    r"(?:\s+\[.*\])?$",
)


def _legacy_frame(value: Any) -> tuple[str, str, int]:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    if isinstance(value, dict):
        function = str(value.get("function") or "").strip()
        file_path = str(value.get("file") or "").strip()
        try:
            line = int(value.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        return function, file_path, line
    return str(value or "").strip(), "", 0


def _frame_label(function: str, file_path: str, line: int) -> str:
    if file_path and line > 0:
        return f"{function} ({file_path}:{line})"
    return function


def legacy_call_chain_to_markdown(values: list[Any] | tuple[Any, ...]) -> str:
    """Convert historical function arrays into the current Markdown shape."""
    frames = [
        frame
        for item in values
        if (frame := _legacy_frame(item))[0]
    ]
    if not frames:
        return ""
    labels = [_frame_label(*frame) for frame in frames]
    chain = "\n".join(
        label if index == 0 else f"{'  ' * index}→ {label}"
        for index, label in enumerate(labels)
    )
    return (
        f"- Entry: {labels[0]}\n"
        "- Call Stack:\n"
        f"{chain}\n"
        f"- Vulnerable Frame: {labels[-1]}\n"
        "- Source To Sink Stack:\n"
        f"{chain}"
    )


def normalize_call_chain_markdown(value: Any) -> str:
    """Return the public Markdown string, accepting historical array forms."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return legacy_call_chain_to_markdown(value)
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("["):
        try:
            decoded = json.loads(text)
        except (TypeError, ValueError):
            decoded = None
        if isinstance(decoded, list):
            return legacy_call_chain_to_markdown(decoded)
    return text


def _plain_function(value: str) -> str:
    text = value.strip().strip("`*").strip()
    backtick = re.match(r"`([^`]+)`", value.strip())
    if backtick:
        return backtick.group(1).strip()
    located = re.match(r"(.+?)\s+\(.+:\d+\)(?:\s+\[.*\])?$", text)
    if located:
        return located.group(1).strip().strip("`*")
    annotated = text.split(" [", 1)[0].strip()
    return annotated


def call_chain_entry_function(value: Any) -> str:
    """Best-effort extraction of the entry function from the Markdown contract."""
    markdown = normalize_call_chain_markdown(value)
    match = _ENTRY_LINE_RE.search(markdown)
    return _plain_function(match.group(1)) if match else ""


def call_chain_details(value: Any) -> tuple[dict[str, Any], ...]:
    """Best-effort structured frames retained for validator compatibility."""
    markdown = normalize_call_chain_markdown(value)
    in_stack = False
    details: list[dict[str, Any]] = []
    for raw_line in markdown.splitlines():
        if _STACK_HEADING_RE.match(raw_line):
            in_stack = True
            continue
        if in_stack and _STACK_END_RE.match(raw_line):
            break
        if not in_stack:
            continue
        line = raw_line.strip().lstrip("→").strip().strip("`*").strip()
        if not line or line.startswith("```"):
            continue
        match = _STACK_FRAME_RE.match(line)
        if not match:
            continue
        details.append({
            "function": match.group("function").strip().strip("`*"),
            "file": match.group("file").strip().strip("`*"),
            "line": int(match.group("line")),
        })
    return tuple(details)


__all__ = [
    "call_chain_details",
    "call_chain_entry_function",
    "legacy_call_chain_to_markdown",
    "normalize_call_chain_markdown",
]
