"""Latest platform & per-scan knowledge-base MCP settings, resolved per task start.

Keep accepted revisions for this Agent process, including completed scans whose
reviews or validations may still be queued. Platform-level MCP URL/header edits
broadcast by the administrator are merged dynamically with each scan's enabled
flag and project_id right before a new task starts, without interrupting
already-running Sessions.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any


@dataclass
class _PlatformKnowledgeBase:
    received: bool = False
    revision: int = 0
    configured: bool = False
    name: str = "knowledge-base"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 300


@dataclass
class _ScanKnowledgeBase:
    revision: int
    config: dict[str, Any] | None
    scan_mode: str


_platform = _PlatformKnowledgeBase()
_states: dict[str, _ScanKnowledgeBase] = {}


def reset_scan_knowledge_base_state() -> None:
    """Test helper: clear in-memory platform and per-scan KB state."""
    global _platform
    _platform = _PlatformKnowledgeBase()
    _states.clear()


def apply_platform_knowledge_base_update(payload: object) -> int:
    """Accept latest administrator-managed global knowledge-base connection info."""
    if not isinstance(payload, dict):
        raise ValueError("Invalid platform knowledge-base payload")
    inner = payload.get("platform_knowledge_base")
    data = inner if isinstance(inner, dict) else payload
    raw_revision = data.get("revision", 0)
    if type(raw_revision) is not int or raw_revision < 0:
        raise ValueError("Invalid platform knowledge-base revision")
    if _platform.received and raw_revision < _platform.revision:
        return _platform.revision
    url = str(data.get("url") or "").strip()
    configured = bool(data.get("configured", bool(url))) and bool(url)
    name = str(data.get("name") or "knowledge-base").strip() or "knowledge-base"
    raw_headers = data.get("headers")
    headers = (
        {str(key): str(value) for key, value in raw_headers.items() if str(key)}
        if isinstance(raw_headers, dict)
        else {}
    )
    try:
        timeout_seconds = max(1, int(data.get("timeout_seconds") or 300))
    except (TypeError, ValueError):
        timeout_seconds = 300
    _platform.received = True
    _platform.revision = raw_revision
    _platform.configured = configured
    _platform.name = name
    _platform.url = url
    _platform.headers = headers
    _platform.timeout_seconds = timeout_seconds
    return _platform.revision


def knowledge_base_mcp_revisions() -> dict[str, int]:
    return {scan_id: state.revision for scan_id, state in _states.items()}


def apply_knowledge_base_update(payload: dict[str, Any]) -> int:
    """Accept a per-scan revision without interrupting live Sessions."""
    scan_id = payload.get("scan_id")
    revision = payload.get("revision")
    config = payload.get("knowledge_base_mcp")
    if not isinstance(scan_id, str) or not scan_id.strip():
        raise ValueError("Invalid knowledge-base scan_id")
    if type(revision) is not int or revision < 0:
        raise ValueError("Invalid knowledge-base revision")
    if config is not None and not isinstance(config, dict):
        raise ValueError("Invalid knowledge-base configuration")
    previous = _states.get(scan_id)
    if previous is not None and previous.revision >= revision:
        return previous.revision
    _states[scan_id] = _ScanKnowledgeBase(
        revision=revision,
        config=copy.deepcopy(config),
        scan_mode=str(payload.get("scan_mode") or "custom"),
    )
    return revision


def apply_command_knowledge_base(command: dict[str, Any]) -> int | None:
    """Seed dispatch snapshots without letting a delayed command roll back edits."""
    if (
        "knowledge_base_mcp" not in command
        and "knowledge_base_mcp_revision" not in command
    ):
        return None
    return apply_knowledge_base_update({
        "scan_id": command.get("scan_id"),
        "revision": command.get("knowledge_base_mcp_revision", 0),
        "knowledge_base_mcp": command.get("knowledge_base_mcp"),
        "scan_mode": command.get("scan_mode"),
    })


def _merge_with_platform(config: dict[str, Any] | None) -> dict[str, Any] | None:
    if config is None:
        return None
    merged = copy.deepcopy(config)
    if not bool(merged.get("enabled")):
        return merged
    project_id = str(merged.get("project_id") or "").strip()
    if not project_id:
        merged["enabled"] = False
        return merged
    if not _platform.received:
        return merged
    if not _platform.configured or not _platform.url:
        # Admin cleared global knowledge-base URL: degrade gracefully for new tasks.
        merged["enabled"] = False
        return merged
    merged["name"] = _platform.name
    merged["transport"] = "remote"
    merged["timeout_seconds"] = _platform.timeout_seconds
    merged["remote"] = {
        "url": _platform.url,
        "headers": copy.deepcopy(_platform.headers),
    }
    merged["project_id"] = project_id
    return merged


def resolve_scan_knowledge_base(
    *,
    scan_id: str,
    fallback: dict[str, Any] | None = None,
    scan_mode: str = "custom",
) -> dict[str, Any] | None:
    """Return the latest merged snapshot; callers freeze it for one task."""
    if scan_mode == "multi_version":
        return None
    if not scan_id:
        return _merge_with_platform(fallback)
    state = _states.get(scan_id)
    if state is None:
        return _merge_with_platform(fallback)
    if state.scan_mode == "multi_version":
        return None
    return _merge_with_platform(state.config)
