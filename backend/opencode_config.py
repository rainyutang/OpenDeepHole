"""Server-side fingerprinting for managed OpenCode MCP configuration."""

from __future__ import annotations

import hashlib
import json
from typing import Any

def _value(value: Any, name: str, default=None):
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def managed_mcp_config_fingerprint(managed: Any) -> str:
    local = _value(managed, "local", {}) or {}
    remote = _value(managed, "remote", {}) or {}
    normalized = {
        "enabled": bool(_value(managed, "enabled", False)),
        "name": str(_value(managed, "name", "") or "").strip(),
        "transport": str(_value(managed, "transport", "local") or "local"),
        "timeout_seconds": max(1, int(_value(managed, "timeout_seconds", 300) or 300)),
        "local": {
            "executable": str(_value(local, "executable", "") or "").strip(),
            "args": [str(item) for item in (_value(local, "args", []) or [])],
            "environment": {
                str(key): str(item)
                for key, item in dict(_value(local, "environment", {}) or {}).items()
            },
        },
        "remote": {
            "url": str(_value(remote, "url", "") or "").strip(),
            "headers": {
                str(key): str(item)
                for key, item in dict(_value(remote, "headers", {}) or {}).items()
            },
        },
    }
    payload = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
