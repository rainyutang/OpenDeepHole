"""Server-side validation and redaction for Agent OpenCode configuration."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


_SENSITIVE_KEY_RE = re.compile(
    r"(api[_-]?key|apikey|token|secret|password|authorization|cookie|credential|headers?)",
    re.IGNORECASE,
)


def _strip_jsonc(text: str) -> str:
    result: list[str] = []
    in_string = False
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if in_string:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            result.append(char)
            index += 1
            continue
        if char == "/" and following == "/":
            result.extend("  ")
            index += 2
            while index < len(text) and text[index] not in "\r\n":
                result.append(" ")
                index += 1
            continue
        if char == "/" and following == "*":
            result.extend("  ")
            index += 2
            while index < len(text):
                if index + 1 < len(text) and text[index:index + 2] == "*/":
                    result.extend("  ")
                    index += 2
                    break
                result.append(text[index] if text[index] in "\r\n" else " ")
                index += 1
            continue
        result.append(char)
        index += 1

    without_comments = "".join(result)
    result = []
    in_string = False
    escaped = False
    for index, char in enumerate(without_comments):
        if in_string:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            result.append(char)
            continue
        if char == ",":
            lookahead = index + 1
            while lookahead < len(without_comments) and without_comments[lookahead].isspace():
                lookahead += 1
            if lookahead < len(without_comments) and without_comments[lookahead] in "}]":
                result.append(" ")
                continue
        result.append(char)
    return "".join(result)


def parse_opencode_jsonc(text: str | None, *, source: str = "OpenCode config") -> dict[str, Any]:
    raw = str(text or "")
    if not raw.strip():
        return {}
    try:
        value = json.loads(_strip_jsonc(raw))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{source} JSONC 格式错误（第 {exc.lineno} 行，第 {exc.colno} 列）：{exc.msg}"
        ) from exc
    if not isinstance(value, dict):
        raise ValueError(f"{source} 必须是 JSON 对象")
    return value


def _redact(value: Any, parent_key: str = "") -> Any:
    if parent_key and _SENSITIVE_KEY_RE.search(parent_key):
        return "***"
    if isinstance(value, dict):
        return {
            key: "***" if _SENSITIVE_KEY_RE.search(str(key)) else _redact(item, str(key))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item, parent_key) for item in value]
    return value


def redact_opencode_config_content(config_content: str, *, pretty: bool = False) -> str:
    if not config_content:
        return ""
    try:
        value = json.loads(config_content)
    except Exception:
        return f"<redacted invalid config content bytes={len(config_content.encode('utf-8'))}>"
    redacted = _redact(value)
    if pretty:
        return json.dumps(redacted, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    return json.dumps(redacted, ensure_ascii=False)


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
