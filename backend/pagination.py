"""Opaque, stable cursors used by the v2 APIs."""

from __future__ import annotations

import base64
import json


def encode_cursor(*values: object) -> str:
    raw = json.dumps(list(values), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(value: str, *, size: int) -> tuple[str, ...]:
    try:
        padded = value + "=" * (-len(value) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        decoded = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError("invalid cursor") from exc
    if not isinstance(decoded, list) or len(decoded) != size:
        raise ValueError("invalid cursor")
    values = tuple(str(item or "") for item in decoded)
    if any(not item for item in values):
        raise ValueError("invalid cursor")
    return values
