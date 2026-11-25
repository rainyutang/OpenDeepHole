"""Mandatory server-side decompression, credential redaction, and secret-box helpers for Javelin."""

from __future__ import annotations

import base64
from email.parser import BytesParser
from email.policy import default as default_email_policy
import gzip
import json
import os
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import zlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.config import AppConfig, get_javelin_secret_box_key
from backend.logger import get_logger

logger = get_logger(__name__)

MAX_DECOMPRESSED_BYTES = 2 * 1024 * 1024
MAX_HTTP_BODY_BYTES = 64 * 1024
MAX_EVENT_TEXT_BYTES = 64 * 1024
MAX_TASK_TEXT_BYTES = 8 * 1024

REDACTED_PLACEHOLDER = "[REDACTED]"
BINARY_PLACEHOLDER = "[BINARY_OMITTED]"
CORRUPT_COMPRESSED_PLACEHOLDER = "[OMITTED_COMPRESSED_OR_CORRUPT_PAYLOAD]"

ALLOWED_HTTP_HEADERS = frozenset({
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "content-disposition",
    "content-encoding",
    "content-language",
    "content-length",
    "content-type",
    "date",
    "etag",
    "host",
    "last-modified",
    "location",
    "origin",
    "pragma",
    "referer",
    "server",
    "user-agent",
    "vary",
    "x-content-type-options",
    "x-frame-options",
    "x-request-id",
    "x-Runtime-id".lower(),
})

SENSITIVE_KEY_SUBSTRINGS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "session",
    "jsessionid",
    "csrf",
    "xsrf",
    "private_key",
    "privatekey",
    "client_secret",
    "credential",
    "passphrase",
)

_CREDENTIAL_PATTERNS = (
    re.compile(r"(?i)\b(authorization|proxy-authorization)\s*[:=]\s*(bearer|basic|digest|token)\s+[^\s,;\"']+"),
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\b(cookie|set-cookie)\s*:\s*[^\r\n]+"),
    re.compile(
        r"(?i)\b(password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|private[_-]?key)\b"
        r"(\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,&;\"'}]+)"
    ),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s:@]+:[^/\s@]+)@"),
)

_CHARSET_RE = re.compile(r"charset\s*=\s*['\"]?([A-Za-z0-9._-]+)", re.IGNORECASE)


def is_sensitive_key(name: str) -> bool:
    lowered = str(name or "").strip().lower()
    if not lowered:
        return False
    return any(marker in lowered for marker in SENSITIVE_KEY_SUBSTRINGS)


def redact_free_text(text: str) -> str:
    if not text:
        return ""
    value = str(text)
    value = _CREDENTIAL_PATTERNS[0].sub(lambda m: f"{m.group(1)}: {m.group(2)} {REDACTED_PLACEHOLDER}", value)
    value = _CREDENTIAL_PATTERNS[1].sub(lambda m: f"{m.group(1)} {REDACTED_PLACEHOLDER}", value)
    value = _CREDENTIAL_PATTERNS[2].sub(lambda m: f"{m.group(1)}: {REDACTED_PLACEHOLDER}", value)
    value = _CREDENTIAL_PATTERNS[3].sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED_PLACEHOLDER}", value)
    value = _CREDENTIAL_PATTERNS[4].sub(REDACTED_PLACEHOLDER, value)
    value = _CREDENTIAL_PATTERNS[5].sub(lambda m: f"{m.group(1)}{REDACTED_PLACEHOLDER}@", value)
    return value


def truncate_utf8_bytes(text: str, max_bytes: int, *, head_tail: bool = False) -> tuple[str, bool, int]:
    encoded = (text or "").encode("utf-8", errors="replace")
    original_size = len(encoded)
    if original_size <= max_bytes:
        return text or "", False, original_size
    if not head_tail or max_bytes < 256:
        clipped = encoded[:max_bytes].decode("utf-8", errors="ignore")
        return clipped, True, original_size
    marker = f"\n...[TRUNCATED {original_size - max_bytes} BYTES]...\n".encode("utf-8")
    budget = max(64, max_bytes - len(marker))
    head_len = budget // 2
    tail_len = budget - head_len
    head_str = encoded[:head_len].decode("utf-8", errors="ignore")
    tail_str = encoded[-tail_len:].decode("utf-8", errors="ignore")
    return f"{head_str}{marker.decode('utf-8')}{tail_str}", True, original_size


def sanitize_url(raw_url: str) -> str:
    text = str(raw_url or "").strip()
    if not text:
        return ""
    try:
        parts = urlsplit(text)
    except Exception:
        return redact_free_text(text)[:4096]
    netloc = parts.netloc
    if "@" in netloc:
        _userinfo, hostpart = netloc.rsplit("@", 1)
        netloc = f"{REDACTED_PLACEHOLDER}@{hostpart}"
    query_pairs = parse_qsl(parts.query, keep_blank_values=True)
    sanitized_pairs = [
        (k, REDACTED_PLACEHOLDER if is_sensitive_key(k) else redact_free_text(v))
        for k, v in query_pairs
    ]
    sanitized_query = urlencode(sanitized_pairs, doseq=True) if query_pairs else ""
    rebuilt = urlunsplit((parts.scheme, netloc, parts.path, sanitized_query, ""))
    return redact_free_text(rebuilt)[:4096]


def sanitize_headers(headers: Any) -> list[dict[str, str]]:
    normalized: list[tuple[str, str]] = []
    if isinstance(headers, dict):
        for k, v in headers.items():
            normalized.append((str(k), str(v)))
    elif isinstance(headers, list):
        for entry in headers:
            if isinstance(entry, dict):
                normalized.append((str(entry.get("name") or ""), str(entry.get("value") or "")))
            elif isinstance(entry, (list, tuple)) and len(entry) >= 2:
                normalized.append((str(entry[0]), str(entry[1])))
    sanitized: list[dict[str, str]] = []
    for raw_name, raw_value in normalized:
        name = raw_name.strip()
        if not name:
            continue
        lower = name.lower()
        if is_sensitive_key(lower) or (
            lower not in ALLOWED_HTTP_HEADERS and not lower.startswith("access-control-")
        ):
            sanitized.append({"name": name, "value": REDACTED_PLACEHOLDER})
        else:
            sanitized.append({"name": name, "value": redact_free_text(raw_value)[:2048]})
    return sanitized


def _decompress_bounded(raw: bytes, encoding: str) -> bytes | None:
    enc = encoding.strip().lower()
    if not enc or enc == "identity":
        return raw if len(raw) <= MAX_DECOMPRESSED_BYTES else None
    try:
        if enc in {"gzip", "x-gzip"}:
            decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            out = decompressor.decompress(raw, MAX_DECOMPRESSED_BYTES + 1)
            if len(out) > MAX_DECOMPRESSED_BYTES or decompressor.unconsumed_tail:
                return None
            return out
        if enc == "deflate":
            try:
                decompressor = zlib.decompressobj(zlib.MAX_WBITS)
                out = decompressor.decompress(raw, MAX_DECOMPRESSED_BYTES + 1)
            except zlib.error:
                decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
                out = decompressor.decompress(raw, MAX_DECOMPRESSED_BYTES + 1)
            if len(out) > MAX_DECOMPRESSED_BYTES or decompressor.unconsumed_tail:
                return None
            return out
        if enc == "br":
            import brotli

            # Reject suspiciously large compressed inputs and enforce strict post-check
            if len(raw) > MAX_DECOMPRESSED_BYTES:
                return None
            decompressor = brotli.Decompressor()
            chunks: list[bytes] = []
            total = 0
            step = 16384
            for offset in range(0, len(raw), step):
                piece = decompressor.process(raw[offset : offset + step])
                total += len(piece)
                if total > MAX_DECOMPRESSED_BYTES:
                    return None
                chunks.append(piece)
            if not decompressor.is_finished():
                return None
            return b"".join(chunks)
    except Exception:
        return None
    return None


def _decode_charset(raw: bytes, content_type: str) -> str | None:
    match = _CHARSET_RE.search(content_type or "")
    candidates = []
    if match:
        candidates.append(match.group(1))
    candidates.extend(["utf-8", "gb18030", "latin-1"])
    # Binary heuristic: null bytes in non-UTF-16 stream
    if b"\x00" in raw[:4096] and not any("utf-16" in c.lower() for c in candidates[:1]):
        return None
    for charset in candidates:
        try:
            return raw.decode(charset)
        except (LookupError, UnicodeDecodeError):
            continue
    return None


def _redact_json_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 24:
        return "[MAX_DEPTH]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for k, v in value.items():
            key_str = str(k)
            if is_sensitive_key(key_str):
                result[key_str] = REDACTED_PLACEHOLDER
            else:
                result[key_str] = _redact_json_value(v, depth=depth + 1)
        return result
    if isinstance(value, list):
        return [_redact_json_value(item, depth=depth + 1) for item in value[:500]]
    if isinstance(value, str):
        return redact_free_text(value)
    return value


def _sanitize_multipart_body(raw: bytes, content_type: str) -> str:
    header_bytes = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8", errors="ignore")
    try:
        msg = BytesParser(policy=default_email_policy).parsebytes(header_bytes + raw)
    except Exception:
        return CORRUPT_COMPRESSED_PLACEHOLDER
    if not msg.is_multipart():
        return CORRUPT_COMPRESSED_PLACEHOLDER
    rendered_parts: list[str] = []
    for part in msg.iter_parts():
        disposition = str(part.get("Content-Disposition") or "")
        field_name = str(part.get_param("name", header="content-disposition") or "")
        filename = part.get_filename()
        part_ct = str(part.get_content_type() or "application/octet-stream")
        payload = part.get_payload(decode=True) or b""
        if is_sensitive_key(field_name):
            body_repr = REDACTED_PLACEHOLDER
        elif filename and not part_ct.startswith("text/") and part_ct not in {"application/json", "application/xml"}:
            body_repr = f"{BINARY_PLACEHOLDER} ({len(payload)} bytes)"
        else:
            decoded = _decode_charset(payload, part_ct)
            if decoded is None:
                body_repr = f"{BINARY_PLACEHOLDER} ({len(payload)} bytes)"
            else:
                body_repr = _sanitize_decoded_text_body(decoded, part_ct)
        safe_disp = redact_free_text(disposition)
        rendered_parts.append(f"--part ({safe_disp}; content-type={part_ct})\n{body_repr}")
    return "\n".join(rendered_parts)


def _sanitize_decoded_text_body(text: str, content_type: str) -> str:
    lowered_ct = (content_type or "").lower()
    stripped = text.strip()
    if "json" in lowered_ct or (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
        try:
            parsed = json.loads(text)
            return json.dumps(_redact_json_value(parsed), ensure_ascii=False, indent=2)
        except Exception:
            pass
    if "application/x-www-form-urlencoded" in lowered_ct:
        try:
            pairs = parse_qsl(text, keep_blank_values=True)
            if pairs:
                redacted = [
                    (k, REDACTED_PLACEHOLDER if is_sensitive_key(k) else redact_free_text(v))
                    for k, v in pairs
                ]
                return urlencode(redacted, doseq=True)
        except Exception:
            pass
    return redact_free_text(text)


def sanitize_http_message(
    message: dict[str, Any] | None,
    *,
    default_url: str = "",
) -> tuple[dict[str, Any], bool]:
    """Sanitize one HTTP request or response object; returns (sanitized_dict, truncated)."""
    msg = dict(message) if isinstance(message, dict) else {}
    raw_headers = msg.get("headers") or []
    content_type = ""
    content_encoding = ""
    if isinstance(raw_headers, dict):
        for k, v in raw_headers.items():
            lk = str(k).lower()
            if lk == "content-type":
                content_type = str(v)
            elif lk == "content-encoding":
                content_encoding = str(v)
    elif isinstance(raw_headers, list):
        for item in raw_headers:
            if isinstance(item, dict):
                lk = str(item.get("name") or "").lower()
                if lk == "content-type":
                    content_type = str(item.get("value") or "")
                elif lk == "content-encoding":
                    content_encoding = str(item.get("value") or "")

    sanitized_hdrs = sanitize_headers(raw_headers)
    body_obj = msg.get("body")
    raw_bytes: bytes | None = None
    body_available = True
    pre_truncated = False

    if body_obj is None:
        raw_text = msg.get("body_text")
        if isinstance(raw_text, str):
            raw_bytes = raw_text.encode("utf-8", errors="replace")
        else:
            body_available = False
    elif isinstance(body_obj, str):
        raw_bytes = body_obj.encode("utf-8", errors="replace")
    elif isinstance(body_obj, dict):
        pre_truncated = bool(body_obj.get("truncated"))
        if body_obj.get("available") is False or body_obj.get("omitted"):
            body_available = False
        elif body_obj.get("encoding") == "base64" and isinstance(body_obj.get("data") or body_obj.get("text"), str):
            try:
                raw_bytes = base64.b64decode(str(body_obj.get("data") or body_obj.get("text")), validate=False)
            except Exception:
                raw_bytes = None
        elif isinstance(body_obj.get("text"), str):
            raw_bytes = body_obj["text"].encode("utf-8", errors="replace")
        else:
            body_available = False
    else:
        body_available = False

    truncated = pre_truncated
    if not body_available:
        sanitized_body = {"available": False, "text": "", "truncated": pre_truncated}
    elif raw_bytes is None:
        sanitized_body = {"available": True, "text": CORRUPT_COMPRESSED_PLACEHOLDER, "truncated": True}
        truncated = True
    else:
        decompressed = _decompress_bounded(raw_bytes, content_encoding)
        if decompressed is None:
            sanitized_body = {"available": True, "text": CORRUPT_COMPRESSED_PLACEHOLDER, "truncated": True}
            truncated = True
        elif "multipart/form-data" in content_type.lower():
            mp_text = _sanitize_multipart_body(decompressed, content_type)
            clipped, was_trunc, _ = truncate_utf8_bytes(mp_text, MAX_HTTP_BODY_BYTES)
            truncated = truncated or was_trunc
            sanitized_body = {"available": True, "text": clipped, "truncated": truncated}
        else:
            decoded = _decode_charset(decompressed, content_type)
            if decoded is None:
                sanitized_body = {"available": True, "text": BINARY_PLACEHOLDER, "truncated": truncated}
            else:
                cleaned = _sanitize_decoded_text_body(decoded, content_type)
                clipped, was_trunc, _ = truncate_utf8_bytes(cleaned, MAX_HTTP_BODY_BYTES)
                truncated = truncated or was_trunc
                sanitized_body = {"available": True, "text": clipped, "truncated": truncated}

    result: dict[str, Any] = {
        "headers": sanitized_hdrs,
        "body": sanitized_body,
    }
    if "method" in msg:
        result["method"] = str(msg.get("method") or "GET").upper()[:16]
    if "url" in msg or default_url:
        result["url"] = sanitize_url(str(msg.get("url") or default_url))
    if "status" in msg or "status_code" in msg:
        raw_status = msg.get("status") if msg.get("status") is not None else msg.get("status_code")
        try:
            result["status"] = int(raw_status) if raw_status is not None else None
        except (TypeError, ValueError):
            result["status"] = None
    if "status_text" in msg and msg.get("status_text") is not None:
        result["status_text"] = redact_free_text(str(msg.get("status_text")))[:120]
    return result, truncated


def sanitize_javelin_task_text(value: str | None, *, max_bytes: int = MAX_TASK_TEXT_BYTES) -> str:
    """Redact credentials and cap task-board free-text fields at 8 KiB (P1 #8)."""
    if not value:
        return ""
    redacted = redact_free_text(str(value))
    clipped, _was_truncated, _orig = truncate_utf8_bytes(redacted, max_bytes)
    return clipped


def sanitize_javelin_task_item(task: dict[str, Any]) -> dict[str, Any]:
    """Sanitize all text/JSON fields of a task-board item before persistence."""
    cleaned = dict(task)
    for field in ("title", "hypothesis", "gap_reason", "quality_review_notes", "root_cause", "prompt", "reason"):
        if field in cleaned and cleaned[field] is not None:
            limit = 256 if field == "title" else MAX_TASK_TEXT_BYTES
            cleaned[field] = sanitize_javelin_task_text(str(cleaned[field]), max_bytes=limit)
    if isinstance(cleaned.get("target"), dict):
        cleaned["target"] = _redact_json_value(cleaned["target"])
    if isinstance(cleaned.get("validation"), dict):
        cleaned["validation"] = _redact_json_value(cleaned["validation"])
    return cleaned


def sanitize_javelin_event_item(event: dict[str, Any]) -> dict[str, Any]:
    """Enforce <= 64 KiB head/tail truncation and credential redaction on Javelin events."""
    cleaned = dict(event)
    was_truncated = bool(cleaned.get("truncated"))
    orig_size = int(cleaned.get("original_size") or 0)
    for key in ("body", "detail", "label"):
        if isinstance(cleaned.get(key), str):
            limit = 512 if key == "label" else MAX_EVENT_TEXT_BYTES
            text_val = redact_free_text(cleaned[key])
            clipped, trunc, size = truncate_utf8_bytes(text_val, limit, head_tail=(key != "label"))
            cleaned[key] = clipped
            if trunc:
                was_truncated = True
                orig_size = max(orig_size, size)
    if isinstance(cleaned.get("detail_json"), dict):
        cleaned["detail_json"] = _redact_json_value(cleaned["detail_json"])
    if isinstance(cleaned.get("view_json"), dict):
        cleaned["view_json"] = _redact_json_value(cleaned["view_json"])
    cleaned["truncated"] = was_truncated
    cleaned["original_size"] = orig_size
    return cleaned


def encrypt_secret_context(
    payload: dict[str, Any],
    *,
    scan_id: str,
    expires_at: str,
    config: AppConfig | None = None,
    distributed: bool = False,
) -> tuple[bytes, dict[str, Any]]:
    """Encrypt transient private runtime-testing context with AES-256-GCM."""
    key = get_javelin_secret_box_key(config, distributed=distributed)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    aad = f"javelin-secret-context:{scan_id}".encode("utf-8")
    plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    meta = {
        "key_id": "hkdf-sha256-v1",
        "alg": "AES-256-GCM",
        "nonce_hex": nonce.hex(),
        "expires_at": expires_at,
    }
    return ciphertext, meta


def decrypt_secret_context(
    ciphertext: bytes,
    meta: dict[str, Any],
    *,
    scan_id: str,
    config: AppConfig | None = None,
    distributed: bool = False,
) -> dict[str, Any]:
    """Decrypt transient private runtime-testing context verified by scan_id AAD."""
    key = get_javelin_secret_box_key(config, distributed=distributed)
    nonce_hex = str(meta.get("nonce_hex") or "")
    nonce = bytes.fromhex(nonce_hex)
    aesgcm = AESGCM(key)
    aad = f"javelin-secret-context:{scan_id}".encode("utf-8")
    plaintext = aesgcm.decrypt(nonce, bytes(ciphertext), aad)
    parsed = json.loads(plaintext.decode("utf-8"))
    return parsed if isinstance(parsed, dict) else {}


def log_secret_context_audit(event_code: str, *, scan_id: str, detail: str = "") -> None:
    """Emit structured audit event for secret_context lifecycle without any secret bytes."""
    safe_detail = re.sub(r"[^A-Za-z0-9_.:=-]", "_", str(detail or ""))[:120]
    logger.info(
        "JAVELIN_SECURITY_AUDIT code=%s scan_id=%s detail=%s",
        event_code,
        scan_id,
        safe_detail or "ok",
    )


def sanitize_validation_errors(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Strip input payloads from FastAPI RequestValidationError entries to prevent 422 leaks."""
    sanitized: list[dict[str, Any]] = []
    for err in errors:
        entry = {
            "type": err.get("type", "validation_error"),
            "loc": err.get("loc", ()),
            "msg": redact_free_text(str(err.get("msg", "Invalid input")))[:500],
        }
        sanitized.append(entry)
    return sanitized
