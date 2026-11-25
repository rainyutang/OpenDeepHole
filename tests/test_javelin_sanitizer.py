"""Unit tests for Javelin HTTP/task/event sanitization, decompression, and AES-256-GCM secret box."""

from __future__ import annotations

import base64
import gzip
import logging
import zlib

import brotli
import pytest

from backend.config import AppConfig, validate_javelin_startup_security
from backend.scans.javelin_sanitizer import (
    CORRUPT_COMPRESSED_PLACEHOLDER,
    MAX_DECOMPRESSED_BYTES as MAX_DECOMPRESSED_HTTP_BYTES,
    MAX_EVENT_TEXT_BYTES as MAX_EVENT_BODY_BYTES,
    MAX_HTTP_BODY_BYTES,
    MAX_TASK_TEXT_BYTES,
    REDACTED_PLACEHOLDER,
    decrypt_secret_context,
    encrypt_secret_context,
    log_secret_context_audit,
    sanitize_http_message,
    sanitize_javelin_event_item,
    sanitize_javelin_task_item,
    sanitize_validation_errors,
)


def test_gzip_deflate_brotli_body_decompression_and_redaction() -> None:
    secret_json = '{"username":"alice","password":"s3cr3t-value","nested":{"access_token":"tok_live_123456"}}'.encode("utf-8")

    for encoding, compressed in [
        ("gzip", gzip.compress(secret_json)),
        ("deflate", zlib.compress(secret_json)),
        ("br", brotli.compress(secret_json)),
    ]:
        msg, truncated = sanitize_http_message({
            "method": "POST",
            "url": "https://user:pass@example.com/api/login?api_key=leak123&ok=1",
            "headers": {
                "Content-Type": "application/json; charset=utf-8",
                "Content-Encoding": encoding,
                "Authorization": "Bearer super-secret-jwt",
                "Cookie": "JSESSIONID=abcdef",
                "X-Custom-Secret": "should-not-pass",
            },
            "body": {
                "encoding": "base64",
                "data": base64.b64encode(compressed).decode("ascii"),
            },
        })
        assert not truncated
        assert "pass" not in msg["url"]
        assert "leak123" not in msg["url"]
        assert "ok=1" in msg["url"]
        hdrs = {h["name"]: h["value"] for h in msg["headers"]}
        assert hdrs["Authorization"] == REDACTED_PLACEHOLDER
        assert hdrs["Cookie"] == REDACTED_PLACEHOLDER
        assert hdrs["X-Custom-Secret"] == REDACTED_PLACEHOLDER
        assert hdrs["Content-Type"] == "application/json; charset=utf-8"
        body_text = msg["body"]["text"]
        assert "s3cr3t-value" not in body_text
        assert "tok_live_123456" not in body_text
        assert REDACTED_PLACEHOLDER in body_text


def test_gzip_bomb_bounded_at_2mib_without_oom() -> None:
    oversized_raw = b"A" * (MAX_DECOMPRESSED_HTTP_BYTES + 512 * 1024)
    compressed = gzip.compress(oversized_raw)
    msg, truncated = sanitize_http_message({
        "headers": {"Content-Encoding": "gzip", "Content-Type": "text/plain"},
        "body": {
            "encoding": "base64",
            "data": base64.b64encode(compressed).decode("ascii"),
        },
    })
    assert truncated is True
    assert msg["body"]["text"] == CORRUPT_COMPRESSED_PLACEHOLDER
    assert len(msg["body"]["text"].encode("utf-8")) <= MAX_HTTP_BODY_BYTES


def test_multipart_form_data_redacts_secret_and_file_parts() -> None:
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    multipart_body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="username"\r\n\r\n'
        "auditor\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="client_secret"\r\n\r\n'
        "my-top-secret-key\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="upload"; filename="id_rsa"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
        "PRIVATE-KEY-CONTENT-BYTES\r\n"
        f"--{boundary}--\r\n"
    )
    msg, _ = sanitize_http_message({
        "headers": {"Content-Type": f"multipart/form-data; boundary={boundary}"},
        "body": multipart_body,
    })
    body_text = msg["body"]["text"]
    assert "auditor" in body_text
    assert "my-top-secret-key" not in body_text
    assert "PRIVATE-KEY-CONTENT-BYTES" not in body_text
    assert REDACTED_PLACEHOLDER in body_text


def test_task_board_and_event_sanitization_and_size_caps() -> None:
    long_prompt = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig\n" + ("x" * (MAX_TASK_TEXT_BYTES + 4096))
    sanitized_task = sanitize_javelin_task_item({
        "task_id": "T-001",
        "title": "Order export SQLi",
        "hypothesis": "Cookie: SESSION=secret_cookie_val",
        "prompt": long_prompt,
    })
    assert "eyJhbGciOiJIUzI1NiJ9" not in sanitized_task["prompt"]
    assert "secret_cookie_val" not in sanitized_task["hypothesis"]
    assert len(sanitized_task["prompt"].encode("utf-8")) <= MAX_TASK_TEXT_BYTES + 128

    huge_event = sanitize_javelin_event_item({
        "sequence": 7,
        "body": "password=my_db_pass\n" + ("B" * (MAX_EVENT_BODY_BYTES + 8192)),
    })
    assert huge_event["truncated"] is True
    assert huge_event["original_size"] > MAX_EVENT_BODY_BYTES
    assert "my_db_pass" not in huge_event["body"]
    assert len(huge_event["body"].encode("utf-8")) <= MAX_EVENT_BODY_BYTES + 128


def test_secret_box_roundtrip_aad_binding_and_audit_logs(caplog: pytest.LogCaptureFixture) -> None:
    cfg = AppConfig()
    cfg.auth.secret_key = "unit-test-explicit-jwt-secret-key-32b"
    ciphertext, meta = encrypt_secret_context(
        {"test_environment_context": "Bearer secret-env-token-999"},
        scan_id="scan-abc",
        expires_at="2099-01-01T00:00:00+00:00",
        config=cfg,
    )
    assert b"secret-env-token-999" not in ciphertext
    recovered = decrypt_secret_context(ciphertext, meta, scan_id="scan-abc", config=cfg)
    assert recovered == {"test_environment_context": "Bearer secret-env-token-999"}

    # Wrong scan_id AAD must fail authentication
    with pytest.raises(Exception):
        decrypt_secret_context(ciphertext, meta, scan_id="scan-other", config=cfg)

    with caplog.at_level(logging.INFO):
        log_secret_context_audit("SECRET_CONTEXT_STORED", scan_id="scan-abc", detail="ok")
        log_secret_context_audit("SECRET_CONTEXT_FETCHED", scan_id="scan-abc", detail="rev=1")
        log_secret_context_audit("SECRET_CONTEXT_WIPED", scan_id="scan-abc", detail="ack")
    joined_logs = "\n".join(caplog.messages)
    assert "SECRET_CONTEXT_STORED" in joined_logs
    assert "SECRET_CONTEXT_FETCHED" in joined_logs
    assert "SECRET_CONTEXT_WIPED" in joined_logs
    assert "secret-env-token-999" not in joined_logs


def test_pg_distributed_startup_rejects_missing_explicit_secret_when_javelin_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENDEEPHOLE_SECRET_KEY", raising=False)
    cfg = AppConfig()
    cfg.javelin.enabled = True
    with pytest.raises(RuntimeError, match="requires an explicit"):
        validate_javelin_startup_security(cfg, distributed=True)

    # Disabled Javelin must NOT affect existing deployments
    cfg.javelin.enabled = False
    validate_javelin_startup_security(cfg, distributed=True)


def test_sanitize_422_validation_errors_strips_raw_input() -> None:
    cleaned = sanitize_validation_errors([
        {
            "type": "string_type",
            "loc": ("body", "javelin_config", "runtime_testing", "test_environment_context"),
            "msg": "Input should be a valid string",
            "input": "SUPER_SECRET_PASSWORD_123",
            "ctx": {"raw": "SUPER_SECRET_PASSWORD_123"},
        }
    ])
    serialized = str(cleaned)
    assert "SUPER_SECRET_PASSWORD_123" not in serialized
    assert cleaned[0]["msg"] == "Input should be a valid string"
