"""Error normalization and redaction for DeepSeek Harness runtime failures."""

from __future__ import annotations

import re
from typing import Any

from ..llm_config import redact_llm_error
from ..serve_client import (
    OpenCodeModelAccessError,
    OpenCodeModelNotFoundError,
    OpenCodeProviderQuotaError,
    OpenCodeServeStartupError,
)

_RETRY_AFTER_RE = re.compile(
    r"(?:retry[-_\s]?after|try again in|after)\s*[:=]?\s*(\d+(?:\.\d+)?)\s*(?:s|sec|seconds?)?",
    re.IGNORECASE,
)
_HTTP_STATUS_RE = re.compile(r"\b(?:http\s*|status\s*[:=]?\s*)([45]\d{2})\b", re.IGNORECASE)


def _redact(message: object, llm_providers: dict[str, Any] | None = None) -> str:
    text = str(message or "").strip()
    if not text:
        return ""
    return redact_llm_error(text, llm_providers or {})


def _extract_status_code(failure: dict[str, Any] | None, text: str) -> int | None:
    if isinstance(failure, dict):
        raw_status = failure.get("status")
        if isinstance(raw_status, int) and not isinstance(raw_status, bool):
            return raw_status
    match = _HTTP_STATUS_RE.search(text)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return None
    return None


def _extract_retry_after(failure: dict[str, Any] | None, text: str) -> float | None:
    if isinstance(failure, dict):
        raw_ms = failure.get("providerRetryAfterMs")
        if isinstance(raw_ms, (int, float)) and not isinstance(raw_ms, bool) and raw_ms > 0:
            return round(float(raw_ms) / 1000.0, 3)
    match = _RETRY_AFTER_RE.search(text)
    if match:
        try:
            value = float(match.group(1))
            if value > 0:
                return value
        except ValueError:
            return None
    return None


def map_dsh_failure(
    *,
    error: BaseException | None = None,
    failure: dict[str, Any] | None = None,
    model: str = "",
    llm_providers: dict[str, Any] | None = None,
    startup_phase: bool = False,
) -> tuple[BaseException, str]:
    """Map a DeepSeek Harness failure to OpenDeepHole's standard exceptions.

    Returns ``(mapped_exception, failure_kind)`` where ``failure_kind`` is one of
    ``"quota"``, ``"access_denied"``, ``"timeout"``, ``"failure"``, or ``"neutral"``.
    """
    if isinstance(
        error,
        (
            OpenCodeServeStartupError,
            OpenCodeProviderQuotaError,
            OpenCodeModelAccessError,
            OpenCodeModelNotFoundError,
        ),
    ):
        kind = (
            "quota"
            if isinstance(error, OpenCodeProviderQuotaError)
            else "access_denied"
            if isinstance(error, OpenCodeModelAccessError)
            else "failure"
        )
        return error, kind

    raw_message = ""
    raw_code = ""
    if isinstance(failure, dict):
        raw_message = str(failure.get("message") or "").strip()
        raw_code = str(failure.get("code") or "").strip()
    if not raw_message and error is not None:
        raw_message = str(error).strip() or type(error).__name__
    detail = _redact(raw_message, llm_providers)
    lowered = f"{raw_code} {detail}".lower()
    status_code = _extract_status_code(failure, detail)
    retry_after = _extract_retry_after(failure, detail)

    if isinstance(error, (ModuleNotFoundError, ImportError)) and "deepseek_harness" in lowered:
        return (
            OpenCodeServeStartupError(
                "未安装 deepseek-harness-sdk，请运行 `pip install deepseek-harness-sdk` "
                f"或在基础配置中指定可用的 dsh 可执行文件路径（{detail}）",
            ),
            "failure",
        )

    if isinstance(error, FileNotFoundError):
        return (
            OpenCodeServeStartupError(
                f"无法找到 DeepSeek Harness 运行时可执行文件：{detail}。"
                "请安装 `deepseek-harness-sdk`（内置运行时）或检查 dsh 可执行文件路径。",
            ),
            "failure",
        )

    # Model not found / unconfigured provider route
    if (
        raw_code.upper() in {"MODEL_NOT_FOUND", "UNKNOWN_MODEL", "UNKNOWN_PROVIDER"}
        or "no adapter registered for provider" in lowered
        or "model not found" in lowered
        or "model_not_found" in lowered
        or "does not exist" in lowered and "model" in lowered
        or (status_code == 404 and "model" in lowered)
    ):
        return OpenCodeModelNotFoundError(model=model), "failure"

    # Quota / rate limit / transient upstream 503/529
    if (
        status_code in {429, 503, 529}
        or raw_code.upper() in {
            "QUOTA_EXCEEDED",
            "RATE_LIMITED",
            "RATE_LIMIT_EXCEEDED",
            "SERVICE_UNAVAILABLE",
            "OVERLOADED",
        }
        or any(
            token in lowered
            for token in (
                "rate limit",
                "rate_limit",
                "too many requests",
                "quota exceeded",
                "insufficient_quota",
                "overloaded",
                "service unavailable",
                "temporarily unavailable",
                "cooldown",
            )
        )
    ):
        reason_kind = "service_unavailable" if status_code in {503, 529} or "overloaded" in lowered or "unavailable" in lowered else "quota"
        return (
            OpenCodeProviderQuotaError(
                error_code=raw_code or (str(status_code) if status_code else "rate_limit"),
                retry_after_seconds=retry_after,
                status_code=status_code,
                reason_kind=reason_kind,
                detail=detail,
            ),
            "quota",
        )

    # Authentication / access / whitelist denial
    if (
        status_code in {401, 403}
        or raw_code.upper() in {
            "MISSING_CREDENTIAL",
            "AUTHENTICATION_ERROR",
            "UNAUTHORIZED",
            "FORBIDDEN",
            "PERMISSION_DENIED",
            "ACCESS_DENIED",
        }
        or any(
            token in lowered
            for token in (
                "missing_credential",
                "no api key",
                "invalid api key",
                "invalid_api_key",
                "unauthorized",
                "forbidden",
                "access denied",
                "not in whitelist",
                "permission denied",
            )
        )
    ):
        return (
            OpenCodeModelAccessError(
                model=model,
                error_code=raw_code or (str(status_code) if status_code else "access_denied"),
                status_code=status_code,
                detail=detail,
            ),
            "access_denied",
        )

    if startup_phase:
        return (
            OpenCodeServeStartupError(
                f"DeepSeek Harness 启动或初始化失败：{detail}",
            ),
            "failure",
        )

    return (
        RuntimeError(f"DeepSeek Harness 执行失败：{detail or 'unknown error'}"),
        "failure",
    )
