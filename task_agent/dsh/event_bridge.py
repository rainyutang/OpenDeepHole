"""Notification/event bridge, token accounting, and bash audit for DeepSeek Harness."""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from ..output_format import format_task_output
from ..serve_client import (
    OpenCodeCommandFailure,
    OpenCodeFileWrite,
    OpenCodeTaskQualityError,
)
from ..token_usage import (
    OpenCodeTokenUsage,
    TokenCounters,
    token_usage_from_models,
)
from .approval_policy import DshApprovalArbitrator

_EXIT_CODE_RE = re.compile(r"\[Command finished with exit code (\d+)\]\s*$")
_TIMEOUT_MARKER = "[Command timed out or OOM]"
_OUTPUT_TAIL_LIMIT_BYTES = 16 * 1024


@dataclass(frozen=True)
class BashAuditRecord:
    """Observed shell command execution extracted from ``tool/call`` + ``tool/result``."""

    call_id: str
    command: str
    exit_code: int | None
    timed_out: bool
    is_error: bool
    output_text: str
    output_tail: str
    output_bytes: int
    output_truncated: bool


def _non_negative_int(value: object) -> int:
    if isinstance(value, bool):
        return 0
    try:
        parsed = int(value or 0)
        return max(0, parsed)
    except (TypeError, ValueError):
        return 0


def _output_tail_info(text: str, limit_bytes: int = _OUTPUT_TAIL_LIMIT_BYTES) -> tuple[str, int, bool]:
    encoded = text.encode("utf-8", errors="replace")
    total_bytes = len(encoded)
    if total_bytes <= limit_bytes:
        return text, total_bytes, False
    tail_text = encoded[-limit_bytes:].decode("utf-8", errors="ignore")
    return tail_text, total_bytes, True


def _extract_tool_result_text(message: dict[str, Any]) -> str:
    content = message.get("content")
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(str(block.get("text") or ""))
    return "\n".join(parts)


def parse_dsh_bash_output(raw_text: str) -> tuple[str, int | None, bool]:
    """Parse ``dsh-tool-bash-persistent`` status markers from tool output text."""
    text = str(raw_text or "")
    timed_out = _TIMEOUT_MARKER in text
    exit_code: int | None = None
    match = _EXIT_CODE_RE.search(text)
    if match:
        try:
            exit_code = int(match.group(1))
        except ValueError:
            exit_code = None
        body = text[: match.start()].rstrip("\r\n")
    else:
        body = text
    return body, exit_code, timed_out


def normalize_dsh_finish_reason(raw_reason: str | None) -> str:
    """Map DeepSeek Harness ``turn/end`` reason kinds to Task Agent conventions."""
    normalized = str(raw_reason or "").strip().lower()
    if normalized in {"max-tokens", "max_tokens", "length"}:
        return "length"
    if normalized == "completed":
        return "stop"
    return normalized


def _preview_tool_call(tool_name: str, raw_args: object) -> str:
    if isinstance(raw_args, str):
        try:
            parsed = json.loads(raw_args)
        except Exception:
            parsed = {}
    elif isinstance(raw_args, dict):
        parsed = raw_args
    else:
        parsed = {}
    if not isinstance(parsed, dict):
        return tool_name
    for key in ("command", "file_path", "filePath", "path", "pattern", "name", "query"):
        val = parsed.get(key)
        if isinstance(val, str) and val.strip():
            preview = val.strip().replace("\n", " ")
            if len(preview) > 120:
                preview = preview[:117] + "..."
            return f"{tool_name} {preview}"
    return tool_name


def parse_dsh_usage(usage_obj: object) -> TokenCounters | None:
    """Parse DeepSeek Harness ``TokenUsage`` dict into ``TokenCounters``."""
    if not isinstance(usage_obj, dict):
        return None
    if not any(
        key in usage_obj
        for key in (
            "inputTokens",
            "outputTokens",
            "reasoningTokens",
            "cacheReadTokens",
            "cacheWriteTokens",
        )
    ):
        return None
    return TokenCounters(
        input_tokens=_non_negative_int(usage_obj.get("inputTokens")),
        output_tokens=_non_negative_int(usage_obj.get("outputTokens")),
        reasoning_tokens=_non_negative_int(usage_obj.get("reasoningTokens")),
        cache_read_tokens=_non_negative_int(usage_obj.get("cacheReadTokens")),
        cache_write_tokens=_non_negative_int(usage_obj.get("cacheWriteTokens")),
    )


class DshEventBridge:
    """Processes streaming DeepSeek Harness notifications for one turn."""

    def __init__(
        self,
        *,
        session_id: str,
        model_label: str,
        log_stage: str,
        arbitrator: DshApprovalArbitrator,
        emit_line: Callable[[str], None] | None = None,
        emit_token_usage: Callable[[OpenCodeTokenUsage], None] | None = None,
        emit_response_model: Callable[[str], None] | None = None,
        emit_file_write: Callable[[OpenCodeFileWrite], None] | None = None,
        emit_model_progress: Callable[[], None] | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self.session_id = session_id
        self.model_label = model_label
        self.log_stage = log_stage
        self.arbitrator = arbitrator
        self._emit_line = emit_line
        self._emit_token_usage = emit_token_usage
        self._emit_response_model = emit_response_model
        self._emit_file_write = emit_file_write
        self._emit_model_progress = emit_model_progress

        self.last_activity_at: float = time.monotonic()
        self.lines: list[str] = []
        self.last_message_id: str = ""
        self.last_output_tokens: int | None = None
        self.finish_reason_raw: str = ""
        self.turn_error: dict[str, Any] | None = None
        self.token_usage_by_model: dict[str, TokenCounters] = {}
        self.bash_audits: list[BashAuditRecord] = []
        self._response_model_emitted = False

    def touch_activity(self) -> None:
        with self._lock:
            self.last_activity_at = time.monotonic()

    def seconds_since_activity(self) -> float:
        with self._lock:
            return max(0.0, time.monotonic() - self.last_activity_at)

    def accumulated_token_usage(self) -> OpenCodeTokenUsage | None:
        with self._lock:
            if not self.token_usage_by_model:
                return None
            return token_usage_from_models(dict(self.token_usage_by_model), complete=True)

    def _record_line(self, category: str, message: str) -> None:
        formatted = format_task_output(self.log_stage, self.session_id, category, message)
        with self._lock:
            self.lines.append(formatted)
        if self._emit_line is not None:
            self._emit_line(formatted)

    def handle_notification(self, notification: Any) -> None:
        """Process one ``deepseek_harness.Notification`` (runs on SDK worker thread)."""
        self.touch_activity()
        method = str(getattr(notification, "method", "") or "")
        payload = getattr(notification, "payload", None)
        if method != "session.event" or not isinstance(payload, dict):
            return
        event = payload.get("event")
        if not isinstance(event, dict):
            return
        event_type = str(event.get("type") or "")
        data = event.get("data")
        if not isinstance(data, dict):
            return

        if event_type == "assistant/message":
            self._handle_assistant_message(data)
        elif event_type == "tool/call":
            self._handle_tool_call(data)
        elif event_type == "tool/result":
            self._handle_tool_result(data)
        elif event_type == "turn/end":
            self._handle_turn_end(data)

    def _handle_assistant_message(self, data: dict[str, Any]) -> None:
        message = data.get("message")
        if isinstance(message, dict):
            msg_id = str(message.get("id") or "").strip()
            if msg_id:
                with self._lock:
                    self.last_message_id = msg_id
            source = message.get("source")
            model_name = self.model_label
            if isinstance(source, dict):
                src_provider = str(source.get("provider") or "").strip()
                src_model = str(source.get("model") or "").strip()
                if src_provider and src_model:
                    model_name = f"{src_provider}/{src_model}"
                elif src_model:
                    model_name = src_model
            if model_name and not self._response_model_emitted:
                self._response_model_emitted = True
                if self._emit_response_model is not None:
                    self._emit_response_model(model_name)

            content = message.get("content")
            if isinstance(content, list):
                has_progress = False
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    btype = block.get("type")
                    if btype == "tool-call":
                        has_progress = True
                        self.arbitrator.register_tool_call(
                            str(block.get("id") or ""),
                            str(block.get("name") or ""),
                            block.get("arguments"),
                        )
                    elif btype in {"text", "reasoning"} and str(block.get("text") or "").strip():
                        has_progress = True
                if has_progress and self._emit_model_progress is not None:
                    self._emit_model_progress()
        else:
            model_name = self.model_label

        counters = parse_dsh_usage(data.get("usage"))
        if counters is not None:
            key = model_name or self.model_label or "unknown"
            with self._lock:
                self.token_usage_by_model[key] = (
                    self.token_usage_by_model.get(key, TokenCounters()) + counters
                )
                self.last_output_tokens = counters.output_tokens + counters.reasoning_tokens
            if self._emit_token_usage is not None:
                self._emit_token_usage(token_usage_from_models({key: counters}, complete=True))

    def _handle_tool_call(self, data: dict[str, Any]) -> None:
        call_id = str(data.get("callId") or "").strip()
        tool_name = str(data.get("name") or "").strip()
        raw_args = data.get("arguments")
        if call_id and tool_name:
            self.arbitrator.register_tool_call(call_id, tool_name, raw_args)
        category = "skill" if tool_name == "skill" else "tool"
        self._record_line(category, f"CALL {_preview_tool_call(tool_name, raw_args)}")

    def _handle_tool_result(self, data: dict[str, Any]) -> None:
        message = data.get("message")
        if not isinstance(message, dict):
            return
        call_id = str(message.get("toolCallId") or "").strip()
        is_error = bool(message.get("isError"))
        text = _extract_tool_result_text(message)

        # File-write reporting
        pending_write = self.arbitrator.pop_pending_write(call_id)
        if pending_write is not None and not is_error:
            if self._emit_file_write is not None:
                self._emit_file_write(
                    OpenCodeFileWrite(
                        call_id=pending_write.call_id,
                        path=pending_write.path,
                        created=pending_write.created,
                    )
                )

        # Bash audit recording
        call_info = self.arbitrator.tool_call_info(call_id)
        tool_name = call_info[0].lower() if call_info else ""
        if tool_name in {"bash", "pwsh", "shell"}:
            canonical_cmd = self.arbitrator.approved_bash_command(call_id)
            raw_cmd = str((call_info[1] if call_info else {}).get("command") or "").strip()
            recorded_cmd = canonical_cmd or raw_cmd
            body, exit_code, timed_out = parse_dsh_bash_output(text)
            if exit_code is None and not is_error and not timed_out:
                exit_code = 0
            tail, total_bytes, truncated = _output_tail_info(body)
            with self._lock:
                self.bash_audits.append(
                    BashAuditRecord(
                        call_id=call_id,
                        command=recorded_cmd,
                        exit_code=exit_code,
                        timed_out=timed_out,
                        is_error=is_error,
                        output_text=body,
                        output_tail=tail,
                        output_bytes=total_bytes,
                        output_truncated=truncated,
                    )
                )

        status = "ERROR" if is_error else "OK"
        category = "skill" if tool_name == "skill" else "tool"
        self._record_line(category, f"RESULT {tool_name or call_id} status={status}")

    def _handle_turn_end(self, data: dict[str, Any]) -> None:
        reason = data.get("reason")
        if not isinstance(reason, dict):
            return
        kind = str(reason.get("kind") or "").strip()
        with self._lock:
            self.finish_reason_raw = kind
            if kind == "error" and isinstance(reason.get("error"), dict):
                self.turn_error = dict(reason["error"])


def _has_exact_line(text: str, marker: str) -> bool:
    if not marker:
        return False
    return any(line.strip() == marker for line in str(text or "").splitlines())


def verify_required_bash_commands(
    *,
    required_commands: Iterable[str],
    success_markers: Iterable[tuple[str, str]],
    audits: Iterable[BashAuditRecord],
) -> None:
    """Enforce OpenDeepHole's required bash command contract after a DSH turn."""
    required = tuple(
        dict.fromkeys(str(cmd).strip() for cmd in required_commands if str(cmd).strip())
    )
    if not required:
        return
    marker_map = {str(cmd).strip(): str(marker).strip() for cmd, marker in success_markers}
    audit_list = list(audits)
    failures: list[OpenCodeCommandFailure] = []

    for command in required:
        matching = [item for item in audit_list if item.command == command]
        if not matching:
            failures.append(
                OpenCodeCommandFailure(
                    failure_kind="command_not_executed",
                    command=command,
                )
            )
            continue
        latest = matching[-1]
        marker = marker_map.get(command, "")
        if latest.timed_out:
            failures.append(
                OpenCodeCommandFailure(
                    failure_kind="command_timeout",
                    command=command,
                    exit_code=latest.exit_code,
                    output_tail=latest.output_tail,
                    output_bytes=latest.output_bytes,
                    output_truncated=latest.output_truncated,
                    timed_out=True,
                )
            )
            continue
        if latest.exit_code is None and not marker:
            failures.append(
                OpenCodeCommandFailure(
                    failure_kind="command_exit_unknown",
                    command=command,
                    exit_code=None,
                    output_tail=latest.output_tail,
                    output_bytes=latest.output_bytes,
                    output_truncated=latest.output_truncated,
                )
            )
            continue
        if latest.is_error or (latest.exit_code is not None and latest.exit_code != 0):
            failures.append(
                OpenCodeCommandFailure(
                    failure_kind="command_exit_failure",
                    command=command,
                    exit_code=latest.exit_code,
                    output_tail=latest.output_tail,
                    output_bytes=latest.output_bytes,
                    output_truncated=latest.output_truncated,
                )
            )
            continue
        if marker and not _has_exact_line(latest.output_text, marker):
            failures.append(
                OpenCodeCommandFailure(
                    failure_kind="command_output_marker_missing",
                    command=command,
                    exit_code=latest.exit_code,
                    output_tail=latest.output_tail,
                    output_bytes=latest.output_bytes,
                    output_truncated=latest.output_truncated,
                )
            )

    if failures:
        first_kind = failures[0].failure_kind
        raise OpenCodeTaskQualityError(
            f"DeepSeek Harness required bash verification failed ({first_kind})",
            failure_kind=first_kind,
            command_failures=tuple(failures),
        )
