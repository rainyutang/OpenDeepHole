"""Programmatic tool approval arbitrator for DeepSeek Harness turns.

Evaluates incoming JSON-RPC ``approval/request`` prompts against OpenDeepHole's
strict task boundaries:
- Source directories stay read-only; writes/edits are allowed only inside
  resolved ``write_roots`` (e.g. ``work_dir`` and ``file_write_allowlist``).
- Shell commands are denied by default and permitted only when matching
  ``allowed_bash_commands`` / ``required_bash_commands`` under ``exact`` or
  ``bound_python_script`` mode.
- When ``disable_all_tools=True``, every tool request is rejected.
"""

from __future__ import annotations

import json
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from ..bash_commands import (
    _PYTHON_NAMES,
    _absolute_command_path,
    _literal_command_args,
    command_binding_metadata,
)

_FILE_MUTATION_TOOLS = frozenset({"write", "edit", "apply_patch", "patch"})
_SHELL_TOOLS = frozenset({"bash", "pwsh", "shell"})
_INTERACTIVE_TOOLS = frozenset({"ask_user_question", "user_question", "question"})
_READ_ONLY_TOOLS = frozenset({
    "read",
    "read_image",
    "glob",
    "grep",
    "skill",
    "get_working_directory",
    "set_working_directory",
})


@dataclass(frozen=True)
class PendingFileWrite:
    """Tracked file-write intent awaiting completion in ``tool/result``."""

    call_id: str
    path: str
    created: bool


def _canonical_target_path(path: Path) -> Path:
    """Canonicalize *path* by resolving symlinks on its deepest existing ancestor."""
    candidate = path.expanduser()
    if not candidate.is_absolute():
        candidate = candidate.resolve()
    missing_parts: list[str] = []
    probe = candidate
    while not probe.exists() and probe != probe.parent:
        missing_parts.append(probe.name)
        probe = probe.parent
    resolved_ancestor = probe.resolve()
    result = resolved_ancestor
    for part in reversed(missing_parts):
        result = result / part
    return result


def _is_path_within_roots(target: Path, roots: tuple[Path, ...]) -> bool:
    for root in roots:
        if target == root or root in target.parents:
            return True
    return False


def _parse_json_object(raw: object) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return {}
    return {}


class DshApprovalArbitrator:
    """Thread-safe approval decision engine shared between event & request loops."""

    def __init__(
        self,
        *,
        cwd: Path,
        write_roots: Iterable[Path] = (),
        allowed_bash_commands: Iterable[str] = (),
        bash_command_match_mode: str = "exact",
        disable_all_tools: bool = False,
        platform: str | None = None,
        python_executable: str | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._cwd = Path(cwd).resolve()
        self._disable_all_tools = bool(disable_all_tools)
        self._write_roots = tuple(
            dict.fromkeys(_canonical_target_path(Path(root)) for root in write_roots)
        )
        self._allowed_commands = tuple(
            dict.fromkeys(
                str(cmd).strip()
                for cmd in allowed_bash_commands
                if str(cmd).strip()
            )
        )
        self._match_mode = str(bash_command_match_mode or "exact").strip() or "exact"
        self._binding_meta = (
            command_binding_metadata(
                self._allowed_commands,
                match_mode=self._match_mode,
                platform=platform,
                python_executable=python_executable,
            )
            if self._allowed_commands
            else {}
        )
        self._platform = platform or sys.platform
        self._tool_call_args: dict[str, tuple[str, dict[str, Any]]] = {}
        self._pending_writes: dict[str, PendingFileWrite] = {}
        self._approved_bash_commands: dict[str, str] = {}
        self._rejected_calls: dict[str, str] = {}

    @property
    def write_roots(self) -> tuple[Path, ...]:
        return self._write_roots

    @property
    def allowed_commands(self) -> tuple[str, ...]:
        return self._allowed_commands

    def register_tool_call(
        self,
        call_id: str,
        tool_name: str,
        raw_arguments: object,
    ) -> None:
        """Record model tool-call arguments ahead of ``approval/request``."""
        normalized_id = str(call_id or "").strip()
        if not normalized_id:
            return
        parsed_args = _parse_json_object(raw_arguments)
        with self._lock:
            self._tool_call_args[normalized_id] = (str(tool_name or "").strip(), parsed_args)

    def pop_pending_write(self, call_id: str) -> PendingFileWrite | None:
        with self._lock:
            return self._pending_writes.pop(str(call_id or "").strip(), None)

    def approved_bash_command(self, call_id: str) -> str:
        with self._lock:
            return self._approved_bash_commands.get(str(call_id or "").strip(), "")

    def tool_call_info(self, call_id: str) -> tuple[str, dict[str, Any]] | None:
        with self._lock:
            return self._tool_call_args.get(str(call_id or "").strip())

    def match_bash_command(self, command: str) -> str:
        """Return the canonical allowed bash command, or ``""`` if disallowed."""
        candidate = str(command or "").strip()
        if not candidate or not self._allowed_commands:
            return ""
        if candidate in self._allowed_commands:
            return candidate
        if self._match_mode != "bound_python_script":
            return ""
        windows = self._binding_meta.get("command_platform") == "win32"
        argv = _literal_command_args(candidate, windows=windows)
        if not argv or len(argv) < 2:
            return ""
        exe = argv[0].lower() if windows else argv[0]
        host_python = _absolute_command_path(
            str(self._binding_meta.get("python_executable") or ""),
            windows=windows,
        )
        if exe not in _PYTHON_NAMES and not (
            host_python and _absolute_command_path(argv[0], windows=windows) == host_python
        ):
            return ""
        script = _absolute_command_path(argv[1], windows=windows)
        if not script:
            return ""
        script_map = self._binding_meta.get("python_script_commands")
        if not isinstance(script_map, dict):
            return ""
        canonical = script_map.get(script)
        if isinstance(canonical, str) and canonical in self._allowed_commands:
            return canonical
        return ""

    def _resolve_args(
        self,
        call_id: str,
        reason: str,
    ) -> dict[str, Any]:
        with self._lock:
            recorded = self._tool_call_args.get(call_id)
        if recorded is not None and recorded[1]:
            return dict(recorded[1])
        reason_obj = _parse_json_object(reason)
        if isinstance(reason_obj.get("args"), dict) and reason_obj["args"]:
            return dict(reason_obj["args"])
        return dict(recorded[1]) if recorded is not None else {}

    def decide(self, params: dict[str, Any]) -> tuple[str, str]:
        """Return ``(outcome, detail)`` where outcome is ``allowed-once`` or ``rejected``."""
        tool_name = str(params.get("toolName") or "").strip().lower()
        call_id = str(params.get("callId") or "").strip()
        reason = str(params.get("reason") or "")

        if self._disable_all_tools:
            return self._reject(call_id, f"tools disabled for task ({tool_name})")

        if tool_name in _INTERACTIVE_TOOLS:
            return self._reject(call_id, f"interactive tool {tool_name!r} is disabled")

        args = self._resolve_args(call_id, reason)

        if tool_name in _FILE_MUTATION_TOOLS:
            return self._decide_file_mutation(call_id, tool_name, args)

        if tool_name in _SHELL_TOOLS:
            return self._decide_shell(call_id, args)

        if tool_name in _READ_ONLY_TOOLS or tool_name.startswith("mcp__"):
            return "allowed-once", f"read-only/mcp tool {tool_name}"

        return self._reject(call_id, f"tool {tool_name!r} is not allowed by OpenDeepHole policy")

    def _decide_file_mutation(
        self,
        call_id: str,
        tool_name: str,
        args: dict[str, Any],
    ) -> tuple[str, str]:
        if not self._write_roots:
            return self._reject(call_id, f"{tool_name} denied: no writable roots configured")

        raw_path = (
            args.get("file_path")
            or args.get("filePath")
            or args.get("path")
            or ""
        )
        raw_path_text = str(raw_path).strip()
        if not raw_path_text:
            return self._reject(call_id, f"{tool_name} denied: missing target file path")

        candidate = Path(raw_path_text).expanduser()
        if not candidate.is_absolute():
            candidate = self._cwd / candidate
        resolved = _canonical_target_path(candidate)

        if not _is_path_within_roots(resolved, self._write_roots):
            return self._reject(
                call_id,
                f"{tool_name} denied: target {resolved} is outside writable roots",
            )

        created = not resolved.exists()
        if call_id:
            with self._lock:
                self._pending_writes[call_id] = PendingFileWrite(
                    call_id=call_id,
                    path=str(resolved),
                    created=created,
                )
        return "allowed-once", f"{tool_name} allowed within writable root: {resolved}"

    def _decide_shell(
        self,
        call_id: str,
        args: dict[str, Any],
    ) -> tuple[str, str]:
        command = str(args.get("command") or args.get("cmd") or "").strip()
        if not command:
            return self._reject(call_id, "bash denied: missing command")
        canonical = self.match_bash_command(command)
        if not canonical:
            return self._reject(
                call_id,
                "bash denied: command is not in OpenDeepHole task allowlist",
            )
        if call_id:
            with self._lock:
                self._approved_bash_commands[call_id] = canonical
        return "allowed-once", f"bash allowed: {canonical}"

    def _reject(self, call_id: str, detail: str) -> tuple[str, str]:
        if call_id:
            with self._lock:
                self._rejected_calls[call_id] = detail
        return "rejected", detail
