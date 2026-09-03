"""Threat analysis implemented as one resilient Codex Goal."""

from __future__ import annotations

import json
import os
import sys
import traceback
from importlib import import_module
from pathlib import Path
from typing import Any, Mapping

_lightweight_contract = import_module(
    "deephole_client.threat_analysis.lightweight_contract"
)
MAX_LIGHTWEIGHT_PROMPT_CHARS = (
    _lightweight_contract.MAX_LIGHTWEIGHT_PROMPT_CHARS
)
build_lightweight_prompt = _lightweight_contract.build_lightweight_prompt
reference_paths = _lightweight_contract.reference_paths

MAX_GOAL_PROMPT_CHARS = MAX_LIGHTWEIGHT_PROMPT_CHARS
_FINAL_DIR = "final"
_VALUE_ASSET_FILE = "value-assets.json"
_HIGH_RISK_MODULES_FILE = "high-risk-modules.json"
_ATTACK_TREE_FILE = "attack-trees.json"
_CONTEXT_FILE = "scan-context.json"
_STATE_FILE = "codex-goal-state.json"
_PROMPT_FILE = "codex-goal-prompt.txt"
_LOG_FILE = "codex-goal.log"
_CODEX_SQLITE_DIR = ".codex-state"
_VALIDATION_POLICY_VERSION = 1
_RESUMABLE_GOAL_STATUSES = {"active", "paused", "usageLimited"}


def run_threat_analysis(
    code_path: str | Path,
    output_path: str | Path,
    is_resume: bool = False,
    product_mcp: str | None = None,
    attack_modes: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Analyze a source tree and return the platform's three artifact paths."""

    try:
        code_root = _required_directory(code_path, "code_path")
        artifact_root = _output_directory(output_path)
        paths = _artifact_paths(artifact_root)
        guidance_path, schema_paths = _reference_paths()

        if is_resume and _completed_goal_outputs(artifact_root, paths):
            return _success(paths)
        if not is_resume:
            _clear_outputs(paths)

        context_path = artifact_root / _CONTEXT_FILE
        _write_json(
            context_path,
            {
                "context_version": 1,
                "source": {
                    "root": str(code_root),
                    "access": "read_only",
                },
                "artifacts": {
                    "root": str(artifact_root),
                    "files": {key: str(path) for key, path in paths.items()},
                },
                "resume_requested": bool(is_resume),
                "optional_inputs": {
                    "product_mcp": product_mcp,
                    "attack_modes": attack_modes,
                },
            },
        )
        prompt = build_goal_prompt(
            code_root=code_root,
            context_path=context_path,
            guidance_path=guidance_path,
            schema_paths=schema_paths,
            paths=paths,
        )
        (artifact_root / _PROMPT_FILE).write_text(prompt + "\n", encoding="utf-8")

        goal_status = _run_goal(
            prompt=prompt,
            artifact_root=artifact_root,
            is_resume=bool(is_resume),
        )
        if goal_status != "complete":
            return {
                "result": False,
                "reason": f"Codex Goal stopped before completion (status={goal_status})",
            }

        return _success(paths)
    except Exception as exc:
        return {
            "result": False,
            "reason": _safe_reason(exc),
        }


def build_goal_prompt(
    *,
    code_root: Path,
    context_path: Path,
    guidance_path: Path,
    schema_paths: Mapping[str, Path],
    paths: Mapping[str, Path],
) -> str:
    """Build the single Goal prompt and enforce its hard size limit."""

    return build_lightweight_prompt(
        code_root=code_root,
        context_path=context_path,
        guidance_path=guidance_path,
        schema_paths=schema_paths,
        paths=paths,
    )


def _run_goal(
    *,
    prompt: str,
    artifact_root: Path,
    is_resume: bool,
) -> str:
    state_path = artifact_root / _STATE_FILE
    saved_state = _read_state(state_path) if is_resume else {}
    saved_thread_id = str(saved_state.get("thread_id") or "").strip() or None
    codex_state = _require_codex_runtime()
    # Imported lazily so method discovery remains available before optional
    # Agent dependencies have been installed.
    from codex_sdk import (
        ApprovalMode,
        CodexConfig,
        CodexController,
        OutputMode,
        ResumePolicy,
        Sandbox,
    )

    launch_args = (
        *codex_state.command,
        "app-server",
        "--listen",
        "stdio://",
    )
    thread_options = {
        "approval_mode": ApprovalMode.deny_all,
        "sandbox": Sandbox.workspace_write,
        "config": {
            "sandbox_workspace_write": {
                "network_access": False,
                "writable_roots": [str(artifact_root)],
            }
        },
    }
    policy = ResumePolicy(max_attempts=6, max_elapsed_seconds=7200)
    log_path = artifact_root / _LOG_FILE
    sqlite_home = artifact_root / _CODEX_SQLITE_DIR
    sqlite_home.mkdir(parents=True, exist_ok=True, mode=0o700)
    codex_env = {"CODEX_SQLITE_HOME": str(sqlite_home)}
    if sys.platform == "win32":
        interpreter_dir = str(Path(sys.executable).resolve().parent)
        existing_path = os.environ.get("PATH", "")
        path_entries = [
            entry
            for entry in existing_path.split(os.pathsep)
            if entry and os.path.normcase(entry) != os.path.normcase(interpreter_dir)
        ]
        codex_env["PATH"] = os.pathsep.join((interpreter_dir, *path_entries))
    codex_config = CodexConfig(
        cwd=str(artifact_root),
        launch_args_override=launch_args,
        # A Goal launched by an Agent can otherwise contend with an enclosing
        # Codex process for the user's shared state databases.  Keep auth,
        # models, and config in the existing CODEX_HOME while isolating only
        # the writable SQLite state needed by this resumable Goal.
        env=codex_env,
    )

    log_mode = "a" if is_resume else "w"
    with log_path.open(log_mode, encoding="utf-8") as output:
        try:
            with CodexController(
                # Keep the writable workspace on the artifact side. The source is
                # supplied as an absolute, read-only reference in the prompt.
                codex_config=codex_config,
                thread_id=saved_thread_id,
                output_mode=OutputMode.HUMAN,
                output=output,
                resume_policy=policy,
            ) as controller:
                if saved_thread_id:
                    controller.resume_thread(saved_thread_id, **thread_options)
                    current = controller.get_goal()
                    _write_codex_goal_state(
                        state_path,
                        controller.thread_id,
                        current.status if current else None,
                    )
                    if (
                        current is not None
                        and current.status in _RESUMABLE_GOAL_STATUSES
                    ):
                        result = controller.resume_goal()
                    else:
                        result = controller.goal(prompt)
                else:
                    controller.start_thread(**thread_options)
                    _write_codex_goal_state(
                        state_path,
                        controller.thread_id,
                        "active",
                    )
                    result = controller.goal(prompt)

                _write_codex_goal_state(
                    state_path,
                    controller.thread_id,
                    result.goal.status,
                )
                return result.goal.status
        except Exception as exc:
            # Startup failures happen before the controller can render an
            # event.  Preserve the SDK's stderr tail instead of leaving an
            # empty log and a bare TransportClosedError in the scan UI.
            detail = _exception_detail(exc)
            output.write(
                f"! Codex Goal runtime failure ({type(exc).__name__})"
                f"{f': {detail}' if detail else ''}\n"
            )
            output.write(traceback.format_exc())
            output.flush()
            raise


def _require_codex_runtime() -> Any:
    """Return the prepared Codex CLI runtime used by app-server."""
    from deephole_client.codex_runtime import get_codex_runtime_state

    state = get_codex_runtime_state()
    if not state.available or not state.command:
        detail = str(state.error or "Codex has no executable command").strip()
        raise ValueError(f"Codex CLI is unavailable: {detail}")

    return state


def _reference_paths() -> tuple[Path, dict[str, Path]]:
    return reference_paths()


def _artifact_paths(root: Path) -> dict[str, Path]:
    final = root / _FINAL_DIR
    final.mkdir(parents=True, exist_ok=True)
    return {
        "value_asset_path": final / _VALUE_ASSET_FILE,
        "high_risk_modules_path": final / _HIGH_RISK_MODULES_FILE,
        "attack_tree_path": final / _ATTACK_TREE_FILE,
    }


def _completed_goal_outputs(
    artifact_root: Path,
    paths: Mapping[str, Path],
) -> bool:
    state = _read_state(artifact_root / _STATE_FILE)
    return (
        state.get("goal_status") == "complete"
        and state.get("validation_policy_version") == _VALIDATION_POLICY_VERSION
        and all(path.is_file() for path in paths.values())
    )


def _clear_outputs(paths: Mapping[str, Path]) -> None:
    for path in paths.values():
        path.unlink(missing_ok=True)


def _success(paths: Mapping[str, Path]) -> dict[str, Any]:
    return {
        "result": True,
        "value_asset_path": str(paths["value_asset_path"]),
        "attack_tree_path": str(paths["attack_tree_path"]),
        "high_risk_modules_path": str(paths["high_risk_modules_path"]),
    }


def _required_directory(value: str | Path, name: str) -> Path:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError(f"{name} is required")
    path = Path(raw).expanduser().resolve()
    if not path.is_dir():
        raise FileNotFoundError(f"{name} is not a directory: {path}")
    return path


def _output_directory(value: str | Path) -> Path:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("output_path is required")
    path = Path(raw).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise NotADirectoryError(f"output_path is not a directory: {path}")
    return path


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )


def _read_state(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(value, dict):
        return {}
    return value


def _write_codex_goal_state(
    path: Path,
    thread_id: str | None,
    goal_status: str | None,
) -> None:
    """Persist only state owned by this threat-analysis method."""

    _write_json(
        path,
        {
            "thread_id": str(thread_id or ""),
            "goal_status": str(goal_status or "unknown"),
            "validation_policy_version": _VALIDATION_POLICY_VERSION,
        },
    )


def _safe_reason(exc: Exception) -> str:
    if isinstance(exc, (FileNotFoundError, NotADirectoryError, ValueError)):
        return str(exc)
    if isinstance(exc, TypeError):
        detail = _exception_detail(exc)
        return f"Codex Goal type error{f': {detail}' if detail else ''}"
    if type(exc).__name__ == "TransportClosedError":
        detail = _exception_detail(exc)
        return (
            "Codex Goal runtime closed unexpectedly"
            f"{f': {detail}' if detail else ''}"
        )
    return f"Codex Goal threat analysis failed ({type(exc).__name__})"


def _exception_detail(exc: BaseException, *, limit: int = 2000) -> str:
    """Return a bounded one-line SDK diagnostic suitable for logs and UI."""

    detail = " ".join(str(exc).split())
    if len(detail) <= limit:
        return detail
    return detail[: limit - 3].rstrip() + "..."
