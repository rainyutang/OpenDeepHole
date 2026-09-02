"""Threat analysis implemented as one logical OpenCode task."""

from __future__ import annotations

import asyncio
import json
from importlib import import_module
from pathlib import Path
from typing import Any, Awaitable, Mapping

_lightweight_contract = import_module(
    "deephole_client.threat_analysis.lightweight_contract"
)
build_lightweight_prompt = _lightweight_contract.build_lightweight_prompt
reference_paths = _lightweight_contract.reference_paths
reference_root = _lightweight_contract.reference_root
validate_artifacts_locally = _lightweight_contract.validate_artifacts_locally
validation_command = _lightweight_contract.validation_command
VALIDATION_SUCCESS_MARKER = _lightweight_contract.VALIDATION_SUCCESS_MARKER


_FINAL_DIR = "final"
_VALUE_ASSET_FILE = "value-assets.json"
_HIGH_RISK_MODULES_FILE = "high-risk-modules.json"
_ATTACK_TREE_FILE = "attack-trees.json"
_CONTEXT_FILE = "scan-context.json"
_STATE_FILE = "opencode-task-state.json"
_PROMPT_FILE = "opencode-task-prompt.txt"
_LOG_FILE = "opencode-task.log"
_VALIDATION_POLICY_VERSION = 1


def run_threat_analysis(
    code_path: str | Path,
    output_path: str | Path,
    is_resume: bool = False,
    product_mcp: str | None = None,
    attack_modes: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Analyze a source tree through one retry-managed OpenCode task."""

    try:
        code_root = _required_directory(code_path, "code_path")
        artifact_root = _output_directory(output_path)
        paths = _artifact_paths(artifact_root)
        guidance_path, schema_paths = _reference_paths()

        if is_resume and _completed_outputs(artifact_root, paths, guidance_path):
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
        prompt = build_task_prompt(
            code_root=code_root,
            context_path=context_path,
            guidance_path=guidance_path,
            schema_paths=schema_paths,
            paths=paths,
        )
        (artifact_root / _PROMPT_FILE).write_text(prompt + "\n", encoding="utf-8")
        command = validation_command(guidance_path=guidance_path, paths=paths)
        saved_state = _read_state(artifact_root / _STATE_FILE) if is_resume else {}
        saved_session_id = str(saved_state.get("session_id") or "").strip() or None

        result = _run_sync(_run_task(
            prompt=prompt,
            reference_root=reference_root(),
            validation_command_value=command,
            session_id=saved_session_id,
        ))
        (artifact_root / _LOG_FILE).write_text(
            str(getattr(result, "text", "") or "") + "\n",
            encoding="utf-8",
        )
        status = str(getattr(result, "status", "") or "failure")
        session_id = str(getattr(result, "session_id", "") or "")
        _write_state(
            artifact_root / _STATE_FILE,
            session_id=session_id,
            status=status,
        )
        if status != "success":
            return {
                "result": False,
                "reason": (
                    str(getattr(result, "text", "") or "").strip()
                    or f"OpenCode lightweight threat analysis stopped (status={status})"
                ),
            }

        validate_artifacts_locally(guidance_path=guidance_path, paths=paths)
        _write_state(
            artifact_root / _STATE_FILE,
            session_id=session_id,
            status="complete",
        )
        return _success(paths)
    except Exception as exc:
        return {
            "result": False,
            "reason": _safe_reason(exc),
        }


def build_task_prompt(
    *,
    code_root: Path,
    context_path: Path,
    guidance_path: Path,
    schema_paths: Mapping[str, Path],
    paths: Mapping[str, Path],
) -> str:
    return build_lightweight_prompt(
        code_root=code_root,
        context_path=context_path,
        guidance_path=guidance_path,
        schema_paths=schema_paths,
        paths=paths,
    )


async def _run_task(
    *,
    prompt: str,
    reference_root: Path,
    validation_command_value: str,
    session_id: str | None,
) -> Any:
    from task_agent import run_opencode_task

    return await run_opencode_task(
        task_name="opencode-lightweight-threat-analysis",
        task_type="threat_analysis",
        prompt=prompt,
        required_capability="high",
        output_schema=None,
        readable_paths=(reference_root,),
        required_bash_commands=(validation_command_value,),
        required_bash_retry_count=1,
        required_bash_success_markers={
            validation_command_value: VALIDATION_SUCCESS_MARKER,
        },
        session_id=session_id,
    )


def _run_sync(awaitable: Awaitable[Any]) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(awaitable)
    close = getattr(awaitable, "close", None)
    if callable(close):
        close()
    raise RuntimeError(
        "OpenCode lightweight threat analysis cannot run inside an active event loop"
    )


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


def _completed_outputs(
    artifact_root: Path,
    paths: Mapping[str, Path],
    guidance_path: Path,
) -> bool:
    state = _read_state(artifact_root / _STATE_FILE)
    if (
        state.get("status") != "complete"
        or state.get("validation_policy_version") != _VALIDATION_POLICY_VERSION
        or not all(path.is_file() for path in paths.values())
    ):
        return False
    try:
        validate_artifacts_locally(guidance_path=guidance_path, paths=paths)
    except Exception:
        return False
    return True


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
    return value if isinstance(value, dict) else {}


def _write_state(path: Path, *, session_id: str, status: str) -> None:
    _write_json(
        path,
        {
            "session_id": session_id,
            "status": status,
            "validation_policy_version": _VALIDATION_POLICY_VERSION,
        },
    )


def _safe_reason(exc: Exception) -> str:
    detail = " ".join(str(exc).split())
    if isinstance(exc, (FileNotFoundError, NotADirectoryError, ValueError)):
        return detail
    return (
        "OpenCode lightweight threat analysis failed "
        f"({type(exc).__name__})"
        + (f": {detail}" if detail else "")
    )
