"""Async framework adapter for directory-discovered threat-analysis methods."""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path
from types import ModuleType
from typing import Any, Mapping

from task_agent import opencode_task_context, run_sync_component

from .threat_analysis.runtime import (
    DEFAULT_THREAT_ANALYSIS_METHOD_ID,
    load_threat_analysis_method_package,
    resolve_threat_analysis_method,
    threat_analysis_method_execution,
)


PROCESS_NAME = "threat_analysis"
_ALLOWED_KEYS = {
    "method_id",
    "code_path",
    "output_path",
    "is_resume",
    "product_mcp",
    "attack_modes",
    "task_agent_config",
    "output",
    "cancel_event",
}
_REQUIRED_KEYS = {"code_path", "output_path"}
_REQUIRED_RESULT_PATHS = (
    "value_asset_path",
    "attack_tree_path",
    "high_risk_modules_path",
)


async def _emit(output: Any, kind: str, message: str, **data: Any) -> None:
    if output is None:
        return
    value = output({
        "process": PROCESS_NAME,
        "kind": kind,
        "message": message,
        "data": data,
    })
    if inspect.isawaitable(value):
        await value


def _directory(value: Any, key: str, *, create: bool = False) -> Path:
    path = Path(value).expanduser().resolve()
    if create:
        path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise FileNotFoundError(f"{key} is not a directory: {path}")
    return path


def _load_implementation(
    method_id: str = DEFAULT_THREAT_ANALYSIS_METHOD_ID,
) -> ModuleType:
    """Load one untouched method under its original top-level package name."""
    manifest = resolve_threat_analysis_method(method_id)
    return load_threat_analysis_method_package(manifest)


def _validate_native_result(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise TypeError("run_threat_analysis() must return a dict")
    succeeded = result.get("result")
    if succeeded is True:
        missing = [
            key
            for key in _REQUIRED_RESULT_PATHS
            if not isinstance(result.get(key), (str, Path))
            or not str(result.get(key) or "").strip()
        ]
        if missing:
            raise ValueError(
                "successful run_threat_analysis() result is missing path field(s): "
                + ", ".join(missing)
            )
    elif succeeded is False:
        if not isinstance(result.get("reason"), str) or not result["reason"].strip():
            raise ValueError(
                "failed run_threat_analysis() result must include a non-empty reason"
            )
    else:
        raise ValueError("run_threat_analysis() result must set result to true or false")
    return result


async def run_threat_analysis(**kwargs: Any) -> dict[str, Any]:
    """Call the untouched native entry point and return its result unchanged."""
    unknown = sorted(set(kwargs) - _ALLOWED_KEYS)
    if unknown:
        raise TypeError(
            "run_threat_analysis() got unexpected key(s): "
            + ", ".join(unknown)
        )
    missing = sorted(
        key for key in _REQUIRED_KEYS if kwargs.get(key) in (None, "")
    )
    if missing:
        raise TypeError(
            "run_threat_analysis() missing required key(s): "
            + ", ".join(missing)
        )

    method_id = str(
        kwargs.get("method_id") or DEFAULT_THREAT_ANALYSIS_METHOD_ID
    ).strip()
    manifest = resolve_threat_analysis_method(method_id)
    code_path = _directory(kwargs["code_path"], "code_path")
    output_path = _directory(
        kwargs["output_path"],
        "output_path",
        create=True,
    )
    output = kwargs.get("output")
    if output is not None and not callable(output):
        raise TypeError("output must be callable or None")
    attack_modes = kwargs.get("attack_modes")
    if attack_modes is not None and not isinstance(attack_modes, Mapping):
        raise TypeError("attack_modes must be a mapping or None")
    task_agent_config = kwargs.get("task_agent_config")
    if task_agent_config is not None:
        task_agent_config = Path(task_agent_config).expanduser().resolve()

    event_loop = asyncio.get_running_loop()
    pending_output_tasks: set[asyncio.Task[Any]] = set()

    def schedule_output(text: str) -> None:
        task = event_loop.create_task(_emit(output, "log", text))
        pending_output_tasks.add(task)
        task.add_done_callback(pending_output_tasks.discard)

    def task_output(line: str) -> None:
        text = str(line or "").strip()
        if not text or output is None:
            return
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None
        if running_loop is event_loop:
            schedule_output(text)
        else:
            event_loop.call_soon_threadsafe(schedule_output, text)

    await _emit(
        output,
        "progress",
        "Threat analysis started",
        method_id=manifest.method_id,
        method_label=manifest.label,
        code_path=str(code_path),
        output_path=str(output_path),
    )

    def invoke_native(**native_kwargs: Any) -> dict[str, Any]:
        with threat_analysis_method_execution():
            implementation = _load_implementation(manifest.method_id)
            native_entry = getattr(implementation, "run_threat_analysis", None)
            if not callable(native_entry):
                raise RuntimeError(
                    "threat_analysis_harness does not export run_threat_analysis"
                )
            return native_entry(**native_kwargs)

    try:
        with opencode_task_context(
            project_dir=code_path,
            work_dir=output_path,
            config_path=task_agent_config,
            skill_paths=list(manifest.skill_roots()),
            task_metadata={"standalone_console": True},
            output=task_output,
            cancel_event=kwargs.get("cancel_event"),
        ):
            result = await run_sync_component(
                invoke_native,
                code_path=code_path,
                output_path=output_path,
                is_resume=bool(kwargs.get("is_resume", False)),
                product_mcp=kwargs.get("product_mcp"),
                attack_modes=attack_modes,
            )
    finally:
        await asyncio.sleep(0)
        if pending_output_tasks:
            await asyncio.gather(*pending_output_tasks, return_exceptions=True)

    result = _validate_native_result(result)
    if result.get("result") is True:
        await _emit(
            output,
            "artifact",
            "Threat analysis completed",
            output_path=str(output_path),
        )
    else:
        await _emit(
            output,
            "error",
            str(result.get("reason") or "Threat analysis failed"),
        )
    return result
