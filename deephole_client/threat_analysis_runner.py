"""Async framework adapter for directory-discovered threat-analysis methods."""

from __future__ import annotations

import asyncio
import inspect
import json
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
    "project_path",
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
_PLATFORM_HIGH_RISK_MODULES_PATH = Path("platform") / "high-risk-modules.json"


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


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _project_relative_module_path(
    value: Any,
    *,
    project_path: Path,
    code_path: Path,
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TypeError("high-risk module code paths must be non-empty strings")
    raw = value.strip().replace("\\", "/")
    path = Path(raw).expanduser()
    if ".." in path.parts:
        raise ValueError(f"high-risk module code path cannot contain '..': {value}")

    if path.is_absolute():
        resolved = path.resolve()
    else:
        project_scan_prefix = code_path.relative_to(project_path)
        prefix_parts = project_scan_prefix.parts
        already_project_relative = bool(
            prefix_parts and path.parts[: len(prefix_parts)] == prefix_parts
        )
        base = project_path if already_project_relative else code_path
        resolved = (base / path).resolve()

    if not _path_is_within(resolved, code_path):
        raise ValueError(
            "high-risk module code path escapes code_path: "
            f"{value} (code_path={code_path})"
        )
    return resolved.relative_to(project_path).as_posix()


def _normalize_module_code_paths(
    value: Any,
    *,
    project_path: Path,
    code_path: Path,
) -> str | list[str]:
    if isinstance(value, str):
        return _project_relative_module_path(
            value,
            project_path=project_path,
            code_path=code_path,
        )
    if isinstance(value, list):
        return [
            _project_relative_module_path(
                item,
                project_path=project_path,
                code_path=code_path,
            )
            for item in value
        ]
    raise TypeError("high-risk module 代码目录 must be a string or string array")


def _adapt_high_risk_modules_for_project(
    result: dict[str, Any],
    *,
    project_path: Path,
    code_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    """Expose project-relative paths without mutating native resume artifacts."""
    if project_path == code_path:
        return result

    source_path = Path(result["high_risk_modules_path"]).expanduser().resolve()
    if not _path_is_within(source_path, output_path):
        raise ValueError(
            "high-risk module artifact escapes output_path: "
            f"{source_path} (output_path={output_path})"
        )
    if not source_path.is_file():
        raise FileNotFoundError(
            f"high-risk module artifact is not a file: {source_path}"
        )
    try:
        modules = json.loads(source_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"high-risk module artifact is not valid JSON: {source_path}"
        ) from exc
    if not isinstance(modules, list):
        raise TypeError("high-risk module artifact must contain a JSON array")

    normalized_modules: list[dict[str, Any]] = []
    for index, module in enumerate(modules):
        if not isinstance(module, dict):
            raise TypeError(
                f"high-risk module item {index} must be a JSON object"
            )
        if "代码目录" not in module:
            raise ValueError(
                f"high-risk module item {index} is missing 代码目录"
            )
        normalized = dict(module)
        normalized["代码目录"] = _normalize_module_code_paths(
            module["代码目录"],
            project_path=project_path,
            code_path=code_path,
        )
        normalized_modules.append(normalized)

    platform_path = (output_path / _PLATFORM_HIGH_RISK_MODULES_PATH).resolve()
    if not _path_is_within(platform_path, output_path):
        raise ValueError(
            "platform high-risk module artifact escapes output_path: "
            f"{platform_path} (output_path={output_path})"
        )
    platform_path.parent.mkdir(parents=True, exist_ok=True)
    platform_path.write_text(
        json.dumps(normalized_modules, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    adapted = dict(result)
    adapted["high_risk_modules_path"] = str(platform_path)
    return adapted


async def run_threat_analysis(**kwargs: Any) -> dict[str, Any]:
    """Call one native method and adapt its artifacts for platform consumers."""
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
    scan_path = _directory(kwargs["code_path"], "code_path")
    project_path = _directory(
        kwargs.get("project_path") or scan_path,
        "project_path",
    )
    if not _path_is_within(scan_path, project_path):
        raise ValueError("code_path must be inside project_path")
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
        project_path=str(project_path),
        code_path=str(scan_path),
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
        # Narrow only method-internal OpenCode sessions. The scanner's outer
        # context remains bound to the full project for every other process.
        with opencode_task_context(
            project_dir=scan_path,
            work_dir=output_path,
            config_path=task_agent_config,
            skill_paths=list(manifest.skill_roots()),
            task_metadata={"standalone_console": True},
            output=task_output,
            cancel_event=kwargs.get("cancel_event"),
        ):
            result = await run_sync_component(
                invoke_native,
                code_path=scan_path,
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
        result = _adapt_high_risk_modules_for_project(
            result,
            project_path=project_path,
            code_path=scan_path,
            output_path=output_path,
        )
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
