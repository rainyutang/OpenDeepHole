"""Independent async entry point for the complete threat-analysis pipeline."""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path
from typing import Any

from .attack_paths import build_analysis_from_attack_paths
from .attack_tree import AttackTreeThreatAnalysis
from .models import ThreatAnalysisSources, ThreatAttackPath
from .opencode_pipeline import run_attack_tree_threat_analysis
from .parsing import (
    apply_threat_analysis_scan_scope,
    build_threat_analysis_scan_scope,
    write_threat_analysis_file,
)


PROCESS_NAME = "threat_analysis"
_ALLOWED_KEYS = {
    "project_path",
    "work_dir",
    "code_scan_path",
    "scan_id",
    "product",
    "reuse_cache",
    "result_path",
    "required_capability",
    "timeout_seconds",
    "max_retries",
    "task_agent_config",
    "opencode_config_path",
    "configured_mcp_names",
    "product_mcp_name",
    "product_mcp_detection_timeout_seconds",
    "mock",
    "output",
    "cancel_event",
}
_REQUIRED_KEYS = {"project_path", "work_dir"}


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


def _cancelled(cancel_event: Any) -> bool:
    return bool(cancel_event is not None and cancel_event.is_set())


def _directory(value: Any, key: str, *, create: bool = False) -> Path:
    path = Path(value).expanduser().resolve()
    if create:
        path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise FileNotFoundError(f"{key} is not a directory: {path}")
    return path


async def run_threat_analysis(**kwargs: Any) -> dict[str, Any]:
    """Build a scope-aware attack-tree threat model for one project."""
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

    project = _directory(kwargs["project_path"], "project_path")
    work_dir = _directory(kwargs["work_dir"], "work_dir", create=True)
    scan_root = _directory(
        kwargs.get("code_scan_path") or project,
        "code_scan_path",
    )
    try:
        scan_root.relative_to(project)
    except ValueError as exc:
        raise ValueError("code_scan_path must be inside project_path") from exc

    output = kwargs.get("output")
    if output is not None and not callable(output):
        raise TypeError("output must be callable or None")
    cancel_event = kwargs.get("cancel_event")
    capability = str(kwargs.get("required_capability") or "high").lower()
    if capability not in {"low", "high"}:
        raise ValueError("required_capability must be 'low' or 'high'")
    configured_mcp_names = kwargs.get("configured_mcp_names") or []
    if not isinstance(configured_mcp_names, list):
        raise TypeError("configured_mcp_names must be a list")

    implementation = AttackTreeThreatAnalysis()
    result_path = Path(
        kwargs.get("result_path") or implementation.result_path(project)
    ).expanduser().resolve()
    if bool(kwargs.get("reuse_cache", True)):
        cached = implementation.load_cached(project, scan_root)
        if cached.analysis is not None:
            await _emit(
                output,
                "artifact",
                cached.message or "Loaded cached threat analysis",
                path=str(result_path),
                cache_hit=True,
            )
            return {
                "status": "success",
                "analysis": cached.analysis.model_dump(mode="json"),
                "cache_hit": True,
                "output_source": {},
            }
        if cached.message:
            await _emit(output, "warning", cached.message)

    if _cancelled(cancel_event):
        return {
            "status": "cancelled",
            "analysis": None,
            "cache_hit": False,
            "output_source": {},
        }

    scan_id = str(kwargs.get("scan_id") or "standalone").strip()
    scan_scope = build_threat_analysis_scan_scope(project, scan_root)

    async def on_attack_paths(paths: list[ThreatAttackPath]) -> None:
        partial = build_analysis_from_attack_paths(
            paths,
            analysis_id=f"{scan_id}-streaming",
            sources=ThreatAnalysisSources(
                repositories=[scan_scope.code_scan_relative_path or "."],
            ),
            scan_scope=scan_scope,
        )
        await _emit(
            output,
            "attack_paths",
            f"Threat analysis produced {len(paths)} attack path(s)",
            attack_paths=[
                path.model_dump(mode="json")
                for path in paths
            ],
            analysis=partial.model_dump(mode="json"),
        )

    event_loop = asyncio.get_running_loop()
    pending_output_tasks: set[asyncio.Task[Any]] = set()

    def on_model_output(line: str) -> None:
        if output is None:
            return
        task = event_loop.create_task(_emit(output, "log", str(line)))
        pending_output_tasks.add(task)
        task.add_done_callback(pending_output_tasks.discard)

    package_root = Path(__file__).resolve().parent
    await _emit(output, "progress", "Threat analysis started", scan_id=scan_id)
    try:
        analysis = await run_attack_tree_threat_analysis(
            workspace=work_dir / "workspace",
            work_dir=work_dir / "run",
            project_id=scan_id,
            skill_path=package_root / "attack-tree-threat-analysis.md",
            reference_catalog_path=package_root / "attack-method-reference-catalog.md",
            on_output=on_model_output,
            cancel_event=cancel_event,
            timeout=max(1, int(kwargs.get("timeout_seconds") or 1200)),
            project_dir=project,
            code_scan_path=scan_root,
            product=str(kwargs.get("product") or ""),
            on_attack_paths=on_attack_paths,
            required_capability=capability,
            max_retries=(
                3
                if kwargs.get("max_retries") is None
                else max(0, int(kwargs["max_retries"]))
            ),
            task_agent_config=kwargs.get("task_agent_config"),
            opencode_config_path=(
                Path(kwargs["opencode_config_path"]).expanduser().resolve()
                if kwargs.get("opencode_config_path")
                else None
            ),
            configured_mcp_names=[
                str(name)
                for name in configured_mcp_names
            ],
            product_mcp_name=str(
                kwargs.get("product_mcp_name") or "product-info"
            ),
            product_mcp_detection_timeout_seconds=max(
                1,
                int(
                    kwargs.get("product_mcp_detection_timeout_seconds")
                    or 60
                ),
            ),
            mock=bool(kwargs.get("mock", False)),
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        if _cancelled(cancel_event):
            return {
                "status": "cancelled",
                "analysis": None,
                "cache_hit": False,
                "output_source": {},
            }
        await _emit(output, "error", f"Threat analysis failed: {exc}")
        return {
            "status": "failure",
            "analysis": None,
            "cache_hit": False,
            "error": str(exc),
            "output_source": {},
        }
    finally:
        if pending_output_tasks:
            await asyncio.gather(*pending_output_tasks, return_exceptions=True)

    if analysis is None:
        status = "cancelled" if _cancelled(cancel_event) else "failure"
        return {
            "status": status,
            "analysis": None,
            "cache_hit": False,
            "error": "" if status == "cancelled" else "No threat analysis result",
            "output_source": {},
        }

    analysis = apply_threat_analysis_scan_scope(
        analysis,
        project,
        scan_root,
    )
    result_path.parent.mkdir(parents=True, exist_ok=True)
    write_threat_analysis_file(result_path, analysis)
    await _emit(
        output,
        "artifact",
        "Threat analysis completed",
        path=str(result_path),
        attack_path_count=len(analysis.attack_paths),
    )
    return {
        "status": "success",
        "analysis": analysis.model_dump(mode="json"),
        "cache_hit": False,
        "output_source": {},
    }
