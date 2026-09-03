"""Platform coordinator for pluggable vulnerability-mining engines."""

from __future__ import annotations

import asyncio
import copy
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.models import (
    MiningEngineSelection,
    ScanEvent,
    ThreatAnalysisRunStatus,
    Vulnerability,
)
from backend.scan_event_log import is_agent_local_task_output
from backend.vulnerability_identity import vulnerability_report_identity
from task_agent import opencode_task_context
from task_agent.model_pool import clear_planned_task, register_planned_task
from task_agent.output_format import is_task_output_line

from .code_graph_build import run_code_graph_build
from .codex_runtime import (
    CodexRuntimeState,
    get_codex_runtime_state,
    prepare_scan_codex_access_async,
    sync_scan_codex_mcp_async,
)
from .config import AgentConfig
from .platform_runtime import configure_platform_runtime
from .process_artifacts import collect_json_artifacts
from .reporter import Reporter
from .scan_modes import (
    SCAN_MODE_CUSTOM,
    SCAN_MODE_THREAT_ANALYSIS_ONLY,
    THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS,
    component_scan_mode,
    normalize_scan_mode,
)
from .threat_analysis_runner import run_threat_analysis
from .vulnerability_mining import (
    MiningEngineRun,
    load_mining_engines,
    run_mining_engine,
)
from .vulnerability_mining.dedup import VulnerabilityDeduplicator
from .vulnerability_mining.runtime import (
    normalize_mining_engine_vulnerabilities,
)


CODEX_THREAT_ANALYSIS_METHOD_ID = "codex_goal_threat_analysis"
OPENCODE_LIGHTWEIGHT_THREAT_ANALYSIS_METHOD_ID = (
    "opencode_lightweight_threat_analysis"
)
DEEPHOLE_THREAT_ANALYSIS_METHOD_ID = "deephole_threat_analysis"
LIGHTWEIGHT_THREAT_ANALYSIS_METHOD_IDS = frozenset({
    CODEX_THREAT_ANALYSIS_METHOD_ID,
    OPENCODE_LIGHTWEIGHT_THREAT_ANALYSIS_METHOD_ID,
})


def _archive_failed_threat_analysis(output_path: Path) -> Path | None:
    """Preserve one failed artifact tree before a clean fallback attempt."""
    output_path = Path(output_path)
    if not output_path.exists():
        output_path.mkdir(parents=True, exist_ok=True)
        return None
    failed_root = output_path.parent / f"{output_path.name}_failed"
    failed_root.mkdir(parents=True, exist_ok=True)
    attempt_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    archive_path = failed_root / attempt_id
    suffix = 1
    while archive_path.exists():
        archive_path = failed_root / f"{attempt_id}-{suffix}"
        suffix += 1
    output_path.rename(archive_path)
    output_path.mkdir(parents=True, exist_ok=False)
    return archive_path


async def _archive_failed_lightweight_best_effort(
    output_path: Path,
) -> tuple[Path | None, str]:
    """Archive a lightweight failure without letting Windows locks block fallback."""

    last_error: Exception | None = None
    for delay in (0.0, 0.05, 0.1, 0.2):
        if delay:
            await asyncio.sleep(delay)
        try:
            return _archive_failed_threat_analysis(output_path), ""
        except PermissionError as exc:
            last_error = exc
        except Exception as exc:
            last_error = exc
            break

    output_path = Path(output_path)
    atomic_detail = (
        f"{type(last_error).__name__}: {last_error}"
        if last_error is not None
        else "unknown archive error"
    )
    if not output_path.exists():
        output_path.mkdir(parents=True, exist_ok=True)
        return None, f"atomic archive failed ({atomic_detail})"

    failed_root = output_path.parent / f"{output_path.name}_failed"
    try:
        failed_root.mkdir(parents=True, exist_ok=True)
        attempt_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        archive_path = failed_root / attempt_id
        suffix = 1
        while archive_path.exists():
            archive_path = failed_root / f"{attempt_id}-{suffix}"
            suffix += 1
        shutil.copytree(output_path, archive_path)
    except Exception as copy_error:
        return None, (
            f"atomic archive failed ({atomic_detail}); diagnostic copy failed "
            f"({type(copy_error).__name__}: {copy_error})"
        )

    cleanup_errors: list[str] = []
    try:
        children = list(output_path.iterdir())
    except Exception as exc:
        children = []
        cleanup_errors.append(f"{output_path}: {type(exc).__name__}: {exc}")
    for child in children:
        try:
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink(missing_ok=True)
        except Exception as exc:
            cleanup_errors.append(
                f"{child}: {type(exc).__name__}: {exc}"
            )

    warning = (
        f"atomic archive failed ({atomic_detail}); copied diagnostics to "
        f"{archive_path}"
    )
    if cleanup_errors:
        warning += "; retained locked source entries: " + "; ".join(cleanup_errors)
    return archive_path, warning


def _resolve_scan_paths(
    project_path: Path,
    code_scan_path: Path | None,
) -> tuple[Path, Path]:
    project = Path(project_path).expanduser().resolve()
    raw_scan_root = Path(code_scan_path).expanduser() if code_scan_path else project
    scan_root = (
        raw_scan_root.resolve()
        if raw_scan_root.is_absolute()
        else (project / raw_scan_root).resolve()
    )
    if not project.is_dir():
        raise FileNotFoundError(f"Project directory does not exist: {project}")
    if not scan_root.is_dir():
        raise FileNotFoundError(
            f"Code scan directory does not exist: {scan_root}",
        )
    try:
        scan_root.relative_to(project)
    except ValueError as exc:
        raise ValueError(
            "code_scan_path must be inside project_path",
        ) from exc
    return project, scan_root


def _format_process_console_line(phase: str, message: str) -> str:
    if is_task_output_line(message):
        return message
    return f"[{phase}] {message}"


def _event_progress_counts(
    event: dict[str, Any],
) -> tuple[int, int] | None:
    if event.get("kind") != "progress":
        return None
    data = event.get("data")
    if not isinstance(data, dict):
        return None
    current = data.get("current")
    total = data.get("total")
    if (
        not isinstance(current, int)
        or isinstance(current, bool)
        or not isinstance(total, int)
        or isinstance(total, bool)
    ):
        return None
    return max(current, 0), max(total, 0)


def _format_process_event_message(
    event: dict[str, Any],
    message: str,
) -> str:
    counts = _event_progress_counts(event)
    if counts is None or counts[1] <= 0:
        return message
    current, total = counts
    percentage = max(0.0, min(100.0, current / total * 100))
    return f"{message}: {current}/{total} ({percentage:.1f}%)"


def _event_candidate_index(event: dict[str, Any]) -> int | None:
    data = event.get("data")
    if not isinstance(data, dict):
        return None
    keys = (
        ("candidate_count",)
        if event.get("process") == "static_analysis"
        else ("candidate_index", "audit_index", "vuln_index")
    )
    for key in keys:
        value = data.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def _resolve_mining_engines(
    *,
    raw_selections: list[dict[str, Any]] | None,
    threat_only: bool,
) -> tuple[Any, list[MiningEngineSelection]]:
    registry = load_mining_engines()
    manifests = registry.manifests()
    available = {item.engine_id: item for item in manifests}

    if raw_selections is not None:
        selections: list[MiningEngineSelection] = []
        seen: set[str] = set()
        for raw in raw_selections:
            selection = MiningEngineSelection.model_validate(raw)
            if selection.engine_id in seen:
                raise ValueError(
                    f"Duplicate mining engine: {selection.engine_id}"
                )
            seen.add(selection.engine_id)
            manifest = available.get(selection.engine_id)
            selections.append(
                selection.model_copy(update={
                    "engine_label": manifest.label,
                })
                if manifest is not None
                else selection
            )
    else:
        selections = [
            MiningEngineSelection(
                engine_id=manifest.engine_id,
                engine_label=manifest.label,
            )
            for manifest in manifests
        ]

    if threat_only:
        selections = [
            item.model_copy(update={
                "enabled": item.engine_id == "threat_audit",
            })
            for item in selections
        ]
    return registry, selections


async def _finish_scan(
    reporter: Reporter,
    scan_id: str,
    *,
    status: str,
    vulnerabilities: list[Vulnerability],
    total: int,
    processed: int,
    error: str | None = None,
    cancel_event: threading.Event | None = None,
    replace_report_batch_ids: list[str] | None = None,
) -> None:
    if bool(getattr(cancel_event, "suppress_terminal_report", False)):
        return
    await reporter.finish_scan(
        scan_id,
        vulnerabilities,
        status,
        total,
        processed,
        error_message=error,
        replace_report_batch_ids=replace_report_batch_ids,
    )


async def _report_process_vulnerabilities(
    *,
    reporter: Reporter,
    config: AgentConfig,
    scan_id: str,
    scan_mode: str = "custom",
    project_path: Path,
    code_scan_path: Path,
    product: str,
    validation_environment: str,
    vulnerability_validation: dict[str, Any] | None = None,
    feedback_entries: list[dict[str, Any]],
    code_graph_mcp: dict[str, Any] | None,
    knowledge_base_mcp: dict[str, Any] | None = None,
    engine: MiningEngineSelection,
    values: list[Any],
    deduplicator: VulnerabilityDeduplicator | None = None,
    provisional: bool = False,
    report_batch_id: str = "",
) -> list[tuple[Vulnerability, dict[str, Any] | None]]:
    reported: list[tuple[Vulnerability, dict[str, Any] | None]] = []
    for value in values:
        if not isinstance(value, (dict, Vulnerability)):
            continue
        vulnerability = Vulnerability.model_validate(value)
        vulnerability.engine_id = engine.engine_id
        vulnerability.engine_label = engine.engine_label
        vulnerability.provisional = provisional
        if deduplicator is not None:
            decision = await deduplicator.assess(vulnerability)
            if not decision.accepted:
                reported.append((
                    vulnerability,
                    {
                        "ok": True,
                        "deduplicated": True,
                        "dedup_method": decision.method,
                        "reason": decision.reason,
                    },
                ))
                continue
        if (
            isinstance(reporter, Reporter)
            or getattr(reporter, "reconcile_vulnerabilities", None) is not None
        ):
            response = await reporter.report_vulnerability(
                scan_id,
                vulnerability,
                provisional=provisional,
                report_batch_id=report_batch_id,
            )
        else:
            response = await reporter.report_vulnerability(
                scan_id,
                vulnerability,
            )
        reported.append((
            vulnerability,
            response if isinstance(response, dict) else None,
        ))
        if not isinstance(response, dict):
            continue
        if provisional:
            continue
        fp_info = response.get("fp_review")
        if isinstance(fp_info, dict) and fp_info.get("queued"):
            from . import server as client_server

            try:
                payload = vulnerability.model_dump(mode="json")
                payload["index"] = int(fp_info["vuln_index"])
                await client_server.enqueue_fp_review(
                    config=config,
                    reporter=reporter,
                    scan_id=scan_id,
                    scan_mode=scan_mode,
                    review_id=str(fp_info["review_id"]),
                    method=str(fp_info.get("method") or "adversarial"),
                    vulnerability=payload,
                    project_path=str(project_path),
                    code_scan_path=str(code_scan_path),
                    feedback_entries=feedback_entries,
                    processed_offset=int(fp_info.get("processed") or 0),
                    code_graph_mcp=code_graph_mcp,
                    knowledge_base_mcp=knowledge_base_mcp,
                )
            except Exception as exc:
                print(
                    "Warning: failed to queue FP review for "
                    f"{scan_id}#{response.get('index')}: {exc}",
                    flush=True,
                )
        if (
            isinstance(vulnerability_validation, dict)
            and bool(vulnerability_validation.get("enabled"))
            and vulnerability.confirmed
            and product
            and response.get("index") is not None
        ):
            from . import server as client_server

            try:
                await client_server.enqueue_vulnerability_validation(
                    config=config,
                    reporter=reporter,
                    scan_id=scan_id,
                    scan_mode=scan_mode,
                    vuln_index=int(response["index"]),
                    vulnerability=vulnerability.model_dump(mode="json"),
                    report_markdown=str(
                        response.get("report_markdown")
                        or vulnerability.vulnerability_report
                        or vulnerability.ai_analysis
                    ),
                    project_path=str(project_path),
                    code_scan_path=str(code_scan_path),
                    product=product,
                    validation_method_id=str(
                        vulnerability_validation.get("method_id") or ""
                    ),
                    validation_method_label=str(
                        vulnerability_validation.get("method_label") or ""
                    ),
                    validation_values=dict(
                        vulnerability_validation.get("values") or {}
                    ),
                    validation_policy=dict(
                        vulnerability_validation.get("policy") or {}
                    ),
                    report_queued=True,
                    code_graph_mcp=code_graph_mcp,
                    knowledge_base_mcp=knowledge_base_mcp,
                )
            except Exception as exc:
                print(
                    "Warning: failed to queue validation for "
                    f"{scan_id}#{response.get('index')}: {exc}",
                    flush=True,
                )
    return reported


def _stable_unique_vulnerabilities(
    vulnerabilities: list[Vulnerability],
) -> list[Vulnerability]:
    """Remove transport replays without changing first-seen result order."""
    unique: list[Vulnerability] = []
    seen: set[tuple[object, ...]] = set()
    for vulnerability in vulnerabilities:
        identity = vulnerability_report_identity(vulnerability)
        if identity in seen:
            continue
        seen.add(identity)
        unique.append(vulnerability)
    return unique


async def _publish_engine_run(
    reporter: Reporter,
    scan_id: str,
    run: MiningEngineRun,
) -> None:
    publish = getattr(reporter, "report_mining_engine_run", None)
    if publish is not None:
        await publish(scan_id, run.as_dict())


async def run_scan(
    config: AgentConfig,
    project_path: Path,
    code_scan_path: Path | None,
    reporter: Reporter,
    scan_name: str,
    product: str,
    validation_environment: str,
    checker_names: list[str],
    scan_id: str,
    cancel_event: threading.Event,
    feedback_entries: list[dict] | None = None,
    checker_packages: list[dict] | None = None,
    is_resume: bool = False,
    retry_candidates: list[dict] | None = None,
    retry_total_candidates: int | None = None,
    retry_processed_offset: int = 0,
    resume_threat_analysis: bool = False,
    retry_mining_engine_ids: list[str] | None = None,
    retry_threat_audit_task_ids: list[str] | None = None,
    scan_mode: str = SCAN_MODE_CUSTOM,
    threat_analysis_enabled: bool = False,
    threat_analysis_method: str = "deephole_threat_analysis",
    vulnerability_validation: dict[str, Any] | None = None,
    code_graph_mcp: dict[str, Any] | None = None,
    knowledge_base_mcp: dict[str, Any] | None = None,
    mining_engines: list[dict[str, Any]] | None = None,
    codex_model_ids: list[str] | None = None,
    multi_versions: list[dict[str, Any]] | None = None,
) -> None:
    """Run the selected directory-discovered mining engines."""
    feedback_entries = list(feedback_entries or [])
    checker_packages = list(checker_packages or [])
    multi_versions = [
        dict(item) for item in (multi_versions or []) if isinstance(item, dict)
    ]
    scan_dir = (
        Path.home() / ".opendeephole" / "scans" / str(scan_id)
    ).expanduser().resolve()
    scan_dir.mkdir(parents=True, exist_ok=True)
    project, scan_root = _resolve_scan_paths(project_path, code_scan_path)
    configure_platform_runtime(config, scan_dir)

    normalized_mode = normalize_scan_mode(scan_mode)
    runtime_scan_mode = component_scan_mode(normalized_mode)
    threat_only = normalized_mode == SCAN_MODE_THREAT_ANALYSIS_ONLY
    threat_analysis_selected = bool(
        threat_analysis_enabled or threat_only
    )
    threat_analysis_method_id = (
        str(threat_analysis_method or "deephole_threat_analysis").strip()
        or "deephole_threat_analysis"
    )
    registry, selections = _resolve_mining_engines(
        raw_selections=mining_engines,
        threat_only=threat_only,
    )
    configured_enabled_selections = [
        item for item in selections if item.enabled
    ]
    if is_resume and retry_mining_engine_ids is not None:
        retry_engine_ids = {
            str(engine_id).strip()
            for engine_id in retry_mining_engine_ids
            if str(engine_id).strip()
        }
        configured_ids = {
            item.engine_id for item in configured_enabled_selections
        }
        unknown_retry_ids = sorted(retry_engine_ids - configured_ids)
        if unknown_retry_ids:
            raise ValueError(
                "Unknown resume mining engine(s): "
                + ", ".join(unknown_retry_ids)
            )
        enabled_selections = [
            item
            for item in configured_enabled_selections
            if item.engine_id in retry_engine_ids
        ]
        preserved_completed_engine_count = (
            len(configured_enabled_selections) - len(enabled_selections)
        )
    else:
        enabled_selections = configured_enabled_selections
        preserved_completed_engine_count = 0
    index_file_progress = {"current": 0, "total": 0}

    async def emit(
        phase: str,
        message: str,
        candidate_index: int | None = None,
    ) -> None:
        await reporter.send_event(
            scan_id,
            ScanEvent.create(phase, message, candidate_index),
        )
        print(_format_process_console_line(phase, message), flush=True)

    async def process_output(event: dict[str, Any]) -> None:
        process = str(event.get("process") or "process")
        kind = str(event.get("kind") or "")
        message = str(event.get("message") or "")
        if message and (
            (process == "threat_analysis" and kind == "log")
            or is_agent_local_task_output(message)
        ):
            print(_format_process_console_line(process, message), flush=True)
            return

        index_status: dict[str, Any] | None = None
        if process == "code_graph_build":
            counts = _event_progress_counts(event)
            if counts is not None:
                current, total = counts
                is_file_progress = message == "Indexing source files"
                if is_file_progress:
                    index_file_progress.update({
                        "current": current,
                        "total": total,
                    })
                index_status = {
                    "parsed_files": index_file_progress["current"],
                    "total_files": index_file_progress["total"],
                    "stage": "" if is_file_progress else message,
                    "stage_current": 0 if is_file_progress else current,
                    "stage_total": 0 if is_file_progress else total,
                }
            elif kind == "progress":
                index_status = {
                    "parsed_files": index_file_progress["current"],
                    "total_files": index_file_progress["total"],
                    "stage": message,
                    "stage_current": 0,
                    "stage_total": 0,
                }
        is_code_graph_progress = (
            process == "code_graph_build" and kind == "progress"
        )
        if message and is_code_graph_progress:
            print(
                _format_process_console_line(
                    process,
                    _format_process_event_message(event, message),
                ),
                flush=True,
            )
        elif message:
            await emit(
                process,
                _format_process_event_message(event, message),
                _event_candidate_index(event),
            )
        if index_status is not None:
            await reporter.send_index_status(
                scan_id,
                "parsing",
                index_status["parsed_files"],
                index_status["total_files"],
                stage=index_status["stage"],
                stage_current=index_status["stage_current"],
                stage_total=index_status["stage_total"],
            )

    await emit("init", f"Scan started: {scan_name}")
    await emit("init", f"Project: {project}")
    await emit("init", f"Code scan path: {scan_root}")
    await emit("init", f"Scan mode: {normalized_mode}")
    await emit(
        "init",
        "Threat analysis: "
        + (
            f"enabled ({threat_analysis_method_id})"
            if threat_analysis_selected
            else "disabled"
        ),
    )
    await emit(
        "init",
        "Mining engines: "
        + (
            ", ".join(item.engine_label for item in enabled_selections)
            if enabled_selections
            else "(none)"
        ),
    )
    for error in registry.errors:
        await emit("mining_engine", f"Engine discovery warning: {error}")

    scan_codex_access_error = ""
    access_result = await prepare_scan_codex_access_async(
        project_path=project,
        scan_dir=scan_dir,
    )
    for warning in access_result.warnings:
        await emit("codex", f"Codex configuration warning: {warning}")
    if access_result.error:
        scan_codex_access_error = access_result.error
        await emit(
            "codex",
            "Codex scan path configuration failed; Codex-dependent stages "
            f"will use their existing fallback: {access_result.error}",
        )
    else:
        await emit(
            "codex",
            "Codex scan paths trusted: "
            f"{len(access_result.trusted_paths)}",
        )

    threat_dependent_engine_selected = any(
        item.engine_id in THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS
        for item in enabled_selections
    )
    if threat_dependent_engine_selected and not threat_analysis_selected:
        await _finish_scan(
            reporter,
            scan_id,
            status="error",
            vulnerabilities=[],
            total=0,
            processed=0,
            error="Selected vulnerability-mining engine requires threat analysis",
            cancel_event=cancel_event,
        )
        return
    if not enabled_selections and not threat_analysis_selected:
        await _finish_scan(
            reporter,
            scan_id,
            status="error",
            vulnerabilities=[],
            total=0,
            processed=0,
            error="No scan process or vulnerability-mining engine is enabled",
            cancel_event=cancel_event,
        )
        return

    codex_threat_selected = bool(
        threat_analysis_selected
        and threat_analysis_method_id == CODEX_THREAT_ANALYSIS_METHOD_ID
    )
    codex_engine_selected = any(
        bool(getattr(loaded.manifest, "requires_codex", False))
        for selection in enabled_selections
        if (loaded := registry.get(selection.engine_id)) is not None
    )
    scan_codex_state: CodexRuntimeState | None = None
    if codex_threat_selected or codex_engine_selected:
        scan_codex_state = get_codex_runtime_state()
        if scan_codex_access_error:
            await emit(
                "threat_analysis" if codex_threat_selected else "codex",
                "Codex is unavailable for this scan because its required "
                "paths could not be configured",
            )
        elif scan_codex_state.models:
            await emit(
                "codex",
                "Using configured Codex default model: "
                f"{scan_codex_state.models[0].id}",
            )
        elif codex_threat_selected:
            await emit(
                "threat_analysis",
                "Codex is unavailable for this scan; DeepHole fallback "
                "will be used",
            )

    if isinstance(code_graph_mcp, dict):
        code_graph_mcp = copy.deepcopy(code_graph_mcp)
        if bool(code_graph_mcp.get("enabled")):
            from .codegraph import prepare_scan_codegraph

            graph_ready = await prepare_scan_codegraph(
                code_graph_mcp,
                project,
                emit=lambda message: emit(
                    "code_graph_mcp",
                    str(message),
                ),
            )
            if not graph_ready:
                code_graph_mcp["enabled"] = False
                await emit(
                    "code_graph_mcp",
                    "Scan code graph MCP preparation failed; continuing with file tools only",
                )

    scan_mcp_result = await sync_scan_codex_mcp_async(
        project_path=project,
        scan_dir=scan_dir,
        code_graph_mcp=code_graph_mcp,
    )
    for warning in scan_mcp_result.warnings:
        await emit("codex", f"Codex CodeGraph MCP warning: {warning}")
    if scan_mcp_result.error:
        await emit(
            "codex",
            "Codex CodeGraph MCP configuration failed; Codex will continue "
            f"with file tools: {scan_mcp_result.error}",
        )
    elif scan_mcp_result.mcp_configured:
        await emit(
            "codex",
            "Scan CodeGraph MCP configured for Codex",
        )

    try:
        graph_result = await run_code_graph_build(
            scan_mode=runtime_scan_mode,
            project_path=project,
            code_scan_path=scan_root,
            work_dir=scan_dir / "code_graph_build",
            reuse_cache=True,
            output=process_output,
            cancel_event=cancel_event,
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        error = (
            f"{type(exc).__name__}: {exc}"
            if str(exc)
            else type(exc).__name__
        )
        await emit(
            "code_graph_build",
            f"Code graph build failed: {error}",
        )
        graph_result = {
            "status": "error",
            "error": error,
        }
    if graph_result.get("status") != "success":
        status = (
            "cancelled"
            if graph_result.get("status") == "cancelled"
            else "error"
        )
        error = str(graph_result.get("error") or "")
        if status == "error":
            await reporter.send_index_status(
                scan_id,
                "error",
                index_file_progress["current"],
                index_file_progress["total"],
                stage="Code graph build failed",
                error=error,
            )
        await _finish_scan(
            reporter,
            scan_id,
            status=status,
            vulnerabilities=[],
            total=0,
            processed=0,
            error=error or None,
            cancel_event=cancel_event,
        )
        return
    index_path = Path(str(graph_result["index_db_path"]))
    stats = dict(graph_result.get("stats") or {})
    await reporter.send_index_status(
        scan_id,
        "done",
        int(stats.get("files") or 0),
        int(stats.get("files") or 0),
        stats=stats,
    )

    if not any(
        item.engine_id in {"static_candidate", "multi_version"}
        for item in configured_enabled_selections
    ):
        await reporter.send_static_progress(scan_id, 0, 0, done=True)

    pool_stop = asyncio.Event()
    pool_task: asyncio.Task[Any] | None = None
    threat_analysis_task: asyncio.Task[
        tuple[ThreatAnalysisRunStatus, dict[str, Any] | None]
    ] | None = None
    engine_tasks: list[
        asyncio.Task[tuple[MiningEngineRun, dict[str, Any] | None]]
    ] = []
    audited: list[Vulnerability] = []
    accepted_streamed_vulnerabilities: dict[str, list[Vulnerability]] = {
        selection.engine_id: []
        for selection in enabled_selections
    }
    existing_vulnerabilities: list[Vulnerability] = []
    if is_resume:
        fetch_dedup_context = getattr(
            reporter,
            "get_vulnerability_dedup_context",
            None,
        )
        if fetch_dedup_context is not None:
            try:
                existing_vulnerabilities = await fetch_dedup_context(scan_id)
            except Exception as exc:
                await process_output({
                    "process": "vulnerability_dedup",
                    "kind": "error",
                    "message": (
                        "Unable to load persisted vulnerability deduplication "
                        f"context; continuing without it: {type(exc).__name__}: "
                        f"{str(exc).strip()}"
                    ),
                })
    deduplicator = VulnerabilityDeduplicator(
        scan_id=scan_id,
        project_path=project,
        required_capability=config.vulnerability_mining.required_capability,
        existing_vulnerabilities=existing_vulnerabilities,
        output=process_output,
        cancel_event=cancel_event,
    )
    total = 0
    processed = 0

    def task_output(line: str) -> None:
        if line:
            print(str(line), flush=True)

    async def execute_threat_analysis(
    ) -> tuple[ThreatAnalysisRunStatus, dict[str, Any] | None]:
        run = ThreatAnalysisRunStatus(
            status="running",
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        await reporter.report_threat_analysis_run(
            scan_id,
            run.model_copy(deep=True),
        )
        output_path = scan_dir / "threat_analysis"
        result: dict[str, Any] | None = None

        async def run_method_attempt(
            method_id: str,
            *,
            resume: bool,
        ) -> dict[str, Any]:
            async def invoke() -> dict[str, Any]:
                return await run_threat_analysis(
                    scan_mode=runtime_scan_mode,
                    method_id=method_id,
                    project_path=project,
                    code_path=scan_root,
                    output_path=output_path,
                    is_resume=resume,
                    product_mcp=(
                        str(
                            knowledge_base_mcp.get("name")
                            or "product-info"
                        )
                        if isinstance(knowledge_base_mcp, dict)
                        and bool(knowledge_base_mcp.get("enabled"))
                        else None
                    ),
                    output=process_output,
                    cancel_event=cancel_event,
                )

            if method_id == OPENCODE_LIGHTWEIGHT_THREAT_ANALYSIS_METHOD_ID:
                planned_task_id = await register_planned_task(
                    scan_id,
                    {
                        "task_type": "threat_analysis",
                        "task_name": "opencode-lightweight-threat-analysis",
                        "required_capability": "high",
                    },
                    task_key="threat-analysis:opencode-lightweight",
                )
                try:
                    # The threat-analysis runner narrows the paths again while
                    # inheriting this planned-task identity.  Its first model
                    # lease therefore consumes the visible planned row instead
                    # of appearing as an unrelated task.
                    with opencode_task_context(
                        project_dir=project,
                        work_dir=scan_dir,
                        task_metadata={"planned_task_id": planned_task_id},
                    ):
                        return await invoke()
                finally:
                    await clear_planned_task(planned_task_id)
            if method_id != CODEX_THREAT_ANALYSIS_METHOD_ID:
                return await invoke()
            if (
                scan_codex_access_error
                or scan_codex_state is None
                or not scan_codex_state.available
                or not scan_codex_state.command
                or not scan_codex_state.models
            ):
                raise RuntimeError(
                    "Codex has no configured default model"
                )
            return await invoke()

        def require_success(value: dict[str, Any]) -> None:
            if value.get("result") is not True:
                raise RuntimeError(
                    str(value.get("reason") or "Threat analysis failed")
                )

        def codex_unavailable_reason() -> str:
            if scan_codex_access_error:
                return scan_codex_access_error
            if scan_codex_state is None:
                return "Codex model preparation did not complete"
            if not scan_codex_state.available:
                return (
                    scan_codex_state.error
                    or "Codex CLI is unavailable"
                )
            if not scan_codex_state.command or not scan_codex_state.models:
                return (
                    scan_codex_state.model_config_error
                    or "Codex has no configured default model"
                )
            return ""

        try:
            artifact_bundle: dict[str, Any]
            if threat_analysis_method_id in LIGHTWEIGHT_THREAT_ANALYSIS_METHOD_IDS:
                primary_name = (
                    "Codex"
                    if threat_analysis_method_id == CODEX_THREAT_ANALYSIS_METHOD_ID
                    else "OpenCode"
                )
                primary_reason = (
                    codex_unavailable_reason()
                    if threat_analysis_method_id == CODEX_THREAT_ANALYSIS_METHOD_ID
                    else ""
                )
                if not primary_reason:
                    try:
                        result = await run_method_attempt(
                            threat_analysis_method_id,
                            resume=is_resume,
                        )
                        require_success(result)
                        artifact_bundle = collect_json_artifacts(
                            result,
                            output_root=output_path,
                        )
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        primary_reason = (
                            str(exc).strip() or type(exc).__name__
                        )
                if primary_reason:
                    if cancel_event.is_set():
                        raise RuntimeError(primary_reason)
                    try:
                        archive_path, archive_warning = (
                            await _archive_failed_lightweight_best_effort(
                                output_path
                            )
                        )
                    except Exception as exc:
                        archive_path = None
                        archive_warning = (
                            "best-effort archive failed unexpectedly: "
                            f"{type(exc).__name__}: {exc}"
                        )
                    await emit(
                        "threat_analysis",
                        f"{primary_name} lightweight threat analysis unavailable or failed; "
                        "starting one clean DeepHole fallback"
                        + (
                            f" (archived at {archive_path})"
                            if archive_path is not None
                            else ""
                        )
                        + (
                            f"; archive warning: {archive_warning}"
                            if archive_warning
                            else ""
                        ),
                    )
                    try:
                        result = await run_method_attempt(
                            DEEPHOLE_THREAT_ANALYSIS_METHOD_ID,
                            resume=False,
                        )
                        require_success(result)
                        artifact_bundle = collect_json_artifacts(
                            result,
                            output_root=output_path,
                        )
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        fallback_reason = (
                            str(exc).strip() or type(exc).__name__
                        )
                        raise RuntimeError(
                            f"{primary_name} lightweight threat analysis failed: "
                            f"{primary_reason}"
                            + (
                                f"; archive warning: {archive_warning}"
                                if archive_warning
                                else ""
                            )
                            + "; DeepHole fallback failed: "
                            f"{fallback_reason}"
                        ) from exc
            else:
                result = await run_method_attempt(
                    threat_analysis_method_id,
                    resume=is_resume,
                )
                if (
                    is_resume
                    and result.get("result") is not True
                    and not cancel_event.is_set()
                ):
                    incremental_reason = str(
                        result.get("reason") or "Threat analysis failed"
                    )
                    try:
                        archive_path = _archive_failed_threat_analysis(
                            output_path,
                        )
                    except Exception as exc:
                        raise RuntimeError(
                            "Incremental threat-analysis resume failed: "
                            f"{incremental_reason}; failed to archive its "
                            f"artifacts: {type(exc).__name__}: {exc}"
                        ) from exc
                    print(
                        _format_process_console_line(
                            "threat_analysis",
                            "Incremental resume failed; starting one clean "
                            "fallback"
                            + (
                                f" (archived at {archive_path})"
                                if archive_path is not None
                                else ""
                            ),
                        ),
                        flush=True,
                    )
                    clean_result = await run_method_attempt(
                        threat_analysis_method_id,
                        resume=False,
                    )
                    if clean_result.get("result") is not True:
                        clean_reason = str(
                            clean_result.get("reason")
                            or "Threat analysis failed"
                        )
                        result = {
                            **clean_result,
                            "result": False,
                            "reason": (
                                "Incremental threat-analysis resume failed: "
                                f"{incremental_reason}; clean fallback "
                                f"failed: {clean_reason}"
                            ),
                        }
                    else:
                        result = clean_result
                require_success(result)
                artifact_bundle = collect_json_artifacts(
                    result,
                    output_root=output_path,
                )
            await reporter.push_threat_analysis(scan_id, artifact_bundle)
            run.status = "success"
            return run, result
        except asyncio.CancelledError:
            run.status = "cancelled"
            raise
        except Exception as exc:
            run.status = (
                "cancelled" if cancel_event.is_set() else "error"
            )
            run.error_message = str(exc).strip() or type(exc).__name__
            return run, None
        finally:
            run.finished_at = datetime.now(timezone.utc).isoformat()
            await reporter.report_threat_analysis_run(
                scan_id,
                run.model_copy(deep=True),
            )

    async def execute_engine(
        selection: MiningEngineSelection,
    ) -> tuple[MiningEngineRun, dict[str, Any] | None]:
        loaded = registry.get(selection.engine_id)
        run = MiningEngineRun(
            engine_id=selection.engine_id,
            engine_label=selection.engine_label,
        )
        if loaded is None:
            run.status = "error"
            run.error_message = "Engine adapter is unavailable"
            run.finished_at = datetime.now(timezone.utc).isoformat()
            await _publish_engine_run(reporter, scan_id, run)
            return run, None
        if (
            is_resume
            and selection.engine_id == "threat_audit"
            and not resume_threat_analysis
            and not threat_only
        ):
            run.status = "skipped"
            run.finished_at = datetime.now(timezone.utc).isoformat()
            await _publish_engine_run(reporter, scan_id, run)
            return run, None

        codex_command: list[str] | None = None
        codex_models: list[dict[str, Any]] | None = None
        if bool(getattr(loaded.manifest, "requires_codex", False)):
            codex_state = scan_codex_state or get_codex_runtime_state()
            if (
                scan_codex_access_error
                or not codex_state.available
                or not codex_state.command
                or not codex_state.models
            ):
                reason = (
                    scan_codex_access_error
                    or codex_state.model_config_error
                    or codex_state.error
                    or "Codex CLI has no executable command on this Agent"
                )
                run.status = "error"
                run.error_message = f"Codex CLI is unavailable: {reason}"
                run.finished_at = datetime.now(timezone.utc).isoformat()
                await emit(
                    "mining_engine",
                    f"{selection.engine_label} cannot start: "
                    f"{run.error_message}",
                )
                await _publish_engine_run(reporter, scan_id, run)
                return run, None
            codex_command = list(codex_state.command)
            codex_models = [
                model.engine_value(codex_state.command)
                for model in codex_state.models
            ]

        threat_analysis_result: dict[str, Any] | None = None
        if selection.engine_id in THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS:
            if threat_analysis_task is None:
                run.status = "error"
                run.error_message = "Threat analysis was not started"
                run.finished_at = datetime.now(timezone.utc).isoformat()
                await _publish_engine_run(reporter, scan_id, run)
                return run, None
            analysis_run, threat_analysis_result = await threat_analysis_task
            if (
                analysis_run.status != "success"
                or threat_analysis_result is None
            ):
                run.status = "skipped"
                run.error_message = (
                    "Blocked because threat analysis failed: "
                    + (
                        analysis_run.error_message
                        or analysis_run.status
                    )
                )
                run.finished_at = datetime.now(timezone.utc).isoformat()
                await _publish_engine_run(reporter, scan_id, run)
                return run, None

        run.status = "running"
        run.started_at = datetime.now(timezone.utc).isoformat()
        await _publish_engine_run(reporter, scan_id, run)

        async def report_values(
            values: list[Any],
        ) -> list[tuple[Vulnerability, dict[str, Any] | None]]:
            normalized = normalize_mining_engine_vulnerabilities(
                loaded,
                values,
            )
            reported = await _report_process_vulnerabilities(
                reporter=reporter,
                config=config,
                scan_id=scan_id,
                scan_mode=runtime_scan_mode,
                project_path=project,
                code_scan_path=scan_root,
                product=product,
                validation_environment=validation_environment,
                vulnerability_validation=vulnerability_validation,
                feedback_entries=feedback_entries,
                code_graph_mcp=code_graph_mcp,
                knowledge_base_mcp=knowledge_base_mcp,
                engine=selection,
                values=normalized,
                deduplicator=deduplicator,
            )
            for vulnerability, response in reported:
                if not (
                    isinstance(response, dict)
                    and response.get("deduplicated") is True
                ):
                    accepted_streamed_vulnerabilities[
                        selection.engine_id
                    ].append(vulnerability.model_copy(deep=True))
            return reported

        engine_work_dir = (
            scan_dir
            if selection.engine_id in {
                "static_candidate",
                "threat_audit",
                "multi_version",
            }
            else scan_dir / "mining_engines" / selection.engine_id
        )
        engine_work_dir.mkdir(parents=True, exist_ok=True)
        engine_kwargs = {
            "engine_id": selection.engine_id,
            "engine_label": selection.engine_label,
            "scan_mode": runtime_scan_mode,
            "scan_id": scan_id,
            "project_path": project,
            "code_scan_path": scan_root,
            "scan_dir": scan_dir,
            "work_dir": engine_work_dir,
            "index_db_path": index_path,
            "config": config,
            "reporter": reporter,
            "checker_names": list(checker_names),
            "checker_packages": list(checker_packages),
            "product": product,
            "validation_environment": validation_environment,
            "vulnerability_validation": copy.deepcopy(
                vulnerability_validation
            ),
            "feedback_entries": list(feedback_entries),
            "code_graph_mcp": copy.deepcopy(code_graph_mcp),
            "knowledge_base_mcp": copy.deepcopy(knowledge_base_mcp),
            "product_mcp": (
                str(knowledge_base_mcp.get("name") or "product-info")
                if isinstance(knowledge_base_mcp, dict)
                and bool(knowledge_base_mcp.get("enabled"))
                else None
            ),
            "is_resume": is_resume,
            "retry_candidates": retry_candidates,
            "retry_total_candidates": retry_total_candidates,
            "retry_processed_offset": retry_processed_offset,
            "resume_threat_analysis": resume_threat_analysis,
            "retry_threat_audit_task_ids": retry_threat_audit_task_ids,
            "output": process_output,
            "cancel_event": cancel_event,
            "report_vulnerabilities": report_values,
        }
        if selection.engine_id == "multi_version":
            engine_kwargs["multi_versions"] = copy.deepcopy(multi_versions)
        if selection.engine_id in THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS:
            engine_kwargs["threat_analysis_result"] = (
                threat_analysis_result
            )
        if codex_command is not None:
            engine_kwargs["codex_command"] = codex_command
            engine_kwargs["codex_models"] = codex_models or []
        try:
            output = await run_mining_engine(loaded, **engine_kwargs)
            run.status = str(output["status"])
            run.error_message = str(output["error_message"])
            return run, output
        except asyncio.CancelledError:
            run.status = "cancelled"
            raise
        except Exception as exc:
            run.status = "error"
            run.error_message = str(exc)
            return run, None
        finally:
            run.finished_at = datetime.now(timezone.utc).isoformat()
            await _publish_engine_run(reporter, scan_id, run)

    def compose_engine_results(
        results: list[tuple[MiningEngineRun, dict[str, Any] | None]],
    ) -> list[Vulnerability]:
        """Return only findings accepted through report_vulnerabilities()."""
        combined: list[Vulnerability] = []
        for run, _output in results:
            selected = accepted_streamed_vulnerabilities.get(run.engine_id, [])
            combined.extend(
                vulnerability.model_copy(deep=True)
                for vulnerability in selected
            )
        return _stable_unique_vulnerabilities(combined)

    def compose_interrupted_results() -> list[Vulnerability]:
        """Use already accepted live results without starting new LLM work."""
        values = [
            vulnerability.model_copy(deep=True)
            for selection in enabled_selections
            for vulnerability in accepted_streamed_vulnerabilities.get(
                selection.engine_id,
                [],
            )
        ]
        result = _stable_unique_vulnerabilities([*audited, *values])
        for vulnerability in result:
            vulnerability.provisional = False
        return result

    try:
        if isinstance(code_graph_mcp, dict) and bool(
            code_graph_mcp.get("enabled")
        ):
            await emit(
                "mcp_ready",
                "Scan-specific code graph MCP selected; runtime connection will be verified before each model task",
            )
        else:
            await emit(
                "mcp_ready",
                "Code graph MCP is not enabled; model tasks will use file tools only",
            )
        pool_task = asyncio.create_task(
            reporter.publish_opencode_pool_until(scan_id, pool_stop),
        )

        with opencode_task_context(
            scan_id=scan_id,
            execution_kind="scan",
            execution_id=scan_id,
            project_dir=project,
            work_dir=scan_dir,
            feedback_entries=feedback_entries,
            code_graph_mcp=code_graph_mcp,
            knowledge_base_mcp=knowledge_base_mcp,
            output=task_output,
            cancel_event=cancel_event,
            task_metadata={"scan_mode": runtime_scan_mode},
        ):
            should_run_threat_analysis = (
                threat_analysis_selected
                and (not is_resume or resume_threat_analysis)
            )
            if should_run_threat_analysis:
                threat_analysis_task = asyncio.create_task(
                    execute_threat_analysis()
                )
            engine_tasks = [
                asyncio.create_task(execute_engine(selection))
                for selection in enabled_selections
            ]
            results = await asyncio.gather(*engine_tasks)
            threat_analysis_outcome = (
                await threat_analysis_task
                if threat_analysis_task is not None
                else None
            )

        successful_runs = preserved_completed_engine_count
        failures: list[str] = []
        if (
            threat_analysis_outcome is not None
            and threat_analysis_outcome[0].status == "error"
        ):
            failures.append(
                "Threat analysis: "
                + (
                    threat_analysis_outcome[0].error_message
                    or "analysis failed"
                )
            )
        for run, output in results:
            if run.status == "success":
                successful_runs += 1
            elif run.status == "error":
                failures.append(
                    f"{run.engine_label}: "
                    f"{run.error_message or 'engine failed'}"
                )
            if output is None:
                continue
            total += int(output["total_candidates"])
            processed += int(output["processed_candidates"])

        # A stage-targeted continuation may not run the static engine that
        # owns the scan-level candidate counters.  Never erase its persisted
        # totals merely because this attempt only repaired threat analysis or
        # another independent engine.
        if is_resume:
            if retry_total_candidates is not None:
                total = max(total, max(0, int(retry_total_candidates)))
            processed = max(processed, max(0, int(retry_processed_offset)))

        if cancel_event.is_set():
            status = "cancelled"
        elif not configured_enabled_selections:
            status = (
                "complete"
                if (
                    threat_analysis_outcome is not None
                    and threat_analysis_outcome[0].status == "success"
                )
                else "error"
            )
        elif successful_runs == 0:
            status = "error"
        else:
            status = "complete"
        warning = "; ".join(failures) or None
        audited[:] = compose_engine_results(results)
        await emit(
            "complete" if status == "complete" else status,
            (
                "Scan cancelled"
                if status == "cancelled"
                else (
                    f"Scan failed: {warning or 'all mining engines failed'}"
                    if status == "error"
                    else (
                        f"Scan complete with engine warning(s): {warning}"
                        if warning
                        else (
                            f"Scan complete: {len(audited)} audit result(s)"
                        )
                    )
                )
            ),
        )
        await _finish_scan(
            reporter,
            scan_id,
            status=status,
            vulnerabilities=audited,
            total=total,
            processed=processed,
            error=warning,
            cancel_event=cancel_event,
        )
    except asyncio.CancelledError:
        cancel_event.set()
        if threat_analysis_task is not None and not threat_analysis_task.done():
            threat_analysis_task.cancel()
        for task in engine_tasks:
            if not task.done():
                task.cancel()
        audited[:] = compose_interrupted_results()
        await _finish_scan(
            reporter,
            scan_id,
            status="cancelled",
            vulnerabilities=audited,
            total=total,
            processed=processed,
            cancel_event=cancel_event,
        )
        raise
    except Exception as exc:
        cancel_event.set()
        if threat_analysis_task is not None and not threat_analysis_task.done():
            threat_analysis_task.cancel()
        for task in engine_tasks:
            if not task.done():
                task.cancel()
        audited[:] = compose_interrupted_results()
        await emit("error", f"Scan failed: {exc}")
        await _finish_scan(
            reporter,
            scan_id,
            status="error",
            vulnerabilities=audited,
            total=total,
            processed=processed,
            error=str(exc),
            cancel_event=cancel_event,
        )
    finally:
        pool_stop.set()
        if pool_task is not None:
            try:
                await pool_task
            except Exception:
                pass


__all__ = ["run_scan"]
