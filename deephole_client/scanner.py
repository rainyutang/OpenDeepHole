"""Platform coordinator for pluggable vulnerability-mining engines."""

from __future__ import annotations

import asyncio
import copy
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
from task_agent import opencode_task_context
from task_agent.output_format import is_task_output_line

from .code_graph_build import run_code_graph_build
from .config import AgentConfig
from .platform_runtime import configure_platform_runtime
from .process_artifacts import collect_json_artifacts
from .reporter import Reporter
from .threat_analysis_runner import run_threat_analysis
from .vulnerability_mining import (
    MiningEngineRun,
    load_mining_engines,
    run_mining_engine,
)
from .vulnerability_mining.runtime import (
    normalize_mining_engine_vulnerabilities,
)


SCAN_MODE_FULL = "full"
SCAN_MODE_THREAT_ANALYSIS_ONLY = "threat_analysis_only"


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


def _resolve_scan_paths(
    project_path: Path,
    code_scan_path: Path | None,
) -> tuple[Path, Path]:
    project = Path(project_path).expanduser().resolve()
    scan_root = Path(code_scan_path or project).expanduser().resolve()
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
    )


async def _report_process_vulnerabilities(
    *,
    reporter: Reporter,
    config: AgentConfig,
    scan_id: str,
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
) -> list[tuple[Vulnerability, dict[str, Any] | None]]:
    reported: list[tuple[Vulnerability, dict[str, Any] | None]] = []
    for value in values:
        if not isinstance(value, (dict, Vulnerability)):
            continue
        vulnerability = Vulnerability.model_validate(value)
        vulnerability.engine_id = engine.engine_id
        vulnerability.engine_label = engine.engine_label
        response = await reporter.report_vulnerability(scan_id, vulnerability)
        reported.append((
            vulnerability,
            response if isinstance(response, dict) else None,
        ))
        if not isinstance(response, dict):
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
    scan_mode: str = SCAN_MODE_FULL,
    threat_analysis_enabled: bool = False,
    threat_analysis_method: str = "deephole_threat_analysis",
    vulnerability_validation: dict[str, Any] | None = None,
    code_graph_mcp: dict[str, Any] | None = None,
    knowledge_base_mcp: dict[str, Any] | None = None,
    mining_engines: list[dict[str, Any]] | None = None,
) -> None:
    """Run the selected directory-discovered mining engines."""
    feedback_entries = list(feedback_entries or [])
    checker_packages = list(checker_packages or [])
    scan_dir = (
        Path.home() / ".opendeephole" / "scans" / str(scan_id)
    ).expanduser().resolve()
    scan_dir.mkdir(parents=True, exist_ok=True)
    project, scan_root = _resolve_scan_paths(project_path, code_scan_path)
    configure_platform_runtime(config, scan_dir)

    normalized_mode = str(scan_mode or SCAN_MODE_FULL).strip().lower()
    if normalized_mode in {"threat_only", "threat-analysis-only"}:
        normalized_mode = SCAN_MODE_THREAT_ANALYSIS_ONLY
    if normalized_mode not in {
        SCAN_MODE_FULL,
        SCAN_MODE_THREAT_ANALYSIS_ONLY,
    }:
        raise ValueError(f"Unknown scan mode: {scan_mode}")
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

    threat_audit_selected = any(
        item.engine_id == "threat_audit"
        for item in enabled_selections
    )
    if threat_audit_selected and not threat_analysis_selected:
        await _finish_scan(
            reporter,
            scan_id,
            status="error",
            vulnerabilities=[],
            total=0,
            processed=0,
            error="Threat audit requires threat analysis",
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

    try:
        graph_result = await run_code_graph_build(
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
        item.engine_id == "static_candidate"
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

        async def run_native_attempt(*, resume: bool) -> dict[str, Any]:
            return await run_threat_analysis(
                method_id=threat_analysis_method_id,
                code_path=scan_root,
                output_path=output_path,
                is_resume=resume,
                product_mcp=(
                    "product-info"
                    if isinstance(knowledge_base_mcp, dict)
                    and bool(knowledge_base_mcp.get("enabled"))
                    else None
                ),
                output=process_output,
                cancel_event=cancel_event,
            )

        try:
            result = await run_native_attempt(resume=is_resume)
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
                        f"{incremental_reason}; failed to archive its artifacts: "
                        f"{type(exc).__name__}: {exc}"
                    ) from exc
                print(
                    _format_process_console_line(
                        "threat_analysis",
                        "Incremental resume failed; starting one clean fallback"
                        + (
                            f" (archived at {archive_path})"
                            if archive_path is not None
                            else ""
                        ),
                    ),
                    flush=True,
                )
                clean_result = await run_native_attempt(resume=False)
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
                            f"{incremental_reason}; clean fallback failed: "
                            f"{clean_reason}"
                        ),
                    }
                else:
                    result = clean_result
            if result.get("result") is not True:
                raise RuntimeError(
                    str(result.get("reason") or "Threat analysis failed")
                )
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

        threat_analysis_result: dict[str, Any] | None = None
        if selection.engine_id == "threat_audit":
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
        reported_vulnerability_counts: dict[str, int] = {}

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
            )
            for vulnerability, response in reported:
                if response is None:
                    continue
                fingerprint = vulnerability.model_dump_json()
                reported_vulnerability_counts[fingerprint] = (
                    reported_vulnerability_counts.get(fingerprint, 0) + 1
                )
            return reported

        engine_work_dir = (
            scan_dir
            if selection.engine_id in {
                "static_candidate",
                "threat_audit",
            }
            else scan_dir / "mining_engines" / selection.engine_id
        )
        engine_work_dir.mkdir(parents=True, exist_ok=True)
        engine_kwargs = {
            "engine_id": selection.engine_id,
            "engine_label": selection.engine_label,
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
                "product-info"
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
        if selection.engine_id == "threat_audit":
            engine_kwargs["threat_analysis_result"] = (
                threat_analysis_result
            )
        try:
            output = await run_mining_engine(loaded, **engine_kwargs)
            vulnerabilities = output["vulnerabilities"]
            unreported: list[Vulnerability] = []
            remaining_reported = dict(reported_vulnerability_counts)
            for vulnerability in vulnerabilities:
                fingerprint = vulnerability.model_dump_json()
                count = remaining_reported.get(fingerprint, 0)
                if count > 0:
                    remaining_reported[fingerprint] = count - 1
                else:
                    unreported.append(vulnerability)
            if unreported:
                await report_values([
                    vulnerability.model_dump(mode="json")
                    for vulnerability in unreported
                ])
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
            project_dir=project,
            work_dir=scan_dir,
            feedback_entries=feedback_entries,
            code_graph_mcp=code_graph_mcp,
            knowledge_base_mcp=knowledge_base_mcp,
            output=task_output,
            cancel_event=cancel_event,
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
            audited.extend(output["vulnerabilities"])
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
