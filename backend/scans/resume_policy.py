"""Scan resume policy services."""

from dataclasses import dataclass
from deephole_client.scan_modes import THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS
from backend.models import (
    Candidate,
    MiningEngineSelection,
    ScanCandidate,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    ScanSummary,
    ThreatAuditTask,
)
from backend.scans.fp_review_policy import _has_final_user_verdict


_RETRYABLE_AI_VERDICTS = {"timeout", "no_result", "failed"}


def _candidate_key(candidate: Candidate) -> tuple[str, int, str, str]:
    return (candidate.file, candidate.line, candidate.function, candidate.vuln_type)


def _is_retryable_vuln(vuln) -> bool:
    return (
        not vuln.provisional
        and _is_static_candidate_vulnerability(vuln)
        and not _has_final_user_verdict(vuln)
        and (vuln.ai_verdict or "") in _RETRYABLE_AI_VERDICTS
    )


def _is_static_candidate_vulnerability(vuln) -> bool:
    """Return whether a result belongs to the static-candidate audit pipeline."""
    source = str(getattr(vuln, "analysis_source", "") or "static_candidate").strip()
    return source == "static_candidate"


def _is_static_scan_candidate(candidate: Candidate) -> bool:
    """Reject threat-analysis placeholders from the persisted static candidate set."""
    if str(candidate.vuln_type or "").strip().lower() == "threat_audit":
        return False
    metadata = candidate.metadata if isinstance(candidate.metadata, dict) else {}
    return str(metadata.get("source") or "").strip().lower() != "threat_analysis"


def _retry_incomplete_candidates(scan: ScanStatus) -> list[Candidate]:
    if scan.candidates:
        return [
            candidate
            for candidate in scan.candidates
            if candidate.audit_state == "failed"
            and candidate.audit_result is not None
            and _is_retryable_vuln(candidate.audit_result)
        ]
    candidates: list[Candidate] = []
    for vuln in scan.vulnerabilities:
        if not _is_retryable_vuln(vuln):
            continue
        candidates.append(
            Candidate(
                file=vuln.file,
                line=vuln.line,
                function=vuln.function,
                description=vuln.description,
                vuln_type=vuln.vuln_type,
            )
        )
    return candidates


def _retry_incomplete_count(scan: ScanStatus) -> int:
    return len(_retry_incomplete_candidates(scan))


def _apply_candidate_audit_progress(scan: ScanStatus) -> None:
    """Derive audit counters from candidate-owned terminal states."""
    candidates = [
        candidate
        for candidate in scan.candidates
        if _is_static_scan_candidate(candidate)
    ]
    if not candidates:
        return
    candidate_count = len(candidates)
    if scan.static_analysis_done:
        scan.total_candidates = candidate_count
    else:
        scan.total_candidates = max(
            candidate_count,
            max(0, int(scan.total_candidates or 0)),
        )
    scan.processed_candidates = sum(
        1
        for candidate in candidates
        if candidate.audit_state in {"success", "failed"}
    )
    if scan.total_candidates > 0:
        scan.progress = scan.processed_candidates / scan.total_candidates


def _incomplete_threat_audit_tasks(scan: ScanStatus) -> list[ThreatAuditTask]:
    return [
        task
        for task in scan.threat_audit_tasks
        if str(task.status or "").strip().lower()
        not in {"completed", "superseded"}
    ]


def _continuable_candidates(
    scan: ScanStatus,
    processed_keys: set[tuple[str, int, str, str]],
) -> list[ScanCandidate]:
    """Return unfinished/retryable candidates by their persisted scan-local index."""
    del processed_keys  # legacy location checkpoints are intentionally ignored
    candidates: list[ScanCandidate] = []
    for candidate in scan.candidates:
        if not _is_static_scan_candidate(candidate):
            continue
        if candidate.audit_state in {"pending", "queued", "running"}:
            candidates.append(candidate)
            continue
        if (
            candidate.audit_state == "failed"
            and candidate.audit_result is not None
            and _is_retryable_vuln(candidate.audit_result)
        ):
            candidates.append(candidate)
    return candidates


def _continuable_task_count(
    scan: ScanStatus,
    processed_keys: set[tuple[str, int, str, str]],
) -> int:
    candidate_count = len(_continuable_candidates(scan, processed_keys))
    threat_task_count = len(_incomplete_threat_audit_tasks(scan))
    return (
        candidate_count
        + threat_task_count
        + _retryable_stage_count(
            scan,
            candidate_count=candidate_count,
            threat_task_count=threat_task_count,
        )
    )


_COMPLETED_ENGINE_RUN_STATUSES = {"success", "skipped"}


def _normalized_run_status(value: object) -> str:
    return str(value or "").strip().lower()


def _threat_analysis_run_needs_retry(
    scan: ScanStatus | ScanSummary,
) -> bool:
    if not scan.threat_analysis_enabled:
        return False
    run = scan.threat_analysis_run
    if run is None:
        return scan.status in {ScanItemStatus.CANCELLED, ScanItemStatus.ERROR}
    return _normalized_run_status(run.status) != "success"


def _retryable_stage_count(
    scan: ScanStatus | ScanSummary,
    *,
    candidate_count: int,
    threat_task_count: int,
) -> int:
    """Count retryable process-level work not represented by finer tasks."""
    threat_analysis_retry = _threat_analysis_run_needs_retry(scan)
    count = 1 if threat_analysis_retry else 0
    interrupted = scan.status in {ScanItemStatus.CANCELLED, ScanItemStatus.ERROR}
    runs_by_id = {item.engine_id: item for item in scan.mining_engine_runs}
    for selection in scan.mining_engines:
        if not selection.enabled:
            continue
        run = runs_by_id.get(selection.engine_id)
        retryable = (
            interrupted
            if run is None
            else _normalized_run_status(run.status)
            not in _COMPLETED_ENGINE_RUN_STATUSES
        )
        if (
            selection.engine_id in THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS
            and threat_analysis_retry
        ):
            retryable = True
        if not retryable:
            continue
        if selection.engine_id == "static_candidate" and candidate_count:
            continue
        if selection.engine_id == "threat_audit" and threat_task_count:
            continue
        count += 1
    return count


def _resume_mining_engine_ids(
    scan: ScanStatus,
    selections: list[MiningEngineSelection],
    *,
    continue_candidates: list[Candidate],
    incomplete_threat_tasks: list[ThreatAuditTask],
    full_pipeline_resume: bool,
    resume_threat_analysis: bool,
) -> list[str]:
    """Return enabled engines that have unfinished work for this continuation."""
    threat_analysis_retry = _threat_analysis_run_needs_retry(scan)
    interrupted = scan.status in {ScanItemStatus.CANCELLED, ScanItemStatus.ERROR}
    runs_by_id = {item.engine_id: item for item in scan.mining_engine_runs}
    retry_ids: list[str] = []
    for selection in selections:
        if not selection.enabled:
            continue
        run = runs_by_id.get(selection.engine_id)
        lifecycle_retry = (
            interrupted
            if run is None
            else _normalized_run_status(run.status)
            not in _COMPLETED_ENGINE_RUN_STATUSES
        )
        has_work = lifecycle_retry
        if selection.engine_id == "static_candidate":
            has_work = has_work or full_pipeline_resume or bool(continue_candidates)
        elif selection.engine_id in THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS:
            has_work = has_work or threat_analysis_retry
            if selection.engine_id == "threat_audit":
                has_work = (
                    has_work
                    or bool(incomplete_threat_tasks)
                    or resume_threat_analysis
                )
        if has_work:
            retry_ids.append(selection.engine_id)
    return retry_ids


def _apply_continue_capability(
    scan: ScanStatus | ScanSummary,
    *,
    continuable_count: int,
    fp_review_running: bool = False,
) -> None:
    running = scan.status in {
        ScanItemStatus.PENDING,
        ScanItemStatus.ANALYZING,
        ScanItemStatus.AUDITING,
    }
    scan.fp_review_running = fp_review_running
    scan.continuable_task_count = continuable_count
    scan.can_continue = not running and not fp_review_running and (
        scan.status in {ScanItemStatus.CANCELLED, ScanItemStatus.ERROR}
        or continuable_count > 0
    )


@dataclass
class ResumePlan:
    continue_candidates: list[ScanCandidate]
    incomplete_threat_tasks: list[ThreatAuditTask]
    continue_count: int
    resume_interrupted: bool
    resume_main_scan: bool
    full_pipeline_resume: bool
    candidate_payload: list[ScanCandidate] | None
    resume_threat_analysis: bool
    retry_mining_engine_ids: list[str]
    rerun_threat_analysis: bool
    threat_task_ids: list[str] | None


def build_resume_plan(
    scan: ScanStatus,
    meta: ScanMeta,
    processed_keys: set[tuple[str, int, str, str]],
) -> ResumePlan:
    """Compute work selection without modifying checkpoints or contacting the Agent."""
    continue_candidates = _continuable_candidates(scan, processed_keys)
    incomplete_threat_tasks = _incomplete_threat_audit_tasks(scan)
    continue_count = (
        len(continue_candidates)
        + len(incomplete_threat_tasks)
        + _retryable_stage_count(
            scan,
            candidate_count=len(continue_candidates),
            threat_task_count=len(incomplete_threat_tasks),
        )
    )
    resume_interrupted = scan.status in {ScanItemStatus.CANCELLED, ScanItemStatus.ERROR}
    resume_main_scan = resume_interrupted or continue_count > 0
    # An interrupted scan without a persisted candidate set may have stopped
    # during indexing/static analysis, so let the Agent resume the full pipeline.
    full_pipeline_resume = resume_interrupted and not (
        scan.candidates or scan.static_analysis_done
    )
    candidate_payload = None if full_pipeline_resume else continue_candidates
    threat_audit_enabled = any(
        item.enabled and item.engine_id == "threat_audit"
        for item in meta.mining_engines
    )
    resume_threat_analysis = meta.threat_analysis_enabled and (
        _threat_analysis_run_needs_retry(scan)
        or bool(incomplete_threat_tasks)
        or (
            resume_interrupted
            and (
                scan.threat_analysis is None
                or (
                    threat_audit_enabled
                    and not scan.threat_audit_tasks
                )
            )
        )
    )
    retry_mining_engine_ids = _resume_mining_engine_ids(
        scan,
        meta.mining_engines,
        continue_candidates=continue_candidates,
        incomplete_threat_tasks=incomplete_threat_tasks,
        full_pipeline_resume=full_pipeline_resume,
        resume_threat_analysis=resume_threat_analysis,
    )
    if (
        resume_interrupted
        and not retry_mining_engine_ids
        and not resume_threat_analysis
    ):
        # A legacy or infrastructure-interrupted row can have a terminal
        # top-level error even though every persisted stage looks complete.
        # Preserve the old recoverability contract instead of dispatching an
        # empty Agent run.
        retry_mining_engine_ids = [
            item.engine_id for item in meta.mining_engines if item.enabled
        ]
        if not retry_mining_engine_ids and meta.threat_analysis_enabled:
            resume_threat_analysis = True
    if any(
        engine_id in THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS
        for engine_id in retry_mining_engine_ids
    ):
        # Threat-analysis-dependent engines consume the native result object
        # from the current Agent process. Resume analysis so it can reuse or
        # reconstruct that object before the engines run.
        resume_threat_analysis = True
    rerun_threat_analysis = resume_threat_analysis and (
        _threat_analysis_run_needs_retry(scan)
        or scan.threat_analysis is None
    )
    if (
        scan.status == ScanItemStatus.CANCELLED
        and "threat_audit" in retry_mining_engine_ids
    ) or (
        resume_threat_analysis
        and (
            _threat_analysis_run_needs_retry(scan)
            or not scan.threat_audit_tasks
        )
    ):
        threat_task_ids: list[str] | None = None
    else:
        threat_task_ids = [task.task_id for task in incomplete_threat_tasks]

    return ResumePlan(
        continue_candidates=continue_candidates,
        incomplete_threat_tasks=incomplete_threat_tasks,
        continue_count=continue_count,
        resume_interrupted=resume_interrupted,
        resume_main_scan=resume_main_scan,
        full_pipeline_resume=full_pipeline_resume,
        candidate_payload=candidate_payload,
        resume_threat_analysis=resume_threat_analysis,
        retry_mining_engine_ids=retry_mining_engine_ids,
        rerun_threat_analysis=rerun_threat_analysis,
        threat_task_ids=threat_task_ids,
    )
