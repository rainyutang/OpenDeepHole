"""Scan API — create, query status, stop, resume, download reports, manage feedback.

All scanning is performed by local agent daemons. This module creates scan records,
delegates execution to agents, and provides read/status/mark endpoints.
"""

import asyncio
import csv
import io
import json
import re
import secrets
import shutil
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse

from backend.checker_sync import build_checker_packages
from backend.auth import get_current_user
from backend.config import get_config
from backend.logger import get_logger
from backend.models import (
    AgentFpReviewFinish,
    AgentFpReviewProgress,
    AgentFpReviewResult,
    AgentFpReviewSummaryFinish,
    AgentFpReviewStageOutput,
    BatchMarkRequest,
    BatchUnmarkRequest,
    Candidate,
    CreateScanRequest,
    FeedbackEntry,
    FpReviewJob,
    FpReviewMethod,
    FpReviewResult,
    FpReviewStatus,
    HistoryPattern,
    MarkRequest,
    MiningEngineCatalog,
    MiningEngineRequest,
    MiningEngineRunStatus,
    MiningEngineSelection,
    ScanItemStatus,
    ScanCandidatePage,
    ScanEventPage,
    ScanMeta,
    ScanOverview,
    ScanValidationTargetList,
    ScanStartResponse,
    ScanStatus,
    ScanSummary,
    ScanSummaryPage,
    SkillReport,
    ThreatAuditTask,
    ThreatAuditTaskPage,
    ThreatAnalysisRunStatus,
    UnmarkRequest,
    UpdateScanValidationTargetRequest,
    User,
    VulnerabilityPage,
    VulnerabilityPageItem,
    VulnerabilityValidation,
    VulnerabilityValidationPage,
)
from backend.feedback_format import build_feedback_section
from backend.scan_metrics import (
    calculate_issue_metrics,
    is_effective_fp_review_result,
    latest_fp_review_result_map,
)
from backend.store import get_scan_store
from backend.store.async_ops import run_store_call
from backend.pagination import decode_cursor, encode_cursor
from backend.registry import CHECKER_VISIBILITY_ADMIN, refresh_registry

router = APIRouter()
logger = get_logger(__name__)

# In-memory state for running scans (high-frequency polling).
# Populated when scans are created/resumed, removed by agent.py when agents finish.
_running_scans: dict[str, ScanStatus] = {}

# Map scan_id → user_id for ownership checks on in-memory scans
_scan_owners: dict[str, str] = {}

_FINAL_USER_VERDICTS = {"confirmed", "false_positive"}
_MARK_VERDICTS = _FINAL_USER_VERDICTS | {"pending_analysis"}
SCAN_MODE_FULL = "full"
SCAN_MODE_THREAT_ANALYSIS_ONLY = "threat_analysis_only"
_SCAN_MODE_ALIASES = {
    "": SCAN_MODE_FULL,
    SCAN_MODE_FULL: SCAN_MODE_FULL,
    "normal": SCAN_MODE_FULL,
    "default": SCAN_MODE_FULL,
    SCAN_MODE_THREAT_ANALYSIS_ONLY: SCAN_MODE_THREAT_ANALYSIS_ONLY,
    "threat_only": SCAN_MODE_THREAT_ANALYSIS_ONLY,
    "threat-analysis-only": SCAN_MODE_THREAT_ANALYSIS_ONLY,
}


def _normalize_scan_mode(value: str | None) -> str:
    mode = str(value or "").strip().lower()
    normalized = _SCAN_MODE_ALIASES.get(mode)
    if normalized is None:
        raise HTTPException(status_code=400, detail=f"Unknown scan mode: {value}")
    return normalized


def _is_threat_analysis_only_mode(value: str | None) -> bool:
    return _normalize_scan_mode(value) == SCAN_MODE_THREAT_ANALYSIS_ONLY


def _repository_mining_engine_catalog() -> MiningEngineCatalog:
    from deephole_client.vulnerability_mining import (
        build_mining_engine_catalog,
    )

    return MiningEngineCatalog.model_validate(
        build_mining_engine_catalog()
    )


@router.get("/api/mining-engines", response_model=MiningEngineCatalog)
async def get_mining_engine_catalog(
    current_user: User = Depends(get_current_user),
) -> MiningEngineCatalog:
    """Return the mining engines shipped by this repository."""
    return _repository_mining_engine_catalog()


def _resolve_scan_mining_engines(
    *,
    scan_overrides: list[MiningEngineRequest] | None,
    scan_mode: str,
    threat_analysis_enabled: bool | None = None,
) -> list[MiningEngineSelection]:
    catalog = _repository_mining_engine_catalog()
    available = {item.engine_id: item for item in catalog.engines}
    requested = scan_overrides
    requested_by_id = {}
    duplicate_ids: set[str] = set()
    for item in requested or []:
        engine_id = item.engine_id.strip()
        if engine_id in requested_by_id:
            duplicate_ids.add(engine_id)
        requested_by_id[engine_id] = item
    if duplicate_ids:
        raise HTTPException(
            status_code=400,
            detail=(
                "Duplicate mining engines: "
                + ", ".join(sorted(duplicate_ids))
            ),
        )
    unknown = sorted(set(requested_by_id) - set(available))
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unknown mining engines: " + ", ".join(unknown)
            ),
        )

    # Keep old callers that only supplied scan_mode working exactly as before.
    # New callers send threat_analysis_enabled explicitly and may select no
    # mining engine for a real analysis-only scan.
    if (
        scan_mode == SCAN_MODE_THREAT_ANALYSIS_ONLY
        and threat_analysis_enabled is None
    ):
        threat_engine = available.get("threat_audit")
        if threat_engine is None:
            raise HTTPException(
                status_code=400,
                detail="Threat-audit engine is unavailable",
            )
        return [MiningEngineSelection(
            engine_id=threat_engine.engine_id,
            engine_label=threat_engine.label,
            enabled=True,
        )]

    if requested is None:
        selected_ids = [item.engine_id for item in catalog.engines]
    else:
        selected_ids = [item.engine_id.strip() for item in requested]
    selections = [
        MiningEngineSelection(
            engine_id=engine_id,
            engine_label=available[engine_id].label,
            enabled=True,
        )
        for engine_id in selected_ids
    ]
    effective_threat_analysis_enabled = _resolve_threat_analysis_enabled(
        requested=threat_analysis_enabled,
        scan_mode=scan_mode,
        selections=selections,
    )
    if any(item.engine_id == "threat_audit" for item in selections) and not (
        effective_threat_analysis_enabled
    ):
        raise HTTPException(
            status_code=400,
            detail="威胁审计要求本次扫描启用威胁分析",
        )
    if not selections and not effective_threat_analysis_enabled:
        raise HTTPException(
            status_code=400,
            detail="请至少启用威胁分析或选择一个漏洞挖掘引擎",
        )
    return selections


def _resolve_threat_analysis_enabled(
    *,
    requested: bool | None,
    scan_mode: str,
    selections: list[MiningEngineSelection],
) -> bool:
    if requested is not None:
        return bool(requested)
    if scan_mode == SCAN_MODE_THREAT_ANALYSIS_ONLY:
        return True
    return any(
        item.enabled and item.engine_id == "threat_audit"
        for item in selections
    )


def _has_final_user_verdict(vuln) -> bool:
    return vuln.user_verdict in _FINAL_USER_VERDICTS


def _is_agent_disconnect_error(error_message: str | None) -> bool:
    """Check if an error message indicates an agent disconnect (not user action)."""
    from backend.api.agent import AGENT_DISCONNECT_ERROR
    return error_message == AGENT_DISCONNECT_ERROR


def _validate_validation_target(product: str, validation_environment: str) -> tuple[str, str]:
    normalized_product = str(product or "").strip()
    normalized_environment = str(validation_environment or "").strip()
    if not normalized_product and not normalized_environment:
        return "", ""
    if not normalized_product or not normalized_environment:
        raise HTTPException(
            status_code=400,
            detail="product and validation_environment must both be set or both be empty",
        )
    from backend.validation_catalog import find_validation_target

    if find_validation_target(normalized_product, normalized_environment) is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unknown validation target: "
                f"{normalized_product}/{normalized_environment}"
            ),
        )
    return normalized_product, normalized_environment


async def _check_scan_owner(scan_id: str, user: User) -> None:
    """Raise 403 if the user doesn't own the scan and isn't admin."""
    if user.role == "admin":
        return
    if scan_id in _scan_owners and _scan_owners[scan_id] == user.user_id:
        return
    meta = await run_store_call(get_scan_store(), "get_scan_meta", scan_id)
    if meta is not None and meta.user_id == user.user_id:
        return
    raise HTTPException(status_code=403, detail="Access denied")


def _latest_fp_review_result_map(scan_id: str) -> dict[int, FpReviewResult]:
    """Return the latest FP review result per vulnerability index for a scan."""
    store = get_scan_store()
    latest: dict[int, FpReviewResult] = {}
    for result in store.list_fp_review_results_by_scan(scan_id):
        if not is_effective_fp_review_result(result):
            continue
        latest[result.vuln_index] = result
    return latest


def _scan_fp_review_settings(
    scan_id: str,
    scan: ScanStatus | None = None,
) -> tuple[bool, FpReviewMethod]:
    """Return the immutable FP-review settings selected when the scan was created."""
    meta = get_scan_store().get_scan_meta(scan_id)
    if meta is not None:
        return meta.auto_fp_review, meta.fp_review_method
    if scan is not None:
        return scan.auto_fp_review, scan.fp_review_method
    return (
        get_config().fp_review.auto_on_complete,
        FpReviewMethod.ADVERSARIAL,
    )


def _ordered_fp_review_candidates(scan: ScanStatus, latest_fp_results: dict[int, FpReviewResult]) -> list[dict]:
    """Return review candidates with unresolved findings first, then already-reviewed findings."""
    unresolved: list[dict] = []
    reviewed: list[dict] = []
    for i, v in enumerate(scan.vulnerabilities):
        if (
            not v.confirmed
            or _has_final_user_verdict(v)
        ):
            continue
        item = {
            "index": i,
            "file": v.file,
            "line": v.line,
            "function": v.function,
            "vuln_type": v.vuln_type,
            "severity": v.severity,
            "description": v.description,
            "ai_analysis": v.ai_analysis,
            "vulnerability_report": v.vulnerability_report,
            "attack_entry": v.attack_entry,
            "root_cause": v.root_cause,
            "trigger_conditions": v.trigger_conditions,
            "impact": v.impact,
            "call_chain": [
                item.model_dump(mode="json")
                if hasattr(item, "model_dump")
                else item
                for item in (v.call_chain or [])
            ],
        }
        if i in latest_fp_results:
            reviewed.append(item)
        else:
            unresolved.append(item)
    return unresolved + reviewed


def _ensure_fp_review_job_for_scan(
    scan_id: str,
    scan: ScanStatus | None = None,
    *,
    allow_cancelled: bool = False,
    publish_started: bool = True,
    require_unresolved: bool = False,
) -> dict | None:
    """Create or reuse the scan-level FP review job for current confirmed findings."""
    store = get_scan_store()
    if scan is None:
        if scan_id in _running_scans:
            scan = _running_scans[scan_id]
        else:
            loaded = store.load_scan(scan_id)
            if loaded is None:
                return None
            scan = loaded[0]

    latest_fp_results = _latest_fp_review_result_map(scan_id)
    ordered = _ordered_fp_review_candidates(scan, latest_fp_results)
    _, method = _scan_fp_review_settings(scan_id, scan)
    if method == FpReviewMethod.FP_CHECK:
        unresolved = [
            item for item in ordered
            if int(item["index"]) not in latest_fp_results
        ]
        confirmed = unresolved or ordered
        total = len(ordered)
        processed = (
            len(ordered) - len(unresolved)
            if unresolved
            else 0
        )
    else:
        confirmed = ordered
        total = len(confirmed)
        processed = sum(
            1
            for item in confirmed
            if int(item["index"]) in latest_fp_results
        )
    if not confirmed:
        return None

    job = store.get_fp_review_by_scan(scan_id)
    created = False
    if (
        method == FpReviewMethod.FP_CHECK
        and require_unresolved
        and not unresolved
    ) or (
        method != FpReviewMethod.FP_CHECK
        and require_unresolved
        and processed >= len(confirmed)
    ):
        if job is None:
            return None
        return {
            "review_id": job.review_id,
            "method": method.value,
            "total": total,
            "processed": (
                len(ordered)
                if method == FpReviewMethod.FP_CHECK
                else processed
            ),
            "confirmed": [],
            "latest_results": latest_fp_results,
            "created": False,
            "cancelled": False,
            "no_unresolved": True,
        }
    if job is not None and job.status == FpReviewStatus.CANCELLED and not allow_cancelled:
        return {
            "review_id": job.review_id,
            "method": method.value,
            "total": total,
            "processed": job.processed,
            "confirmed": confirmed,
            "latest_results": latest_fp_results,
            "created": False,
            "cancelled": True,
        }
    previous_job = job
    if job is None or (job.status == FpReviewStatus.CANCELLED and allow_cancelled):
        review_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat()
        store.create_fp_review_job(
            review_id,
            scan_id,
            total,
            now,
            method.value,
        )
        job = store.get_fp_review_job(review_id)
        created = True
        if (
            job is not None
            and previous_job is not None
            and method == FpReviewMethod.FP_CHECK
            and previous_job.summary_markdown.strip()
        ):
            # A cancelled Agent task gets a fresh review_id so late callbacks
            # cannot corrupt the retry. Carry only the last successful summary
            # presentation forward; the new run will mark it stale below.
            store.update_fp_review_job(
                review_id,
                summary_markdown=previous_job.summary_markdown,
                summary_output_source=previous_job.summary_output_source,
            )
    if job is None:
        return None

    update_values: dict = {
        "status": FpReviewStatus.RUNNING.value,
        "total": total,
        "processed": processed,
        "error_message": "",
    }
    if method == FpReviewMethod.FP_CHECK:
        update_values.update({
            "summary_status": FpReviewStatus.PENDING.value,
            "summary_error_message": "",
        })
    store.update_fp_review_job(job.review_id, **update_values)
    if publish_started:
        from backend.sse import publish
        publish(scan_id, "fp_review_started", {
            "review_id": job.review_id,
            "method": method.value,
            "status": FpReviewStatus.RUNNING.value,
            "total": total,
            "processed": processed,
            "summary_status": (
                FpReviewStatus.PENDING.value
                if method == FpReviewMethod.FP_CHECK
                else None
            ),
        })
    return {
        "review_id": job.review_id,
        "method": method.value,
        "total": total,
        "processed": processed,
        "confirmed": confirmed,
        "latest_results": latest_fp_results,
        "created": created,
        "cancelled": False,
        "no_unresolved": False,
    }


def _merge_latest_fp_review_results(job: FpReviewJob, scan_id: str) -> FpReviewJob:
    """Attach scan-wide latest per-vulnerability results to the current job.

    Stage outputs pushed by the current job are merged in even when no final
    result exists yet (failed or in-progress reviews), so a page reload still
    shows the per-stage Markdown instead of dropping the entry entirely.
    """
    store = get_scan_store()
    latest_map = _latest_fp_review_result_map(scan_id)
    stage_outputs_map: dict[int, dict[str, str]] = {}
    stage_output_sources_map: dict[int, dict] = {}
    stage_updated_at: dict[int, str] = {}
    for output in store.list_fp_review_stage_outputs_by_review(job.review_id):
        stage_outputs_map.setdefault(output.vuln_index, {})[output.stage] = output.markdown
        stage_output_sources_map.setdefault(output.vuln_index, {})[output.stage] = output.output_source
        stage_updated_at[output.vuln_index] = output.updated_at

    merged: list[FpReviewResult] = []
    for vuln_index, result in latest_map.items():
        current_stages = stage_outputs_map.pop(vuln_index, None)
        current_stage_sources = stage_output_sources_map.pop(vuln_index, None)
        if current_stages:
            result = result.model_copy(
                update={
                    "stage_outputs": {**result.stage_outputs, **current_stages},
                    "stage_output_sources": {
                        **(result.stage_output_sources or {}),
                        **(current_stage_sources or {}),
                    },
                }
            )
        merged.append(result)
    for vuln_index, stages in stage_outputs_map.items():
        # No final verdict for this vulnerability in any job — expose a
        # placeholder entry (same shape the SSE stage_output handler builds).
        merged.append(FpReviewResult(
            vuln_index=vuln_index,
            verdict=(
                "uncertain"
                if job.method == FpReviewMethod.FP_CHECK
                else "tp"
            ),
            severity="low",
            reason="",
            vulnerability_report="",
            stage_outputs=stages,
            stage_output_sources=stage_output_sources_map.get(vuln_index, {}),
            created_at=stage_updated_at.get(vuln_index, job.created_at),
        ))
    merged.sort(key=lambda result: result.vuln_index)

    return FpReviewJob(
        review_id=job.review_id,
        scan_id=job.scan_id,
        method=job.method,
        status=job.status,
        created_at=job.created_at,
        total=job.total,
        processed=job.processed,
        current_vuln_index=job.current_vuln_index,
        current_vuln_indices=job.current_vuln_indices,
        results=merged,
        summary_markdown=job.summary_markdown,
        summary_output_source=job.summary_output_source,
        summary_status=job.summary_status,
        summary_error_message=job.summary_error_message,
        error_message=job.error_message,
    )


def _scan_feedback_ids(scan_id: str) -> list[str]:
    scan = _running_scans.get(scan_id)
    if scan is not None:
        return scan.feedback_ids
    meta = get_scan_store().get_scan_meta(scan_id)
    if meta is None:
        return []
    return meta.feedback_ids


def _selected_feedback_entries(scan_id: str, feedback_ids: list[str] | None = None) -> list[FeedbackEntry]:
    ids = feedback_ids if feedback_ids is not None else _scan_feedback_ids(scan_id)
    if not ids:
        return []
    return get_scan_store().get_feedback_by_ids(ids)


async def _resolve_scan_agent_id(meta: ScanMeta) -> str | None:
    from backend.api.agent import (
        _agent_ws,
        _registered_agents,
        resolve_agent_connection_async,
    )

    if meta.agent_key:
        resolved = await resolve_agent_connection_async(meta.agent_key)
        if resolved is not None:
            return resolved[0]
    agent_id = meta.agent_id
    if agent_id and agent_id in _agent_ws:
        return agent_id
    if meta.agent_name:
        for aid, ainfo in _registered_agents.items():
            if ainfo.name == meta.agent_name and aid in _agent_ws:
                return aid
    store = get_scan_store()
    if getattr(store, "distributed", False):
        if agent_id:
            session = await run_store_call(
                store,
                "get_live_agent_session",
                agent_id=agent_id,
            )
            if session is not None:
                return str(session["agent_id"])
        if meta.agent_name:
            session = await run_store_call(
                store,
                "get_live_agent_session_by_name",
                meta.agent_name,
                user_id=meta.user_id or None,
            )
            if session is not None:
                return str(session["agent_id"])
    return None


def _server_url_from_request(request: Request) -> str:
    return str(request.base_url).rstrip("/")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _publish_validation(scan_id: str, validation: VulnerabilityValidation) -> None:
    from backend.sse import publish

    publish(scan_id, "vulnerability_validation", {
        "validation": validation.model_dump(),
    })


def _update_running_validation(scan_id: str, validation: VulnerabilityValidation) -> None:
    scan = _running_scans.get(scan_id)
    if scan is None:
        return
    existing = next(
        (idx for idx, item in enumerate(scan.validations) if item.vuln_index == validation.vuln_index),
        None,
    )
    if existing is None:
        scan.validations.append(validation)
        scan.validations.sort(key=lambda item: item.vuln_index)
    else:
        scan.validations[existing] = validation


def _validated_checker_names(checkers: list[str], user: User) -> list[str]:
    """Refresh checker registry and validate requested scan checkers."""
    registry = refresh_registry()
    names = list(dict.fromkeys(checkers))
    if not names:
        raise HTTPException(status_code=400, detail="No checkers selected")

    unknown = [name for name in names if name not in registry]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown checkers: {', '.join(unknown)}")

    admin_only = [
        name for name in names
        if registry[name].visibility == CHECKER_VISIBILITY_ADMIN and user.role != "admin"
    ]
    if admin_only:
        raise HTTPException(status_code=403, detail=f"Checker is admin-only: {', '.join(admin_only)}")

    return names


def _checker_packages_for(names: list[str]) -> list[dict[str, str]]:
    registry = refresh_registry()
    missing = [name for name in names if name not in registry]
    if missing:
        raise HTTPException(status_code=400, detail=f"Checker unavailable: {', '.join(missing)}")
    return build_checker_packages(registry, names)


_RETRYABLE_AI_VERDICTS = {"timeout", "no_result", "failed"}


def _candidate_key(candidate: Candidate) -> tuple[str, int, str, str]:
    return (candidate.file, candidate.line, candidate.function, candidate.vuln_type)


def _is_retryable_vuln(vuln) -> bool:
    return (
        _is_static_candidate_vulnerability(vuln)
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


def _incomplete_threat_audit_tasks(scan: ScanStatus) -> list[ThreatAuditTask]:
    return [task for task in scan.threat_audit_tasks if task.status != "completed"]


def _continuable_candidates(
    scan: ScanStatus,
    processed_keys: set[tuple[str, int, str, str]],
) -> list[Candidate]:
    """Return the deduplicated union of unprocessed and retryable candidates."""
    candidates: list[Candidate] = []
    seen: set[tuple[str, int, str, str]] = set()

    for stored in scan.candidates:
        candidate = Candidate(**stored.model_dump(exclude={"idx"}))
        if not _is_static_scan_candidate(candidate):
            continue
        key = _candidate_key(candidate)
        if key in processed_keys or key in seen:
            continue
        candidates.append(candidate)
        seen.add(key)

    stored_by_key = {
        _candidate_key(Candidate(**stored.model_dump(exclude={"idx"}))): stored
        for stored in scan.candidates
        if _is_static_scan_candidate(stored)
    }
    for retry in _retry_incomplete_candidates(scan):
        key = _candidate_key(retry)
        if key in seen:
            continue
        stored = stored_by_key.get(key)
        candidate = Candidate(**stored.model_dump(exclude={"idx"})) if stored is not None else retry
        candidates.append(candidate)
        seen.add(key)
    return candidates


def _continuable_task_count(
    scan: ScanStatus,
    processed_keys: set[tuple[str, int, str, str]],
) -> int:
    return len(_continuable_candidates(scan, processed_keys)) + len(
        _incomplete_threat_audit_tasks(scan)
    )


def _apply_continue_capability(
    scan: ScanStatus | ScanSummary,
    *,
    continuable_count: int,
) -> None:
    running = scan.status in {
        ScanItemStatus.PENDING,
        ScanItemStatus.ANALYZING,
        ScanItemStatus.AUDITING,
    }
    scan.continuable_task_count = continuable_count
    scan.can_continue = not running and (
        scan.status in {ScanItemStatus.CANCELLED, ScanItemStatus.ERROR}
        or continuable_count > 0
    )


def _apply_task_progress(scan: ScanStatus | ScanSummary, pool=None) -> None:
    pool = pool if pool is not None else getattr(scan, "opencode_pool", None)
    scan.total_task_count = pool.total_tasks if pool is not None else 0
    scan.completed_task_count = pool.completed_task_count if pool is not None else 0


async def _push_feedback_selection_update(scan_id: str, feedback_ids: list[str]) -> None:
    """Best-effort update of the selected feedback entries on the owning agent."""
    store = get_scan_store()
    meta = await run_store_call(store, "get_scan_meta", scan_id)
    if meta is None:
        return
    agent_id = await _resolve_scan_agent_id(meta)
    if agent_id is None:
        return
    from backend.api.agent import send_agent_command

    selected = await run_store_call(
        store,
        _selected_feedback_entries,
        scan_id,
        feedback_ids,
    )
    entries = [entry.model_dump() for entry in selected]
    await send_agent_command(agent_id, {
        "type": "feedback_selection_update",
        "scan_id": scan_id,
        "feedback_entries": entries,
    })


# ---------------------------------------------------------------------------
# Create scan (new flow: agent_id + project_path instead of upload)
# ---------------------------------------------------------------------------


async def create_agent_scan(
    body: CreateScanRequest,
    request: Request,
    current_user: User,
    *,
    checker_names: list[str] | None = None,
    public_access_token: str = "",
    enforce_agent_owner: bool = True,
) -> ScanStartResponse:
    """Create a new scan and dispatch it to the specified agent daemon."""
    from backend.api.agent import (
        _registered_agents,
        agent_config_has_explicit_model,
        ensure_agent_accepting_tasks_async,
        get_managed_agent_config_async,
        resolve_agent_connection_async,
        resolve_agent_id_connection_async,
    )

    selected_agent_key = body.agent_key.strip()
    resolved = (
        await resolve_agent_connection_async(selected_agent_key)
        if selected_agent_key
        else None
    )
    if resolved is not None:
        agent_id, agent = resolved
    else:
        agent_id = body.agent_id.strip()
        by_id = await resolve_agent_id_connection_async(agent_id) if agent_id else None
        agent = by_id[1] if by_id is not None else _registered_agents.get(agent_id)
        if agent is not None:
            selected_agent_key = agent.agent_key
    if agent is None:
        raise HTTPException(status_code=404, detail="所选 Agent 不在线")

    # Verify the agent belongs to this user (or user is admin)
    if enforce_agent_owner and current_user.role != "admin" and agent.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Agent does not belong to you")
    await ensure_agent_accepting_tasks_async(selected_agent_key)
    managed_config = (
        await get_managed_agent_config_async(selected_agent_key)
        if selected_agent_key
        else None
    )
    if managed_config is not None and not agent_config_has_explicit_model(managed_config):
        raise HTTPException(
            status_code=400,
            detail="所选 Agent 尚未配置启用的显式模型，请先在 Agent 配置页面手动添加模型",
        )
    code_graph_mcp = None
    if body.code_graph_mcp is not None and body.code_graph_mcp.enabled:
        from backend.api.agent import _validate_mcp_config

        _validate_mcp_config(
            body.code_graph_mcp,
            label="扫描代码图谱",
            require_enabled=True,
        )
        code_graph_mcp = body.code_graph_mcp.model_copy(deep=True)

    requested_scan_mode = _normalize_scan_mode(body.scan_mode)
    mining_engine_selections = _resolve_scan_mining_engines(
        scan_overrides=body.mining_engines,
        scan_mode=requested_scan_mode,
        threat_analysis_enabled=body.threat_analysis_enabled,
    )
    threat_analysis_enabled = _resolve_threat_analysis_enabled(
        requested=body.threat_analysis_enabled,
        scan_mode=requested_scan_mode,
        selections=mining_engine_selections,
    )
    scan_mode = (
        SCAN_MODE_THREAT_ANALYSIS_ONLY
        if (
            body.threat_analysis_enabled is not None
            and threat_analysis_enabled
            and not mining_engine_selections
        )
        else (
            SCAN_MODE_FULL
            if body.threat_analysis_enabled is not None
            else requested_scan_mode
        )
    )
    auto_fp_review = (
        body.auto_fp_review
        if body.auto_fp_review is not None
        else get_config().fp_review.auto_on_complete
    )
    fp_review_method = body.fp_review_method
    selected_checkers = checker_names if checker_names is not None else body.checkers
    static_engine_enabled = any(
        item.enabled and item.engine_id == "static_candidate"
        for item in mining_engine_selections
    )
    if not static_engine_enabled:
        validated_checker_names = []
        checker_packages = []
    else:
        validated_checker_names = _validated_checker_names(selected_checkers, current_user)
        checker_packages = _checker_packages_for(validated_checker_names)
    scan_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    project_path = body.project_path.strip()
    if not project_path:
        raise HTTPException(status_code=400, detail="project_path is required")
    code_scan_path = body.code_scan_path.strip() or project_path
    scan_name = body.scan_name or project_path.split("/")[-1] or scan_id
    product, validation_environment = _validate_validation_target(
        body.product,
        body.validation_environment,
    )
    if selected_agent_key and product and validation_environment:
        import json as _json
        record = await run_store_call(
            get_scan_store(),
            "get_agent_record",
            selected_agent_key,
        )
        try:
            registrations = (_json.loads(str(record.get("validator_catalog_json") or "{}")) if record else {}).get("registrations", [])
        except Exception:
            registrations = []
        if not any(
            str(item.get("product") or "") == product
            and str(item.get("environment") or "") == validation_environment
            for item in registrations
            if isinstance(item, dict)
        ):
            raise HTTPException(status_code=400, detail=f"所选 Agent 不支持验证环境：{product}/{validation_environment}")

    scan = ScanStatus(
        scan_id=scan_id,
        project_id=scan_name,
        scan_mode=scan_mode,
        threat_analysis_enabled=threat_analysis_enabled,
        threat_analysis_run=(
            ThreatAnalysisRunStatus()
            if threat_analysis_enabled
            else None
        ),
        auto_fp_review=auto_fp_review,
        fp_review_method=fp_review_method,
        product=product,
        validation_environment=validation_environment,
        scan_items=validated_checker_names,
        mining_engines=mining_engine_selections,
        mining_engine_runs=[
            MiningEngineRunStatus(
                engine_id=item.engine_id,
                engine_label=item.engine_label,
            )
            for item in mining_engine_selections
            if item.enabled
        ],
        created_at=now,
        status=ScanItemStatus.PENDING,
        progress=0.0,
        total_candidates=0,
        processed_candidates=0,
        vulnerabilities=[],
        agent_name=agent.name,
        agent_online=True,
    )
    meta = ScanMeta(
        scan_items=validated_checker_names,
        created_at=now,
        scan_mode=scan_mode,
        threat_analysis_enabled=threat_analysis_enabled,
        mining_engines=mining_engine_selections,
        auto_fp_review=auto_fp_review,
        fp_review_method=fp_review_method,
        feedback_ids=body.feedback_ids,
        agent_id=agent_id,
        agent_key=selected_agent_key,
        agent_name=agent.name,
        project_path=project_path,
        code_scan_path=code_scan_path,
        scan_name=scan_name,
        product=product,
        validation_environment=validation_environment,
        user_id=current_user.user_id,
        public_access_token=public_access_token,
        code_graph_mcp=code_graph_mcp,
    )

    store = get_scan_store()
    await run_store_call(store, "save_scan", scan, meta)
    _running_scans[scan_id] = scan
    _scan_owners[scan_id] = current_user.user_id

    # Dispatch to agent via WebSocket
    from backend.api.agent import (
        create_agent_task_runtime_update_payload_async,
        send_agent_command,
    )
    selected_feedback = await run_store_call(
        store,
        _selected_feedback_entries,
        scan_id,
        body.feedback_ids,
    )
    feedback_entries = [entry.model_dump() for entry in selected_feedback]
    ok = await send_agent_command(agent_id, {
        "type": "task",
        "scan_id": scan_id,
        "project_path": project_path,
        "code_scan_path": code_scan_path,
        "checkers": validated_checker_names,
        "scan_mode": scan_mode,
        "threat_analysis_enabled": threat_analysis_enabled,
        "scan_name": scan_name,
        "product": product,
        "validation_environment": validation_environment,
        "feedback_entries": feedback_entries,
        "checker_packages": checker_packages,
        "mining_engines": [
            item.model_dump(mode="json")
            for item in mining_engine_selections
        ],
        "code_graph_mcp": (
            code_graph_mcp.model_dump(mode="json")
            if code_graph_mcp is not None
            else None
        ),
        "agent_runtime_update": await create_agent_task_runtime_update_payload_async(
            _server_url_from_request(request),
            selected_agent_key,
        ),
    })
    if not ok:
        await run_store_call(
            store,
            "update_scan_progress",
            scan_id,
            status=ScanItemStatus.ERROR,
            error_message="Agent not connected",
        )
        scan.status = ScanItemStatus.ERROR
        _running_scans.pop(scan_id, None)
        logger.error("Failed to dispatch scan %s: agent %s not connected", scan_id, agent_id)
        raise HTTPException(status_code=502, detail="Agent not connected")

    logger.info(
        "Created scan %s for project '%s', dispatched to agent %s (%s)",
        scan_id, scan_name, agent_id, agent.ip,
    )
    return ScanStartResponse(scan_id=scan_id)


@router.post("/api/scan", response_model=ScanStartResponse)
async def create_scan(
    body: CreateScanRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> ScanStartResponse:
    """Create a new scan and dispatch it to the specified agent daemon."""
    return await create_agent_scan(body, request, current_user)


# ---------------------------------------------------------------------------
# List / Status / Stop / Resume / Delete
# ---------------------------------------------------------------------------


async def _enrich_scan_summaries(
    summaries: list[ScanSummary],
) -> list[ScanSummary]:
    """Add live state and effective issue metrics without blocking the loop."""
    from backend.api.agent import (
        reconcile_offline_agent_scan_state,
        reconcile_offline_agent_summary_state,
    )

    store = get_scan_store()
    distributed = bool(getattr(store, "distributed", False))
    local_scan_ids = set() if distributed else set(_running_scans)
    stored_ids = [s.scan_id for s in summaries if s.scan_id not in local_scan_ids]
    vuln_stats, fp_verdicts, incomplete_threat_counts = await asyncio.gather(
        run_store_call(store, "get_vuln_stats_by_scans", stored_ids),
        run_store_call(
            store,
            "list_fp_review_verdicts_by_scans",
            [s.scan_id for s in summaries],
        ),
        run_store_call(store, "get_incomplete_threat_audit_counts", stored_ids),
    )
    live_identities: set[tuple[str, str]] = set()
    if distributed:
        sessions = await run_store_call(store, "list_live_agent_sessions")
        live_identities = {
            (str(item["name"]), str(item["user_id"] or ""))
            for item in sessions
        }
    running_ids = [s.scan_id for s in summaries if s.scan_id in local_scan_ids]
    processed_by_scan = dict(zip(
        running_ids,
        await asyncio.gather(*(
            run_store_call(store, "get_processed_keys", scan_id)
            for scan_id in running_ids
        )),
    ))

    for s in summaries:
        if s.scan_id in local_scan_ids:
            processed_keys = processed_by_scan.get(s.scan_id, set())
            live = _running_scans[s.scan_id]
            live.agent_name = s.agent_name or live.agent_name
            vulnerabilities = live.vulnerabilities
            live = reconcile_offline_agent_scan_state(s.scan_id, live)
            s.status = live.status
            s.progress = live.progress
            s.total_candidates = live.total_candidates
            s.processed_candidates = live.processed_candidates
            s.agent_online = live.agent_online
            _apply_task_progress(s, live.opencode_pool)
            continuable_count = _continuable_task_count(live, processed_keys)
        else:
            # status/progress 等字段与 load_scan 同源于 scans 表同一行，直接用 summary 值
            if distributed:
                s.agent_online = (
                    (s.agent_name, s.user_id or "") in live_identities
                    if s.agent_name
                    else False
                )
            else:
                s = reconcile_offline_agent_summary_state(s)
            vulnerabilities = vuln_stats.get(s.scan_id, [])
            continuable_count = (
                max(s.total_candidates - s.processed_candidates, 0)
                + sum(1 for v in vulnerabilities if _is_retryable_vuln(v))
                + incomplete_threat_counts.get(s.scan_id, 0)
            )
        s.retryable_candidates_count = sum(
            1 for v in vulnerabilities if _is_retryable_vuln(v)
        )
        _apply_continue_capability(s, continuable_count=continuable_count)

        metrics = calculate_issue_metrics(
            vulnerabilities,
            latest_fp_review_result_map(fp_verdicts.get(s.scan_id, [])),
        )
        s.vulnerability_count = metrics.effective_issue_count
        s.human_confirmed_count = metrics.human_confirmed_count
    return summaries


@router.get("/api/scans", response_model=list[ScanSummary])
async def list_scans(current_user: User = Depends(get_current_user)) -> list[ScanSummary]:
    """Legacy unpaginated scan list retained for one Agent/UI release."""
    store = get_scan_store()
    operation = "list_scans" if current_user.role == "admin" else "list_scans_by_user"
    args = () if current_user.role == "admin" else (current_user.user_id,)
    summaries = await run_store_call(store, operation, *args)
    return await _enrich_scan_summaries(summaries)


@router.get("/api/v2/scans", response_model=ScanSummaryPage)
async def list_scans_v2(
    limit: int = Query(50, ge=1, le=100),
    cursor: str | None = Query(None),
    current_user: User = Depends(get_current_user),
) -> ScanSummaryPage:
    """Return a bounded, stable page of scans visible to the current user."""
    before_created_at = None
    before_scan_id = None
    if cursor:
        try:
            before_created_at, before_scan_id = decode_cursor(cursor, size=2)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid scan cursor") from exc

    store = get_scan_store()
    summaries = await run_store_call(
        store,
        "list_scans_page",
        limit=limit + 1,
        user_id=None if current_user.role == "admin" else current_user.user_id,
        before_created_at=before_created_at,
        before_scan_id=before_scan_id,
    )
    has_more = len(summaries) > limit
    items = await _enrich_scan_summaries(summaries[:limit])
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = encode_cursor(last.created_at, last.scan_id)
    return ScanSummaryPage(
        items=items,
        next_cursor=next_cursor,
        has_more=has_more,
    )


@router.get("/api/scan/validation-targets", response_model=ScanValidationTargetList)
async def list_scan_validation_targets(
    _current_user: User = Depends(get_current_user),
) -> ScanValidationTargetList:
    """Return valid product/environment pairs from server validator manifests."""
    from backend.validation_catalog import get_validation_catalog

    return ScanValidationTargetList(targets=get_validation_catalog())


@router.get("/api/scan/{scan_id}", response_model=ScanStatus)
async def get_scan_status(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> ScanStatus:
    """Get the current status and results of a scan."""
    from backend.api.agent import reconcile_offline_agent_scan_state

    await _check_scan_owner_v2(scan_id, current_user)
    store = get_scan_store()
    distributed = bool(getattr(store, "distributed", False))
    meta = None
    if not distributed and scan_id in _running_scans:
        scan = _running_scans[scan_id]
    else:
        result = await run_store_call(store, "load_scan", scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        scan, meta = result
        scan.agent_name = meta.agent_name
    if distributed:
        session = (
            await run_store_call(
                store,
                "get_live_agent_session_by_name",
                meta.agent_name,
                user_id=meta.user_id or None,
            )
            if meta is not None and meta.agent_name
            else None
        )
        scan.agent_online = session is not None
    else:
        scan = reconcile_offline_agent_scan_state(scan_id, scan)
    scan.retryable_candidates_count = _retry_incomplete_count(scan)
    _apply_task_progress(scan)
    processed_keys = await run_store_call(store, "get_processed_keys", scan_id)
    _apply_continue_capability(
        scan,
        continuable_count=_continuable_task_count(scan, processed_keys),
    )
    return scan


async def _check_scan_owner_v2(scan_id: str, current_user: User) -> None:
    """Compatibility name used by the split v2 detail routes."""
    await _check_scan_owner(scan_id, current_user)


@router.get("/api/v2/scans/{scan_id}/overview", response_model=ScanOverview)
async def get_scan_overview_v2(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> ScanOverview:
    """Return frequently refreshed state without large result collections."""
    from backend.api.agent import reconcile_offline_agent_scan_state

    store = get_scan_store()
    distributed = bool(getattr(store, "distributed", False))
    loaded = await run_store_call(store, "load_scan_overview", scan_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    stored_scan, meta, counts = loaded
    if current_user.role != "admin" and meta.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Access denied")

    if not distributed and scan_id in _running_scans:
        scan = _running_scans[scan_id]
        counts = {
            **counts,
            "candidates": max(counts["candidates"], len(scan.candidates)),
            "vulnerabilities": max(counts["vulnerabilities"], len(scan.vulnerabilities)),
            "events": max(counts["events"], len(scan.events)),
            "threat_audit_tasks": max(
                counts["threat_audit_tasks"],
                len(scan.threat_audit_tasks),
            ),
            "validations": max(counts["validations"], len(scan.validations)),
            "skill_reports": max(counts["skill_reports"], len(scan.skill_reports)),
        }
        processed_keys = await run_store_call(store, "get_processed_keys", scan_id)
        scan.retryable_candidates_count = _retry_incomplete_count(scan)
        continuable_count = _continuable_task_count(scan, processed_keys)
    else:
        scan = stored_scan
        vuln_stats, incomplete_counts = await asyncio.gather(
            run_store_call(store, "get_vuln_stats_by_scans", [scan_id]),
            run_store_call(store, "get_incomplete_threat_audit_counts", [scan_id]),
        )
        vulnerabilities = vuln_stats.get(scan_id, [])
        scan.retryable_candidates_count = sum(
            1 for vuln in vulnerabilities if _is_retryable_vuln(vuln)
        )
        continuable_count = (
            max(scan.total_candidates - scan.processed_candidates, 0)
            + scan.retryable_candidates_count
            + incomplete_counts.get(scan_id, 0)
        )

    scan.agent_name = meta.agent_name
    if distributed:
        session = (
            await run_store_call(
                store,
                "get_live_agent_session_by_name",
                meta.agent_name,
                user_id=meta.user_id or None,
            )
            if meta.agent_name
            else None
        )
        scan.agent_online = session is not None
    else:
        scan = reconcile_offline_agent_scan_state(scan_id, scan)
    _apply_task_progress(scan)
    _apply_continue_capability(scan, continuable_count=continuable_count)
    payload = scan.model_dump(mode="python")
    payload.update({
        "candidates": [],
        "vulnerabilities": [],
        "skill_reports": [],
        "threat_analysis": None,
        "threat_audit_tasks": [],
        "validations": [],
        "events": [],
        "detail_counts": counts,
    })
    return ScanOverview.model_validate(payload)


@router.get(
    "/api/v2/scans/{scan_id}/candidates",
    response_model=ScanCandidatePage,
)
async def get_scan_candidates_v2(
    scan_id: str,
    limit: int = Query(200, ge=1, le=500),
    after: int = Query(-1, ge=-1),
    current_user: User = Depends(get_current_user),
) -> ScanCandidatePage:
    await _check_scan_owner_v2(scan_id, current_user)
    rows = await run_store_call(
        get_scan_store(),
        "list_scan_candidates_page",
        scan_id,
        after_index=after,
        limit=limit + 1,
    )
    has_more = len(rows) > limit
    items = rows[:limit]
    return ScanCandidatePage(
        items=items,
        has_more=has_more,
        next_cursor=items[-1].idx if has_more and items else None,
    )


@router.get(
    "/api/v2/scans/{scan_id}/vulnerabilities",
    response_model=VulnerabilityPage,
)
async def get_scan_vulnerabilities_v2(
    scan_id: str,
    limit: int = Query(100, ge=1, le=500),
    after: int = Query(-1, ge=-1),
    current_user: User = Depends(get_current_user),
) -> VulnerabilityPage:
    await _check_scan_owner_v2(scan_id, current_user)
    rows = await run_store_call(
        get_scan_store(),
        "get_vulnerabilities_page",
        scan_id,
        after_index=after,
        limit=limit + 1,
    )
    has_more = len(rows) > limit
    rows = rows[:limit]
    items = [
        VulnerabilityPageItem(index=index, vulnerability=vulnerability)
        for index, vulnerability in rows
    ]
    return VulnerabilityPage(
        items=items,
        has_more=has_more,
        next_cursor=items[-1].index if has_more and items else None,
    )


@router.get("/api/v2/scans/{scan_id}/events", response_model=ScanEventPage)
async def get_scan_events_v2(
    scan_id: str,
    limit: int = Query(200, ge=1, le=500),
    before: int | None = Query(None, ge=1),
    current_user: User = Depends(get_current_user),
) -> ScanEventPage:
    await _check_scan_owner_v2(scan_id, current_user)
    rows = await run_store_call(
        get_scan_store(),
        "get_events_page",
        scan_id,
        before_id=before,
        limit=limit + 1,
    )
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = min((event_id for event_id, _ in rows), default=None)
    return ScanEventPage(
        items=[event for _, event in reversed(rows)],
        has_more=has_more,
        next_cursor=next_cursor if has_more else None,
    )


@router.get(
    "/api/v2/scans/{scan_id}/threat-audit-tasks",
    response_model=ThreatAuditTaskPage,
)
async def get_scan_threat_audit_tasks_v2(
    scan_id: str,
    limit: int = Query(100, ge=1, le=500),
    cursor: str | None = Query(None),
    current_user: User = Depends(get_current_user),
) -> ThreatAuditTaskPage:
    await _check_scan_owner_v2(scan_id, current_user)
    after: tuple[str, str] | None = None
    if cursor:
        try:
            after = decode_cursor(cursor, size=2)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid task cursor") from exc
    tasks = await run_store_call(
        get_scan_store(),
        "list_threat_audit_tasks",
        scan_id,
        after_created_at=after[0] if after is not None else None,
        after_task_id=after[1] if after is not None else None,
        limit=limit + 1,
    )
    has_more = len(tasks) > limit
    items = tasks[:limit]
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = encode_cursor(last.created_at or "", last.task_id)
    return ThreatAuditTaskPage(
        items=items,
        has_more=has_more,
        next_cursor=next_cursor,
    )


@router.get(
    "/api/v2/scans/{scan_id}/validations",
    response_model=VulnerabilityValidationPage,
)
async def get_scan_validations_v2(
    scan_id: str,
    limit: int = Query(200, ge=1, le=500),
    after: int = Query(-1, ge=-1),
    current_user: User = Depends(get_current_user),
) -> VulnerabilityValidationPage:
    await _check_scan_owner_v2(scan_id, current_user)
    rows = await run_store_call(
        get_scan_store(),
        "list_vulnerability_validations",
        scan_id,
        after_index=after,
        limit=limit + 1,
    )
    has_more = len(rows) > limit
    items = rows[:limit]
    return VulnerabilityValidationPage(
        items=items,
        has_more=has_more,
        next_cursor=items[-1].vuln_index if has_more and items else None,
    )


@router.put("/api/scan/{scan_id}/validation-target")
async def update_scan_validation_target(
    scan_id: str,
    body: UpdateScanValidationTargetRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Update the complete validation target associated with an existing scan."""
    await _check_scan_owner(scan_id, current_user)
    product, validation_environment = _validate_validation_target(
        body.product,
        body.validation_environment,
    )
    store = get_scan_store()
    if await run_store_call(store, "get_scan_meta", scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan_id in _running_scans:
        _running_scans[scan_id].product = product
        _running_scans[scan_id].validation_environment = validation_environment
    await run_store_call(
        store,
        "update_scan_validation_target",
        scan_id,
        product,
        validation_environment,
    )
    return {"ok": True}


@router.post("/api/scan/{scan_id}/stop")
async def stop_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Immediately cancel the scan, then best-effort notify the agent."""
    await _check_scan_owner(scan_id, current_user)
    store = get_scan_store()

    # Resolve agent_id BEFORE popping from memory
    meta = await run_store_call(store, "get_scan_meta", scan_id)
    agent_id = await _resolve_scan_agent_id(meta) if meta else ""

    # Immediately mark as CANCELLED in DB and in-memory
    await run_store_call(
        store,
        "update_scan_progress",
        scan_id,
        status=ScanItemStatus.CANCELLED,
        error_message="用户手动停止",
        clear_current_candidate=True,
    )
    scan = _running_scans.pop(scan_id, None)
    if scan is not None:
        scan.status = ScanItemStatus.CANCELLED
        scan.error_message = "用户手动停止"
    _scan_owners.pop(scan_id, None)

    # Best-effort: send stop command to agent (fire-and-forget)
    if agent_id:
        from backend.api.agent import send_agent_command
        try:
            await send_agent_command(agent_id, {"type": "stop", "scan_id": scan_id})
        except Exception:
            pass

    logger.info("Scan %s cancelled immediately by user", scan_id)
    return {"ok": True}


async def _continue_scan(
    scan_id: str,
    request: Request,
    current_user: User,
) -> ScanStartResponse:
    """Continue all unfinished and retryable work for one scan."""
    await _check_scan_owner_v2(scan_id, current_user)
    from backend.api.agent import (
        _registered_agents,
        agent_config_has_explicit_model,
        ensure_agent_accepting_tasks_async,
        get_managed_agent_config_async,
        resolve_agent_connection_async,
    )

    if scan_id in _running_scans:
        raise HTTPException(status_code=400, detail="Scan is already running")

    store = get_scan_store()
    result = await run_store_call(store, "load_scan", scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan, meta = result
    if scan.status in {ScanItemStatus.PENDING, ScanItemStatus.ANALYZING, ScanItemStatus.AUDITING}:
        raise HTTPException(status_code=400, detail="Scan is already running")

    processed_keys = await run_store_call(store, "get_processed_keys", scan_id)
    continue_candidates = _continuable_candidates(scan, processed_keys)
    incomplete_threat_tasks = _incomplete_threat_audit_tasks(scan)
    continue_count = len(continue_candidates) + len(incomplete_threat_tasks)
    resume_interrupted = scan.status in {ScanItemStatus.CANCELLED, ScanItemStatus.ERROR}
    if not resume_interrupted and continue_count == 0:
        raise HTTPException(status_code=400, detail="当前扫描没有可续扫的任务")

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
        bool(incomplete_threat_tasks)
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
    if resume_threat_analysis and not scan.threat_audit_tasks:
        threat_task_ids: list[str] | None = None
    else:
        threat_task_ids = [task.task_id for task in incomplete_threat_tasks]

    # Only allow resume when the original agent (by name) is online
    stable = (
        await resolve_agent_connection_async(meta.agent_key)
        if meta.agent_key
        else None
    )
    if stable is not None:
        agent_id, agent = stable
    else:
        agent_id = meta.agent_id
        agent = _registered_agents.get(agent_id) if agent_id else None

    # If original agent_id is stale (reconnected), find it by name
    if agent is None and meta.agent_name:
        from backend.api.agent import _agent_ws
        for aid, ainfo in _registered_agents.items():
            if ainfo.name == meta.agent_name and aid in _agent_ws:
                if current_user.role == "admin" or ainfo.user_id == current_user.user_id:
                    agent = ainfo
                    agent_id = aid
                    break

    if agent is None:
        raise HTTPException(
            status_code=400,
            detail=f"扫描关联的 Agent「{meta.agent_name or '未知'}」不在线，请先启动该 Agent",
        )

    await ensure_agent_accepting_tasks_async(meta.agent_key or agent.agent_key)
    managed_config = (
        await get_managed_agent_config_async(meta.agent_key)
        if meta.agent_key
        else None
    )
    if managed_config is not None and not agent_config_has_explicit_model(managed_config):
        raise HTTPException(
            status_code=400,
            detail="扫描关联的 Agent 尚未配置启用的显式模型，请先完成 Agent 模型配置",
        )

    # Update scan meta with new agent_id if it changed
    if agent_id != meta.agent_id:
        meta.agent_id = agent_id
        meta.agent_name = agent.name
        await run_store_call(
            store,
            "update_scan_agent",
            scan_id,
            agent_id,
            agent.name,
            agent.agent_key,
        )

    total_candidates = scan.total_candidates or len(scan.candidates) or len(scan.vulnerabilities)
    if candidate_payload is None:
        processed_offset = scan.processed_candidates
        progress = scan.progress
    else:
        processed_offset = max(total_candidates - len(candidate_payload), 0)
        progress = processed_offset / total_candidates if total_candidates > 0 else 0.0

    retry_keys = [_candidate_key(candidate) for candidate in continue_candidates]
    removed_processed_keys = [key for key in retry_keys if key in processed_keys]

    scan.status = ScanItemStatus.PENDING
    scan.error_message = None
    scan.current_candidate = None
    scan.agent_name = agent.name
    scan.agent_online = True
    scan.processed_candidates = processed_offset
    scan.progress = progress
    await run_store_call(
        store,
        "update_scan_progress",
        scan_id,
        status=ScanItemStatus.PENDING,
        processed_candidates=processed_offset,
        progress=progress,
        error_message="",
        clear_current_candidate=True,
    )
    await run_store_call(store, "remove_processed_keys", scan_id, retry_keys)

    _running_scans[scan_id] = scan
    _scan_owners[scan_id] = current_user.user_id

    from backend.api.agent import (
        create_agent_task_runtime_update_payload_async,
        send_agent_command,
    )
    selected_feedback = await run_store_call(
        store,
        _selected_feedback_entries,
        scan_id,
        meta.feedback_ids,
    )
    feedback_entries = [entry.model_dump() for entry in selected_feedback]
    runtime_update = await create_agent_task_runtime_update_payload_async(
        _server_url_from_request(request),
        meta.agent_key,
    )
    resume_payload = {
        "type": "resume",
        "scan_id": scan_id,
        "project_path": meta.project_path,
        "code_scan_path": meta.code_scan_path or meta.project_path,
        "checkers": meta.scan_items,
        "scan_mode": meta.scan_mode,
        "threat_analysis_enabled": meta.threat_analysis_enabled,
        "scan_name": meta.scan_name,
        "product": meta.product,
        "validation_environment": meta.validation_environment,
        "feedback_entries": feedback_entries,
        "checker_packages": (
            []
            if (
                _is_threat_analysis_only_mode(meta.scan_mode)
                or (
                    bool(meta.mining_engines)
                    and not any(
                        item.enabled
                        and item.engine_id == "static_candidate"
                        for item in meta.mining_engines
                    )
                )
            )
            else _checker_packages_for(meta.scan_items)
        ),
        # Empty is meaningful: it is the explicit analysis-only selection.
        # Legacy rows with no snapshot are materialized during migration.
        "mining_engines": [
            item.model_dump(mode="json")
            for item in meta.mining_engines
        ],
        "retry_candidates": (
            [candidate.model_dump() for candidate in candidate_payload]
            if candidate_payload is not None
            else None
        ),
        "retry_total_candidates": total_candidates,
        "retry_processed_offset": processed_offset,
        "resume_threat_analysis": resume_threat_analysis,
        "retry_threat_audit_task_ids": threat_task_ids,
        "code_graph_mcp": (
            meta.code_graph_mcp.model_dump(mode="json")
            if meta.code_graph_mcp is not None
            else None
        ),
        "agent_runtime_update": runtime_update,
    }
    if agent.protocol_version >= 2:
        manifest_token = secrets.token_urlsafe(32)
        payload_json = await run_store_call(
            store,
            json.dumps,
            resume_payload,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        await run_store_call(
            store,
            "create_resume_manifest",
            token=manifest_token,
            scan_id=scan_id,
            agent_key=meta.agent_key or agent.agent_key,
            payload_json=payload_json,
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
        )
        command = {
            "type": "resume",
            "scan_id": scan_id,
            "resume_manifest_url": (
                f"{_server_url_from_request(request)}"
                f"/api/agent/v2/resume-manifests/{manifest_token}"
            ),
            "agent_runtime_update": runtime_update,
        }
    else:
        command = resume_payload
    ok = await send_agent_command(agent_id, command)
    if not ok:
        await run_store_call(
            store,
            "add_processed_keys_batch",
            scan_id,
            removed_processed_keys,
        )
        await run_store_call(
            store,
            "update_scan_progress",
            scan_id,
            status=ScanItemStatus.ERROR,
            error_message="Agent not connected",
        )
        scan.status = ScanItemStatus.ERROR
        _running_scans.pop(scan_id, None)
        logger.error("Failed to resume scan %s: agent %s not connected", scan_id, agent_id)
        raise HTTPException(status_code=502, detail="Agent not connected")

    logger.info(
        "Continuing scan %s via agent %s: candidates=%s threat_tasks=%d",
        scan_id,
        agent_id,
        "full-pipeline" if candidate_payload is None else len(candidate_payload),
        len(incomplete_threat_tasks),
    )
    return ScanStartResponse(scan_id=scan_id)


@router.post("/api/scan/{scan_id}/resume", response_model=ScanStartResponse)
async def resume_scan(
    scan_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> ScanStartResponse:
    return await _continue_scan(scan_id, request, current_user)


@router.post("/api/scan/{scan_id}/retry-incomplete", response_model=ScanStartResponse)
async def retry_incomplete_scan(
    scan_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> ScanStartResponse:
    """Compatibility alias for the unified continue action."""
    return await _continue_scan(scan_id, request, current_user)


@router.delete("/api/scan/{scan_id}")
async def delete_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Delete a scan record and clean up project directory if orphaned."""
    await _check_scan_owner(scan_id, current_user)
    if scan_id in _running_scans:
        raise HTTPException(status_code=400, detail="Cannot delete a running scan")
    store = get_scan_store()

    # Load scan to get project_id before deletion
    result = await run_store_call(store, "load_scan", scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan, _meta = result
    project_id = scan.project_id

    if not await run_store_call(store, "delete_scan", scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")

    # Clean up project directory if no other scans reference it
    if await run_store_call(store, "count_scans_for_project", project_id) == 0:
        config = get_config()
        project_dir = Path(config.storage.projects_dir) / project_id
        if project_dir.is_dir():
            await asyncio.to_thread(shutil.rmtree, project_dir, ignore_errors=True)
            logger.info("Cleaned up orphaned project directory: %s", project_dir)

    return {"ok": True}


# ---------------------------------------------------------------------------
# Report / Mark / Save-FP
# ---------------------------------------------------------------------------


@router.get("/api/scan/{scan_id}/report")
async def download_report(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> Response:
    """Download the scan results as a CSV report."""
    await _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    buf = io.StringIO()
    writer = csv.writer(buf)
    fp_map = await run_store_call(get_scan_store(), _scan_fp_result_map, scan_id)
    writer.writerow([
        "engine_id", "engine_label", "file", "line", "function",
        "vuln_type", "severity", "confirmed",
        "fp_verdict", "fp_confirmed", "fp_severity",
        "match_type", "match_reference", "variant_of",
        "description", "ai_analysis",
    ])
    for i, v in enumerate(scan.vulnerabilities):
        fp = fp_map.get(i)
        writer.writerow([
            v.engine_id, v.engine_label, v.file, v.line, v.function,
            v.vuln_type, v.severity, v.confirmed,
            fp.verdict if fp else "",
            fp.verdict == "tp" if fp and is_effective_fp_review_result(fp) else "",
            fp.severity if fp else "",
            fp.match_type if fp else "", fp.match_reference if fp else "",
            v.variant_of, v.description, v.ai_analysis,
        ])
    return Response(
        content="﻿" + buf.getvalue(),
        media_type="text/csv; charset=utf-8-sig",
        headers={"Content-Disposition": f'attachment; filename="report-{scan_id}.csv"'},
    )


# Stage key -> Chinese title for the FP-review debate sections.
_FP_STAGE_TITLES = [
    ("history_match", "历史/校验匹配 (history_match)"),
    ("prove_bug", "确认漏洞 (prove_bug)"),
    ("prove_fp", "证明误报 (prove_fp)"),
    ("final_judge", "最终裁定 (final_judge)"),
]
_FP_CHECK_STAGE_TITLES = [
    ("claim_context", "主张与上下文"),
    ("standard_verification", "标准验证"),
    ("data_flow", "数据流分析"),
    ("exploitability", "可利用性验证"),
    ("impact", "影响评估"),
    ("poc", "PoC 构建"),
    ("devil_advocate", "反方审查"),
    ("gate_review", "六道门复核"),
]
_FP_REVIEW_STAGE_KEYS = {
    FpReviewMethod.ADVERSARIAL: {key for key, _ in _FP_STAGE_TITLES},
    FpReviewMethod.FP_CHECK: {key for key, _ in _FP_CHECK_STAGE_TITLES},
}


def _scan_fp_result_map(scan_id: str) -> dict[int, FpReviewResult]:
    """Return a {vuln_index: FpReviewResult} map (with merged stage outputs) for a scan."""
    store = get_scan_store()
    job = store.get_fp_review_by_scan(scan_id)
    if job is None:
        return {}
    merged = _merge_latest_fp_review_results(job, scan_id)
    return {r.vuln_index: r for r in merged.results}


def _safe_filename_part(text: str) -> str:
    """Sanitize a string for safe use inside a download filename / zip entry."""
    cleaned = re.sub(r"[^\w.-]+", "_", text.strip())
    return cleaned.strip("._") or "item"


def _format_output_source(source) -> str:
    if source is None:
        return ""
    agent = source.agent_name or source.agent_id or ""
    tool = source.tool or source.backend or ""
    model = source.model or ("CLI 默认模型" if source.use_default_model else source.model_id or "")
    model_label = f"{source.model_id} / {model}" if source.model_id and source.model_id != model else model
    parts = [part for part in [agent, tool, model_label] if part]
    return " / ".join(parts)


def _validation_sections_for_report(validation: VulnerabilityValidation) -> list[dict]:
    sections: list[dict] = []
    for raw in validation.output_sections or []:
        if not isinstance(raw, dict):
            continue
        title = str(raw.get("title") or "").strip() or "中间产出"
        content = str(raw.get("content") or "")
        sections.append({
            "title": title,
            "content": content,
            "updated_at": str(raw.get("updated_at") or ""),
        })
    if not sections and validation.intermediate_output:
        sections.append({
            "title": "中间产出",
            "content": validation.intermediate_output,
            "updated_at": validation.updated_at,
        })
    return sections


def _artifact_title(artifact: dict) -> str:
    return str(artifact.get("title") or "").strip() or "产物"


def _markdown_fence(content: str) -> tuple[str, str]:
    fence = "```"
    while fence in content:
        fence += "`"
    return fence, fence


def _append_fenced_block(lines: list[str], content: str) -> None:
    fence_start, fence_end = _markdown_fence(content)
    lines.append(fence_start)
    lines.append(content)
    lines.append(fence_end)
    lines.append("")


def _append_validation_markdown(lines: list[str], validation: VulnerabilityValidation | None) -> None:
    if validation is None:
        return

    lines.append("## 漏洞验证")
    lines.append("")
    lines.append("| 字段 | 内容 |")
    lines.append("| --- | --- |")
    lines.append(f"| 状态 | {validation.status} |")
    if validation.product:
        lines.append(f"| 产品 | {validation.product} |")
    if validation.validation_environment:
        lines.append(f"| 验证环境 | {validation.validation_environment} |")
    lines.append(f"| 验证成功 | {validation.validation_success} |")
    lines.append(f"| 是否问题 | {validation.is_problem} |")
    lines.append(f"| 人工介入 | {validation.requires_human_intervention} |")
    if validation.started_at:
        lines.append(f"| 开始时间 | {validation.started_at} |")
    if validation.finished_at:
        lines.append(f"| 结束时间 | {validation.finished_at} |")
    lines.append("")

    final_output = validation.final_output or validation.validation_output
    if final_output:
        lines.append("### 最终结论")
        lines.append("")
        lines.append(final_output)
        lines.append("")

    sections = _validation_sections_for_report(validation)
    if sections:
        lines.append("### 输出栏")
        lines.append("")
        for section in sections:
            lines.append(f"#### {section['title']}")
            lines.append("")
            _append_fenced_block(lines, section["content"] or "（暂无）")

    artifacts = [item for item in (validation.artifacts or []) if isinstance(item, dict)]
    if artifacts:
        lines.append("### 验证产物")
        lines.append("")
        groups: dict[str, list[dict]] = {}
        for artifact in artifacts:
            groups.setdefault(_artifact_title(artifact), []).append(artifact)
        for title, items in groups.items():
            lines.append(f"#### {title}")
            lines.append("")
            for artifact in items:
                name = str(artifact.get("name") or "artifact")
                kind = str(artifact.get("kind") or "")
                path = str(artifact.get("path") or "")
                updated_at = str(artifact.get("updated_at") or "")
                lines.append(f"##### {name}")
                lines.append("")
                if kind:
                    lines.append(f"- **类型**：{kind}")
                if path:
                    lines.append(f"- **路径**：`{path}`")
                if updated_at:
                    lines.append(f"- **更新时间**：{updated_at}")
                content = str(artifact.get("content") or "")
                if content:
                    lines.append("")
                    _append_fenced_block(lines, content)
                else:
                    lines.append("")


def _normalized_call_chain(value: object) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for item in value or []:
        if hasattr(item, "model_dump"):
            item = item.model_dump(mode="json")
        if isinstance(item, dict):
            function = str(item.get("function") or "").strip()
            file_path = str(item.get("file") or "").strip()
            try:
                line = int(item.get("line") or 0)
            except (TypeError, ValueError):
                line = 0
            if function:
                result.append({
                    "function": function,
                    "file": file_path,
                    "line": line,
                })
            continue
        function = str(item or "").strip()
        if function:
            result.append({"function": function, "file": "", "line": 0})
    return result


def _call_chain_label(item: dict[str, object]) -> str:
    function = str(item.get("function") or "") or "未知函数"
    file_path = str(item.get("file") or "")
    line = int(item.get("line") or 0)
    if file_path and line > 0:
        return f"{function} — {file_path}:{line}"
    return function


def _vuln_report_markdown(
    idx,
    vuln,
    fp_result: FpReviewResult | None,
    validation: VulnerabilityValidation | None = None,
) -> str:
    """Render a single vulnerability (AI analysis + FP-review stages) as Markdown."""
    severity_labels = {
        "critical": "致命",
        "high": "严重",
        "medium": "一般",
        "low": "提示",
    }
    severity = str(vuln.severity or "")
    severity_text = (
        f"{severity_labels[severity]} ({severity})"
        if severity in severity_labels
        else severity or "未知"
    )
    vuln_type = str(vuln.vuln_type or "").strip() or "未知类型"
    file_path = str(vuln.file or "").strip() or "未知文件"
    line = int(vuln.line or 0)
    line_text = str(line) if line > 0 else "未知"
    function = str(vuln.function or "").strip() or "未知函数"
    lines: list[str] = []
    lines.append(
        f"# 漏洞报告 — {vuln_type} @ {file_path}:{line_text}"
    )
    lines.append("")
    lines.append("| 字段 | 内容 |")
    lines.append("| --- | --- |")
    lines.append(f"| 是否是问题 | {'是' if vuln.confirmed else '否'} |")
    lines.append(
        f"| 漏洞挖掘引擎 | {vuln.engine_label} ({vuln.engine_id}) |"
    )
    lines.append(f"| 严重程度 | {severity_text} |")
    lines.append(f"| 漏洞文件 | {file_path} |")
    lines.append(f"| 漏洞函数 | {function} |")
    lines.append(f"| 漏洞行号 | {line_text} |")
    lines.append(f"| 漏洞类型 | {vuln_type} |")
    call_chain = _normalized_call_chain(
        getattr(vuln, "call_chain", None) or [],
    )
    if not call_chain and vuln.function:
        call_chain = [{
            "function": vuln.function,
            "file": vuln.file,
            "line": int(getattr(vuln, "function_start_line", None) or vuln.line),
        }]
    if call_chain:
        lines.append(
            f"| 验证入口函数 | {call_chain[0]['function']} |"
        )
    if getattr(vuln, "variant_of", ""):
        lines.append(f"| 同类变体来源 | {vuln.variant_of} |")
    source_text = _format_output_source(getattr(vuln, "output_source", None))
    if source_text:
        lines.append(f"| AI 输出来源 | {source_text} |")
    if vuln.user_verdict:
        lines.append(f"| 用户判定 | {vuln.user_verdict} |")
    lines.append("")
    lines.append("## 漏洞描述")
    lines.append("")
    lines.append(vuln.description or "未知")
    lines.append("")
    impact = str(getattr(vuln, "impact", "") or "").strip()
    if impact:
        lines.append("## 漏洞影响")
        lines.append("")
        lines.append(impact)
        lines.append("")
    vulnerable_code = str(
        getattr(vuln, "vulnerable_code", "") or ""
    ).strip()
    if vulnerable_code:
        lines.append("## 漏洞代码")
        lines.append("")
        _append_fenced_block(lines, vulnerable_code)
        lines.append("")
    if call_chain:
        lines.append("## 漏洞调用链")
        lines.append("")
        for position, item in enumerate(call_chain, start=1):
            lines.append(f"{position}. `{_call_chain_label(item)}`")
        lines.append("")
    for field, title in (
        ("attack_entry", "攻击入口"),
        ("root_cause", "漏洞根因"),
        ("trigger_conditions", "触发条件"),
    ):
        content = str(getattr(vuln, field, "") or "").strip()
        if not content:
            continue
        lines.append(f"## {title}")
        lines.append("")
        lines.append(content)
        lines.append("")
    vulnerability_report = str(getattr(vuln, "vulnerability_report", "") or "").strip()
    if vulnerability_report:
        lines.append("## 漏洞挖掘引擎报告")
        lines.append("")
        lines.append(vulnerability_report)
        lines.append("")
    if vuln.user_verdict_reason:
        lines.append("## 用户判定理由")
        lines.append("")
        lines.append(vuln.user_verdict_reason)
        lines.append("")
    if vuln.ai_analysis:
        lines.append("## 旧版 AI 分析")
        lines.append("")
        lines.append(vuln.ai_analysis)
        lines.append("")

    if fp_result is not None:
        lines.append("## 去误报复核")
        lines.append("")
        verdict_label = {"tp": "真实漏洞 (tp)", "fp": "误报 (fp)"}.get(fp_result.verdict, fp_result.verdict)
        lines.append(f"- **最终结论**：{verdict_label}")
        fp_severity = str(fp_result.severity or "")
        fp_severity_text = (
            f"{severity_labels[fp_severity]} ({fp_severity})"
            if fp_severity in severity_labels
            else fp_severity
        )
        lines.append(f"- **严重级别**：{fp_severity_text}")
        if getattr(fp_result, "match_type", ""):
            match_label = {"history": "对应历史问题模式", "validation": "对应其它函数校验"}.get(
                fp_result.match_type, fp_result.match_type
            )
            lines.append(f"- **匹配类型**：{match_label}")
        if getattr(fp_result, "match_reference", ""):
            lines.append(f"- **对应修复/校验**：{fp_result.match_reference}")
        fp_source_text = _format_output_source(fp_result.output_source)
        if fp_source_text:
            lines.append(f"- **最终输出来源**：{fp_source_text}")
        if fp_result.reason:
            lines.append(f"- **理由**：{fp_result.reason}")
        lines.append("")
        for key, title in _FP_STAGE_TITLES + _FP_CHECK_STAGE_TITLES:
            stage_md = (fp_result.stage_outputs or {}).get(key)
            if not stage_md:
                continue
            lines.append(f"### 阶段：{title}")
            lines.append("")
            stage_source = _format_output_source((fp_result.stage_output_sources or {}).get(key))
            if stage_source:
                lines.append(f"> 输出来源：{stage_source}")
                lines.append("")
            lines.append(stage_md)
            lines.append("")

    _append_validation_markdown(lines, validation)

    return "\n".join(lines).rstrip() + "\n"


@router.get("/api/scan/{scan_id}/vulnerability/{idx}/report")
async def download_vulnerability_report(
    scan_id: str,
    idx: int,
    current_user: User = Depends(get_current_user),
) -> Response:
    """Download a single vulnerability's report (AI analysis + FP review) as Markdown."""
    await _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    if idx < 0 or idx >= len(scan.vulnerabilities):
        raise HTTPException(status_code=404, detail="Vulnerability index out of range")
    vuln = scan.vulnerabilities[idx]
    fp_map = await run_store_call(get_scan_store(), _scan_fp_result_map, scan_id)
    validation_map = {item.vuln_index: item for item in scan.validations}
    markdown = _vuln_report_markdown(idx, vuln, fp_map.get(idx), validation_map.get(idx))
    fname = (
        f"vuln-{idx}-"
        f"{_safe_filename_part(vuln.file or 'unknown')}_"
        f"{vuln.line if vuln.line > 0 else 'unknown'}.md"
    )
    return Response(
        content=markdown,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


async def _trigger_vulnerability_validation(
    scan_id: str,
    idx: int,
    _server_url: str,
) -> dict:
    """Start Agent-side local validation for one AI-confirmed vulnerability."""
    from backend.api.agent import (
        create_agent_task_runtime_update_payload_async,
        ensure_agent_accepting_tasks_async,
        send_agent_command,
    )

    store = get_scan_store()
    loaded = await run_store_call(store, "load_scan", scan_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan, meta = loaded

    if idx < 0 or idx >= len(scan.vulnerabilities):
        raise HTTPException(status_code=404, detail="Vulnerability index out of range")
    vuln = scan.vulnerabilities[idx]
    if not (vuln.confirmed or vuln.ai_verdict == "confirmed"):
        raise HTTPException(status_code=400, detail="Only AI-confirmed vulnerabilities can be validated")
    product, validation_environment = _validate_validation_target(
        meta.product,
        meta.validation_environment,
    )
    if not product:
        raise HTTPException(
            status_code=400,
            detail="Scan has no configured product validation target",
        )
    if meta.agent_key:
        from backend.api.agent import get_managed_agent_config_async

        managed_config = await get_managed_agent_config_async(meta.agent_key)
        env_config = managed_config.vulnerability_validation.environments.get(
            validation_environment
        )
        if env_config is not None:
            supported = {str(item).strip().casefold() for item in env_config.supported_vulnerability_types}
            vulnerability_type = vuln.vuln_type.strip().casefold()
            if (
                vulnerability_type
                and "*" not in supported
                and vulnerability_type not in supported
            ):
                raise HTTPException(
                    status_code=400,
                    detail=f"验证环境 {validation_environment} 不支持漏洞类型 {vuln.vuln_type}",
                )

    existing = next((item for item in scan.validations if item.vuln_index == idx), None)
    if existing is not None and existing.running:
        raise HTTPException(status_code=409, detail="Validation already running")

    if not meta.agent_id and not meta.agent_name:
        raise HTTPException(status_code=400, detail="No agent associated with this scan")
    agent_id = await _resolve_scan_agent_id(meta)
    if agent_id is None:
        raise HTTPException(
            status_code=400,
            detail=f"扫描关联的 Agent「{meta.agent_name or '未知'}」不在线，请先启动该 Agent",
        )
    await ensure_agent_accepting_tasks_async(meta.agent_key)
    if agent_id != meta.agent_id:
        await run_store_call(
            store,
            "update_scan_agent",
            scan_id,
            agent_id,
            meta.agent_name,
            meta.agent_key,
        )

    now = _now_iso()
    validation = await run_store_call(
        store,
        "upsert_vulnerability_validation",
        scan_id,
        VulnerabilityValidation(
            scan_id=scan_id,
            vuln_index=idx,
            status="queued",
            running=True,
            product=product,
            validation_environment=validation_environment,
            started_at=now,
            updated_at=now,
        ),
    )
    _publish_validation(scan_id, validation)
    _update_running_validation(scan_id, validation)

    fp_map = await run_store_call(store, _scan_fp_result_map, scan_id)
    ok = await send_agent_command(agent_id, {
        "type": "vulnerability_validation",
        "scan_id": scan_id,
        "vuln_index": idx,
        "project_path": meta.project_path,
        "code_scan_path": meta.code_scan_path or meta.project_path,
        "product": product,
        "validation_environment": validation_environment,
        "vulnerability": vuln.model_dump(),
        "report_markdown": _vuln_report_markdown(idx, vuln, fp_map.get(idx)),
        "code_graph_mcp": (
            meta.code_graph_mcp.model_dump(mode="json")
            if meta.code_graph_mcp is not None
            else None
        ),
        "agent_runtime_update": await create_agent_task_runtime_update_payload_async(
            _server_url,
            meta.agent_key,
        ),
    })
    if not ok:
        failed = await run_store_call(
            store,
            "upsert_vulnerability_validation",
            scan_id,
            validation.model_copy(update={
                "status": "error",
                "running": False,
                "validation_output": "Agent not connected",
                "requires_human_intervention": True,
                "finished_at": _now_iso(),
                "updated_at": _now_iso(),
            }),
        )
        _publish_validation(scan_id, failed)
        _update_running_validation(scan_id, failed)
        raise HTTPException(status_code=502, detail="Agent not connected")

    logger.info("Manual vulnerability validation triggered for scan %s idx %d via agent %s", scan_id, idx, agent_id)
    return {"ok": True, "vuln_index": idx}


async def _stop_vulnerability_validation(scan_id: str, idx: int) -> dict:
    """Cancel one Agent-side local validation for a vulnerability."""
    from backend.api.agent import send_agent_command

    store = get_scan_store()
    loaded = await run_store_call(store, "load_scan", scan_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan, meta = loaded

    if idx < 0 or idx >= len(scan.vulnerabilities):
        raise HTTPException(status_code=404, detail="Vulnerability index out of range")

    existing = next((item for item in scan.validations if item.vuln_index == idx), None)
    if existing is None:
        raise HTTPException(status_code=404, detail="Validation not found")

    active = existing.running or existing.status in {"pending", "queued", "running"}
    if active:
        now = _now_iso()
        validation = await run_store_call(
            store,
            "upsert_vulnerability_validation",
            scan_id,
            existing.model_copy(update={
                "status": "cancelled",
                "running": False,
                "validation_success": False,
                "requires_human_intervention": True,
                "validation_output": "用户手动停止",
                "final_output": "用户手动停止",
                "finished_at": now,
                "updated_at": now,
            }),
        )
        _publish_validation(scan_id, validation)
        _update_running_validation(scan_id, validation)
    else:
        validation = existing

    agent_id = await _resolve_scan_agent_id(meta)
    if active and agent_id is not None:
        if agent_id != meta.agent_id:
            await run_store_call(
                store,
                "update_scan_agent",
                scan_id,
                agent_id,
                meta.agent_name,
                meta.agent_key,
            )
        await send_agent_command(agent_id, {
            "type": "vulnerability_validation_stop",
            "scan_id": scan_id,
            "vuln_index": idx,
        })

    logger.info("Vulnerability validation for scan %s idx %d cancelled by user", scan_id, idx)
    return {"ok": True, "vuln_index": idx, "status": validation.status}


@router.post("/api/scan/{scan_id}/vulnerability/{idx}/validation")
async def trigger_vulnerability_validation(
    scan_id: str,
    idx: int,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Manually start Agent-side local validation for one confirmed vulnerability."""
    await _check_scan_owner(scan_id, current_user)
    return await _trigger_vulnerability_validation(scan_id, idx, _server_url_from_request(request))


@router.post("/api/scan/{scan_id}/vulnerability/{idx}/validation/stop")
async def stop_vulnerability_validation(
    scan_id: str,
    idx: int,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Cancel Agent-side local validation for one vulnerability."""
    await _check_scan_owner(scan_id, current_user)
    return await _stop_vulnerability_validation(scan_id, idx)


@router.get("/api/scan/{scan_id}/report.zip")
async def download_report_zip(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> Response:
    """Download all AI-confirmed vulnerabilities as a zip of Markdown reports."""
    await _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    fp_map, fp_job = await asyncio.gather(
        run_store_call(store, _scan_fp_result_map, scan_id),
        run_store_call(store, "get_fp_review_by_scan", scan_id),
    )
    validation_map = {item.vuln_index: item for item in scan.validations}

    confirmed = [
        (i, v)
        for i, v in enumerate(scan.vulnerabilities)
        if v.confirmed or v.ai_verdict == "confirmed"
    ]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if not confirmed:
            zf.writestr("README.md", f"# 扫描 {scan_id}\n\n本次扫描没有 AI 确认为问题的漏洞。\n")
        else:
            index_lines = [f"# 扫描 {scan_id} 漏洞报告索引", "", f"共 {len(confirmed)} 个 AI 确认问题：", ""]
            if fp_job is not None and fp_job.summary_markdown:
                index_lines.extend([
                    f"- [{'Trail of Bits fp-check 复核' if fp_job.method == FpReviewMethod.FP_CHECK else '对抗式复核'}批次汇总](fp-review-summary.md)",
                    "",
                ])
                summary_content = fp_job.summary_markdown.rstrip() + "\n"
                if (
                    fp_job.method == FpReviewMethod.FP_CHECK
                    and fp_job.summary_status != FpReviewStatus.COMPLETE
                ):
                    summary_state = (
                        fp_job.summary_status.value
                        if fp_job.summary_status is not None
                        else "pending"
                    )
                    warning = (
                        "> 注意：这是上一次成功生成的批次汇总，"
                        f"当前汇总状态为 `{summary_state}`，内容可能已过期。"
                    )
                    if fp_job.summary_error_message:
                        warning += (
                            "\n>\n> 最近一次更新失败原因："
                            + fp_job.summary_error_message
                        )
                    summary_content = warning + "\n\n" + summary_content
                zf.writestr("fp-review-summary.md", summary_content)
            for i, v in confirmed:
                export_file = v.file or "unknown"
                export_line = v.line if v.line > 0 else "unknown"
                entry = (
                    f"vuln-{i}-{_safe_filename_part(export_file)}_"
                    f"{export_line}.md"
                )
                index_lines.append(
                    f"- [{v.engine_label} · "
                    f"{v.vuln_type or '未知类型'} @ "
                    f"{v.file or '未知文件'}:"
                    f"{v.line if v.line > 0 else '未知'}]({entry})"
                )
                zf.writestr(entry, _vuln_report_markdown(i, v, fp_map.get(i), validation_map.get(i)))
            zf.writestr("README.md", "\n".join(index_lines) + "\n")
    buf.seek(0)
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-report.zip"'},
    )


async def _mark_single(
    scan_id: str,
    scan: ScanStatus,
    store,
    index: int,
    verdict: str,
    reason: str,
    ticket_submitted: bool = False,
    ticket_id: str = "",
) -> tuple[str | None, list[str]]:
    """Mark a vulnerability. Final verdicts create feedback; pending analysis does not."""
    if verdict not in _MARK_VERDICTS:
        raise HTTPException(status_code=400, detail="Invalid verdict")
    if index < 0 or index >= len(scan.vulnerabilities):
        raise HTTPException(status_code=400, detail=f"Invalid vulnerability index: {index}")

    vuln = scan.vulnerabilities[index]
    normalized_ticket_id = ticket_id.strip() if ticket_submitted else ""

    removed_feedback_ids: list[str] = []
    if verdict == "pending_analysis":
        removed_feedback_ids = await run_store_call(
            store,
            "clear_vulnerability_user_verdict",
            scan_id,
            index,
        )

    if scan_id in _running_scans:
        live = _running_scans[scan_id]
        if index < len(live.vulnerabilities):
            live.vulnerabilities[index].user_verdict = verdict
            live.vulnerabilities[index].user_verdict_reason = reason
            live.vulnerabilities[index].ticket_submitted = ticket_submitted
            live.vulnerabilities[index].ticket_id = normalized_ticket_id

    vuln.user_verdict = verdict
    vuln.user_verdict_reason = reason
    vuln.ticket_submitted = ticket_submitted
    vuln.ticket_id = normalized_ticket_id

    await run_store_call(
        store,
        "update_vulnerability",
        scan_id,
        index,
        verdict,
        reason,
        ticket_submitted,
        normalized_ticket_id,
    )

    if verdict == "pending_analysis":
        logger.info(
            "Scan %s: vulnerability %d marked as pending analysis, removed feedback IDs: %s",
            scan_id,
            index,
            removed_feedback_ids,
        )
        return None, removed_feedback_ids

    now = datetime.now(timezone.utc).isoformat()
    entry = FeedbackEntry(
        id=uuid.uuid4().hex,
        project_id=scan.project_id,
        vuln_type=vuln.vuln_type,
        verdict=verdict,
        file=vuln.file,
        line=vuln.line,
        function=vuln.function,
        description=vuln.description,
        reason=reason,
        ticket_submitted=ticket_submitted,
        ticket_id=normalized_ticket_id,
        function_source=vuln.function_source,
        function_start_line=vuln.function_start_line,
        source_scan_id=scan_id,
        created_at=now,
        updated_at=now,
    )
    entry = await run_store_call(store, "upsert_feedback_for_report", entry)
    logger.info("Scan %s: vulnerability %d marked as %s, feedback %s", scan_id, index, verdict, entry.id)

    # Push feedback update to the agent that ran this scan (best-effort)
    try:
        smeta = await run_store_call(store, "get_scan_meta", scan_id)
        if smeta is not None:
            from backend.api.agent import send_agent_command

            target_id = await _resolve_scan_agent_id(smeta)
            if target_id:
                asyncio.create_task(send_agent_command(target_id, {
                    "type": "feedback_update",
                    "entry": entry.model_dump(),
                }))
    except Exception:
        pass

    return entry.id, removed_feedback_ids


async def _remove_feedback_ids_from_scan(
    scan_id: str,
    scan: ScanStatus,
    feedback_ids: list[str],
) -> None:
    if not feedback_ids:
        return
    removed = set(feedback_ids)
    next_ids = [fid for fid in scan.feedback_ids if fid not in removed]
    if next_ids == scan.feedback_ids:
        loaded = await run_store_call(get_scan_store(), "load_scan", scan_id)
        if loaded is not None:
            next_ids = [fid for fid in loaded[1].feedback_ids if fid not in removed]
            if next_ids == loaded[1].feedback_ids:
                return
        else:
            return
    scan.feedback_ids = next_ids
    if scan_id in _running_scans:
        _running_scans[scan_id].feedback_ids = next_ids
    await run_store_call(
        get_scan_store(),
        "update_scan_feedback_ids",
        scan_id,
        next_ids,
    )


async def _unmark_single(
    scan_id: str,
    scan: ScanStatus,
    store,
    index: int,
) -> list[str]:
    """Clear a vulnerability's manual verdict and delete its same-source feedback."""
    if index < 0 or index >= len(scan.vulnerabilities):
        raise HTTPException(status_code=400, detail=f"Invalid vulnerability index: {index}")

    if scan_id in _running_scans:
        live = _running_scans[scan_id]
        if index < len(live.vulnerabilities):
            live.vulnerabilities[index].user_verdict = None
            live.vulnerabilities[index].user_verdict_reason = None
            live.vulnerabilities[index].ticket_submitted = False
            live.vulnerabilities[index].ticket_id = ""

    vuln = scan.vulnerabilities[index]
    vuln.user_verdict = None
    vuln.user_verdict_reason = None
    vuln.ticket_submitted = False
    vuln.ticket_id = ""

    removed_feedback_ids = await run_store_call(
        store,
        "clear_vulnerability_user_verdict",
        scan_id,
        index,
    )
    logger.info(
        "Scan %s: vulnerability %d manual verdict cleared, removed feedback IDs: %s",
        scan_id,
        index,
        removed_feedback_ids,
    )
    return removed_feedback_ids


@router.post("/api/scan/{scan_id}/mark")
async def mark_vulnerability(
    scan_id: str,
    body: MarkRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Mark a vulnerability with manual triage feedback."""
    await _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    feedback_id, removed_feedback_ids = await _mark_single(
        scan_id,
        scan,
        store,
        body.index,
        body.verdict,
        body.reason,
        body.ticket_submitted,
        body.ticket_id,
    )
    await _remove_feedback_ids_from_scan(scan_id, scan, removed_feedback_ids)
    if removed_feedback_ids:
        await _push_feedback_selection_update(scan_id, scan.feedback_ids)
    return {"ok": True, "feedback_id": feedback_id, "removed_feedback_ids": removed_feedback_ids}


@router.post("/api/scan/{scan_id}/unmark")
async def unmark_vulnerability(
    scan_id: str,
    body: UnmarkRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Clear a vulnerability's manual verdict and remove its generated feedback."""
    await _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    removed_feedback_ids = await _unmark_single(
        scan_id,
        scan,
        store,
        body.index,
    )
    await _remove_feedback_ids_from_scan(scan_id, scan, removed_feedback_ids)
    if removed_feedback_ids:
        await _push_feedback_selection_update(scan_id, scan.feedback_ids)
    return {"ok": True, "removed_feedback_ids": removed_feedback_ids}


@router.post("/api/scan/{scan_id}/batch-mark")
async def batch_mark_vulnerabilities(
    scan_id: str,
    body: BatchMarkRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Batch-mark multiple vulnerabilities with manual triage feedback."""
    await _check_scan_owner(scan_id, current_user)
    if not body.items:
        raise HTTPException(status_code=400, detail="No items provided")
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    feedback_ids: list[str] = []
    removed_feedback_ids: list[str] = []
    for item in body.items:
        feedback_id, removed_ids = await _mark_single(
            scan_id,
            scan,
            store,
            item.index,
            item.verdict,
            item.reason,
            item.ticket_submitted,
            item.ticket_id,
        )
        if feedback_id is not None:
            feedback_ids.append(feedback_id)
        removed_feedback_ids.extend(removed_ids)
    await _remove_feedback_ids_from_scan(scan_id, scan, removed_feedback_ids)
    if removed_feedback_ids:
        await _push_feedback_selection_update(scan_id, scan.feedback_ids)
    return {"ok": True, "feedback_ids": feedback_ids, "removed_feedback_ids": removed_feedback_ids}


@router.post("/api/scan/{scan_id}/batch-unmark")
async def batch_unmark_vulnerabilities(
    scan_id: str,
    body: BatchUnmarkRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Clear manual verdicts and remove generated feedback for multiple vulnerabilities."""
    await _check_scan_owner(scan_id, current_user)
    if not body.indices:
        raise HTTPException(status_code=400, detail="No indices provided")
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    removed_feedback_ids: list[str] = []
    for index in dict.fromkeys(body.indices):
        removed_feedback_ids.extend(
            await _unmark_single(scan_id, scan, store, index)
        )
    await _remove_feedback_ids_from_scan(scan_id, scan, removed_feedback_ids)
    if removed_feedback_ids:
        await _push_feedback_selection_update(scan_id, scan.feedback_ids)
    return {"ok": True, "removed_feedback_ids": removed_feedback_ids}


# ---------------------------------------------------------------------------
# Scan feedback endpoint (DB-only; no server-side workspace to refresh)
# ---------------------------------------------------------------------------


async def _start_fp_review(
    scan_id: str,
    server_url: str,
    *,
    raise_on_error: bool = True,
    require_unresolved: bool = False,
) -> dict | None:
    """Start an AI false-positive review for all confirmed vulnerabilities in a scan.

    Shared by the manual trigger endpoint and the auto-trigger on scan completion.
    When ``raise_on_error`` is False, failures are logged and ``None`` is returned
    instead of raising — used by the auto-trigger path so a failed/blocked review
    never breaks scan-finish handling.
    """
    from backend.api.agent import (
        create_agent_task_runtime_update_payload_async,
        ensure_agent_accepting_tasks_async,
        send_agent_command,
    )

    def _fail(status_code: int, detail: str) -> None:
        if raise_on_error:
            raise HTTPException(status_code=status_code, detail=detail)
        logger.warning("Auto FP review for scan %s skipped: %s", scan_id, detail)
        return None

    store = get_scan_store()
    if scan_id in _running_scans:
        scan = _running_scans[scan_id]
    else:
        loaded = await run_store_call(store, "load_scan", scan_id)
        if loaded is None:
            return _fail(404, "Scan not found")
        scan = loaded[0]

    meta = await run_store_call(store, "get_scan_meta", scan_id)
    if meta is None:
        return _fail(404, "Scan not found")
    try:
        await ensure_agent_accepting_tasks_async(meta.agent_key)
    except HTTPException as exc:
        return _fail(exc.status_code, str(exc.detail))

    if not meta.agent_id and not meta.agent_name:
        return _fail(400, "No agent associated with this scan")

    # Resolve the Agent before creating/reopening the item job. Otherwise an
    # offline Agent can leave the persisted job looking "running" even though
    # no command was dispatched.
    agent_id = await _resolve_scan_agent_id(meta)
    if agent_id is None:
        return _fail(
            400,
            f"扫描关联的 Agent「{meta.agent_name or '未知'}」不在线，请先启动该 Agent",
        )

    fp_job_info = await run_store_call(
        store,
        _ensure_fp_review_job_for_scan,
        scan_id,
        scan,
        allow_cancelled=True,
        publish_started=False,
        require_unresolved=require_unresolved,
    )
    if fp_job_info is None:
        return _fail(400, "No confirmed vulnerabilities to review")
    confirmed = fp_job_info["confirmed"]
    review_id = str(fp_job_info["review_id"])
    method = FpReviewMethod(str(fp_job_info["method"]))

    # Update stored agent_id if it changed
    if agent_id != meta.agent_id:
        await run_store_call(
            store,
            "update_scan_agent",
            scan_id,
            agent_id,
            meta.agent_name,
            meta.agent_key,
        )

    selected_feedback = await run_store_call(
        store,
        _selected_feedback_entries,
        scan_id,
        meta.feedback_ids,
    )
    feedback_entries = [entry.model_dump() for entry in selected_feedback]

    dispatched_items = not fp_job_info.get("no_unresolved")
    if dispatched_items:
        from backend.sse import publish
        publish(scan_id, "fp_review_started", {
            "review_id": review_id,
            "method": method.value,
            "status": "running",
            "total": int(fp_job_info.get("total") or len(confirmed)),
            "processed": int(fp_job_info.get("processed") or 0),
            "summary_status": (
                "pending"
                if method == FpReviewMethod.FP_CHECK
                else None
            ),
        })
        ok = await send_agent_command(agent_id, {
            "type": "fp_review",
            "scan_id": scan_id,
            "review_id": review_id,
            "method": method.value,
            "project_path": meta.project_path,
            "vulnerabilities": confirmed,
            "feedback_entries": feedback_entries,
            "processed_offset": int(fp_job_info.get("processed") or 0),
            "code_graph_mcp": (
                meta.code_graph_mcp.model_dump(mode="json")
                if meta.code_graph_mcp is not None
                else None
            ),
            "agent_runtime_update": await create_agent_task_runtime_update_payload_async(
                server_url,
                meta.agent_key,
            ),
        })
        if not ok:
            await run_store_call(
                store,
                "update_fp_review_job",
                review_id,
                status="error",
                error_message="Agent not connected",
            )
            publish(scan_id, "fp_review_finish", {
                "review_id": review_id,
                "status": FpReviewStatus.ERROR.value,
                "method": method.value,
                "error_message": "Agent not connected",
            })
            return _fail(502, "Agent not connected")

        logger.info(
            "FP review %s triggered for scan %s (%d candidates)",
            review_id,
            scan_id,
            len(confirmed),
        )

    summary_started = None
    if (
        method == FpReviewMethod.FP_CHECK
        and scan.status == ScanItemStatus.COMPLETE
    ):
        summary_started = await _start_fp_review_summary(
            scan_id,
            server_url,
            raise_on_error=raise_on_error,
        )
    return {
        "ok": True,
        "review_id": review_id,
        "method": method.value,
        "status": "running" if dispatched_items else fp_job_info.get("status", "complete"),
        "total": int(fp_job_info.get("total") or len(confirmed)),
        "processed": int(fp_job_info.get("processed") or 0),
        "items_dispatched": dispatched_items,
        "summary_started": bool(summary_started),
        "summary_status": (
            summary_started.get("status")
            if isinstance(summary_started, dict)
            else (
                FpReviewStatus.PENDING.value
                if method == FpReviewMethod.FP_CHECK
                else None
            )
        ),
    }


async def _start_fp_review_summary(
    scan_id: str,
    server_url: str,
    *,
    raise_on_error: bool = True,
) -> dict | None:
    """Start only the independent fp-check chain analysis and summary."""
    from backend.api.agent import (
        create_agent_task_runtime_update_payload_async,
        ensure_agent_accepting_tasks_async,
        send_agent_command,
    )

    def _fail(status_code: int, detail: str) -> None:
        if raise_on_error:
            raise HTTPException(status_code=status_code, detail=detail)
        logger.warning("FP review summary for scan %s skipped: %s", scan_id, detail)
        return None

    store = get_scan_store()
    loaded = await run_store_call(store, "load_scan", scan_id)
    scan = _running_scans.get(scan_id) or (loaded[0] if loaded is not None else None)
    if scan is None:
        return _fail(404, "Scan not found")
    if scan.status != ScanItemStatus.COMPLETE:
        return _fail(409, "跨漏洞攻击链检查只能在扫描完成后启动")
    job = await run_store_call(store, "get_fp_review_by_scan", scan_id)
    if job is None or job.method != FpReviewMethod.FP_CHECK:
        return _fail(404, "No Trail of Bits fp-check review found")
    if job.status == FpReviewStatus.CANCELLED:
        return _fail(409, "FP review was cancelled; restart item review first")
    if job.summary_status == FpReviewStatus.RUNNING:
        return {
            "ok": True,
            "review_id": job.review_id,
            "status": FpReviewStatus.RUNNING.value,
            "already_running": True,
        }

    async def _mark_summary_error(message: str) -> None:
        await run_store_call(
            store,
            "update_fp_review_job",
            job.review_id,
            summary_status=FpReviewStatus.ERROR.value,
            summary_error_message=message,
        )
        from backend.sse import publish
        publish(scan_id, "fp_review_summary_finish", {
            "review_id": job.review_id,
            "status": FpReviewStatus.ERROR.value,
            "error_message": message,
            "summary_markdown": None,
            "summary_output_source": None,
        })

    meta = await run_store_call(store, "get_scan_meta", scan_id)
    if meta is None:
        return _fail(404, "Scan not found")
    try:
        await ensure_agent_accepting_tasks_async(meta.agent_key)
    except HTTPException as exc:
        await _mark_summary_error(str(exc.detail))
        return _fail(exc.status_code, str(exc.detail))
    agent_id = await _resolve_scan_agent_id(meta)
    if agent_id is None:
        await _mark_summary_error("Agent not connected")
        return _fail(
            400,
            f"扫描关联的 Agent「{meta.agent_name or '未知'}」不在线，请先启动该 Agent",
        )
    if agent_id != meta.agent_id:
        await run_store_call(
            store,
            "update_scan_agent",
            scan_id,
            agent_id,
            meta.agent_name,
            meta.agent_key,
        )
    selected_feedback = await run_store_call(
        store,
        _selected_feedback_entries,
        scan_id,
        meta.feedback_ids,
    )
    feedback_entries = [entry.model_dump() for entry in selected_feedback]
    # Persist the running state before dispatch. A deterministic summary can
    # finish almost immediately; updating after the WebSocket send could race
    # with its completion callback and overwrite "complete" with "running".
    await run_store_call(
        store,
        "update_fp_review_job",
        job.review_id,
        summary_status=FpReviewStatus.RUNNING.value,
        summary_error_message="",
    )
    from backend.sse import publish
    publish(scan_id, "fp_review_summary_started", {
        "review_id": job.review_id,
        "status": FpReviewStatus.RUNNING.value,
    })
    ok = await send_agent_command(agent_id, {
        "type": "fp_review_summary",
        "scan_id": scan_id,
        "review_id": job.review_id,
        "project_path": meta.project_path,
        "feedback_entries": feedback_entries,
        "code_graph_mcp": (
            meta.code_graph_mcp.model_dump(mode="json")
            if meta.code_graph_mcp is not None
            else None
        ),
        "agent_runtime_update": await create_agent_task_runtime_update_payload_async(
            server_url,
            meta.agent_key,
        ),
    })
    if not ok:
        await _mark_summary_error("Agent not connected")
        return _fail(502, "Agent not connected")
    logger.info(
        "Independent fp-check summary %s triggered for scan %s",
        job.review_id,
        scan_id,
    )
    return {
        "ok": True,
        "review_id": job.review_id,
        "status": FpReviewStatus.RUNNING.value,
        "already_running": False,
    }


@router.post("/api/scan/{scan_id}/fp_review", response_model=dict)
async def trigger_fp_review(
    scan_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Trigger AI false-positive review for all confirmed vulnerabilities in a scan."""
    await _check_scan_owner(scan_id, current_user)
    return await _start_fp_review(scan_id, _server_url_from_request(request), raise_on_error=True)


@router.post("/api/scan/{scan_id}/fp_review/summary", response_model=dict)
async def trigger_fp_review_summary(
    scan_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Retry only the independent fp-check summary."""
    await _check_scan_owner(scan_id, current_user)
    result = await _start_fp_review_summary(
        scan_id,
        _server_url_from_request(request),
        raise_on_error=True,
    )
    assert result is not None
    return result


@router.post("/api/scan/{scan_id}/fp_review/stop")
async def stop_fp_review(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Cancel the latest running FP review job for a scan."""
    await _check_scan_owner(scan_id, current_user)
    from backend.api.agent import send_agent_command

    store = get_scan_store()
    job = await run_store_call(store, "get_fp_review_by_scan", scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No FP review found for this scan")
    item_running = job.status in {
        FpReviewStatus.PENDING,
        FpReviewStatus.RUNNING,
    }
    summary_running = job.summary_status == FpReviewStatus.RUNNING
    if not item_running and not summary_running:
        return {"ok": True, "review_id": job.review_id}

    meta = await run_store_call(store, "get_scan_meta", scan_id)
    if meta is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    updates: dict = {}
    if item_running:
        updates.update({
            "status": FpReviewStatus.CANCELLED.value,
            "clear_current_vuln_index": True,
            "error_message": "用户手动停止",
        })
    if summary_running:
        updates.update({
            "summary_status": FpReviewStatus.CANCELLED.value,
            "summary_error_message": "用户手动停止",
        })
    await run_store_call(
        store,
        "update_fp_review_job",
        job.review_id,
        **updates,
    )

    agent_id = await _resolve_scan_agent_id(meta)
    if agent_id is not None:
        await send_agent_command(agent_id, {
            "type": "fp_review_stop",
            "scan_id": scan_id,
            "review_id": job.review_id,
        })

    logger.info("FP review %s for scan %s cancelled by user", job.review_id, scan_id)
    return {"ok": True, "review_id": job.review_id}


@router.get("/api/scan/{scan_id}/fp_review", response_model=FpReviewJob)
async def get_fp_review(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> FpReviewJob:
    """Get the latest FP review job and results for a scan."""
    await _check_scan_owner(scan_id, current_user)
    store = get_scan_store()
    job = await run_store_call(store, "get_fp_review_by_scan", scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No FP review found for this scan")
    return await run_store_call(
        store,
        _merge_latest_fp_review_results,
        job,
        scan_id,
    )


@router.get("/api/scan/{scan_id}/git_history", response_model=list[HistoryPattern])
async def get_scan_git_history(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> list[HistoryPattern]:
    """Return the git-history security problem patterns mined for a scan."""
    await _check_scan_owner(scan_id, current_user)
    return await run_store_call(
        get_scan_store(),
        "get_git_history_patterns",
        scan_id,
    )


@router.get("/api/scan/{scan_id}/threat-analysis", response_model=dict)
async def get_scan_threat_analysis(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return the opaque threat-analysis artifact bundle for a scan."""
    await _check_scan_owner(scan_id, current_user)
    analysis = await run_store_call(
        get_scan_store(),
        "get_threat_analysis",
        scan_id,
    )
    if analysis is None:
        raise HTTPException(status_code=404, detail="No threat analysis found for this scan")
    return analysis


@router.get("/api/scan/{scan_id}/threat-audit-tasks", response_model=list[ThreatAuditTask])
async def get_scan_threat_audit_tasks(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> list[ThreatAuditTask]:
    """Return threat-analysis-derived audit tasks for a scan."""
    await _check_scan_owner(scan_id, current_user)
    return await run_store_call(
        get_scan_store(),
        "list_threat_audit_tasks",
        scan_id,
    )


@router.get("/api/scan/{scan_id}/events")
async def scan_events_sse(
    scan_id: str,
    request: Request,
    token: str = Query(...),
) -> StreamingResponse:
    """SSE stream for real-time scan and FP review status updates.

    The browser EventSource API does not support custom headers, so the
    JWT is passed as a query parameter.
    """
    from backend.auth import decode_token
    from backend.sse import subscribe, unsubscribe, format_sse, SSE_KEEPALIVE
    import jwt as _jwt

    try:
        payload = decode_token(token)
    except _jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = payload.get("sub", "")
    role = payload.get("role", "")
    if role != "admin":
        store = get_scan_store()
        meta = await run_store_call(store, "get_scan_meta", scan_id)
        if meta is not None:
            if meta.user_id != user_id:
                raise HTTPException(status_code=403, detail="Access denied")
        elif scan_id not in _scan_owners or _scan_owners[scan_id] != user_id:
            raise HTTPException(status_code=403, detail="Access denied")

    async def event_generator() -> AsyncGenerator[str, None]:
        queue = subscribe(scan_id)
        try:
            last_event_id = 0
            try:
                last_event_id = max(0, int(request.headers.get("last-event-id") or 0))
            except (TypeError, ValueError):
                pass
            if last_event_id and getattr(get_scan_store(), "distributed", False):
                replay = await run_store_call(
                    get_scan_store(),
                    "list_stream_events",
                    last_event_id,
                    1000,
                    scan_id=scan_id,
                )
                for item in replay:
                    try:
                        data = json.loads(str(item["data_json"]))
                    except Exception:
                        data = {}
                    yield format_sse(
                        str(item["event_type"]),
                        data,
                        int(item["id"]),
                    )
            yield format_sse("connected", {"scan_id": scan_id})
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=30)
                    yield format_sse(msg["event"], msg["data"], msg.get("id"))
                except asyncio.TimeoutError:
                    yield SSE_KEEPALIVE
        except (asyncio.CancelledError, GeneratorExit):
            pass
        finally:
            unsubscribe(scan_id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/api/scan/{scan_id}/fp_review/progress")
async def agent_fp_review_progress(scan_id: str, body: AgentFpReviewProgress) -> dict:
    """Agent reports which vulnerability is currently being reviewed."""
    store = get_scan_store()
    job = await run_store_call(store, "get_fp_review_job", body.review_id)
    if job is None or job.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="FP review not found")
    if job.status == FpReviewStatus.CANCELLED:
        return {"ok": True}
    # Progress is authoritative for a non-cancelled task. This also closes the
    # narrow race where a previous incremental wave finishes while a newly
    # queued item is already starting.
    if job.status not in {FpReviewStatus.PENDING, FpReviewStatus.RUNNING}:
        await run_store_call(
            store,
            "update_fp_review_job",
            body.review_id,
            status="running",
            error_message="",
        )
        logger.info("FP review %s resumed from Agent progress", body.review_id)
    await run_store_call(
        store,
        "update_fp_review_job",
        body.review_id,
        current_vuln_index=body.vuln_index,
        current_vuln_indices=body.active_indices,
        processed=body.processed,
    )
    from backend.sse import publish
    publish(scan_id, "fp_review_progress", {
        "review_id": body.review_id, "vuln_index": body.vuln_index,
        "method": job.method.value,
        "active_indices": body.active_indices,
        "processed": body.processed, "total": job.total,
    })
    logger.debug("FP review progress for %s: vuln[%d]", scan_id, body.vuln_index)
    return {"ok": True}


@router.post("/api/scan/{scan_id}/fp_review/result")
async def agent_fp_review_result(scan_id: str, body: AgentFpReviewResult) -> dict:
    """Agent pushes a single FP review result."""
    store = get_scan_store()
    job = await run_store_call(store, "get_fp_review_job", body.review_id)
    if job is None or job.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="FP review not found")
    if job.status == FpReviewStatus.CANCELLED:
        return {"ok": True}
    if job.status not in {FpReviewStatus.PENDING, FpReviewStatus.RUNNING}:
        await run_store_call(
            store,
            "update_fp_review_job",
            body.review_id,
            status="running",
            error_message="",
        )
        logger.info("FP review %s resumed from Agent result", body.review_id)
    now = datetime.now(timezone.utc).isoformat()
    # 去误报定级简化为二元：tp 且外部可触发（或命中历史/校验匹配）为 high，其余一律 low。
    severity = "high" if (body.verdict == "tp" and body.severity == "high") else "low"
    result = FpReviewResult(
        vuln_index=body.vuln_index,
        verdict=body.verdict,
        severity=severity,
        reason=body.reason,
        vulnerability_report=body.vulnerability_report if body.verdict == "tp" else "",
        stage_outputs=body.stage_outputs,
        match_reference=body.match_reference,
        match_type=body.match_type,
        stage_output_sources=body.stage_output_sources,
        output_source=body.output_source,
        created_at=now,
    )
    await run_store_call(
        store,
        "add_fp_review_result",
        body.review_id,
        result,
    )
    if (
        job.method == FpReviewMethod.FP_CHECK
        and job.summary_status != FpReviewStatus.RUNNING
    ):
        await run_store_call(
            store,
            "update_fp_review_job",
            body.review_id,
            summary_status=FpReviewStatus.PENDING.value,
            summary_error_message="",
        )
    from backend.sse import publish
    publish(scan_id, "fp_review_result", {
        "review_id": body.review_id, "vuln_index": body.vuln_index,
        "method": job.method.value,
        "verdict": body.verdict, "severity": severity, "reason": body.reason,
        "vulnerability_report": result.vulnerability_report,
        "stage_outputs": result.stage_outputs,
        "match_reference": result.match_reference,
        "match_type": result.match_type,
        "stage_output_sources": {
            key: value.model_dump() for key, value in result.stage_output_sources.items()
        },
        "output_source": result.output_source.model_dump(),
    })
    logger.debug("FP review result for %s vuln[%d]: %s", scan_id, body.vuln_index, body.verdict)
    return {"ok": True}


@router.post("/api/scan/{scan_id}/fp_review/stage-output")
async def agent_fp_review_stage_output(scan_id: str, body: AgentFpReviewStageOutput) -> dict:
    """Agent pushes one stage's Markdown output while FP review is running."""
    store = get_scan_store()
    job = await run_store_call(store, "get_fp_review_job", body.review_id)
    if job is None or job.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="FP review not found")
    if job.status == FpReviewStatus.CANCELLED:
        return {"ok": True}
    if job.status not in {FpReviewStatus.PENDING, FpReviewStatus.RUNNING}:
        await run_store_call(
            store,
            "update_fp_review_job",
            body.review_id,
            status="running",
            error_message="",
        )
        logger.info("FP review %s resumed from Agent stage output", body.review_id)
    if body.stage not in _FP_REVIEW_STAGE_KEYS[job.method]:
        raise HTTPException(status_code=400, detail="Invalid FP review stage")
    now = datetime.now(timezone.utc).isoformat()
    await run_store_call(
        store,
        "upsert_fp_review_stage_output",
        body.review_id,
        body.vuln_index,
        body.stage,
        body.markdown,
        now,
        body.output_source,
    )
    from backend.sse import publish
    publish(scan_id, "fp_review_stage_output", {
        "review_id": body.review_id,
        "method": job.method.value,
        "vuln_index": body.vuln_index,
        "stage": body.stage,
        "markdown": body.markdown,
        "output_source": body.output_source.model_dump(),
    })
    logger.debug("FP review stage output for %s vuln[%d]: %s", scan_id, body.vuln_index, body.stage)
    return {"ok": True}


@router.post("/api/scan/{scan_id}/fp_review/finish")
async def agent_fp_review_finish(scan_id: str, body: AgentFpReviewFinish) -> dict:
    """Agent signals the single-item FP review queue is complete."""
    store = get_scan_store()
    job = await run_store_call(store, "get_fp_review_job", body.review_id)
    if job is None or job.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="FP review not found")
    if job.status == FpReviewStatus.CANCELLED:
        return {"ok": True}
    updates: dict = {
        "status": body.status,
        "clear_current_vuln_index": True,
        "error_message": body.error_message or "",
    }
    # Backward compatibility for an older batch fp-check Agent. Empty legacy
    # fields must never erase a separately persisted successful summary.
    if body.summary_markdown.strip():
        updates.update({
            "summary_markdown": body.summary_markdown,
            "summary_output_source": body.summary_output_source,
            "summary_status": FpReviewStatus.COMPLETE.value,
            "summary_error_message": "",
        })
    await run_store_call(
        store,
        "update_fp_review_job",
        body.review_id,
        **updates,
    )
    from backend.sse import publish
    publish(scan_id, "fp_review_finish", {
        "review_id": body.review_id, "status": body.status,
        "method": job.method.value,
        "error_message": body.error_message,
    })
    logger.info("FP review %s finished with status %s", body.review_id, body.status)
    return {"ok": True}


@router.post("/api/scan/{scan_id}/fp_review/summary/finish")
async def agent_fp_review_summary_finish(
    scan_id: str,
    body: AgentFpReviewSummaryFinish,
) -> dict:
    """Agent completes the independent fp-check summary lifecycle."""
    store = get_scan_store()
    job = await run_store_call(store, "get_fp_review_job", body.review_id)
    if (
        job is None
        or job.scan_id != scan_id
        or job.method != FpReviewMethod.FP_CHECK
    ):
        raise HTTPException(status_code=404, detail="fp-check review not found")
    if (
        job.summary_status == FpReviewStatus.CANCELLED
        and body.status != FpReviewStatus.CANCELLED.value
    ):
        return {"ok": True}
    updates: dict = {
        "summary_status": body.status,
        "summary_error_message": body.error_message or "",
    }
    if (
        body.status == FpReviewStatus.COMPLETE.value
        and body.summary_markdown.strip()
    ):
        updates.update({
            "summary_markdown": body.summary_markdown,
            "summary_output_source": body.summary_output_source,
        })
    await run_store_call(
        store,
        "update_fp_review_job",
        body.review_id,
        **updates,
    )
    from backend.sse import publish
    publish(scan_id, "fp_review_summary_finish", {
        "review_id": body.review_id,
        "status": body.status,
        "error_message": body.error_message,
        "summary_markdown": (
            body.summary_markdown
            if body.status == FpReviewStatus.COMPLETE.value
            else None
        ),
        "summary_output_source": (
            body.summary_output_source.model_dump()
            if body.status == FpReviewStatus.COMPLETE.value
            else None
        ),
    })
    logger.info(
        "FP review summary %s finished with status %s",
        body.review_id,
        body.status,
    )
    return {"ok": True}


@router.put("/api/scan/{scan_id}/feedback")
async def update_scan_feedback(
    scan_id: str,
    body: dict,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Update the feedback entry IDs associated with a scan."""
    await _check_scan_owner(scan_id, current_user)
    feedback_ids: list[str] = body.get("feedback_ids", [])
    store = get_scan_store()
    if scan_id in _running_scans:
        _running_scans[scan_id].feedback_ids = feedback_ids
    await run_store_call(
        store,
        "update_scan_feedback_ids",
        scan_id,
        feedback_ids,
    )
    try:
        await _push_feedback_selection_update(scan_id, feedback_ids)
    except Exception as exc:
        logger.debug("Failed to push feedback selection update for scan %s: %s", scan_id, exc)
    return {"ok": True}


@router.get("/api/scan/{scan_id}/skill/{vuln_type}")
async def get_scan_skill(
    scan_id: str,
    vuln_type: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Get the SKILL/prompt content for a vuln_type, merged with scan feedback.

    Reads directly from the checker registry (not the workspace) so it works
    regardless of where the agent runs.  Feedback entries associated with
    this scan are merged into a "历史用户经验" section, same as the agent
    workspace builder does.
    """
    from backend.registry import get_registry

    registry = get_registry()
    entry = registry.get(vuln_type)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Checker not found: {vuln_type}")

    # Read base content
    if entry.mode == "api":
        if not entry.prompt_path or not entry.prompt_path.is_file():
            raise HTTPException(status_code=404, detail=f"prompt.txt not found for {vuln_type}")
        original = entry.prompt_path.read_text(encoding="utf-8")
    else:
        if not entry.skill_path.is_file():
            raise HTTPException(status_code=404, detail=f"SKILL.md not found for {vuln_type}")
        original = entry.skill_path.read_text(encoding="utf-8")

    # Collect only feedback entries selected for this scan.
    all_fb: list[FeedbackEntry] = await run_store_call(
        get_scan_store(),
        _selected_feedback_entries,
        scan_id,
    )

    # Deduplicate by id
    seen: set[str] = set()
    unique_fb: list[FeedbackEntry] = []
    for fb in all_fb:
        if fb.id not in seen:
            seen.add(fb.id)
            unique_fb.append(fb)

    fp_section = build_feedback_section(
        (fb for fb in unique_fb if fb.vuln_type == vuln_type),
        "以下是用户在审计过程中选择注入的经验，分析时应结合这些经验校验结论：",
    )

    return {"vuln_type": vuln_type, "content": original.rstrip() + fp_section}


@router.get("/api/scan/{scan_id}/skill-reports")
async def get_scan_skill_reports(
    scan_id: str,
    checker_name: str | None = None,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return Markdown reports generated by report-mode user SKILLs."""
    await _check_scan_owner(scan_id, current_user)
    reports = await run_store_call(
        get_scan_store(),
        "list_skill_reports",
        scan_id,
        checker_name,
    )
    return {"reports": [report.model_dump() for report in reports]}


@router.get("/api/scan/{scan_id}/fp-review/skill")
async def get_fp_review_skill(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return the FP review skill content, merged with user feedback for this scan."""
    await _check_scan_owner(scan_id, current_user)
    meta = await run_store_call(get_scan_store(), "get_scan_meta", scan_id)
    method = (
        meta.fp_review_method
        if meta is not None
        else FpReviewMethod.ADVERSARIAL
    )
    package_root = Path(__file__).resolve().parent.parent.parent / "deephole_client"
    if method == FpReviewMethod.FP_CHECK:
        skills_dir = package_root / "fp_check_review" / "skills" / "fp-check"
        skill_paths = [
            ("Trail of Bits fp-check 复核", skills_dir / "SKILL.md"),
            ("标准验证", skills_dir / "references" / "standard-verification.md"),
            ("深度验证", skills_dir / "references" / "deep-verification.md"),
            ("六道门复核", skills_dir / "references" / "gate-reviews.md"),
            ("漏洞类别验证", skills_dir / "references" / "bug-class-verification.md"),
            ("误报模式", skills_dir / "references" / "false-positive-patterns.md"),
            ("证据模板", skills_dir / "references" / "evidence-templates.md"),
            ("数据流分析器", skills_dir / "agents" / "data-flow-analyzer.md"),
            ("可利用性验证器", skills_dir / "agents" / "exploitability-verifier.md"),
            ("PoC 构建器", skills_dir / "agents" / "poc-builder.md"),
        ]
    else:
        skills_dir = package_root / "fp_review" / "skills"
        skill_paths = [
            ("prove-bug", skills_dir / "prove_bug.md"),
            ("prove-fp", skills_dir / "prove_fp.md"),
            ("final-judge", skills_dir / "final_judge.md"),
        ]
    missing = [path.name for _, path in skill_paths if not path.is_file()]
    if missing:
        raise HTTPException(status_code=404, detail=f"FP review skill not found: {', '.join(missing)}")

    # Merge only feedback entries selected for this scan.
    all_fb: list[FeedbackEntry] = await run_store_call(
        get_scan_store(),
        _selected_feedback_entries,
        scan_id,
    )

    seen: set[str] = set()
    unique_fb: list[FeedbackEntry] = []
    for fb in all_fb:
        if fb.id not in seen:
            seen.add(fb.id)
            unique_fb.append(fb)

    fp_section = build_feedback_section(
        unique_fb,
        "以下是用户在审计过程中选择注入的经验，复核时应结合这些经验校验结论：",
    )

    content = "\n\n---\n\n".join(
        f"# {name}\n\n{path.read_text(encoding='utf-8').rstrip()}"
        for name, path in skill_paths
    )
    return {"content": content + fp_section}
