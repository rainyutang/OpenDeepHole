"""Scan continuation services."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import secrets
from backend.application import ApplicationError, get_runtime, get_scan_store, run_store_call
from backend.logger import get_logger
from backend.models import (
    MiningEngineRunStatus,
    ScanCandidate,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    ThreatAnalysisRunStatus,
    User,
)
from backend.scans.resume_policy import ResumePlan, _candidate_key

logger = get_logger(__name__)


@dataclass
class ResumeCheckpoint:
    total_candidates: int
    processed_offset: int
    progress: float
    retry_keys: list[tuple[str, int, str, str]]
    removed_processed_keys: list[tuple[str, int, str, str]]
    retry_candidate_indexes: list[int]
    previous_candidate_audits: list[ScanCandidate]
    previous_threat_analysis_run: ThreatAnalysisRunStatus | None
    previous_mining_engine_runs: list[MiningEngineRunStatus]
    pending_threat_analysis_run: ThreatAnalysisRunStatus | None
    pending_mining_engine_runs: list[MiningEngineRunStatus]


def capture_resume_checkpoint(
    scan: ScanStatus,
    meta: ScanMeta,
    processed_keys: set,
    plan: ResumePlan,
) -> ResumeCheckpoint:
    continue_candidates = plan.continue_candidates
    candidate_payload = plan.candidate_payload
    retry_mining_engine_ids = plan.retry_mining_engine_ids
    rerun_threat_analysis = plan.rerun_threat_analysis
    total_candidates = scan.total_candidates or len(scan.candidates) or len(scan.vulnerabilities)
    if candidate_payload is None:
        processed_offset = scan.processed_candidates
        progress = scan.progress
    else:
        processed_offset = max(total_candidates - len(candidate_payload), 0)
        progress = processed_offset / total_candidates if total_candidates > 0 else 0.0

    retry_keys = [_candidate_key(candidate) for candidate in continue_candidates]
    removed_processed_keys = [key for key in retry_keys if key in processed_keys]
    retry_candidate_indexes = [candidate.idx for candidate in continue_candidates]
    previous_candidate_audits = [
        candidate.model_copy(deep=True) for candidate in continue_candidates
    ]

    previous_threat_analysis_run = (
        scan.threat_analysis_run.model_copy(deep=True)
        if scan.threat_analysis_run is not None
        else None
    )
    previous_mining_engine_runs = [
        item.model_copy(deep=True) for item in scan.mining_engine_runs
    ]
    pending_threat_analysis_run = (
        ThreatAnalysisRunStatus()
        if rerun_threat_analysis
        else previous_threat_analysis_run
    )
    engine_runs_by_id = {
        item.engine_id: item.model_copy(deep=True)
        for item in previous_mining_engine_runs
    }
    selection_by_id = {
        item.engine_id: item
        for item in meta.mining_engines
        if item.enabled
    }
    for engine_id in retry_mining_engine_ids:
        selection = selection_by_id.get(engine_id)
        if selection is None:
            continue
        engine_runs_by_id[engine_id] = MiningEngineRunStatus(
            engine_id=engine_id,
            engine_label=selection.engine_label,
        )
    pending_mining_engine_runs = sorted(
        engine_runs_by_id.values(),
        key=lambda item: (item.engine_label, item.engine_id),
    )
    return ResumeCheckpoint(
        total_candidates=total_candidates,
        processed_offset=processed_offset,
        progress=progress,
        retry_keys=retry_keys,
        removed_processed_keys=removed_processed_keys,
        retry_candidate_indexes=retry_candidate_indexes,
        previous_candidate_audits=previous_candidate_audits,
        previous_threat_analysis_run=previous_threat_analysis_run,
        previous_mining_engine_runs=previous_mining_engine_runs,
        pending_threat_analysis_run=pending_threat_analysis_run,
        pending_mining_engine_runs=pending_mining_engine_runs,
    )


async def claim_and_prepare_resume(
    scan_id: str,
    scan: ScanStatus,
    meta: ScanMeta,
    selected,
    plan: ResumePlan,
    checkpoint: ResumeCheckpoint,
    resume_payload: dict,
    server_url: str,
    claimed_execution_revision: int | None,
) -> tuple[int, dict]:
    store = get_scan_store()
    agent_id, agent = selected.agent_id, selected.agent
    runtime_update = resume_payload["agent_runtime_update"]
    resume_threat_analysis = plan.resume_threat_analysis
    retry_mining_engine_ids = plan.retry_mining_engine_ids
    processed_offset = checkpoint.processed_offset
    progress = checkpoint.progress
    retry_keys = checkpoint.retry_keys
    retry_candidate_indexes = checkpoint.retry_candidate_indexes
    pending_threat_analysis_run = checkpoint.pending_threat_analysis_run
    pending_mining_engine_runs = checkpoint.pending_mining_engine_runs
    claimed = await run_store_call(
        store,
        "claim_scan_for_resume",
        scan_id,
        processed_candidates=processed_offset,
        progress=progress,
        expected_revision=meta.execution_revision,
        agent_id=agent_id,
        agent_session_id=agent.agent_session_id,
        claimed_revision=claimed_execution_revision,
    )
    if not claimed:
        raise ApplicationError(status_code=400, detail="Scan is already running")

    execution_revision = claimed
    try:
        resume_payload["execution_revision"] = execution_revision
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
                "execution_revision": execution_revision,
                "resume_manifest_url": (
                    f"{server_url}"
                    f"/api/agent/v2/resume-manifests/{manifest_token}"
                ),
                "agent_runtime_update": runtime_update,
            }
        else:
            command = resume_payload

        scan.opencode_pool = await run_store_call(
            store, "normalize_scan_pool", scan_id, scan.opencode_pool, terminal_scan=True,
        )
        if scan.opencode_pool is not None:
            scan.opencode_pool = scan.opencode_pool.model_copy(update={
                "execution_revision": execution_revision,
                "agent_session_id": agent.agent_session_id,
            })
        if resume_threat_analysis or retry_mining_engine_ids:
            replaced = await run_store_call(
                store,
                "replace_scan_stage_runs",
                scan_id,
                pending_threat_analysis_run,
                pending_mining_engine_runs,
            )
            if not replaced:
                raise ApplicationError(status_code=404, detail="Scan not found")
            scan.threat_analysis_run = pending_threat_analysis_run
            scan.mining_engine_runs = pending_mining_engine_runs

        scan.status = ScanItemStatus.PENDING
        scan.execution_revision = execution_revision
        scan.error_message = None
        scan.current_candidate = None
        scan.agent_name = agent.name
        scan.agent_online = True
        scan.processed_candidates = processed_offset
        scan.progress = progress
        await run_store_call(
            store,
            "reset_scan_candidate_audits",
            scan_id,
            retry_candidate_indexes,
        )
        retry_index_set = set(retry_candidate_indexes)
        scan.candidates = [
            candidate.model_copy(update={
                "audit_state": "pending",
                "audit_result": None,
                "vulnerability_idx": None,
                "dedup_decision": {},
                "audit_updated_at": "",
            })
            if candidate.idx in retry_index_set
            else candidate
            for candidate in scan.candidates
        ]
        await run_store_call(store, "remove_processed_keys", scan_id, retry_keys)
    except Exception as exc:
        logger.exception("Failed to prepare scan resume for %s", scan_id)
        await run_store_call(
            store, "fail_scan_execution", scan_id,
            agent_session_id=agent.agent_session_id,
            execution_revision=execution_revision,
            error_message="续扫准备失败，请稍后再次续扫",
        )
        raise ApplicationError(status_code=502, detail="续扫准备失败，请稍后再次续扫") from exc

    return execution_revision, command


async def dispatch_resume(
    scan_id: str,
    scan: ScanStatus,
    current_user: User,
    selected,
    plan: ResumePlan,
    checkpoint: ResumeCheckpoint,
    command: dict,
) -> None:
    from backend.agents.gateway import send_agent_command
    store = get_scan_store()
    agent_id = selected.agent_id
    resume_threat_analysis = plan.resume_threat_analysis
    retry_mining_engine_ids = plan.retry_mining_engine_ids
    removed_processed_keys = checkpoint.removed_processed_keys
    previous_candidate_audits = checkpoint.previous_candidate_audits
    previous_threat_analysis_run = checkpoint.previous_threat_analysis_run
    previous_mining_engine_runs = checkpoint.previous_mining_engine_runs
    get_runtime().scans.running_scans[scan_id] = scan
    get_runtime().scans.scan_owners[scan_id] = current_user.user_id

    try:
        ok = await send_agent_command(agent_id, command)
    except Exception:
        logger.exception(
            "Failed to dispatch resume command for scan %s via agent %s",
            scan_id,
            agent_id,
        )
        ok = False
    if not ok:
        if resume_threat_analysis or retry_mining_engine_ids:
            await run_store_call(
                store,
                "replace_scan_stage_runs",
                scan_id,
                previous_threat_analysis_run,
                previous_mining_engine_runs,
            )
            scan.threat_analysis_run = previous_threat_analysis_run
            scan.mining_engine_runs = previous_mining_engine_runs
        await run_store_call(
            store,
            "add_processed_keys_batch",
            scan_id,
            removed_processed_keys,
        )
        for candidate in previous_candidate_audits:
            await run_store_call(
                store,
                "update_scan_candidate_audit",
                scan_id,
                candidate.idx,
                state=candidate.audit_state,
                result=candidate.audit_result,
                vulnerability_idx=candidate.vulnerability_idx,
                dedup_decision=candidate.dedup_decision,
            )
        restored_by_index = {
            candidate.idx: candidate for candidate in previous_candidate_audits
        }
        scan.candidates = [
            restored_by_index.get(candidate.idx, candidate)
            for candidate in scan.candidates
        ]
        await run_store_call(
            store,
            "update_scan_progress",
            scan_id,
            status=ScanItemStatus.ERROR,
            error_message="Agent not connected",
        )
        scan.status = ScanItemStatus.ERROR
        get_runtime().scans.running_scans.pop(scan_id, None)
        get_runtime().scans.scan_owners.pop(scan_id, None)
        logger.error("Failed to resume scan %s: agent %s not connected", scan_id, agent_id)
        raise ApplicationError(status_code=502, detail="Agent not connected")
