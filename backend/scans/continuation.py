"""Scan continuation services."""

from dataclasses import dataclass
from deephole_client.scan_modes import STATIC_ANALYSIS_ENGINE_IDS
import asyncio
from backend.application import ApplicationError, get_runtime, get_scan_store, run_store_call
from backend.logger import get_logger
from backend.models import (
    AgentInfo,
    AgentRemoteConfig,
    ScanItemStatus,
    ScanMeta,
    ScanStartResponse,
    ScanStatus,
    User,
)
from backend.scan_metrics import latest_fp_review_result_map
from backend.scan_runtime import AGENT_RECOVERY_IN_PROGRESS
from backend.scans.access import _check_scan_owner_v2
from backend.scans.configuration import (
    _checker_packages_for,
    _is_threat_analysis_only_mode,
    _resolve_threat_analysis_method,
)
from backend.scans.feedback_selection import _selected_feedback_entries
from backend.scans.fp_review import _start_fp_review
from backend.scans.fp_review_policy import _fp_review_resume_state
from backend.scans.resume_execution import (
    ResumeCheckpoint,
    capture_resume_checkpoint,
    claim_and_prepare_resume,
    dispatch_resume,
)
from backend.scans.resume_policy import ResumePlan, build_resume_plan

logger = get_logger(__name__)


@dataclass
class ResumeAgent:
    agent_id: str
    agent: AgentInfo
    managed_config: AgentRemoteConfig


async def _prepare_resume_agent(
    scan_id: str,
    meta: ScanMeta,
    current_user: User,
    claimed_execution_revision: int | None,
) -> ResumeAgent:
    from backend.agents.configuration import agent_config_has_explicit_model, get_scan_agent_config_async
    from backend.agents.directory import resolve_agent_connection_async
    from backend.agents.runtime_updates import ensure_agent_accepting_tasks_async
    store = get_scan_store()
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
        agent = get_runtime().agents.registered_agents.get(agent_id) if agent_id else None

    # If original agent_id is stale (reconnected), find it by name
    if agent is None and meta.agent_name:
        for aid, ainfo in get_runtime().agents.registered_agents.items():
            if ainfo.name == meta.agent_name and aid in get_runtime().agents.agent_ws:
                if current_user.role == "admin" or ainfo.user_id == current_user.user_id:
                    agent = ainfo
                    agent_id = aid
                    break

    if agent is None:
        raise ApplicationError(
            status_code=400,
            detail=f"扫描关联的 Agent「{meta.agent_name or '未知'}」不在线，请先启动该 Agent",
        )

    if (
        claimed_execution_revision is not None
        and meta.execution_agent_session_id != agent.agent_session_id
    ):
        raise ApplicationError(status_code=409, detail="自动恢复 Agent 会话已过期")
    await ensure_agent_accepting_tasks_async(meta.agent_key or agent.agent_key)
    managed_config = await get_scan_agent_config_async(agent, meta.agent_key)
    if not agent_config_has_explicit_model(managed_config):
        raise ApplicationError(
            status_code=400,
            detail="扫描关联的客户端尚未配置启用的显式模型，请先完成客户端模型配置",
        )

    if not agent.scan_paths_probe and any(
        scope.code_scan_paths and scope.code_scan_paths != [scope.code_scan_path or scope.project_path]
        for scope in (meta, *meta.multi_versions)
    ):
        raise ApplicationError(status_code=409, detail="请先更新 Agent 后续扫（当前 Agent 不支持多路径和单文件扫描范围）")

    # Confirm local quiescence before changing progress/checkpoints or reserving
    # a new identity. The revision bound protects a competing newer resume from
    # a delayed stop RPC issued by this server_url.
    from backend.agents.gateway import request_agent_scan_stop

    acknowledgement = await request_agent_scan_stop(
        agent_id, scan_id, execution_revision=meta.execution_revision,
    )
    if (
        not isinstance(acknowledgement, dict)
        or acknowledgement.get("still_active") is not False
        or str(acknowledgement.get("error") or "").strip()
    ):
        raise ApplicationError(
            status_code=409,
            detail="旧扫描尚未确认退出或清理超时，未启动续扫；请稍后再次续扫",
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

    return ResumeAgent(
        agent_id=agent_id,
        agent=agent,
        managed_config=managed_config,
    )


async def _resume_payload(
    scan_id: str,
    meta: ScanMeta,
    selected: ResumeAgent,
    plan: ResumePlan,
    checkpoint: ResumeCheckpoint,
    server_url: str,
) -> dict:
    from backend.agents.configuration import agent_explicit_model_ids
    store = get_scan_store()
    managed_config = selected.managed_config
    candidate_payload = plan.candidate_payload
    resume_threat_analysis = plan.resume_threat_analysis
    retry_mining_engine_ids = plan.retry_mining_engine_ids
    threat_task_ids = plan.threat_task_ids
    total_candidates = checkpoint.total_candidates
    processed_offset = checkpoint.processed_offset
    from backend.agents.artifacts import create_agent_task_runtime_update_payload_async
    selected_feedback = await run_store_call(
        store,
        _selected_feedback_entries,
        scan_id,
        meta.feedback_ids,
    )
    feedback_entries = [entry.model_dump() for entry in selected_feedback]
    runtime_update = await create_agent_task_runtime_update_payload_async(
        server_url,
        meta.agent_key,
    )
    from backend.review_notes import scan_review_notes_payload

    resume_payload = {
        "type": "resume",
        "scan_id": scan_id,
        "review_notes": await scan_review_notes_payload(scan_id, store=store),
        "project_path": meta.project_path,
        "code_scan_path": meta.code_scan_path or meta.project_path,
        "code_scan_paths": meta.code_scan_paths or [meta.code_scan_path or meta.project_path],
        "multi_versions": [
            item.model_dump(mode="json") for item in meta.multi_versions
        ],
        "checkers": meta.scan_items,
        "scan_mode": meta.scan_mode,
        "threat_analysis_enabled": meta.threat_analysis_enabled,
        "threat_analysis_method": meta.threat_analysis_method,
        "scan_name": meta.scan_name,
        "product": meta.runtime_product,
        "validation_environment": meta.validation_environment,
        "vulnerability_validation": (
            meta.vulnerability_validation.model_dump(mode="json")
            if meta.vulnerability_validation is not None
            else None
        ),
        "feedback_entries": feedback_entries,
        "checker_packages": (
            []
            if (
                _is_threat_analysis_only_mode(meta.scan_mode)
                or (
                    bool(meta.mining_engines)
                    and not any(
                        item.enabled
                        and item.engine_id in STATIC_ANALYSIS_ENGINE_IDS
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
            [
                candidate.model_dump(
                    mode="json",
                    exclude={
                        "audit_state",
                        "audit_result",
                        "vulnerability_idx",
                        "dedup_decision",
                        "audit_updated_at",
                    },
                )
                for candidate in candidate_payload
            ]
            if candidate_payload is not None
            else None
        ),
        "retry_total_candidates": total_candidates,
        "retry_processed_offset": processed_offset,
        "resume_threat_analysis": resume_threat_analysis,
        "retry_mining_engine_ids": retry_mining_engine_ids,
        "retry_threat_audit_task_ids": threat_task_ids,
        "codex_model_ids": agent_explicit_model_ids(managed_config),
        "code_graph_mcp_revision": meta.code_graph_mcp_revision,
        "code_graph_mcp": (
            meta.code_graph_mcp.model_dump(mode="json")
            if meta.code_graph_mcp is not None
            else None
        ),
        "knowledge_base_mcp": (
            meta.knowledge_base_mcp.model_dump(mode="json")
            if meta.knowledge_base_mcp is not None
            else None
        ),
        "agent_runtime_update": runtime_update,
    }
    return resume_payload


async def _finish_resume(
    scan_id: str,
    scan: ScanStatus,
    selected: ResumeAgent,
    plan: ResumePlan,
    checkpoint: ResumeCheckpoint,
    execution_revision: int,
    fp_resume_count: int,
    claimed_execution_revision: int | None,
    server_url: str,
) -> ScanStartResponse:
    agent_id = selected.agent_id
    incomplete_threat_tasks = plan.incomplete_threat_tasks
    candidate_payload = plan.candidate_payload
    resume_threat_analysis = plan.resume_threat_analysis
    retry_mining_engine_ids = plan.retry_mining_engine_ids
    total_candidates = checkpoint.total_candidates
    processed_offset = checkpoint.processed_offset
    progress = checkpoint.progress
    logger.info(
        "Continuing scan %s via agent %s: candidates=%s threat_tasks=%d engines=%s threat_analysis=%s",
        scan_id,
        agent_id,
        "full-pipeline" if candidate_payload is None else len(candidate_payload),
        len(incomplete_threat_tasks),
        retry_mining_engine_ids,
        resume_threat_analysis,
    )
    from backend.application import publish

    publish(scan_id, "scan_status", {
        "execution_revision": execution_revision,
        "status": ScanItemStatus.PENDING,
        "progress": progress,
        "total_candidates": total_candidates,
        "processed_candidates": processed_offset,
        "error_message": "",
        "opencode_pool": (
            scan.opencode_pool.model_dump(mode="json")
            if scan.opencode_pool is not None
            else None
        ),
    })
    if fp_resume_count:
        fp_resume = await _start_fp_review(
            scan_id,
            server_url,
            raise_on_error=False,
            require_unresolved=True,
            allow_cancelled=claimed_execution_revision is None,
        )
        if fp_resume is None:
            logger.warning(
                "Main scan %s resumed, but its %d FP-review items remain retryable",
                scan_id,
                fp_resume_count,
            )
    return ScanStartResponse(scan_id=scan_id)


async def _continue_scan(
    scan_id: str,
    server_url: str,
    current_user: User,
    *,
    server_url_override: str = "",
    skip_owner_check: bool = False,
    claimed_execution_revision: int | None = None,
) -> ScanStartResponse:
    """Continue all unfinished and retryable work for one scan."""
    if not skip_owner_check:
        await _check_scan_owner_v2(scan_id, current_user)
    server_url = server_url_override or server_url
    if not server_url:
        raise RuntimeError("scan continuation requires server_url")

    store = get_scan_store()
    result = await run_store_call(store, "load_scan", scan_id)
    if result is None:
        raise ApplicationError(status_code=404, detail="Scan not found")

    scan, meta = result
    if claimed_execution_revision is not None and (
        meta.execution_revision != claimed_execution_revision
        or scan.status != ScanItemStatus.CANCELLED
        or scan.error_message != AGENT_RECOVERY_IN_PROGRESS
    ):
        raise ApplicationError(status_code=409, detail="自动恢复已被停止或轮次已过期")
    if scan.status in {ScanItemStatus.PENDING, ScanItemStatus.ANALYZING, ScanItemStatus.AUDITING}:
        raise ApplicationError(status_code=400, detail="Scan is already running")
    # PostgreSQL workers keep process-local scan caches only as an optimization.
    # A cancellation handled by another worker can leave this entry behind even
    # though the durable row is terminal; never let that stale cache veto resume.
    get_runtime().scans.running_scans.pop(scan_id, None)
    get_runtime().scans.scan_owners.pop(scan_id, None)

    processed_keys, fp_verdicts, fp_states = await asyncio.gather(
        run_store_call(store, "get_processed_keys", scan_id),
        run_store_call(store, "list_fp_review_verdicts_by_scans", [scan_id]),
        run_store_call(store, "list_fp_review_states_by_scans", [scan_id]),
    )
    fp_review_running, fp_resume_count = _fp_review_resume_state(
        scan.vulnerabilities,
        latest_fp_review_result_map(fp_verdicts.get(scan_id, [])),
        fp_states.get(scan_id, []),
    )
    # Restart recovery owns a fenced scan revision. Independent reviews are
    # adopted/recovered separately and must not veto restoration of that scan.
    if fp_review_running and claimed_execution_revision is None:
        raise ApplicationError(status_code=400, detail="去误报任务正在运行")
    plan = build_resume_plan(scan, meta, processed_keys)
    if not plan.resume_main_scan and fp_resume_count == 0:
        raise ApplicationError(status_code=400, detail="当前扫描没有可续扫的任务")
    if not plan.resume_main_scan:
        await _start_fp_review(
            scan_id, server_url, raise_on_error=True,
            require_unresolved=True, allow_cancelled=True,
        )
        logger.info("Continuing scan %s with FP-review work only: unresolved=%d", scan_id, fp_resume_count)
        return ScanStartResponse(scan_id=scan_id)
    if meta.threat_analysis_enabled:
        try:
            _resolve_threat_analysis_method(meta.threat_analysis_method)
        except ApplicationError as exc:
            raise ApplicationError(
                status_code=400,
                detail=(
                    "扫描关联的威胁分析方法当前不可用："
                    f"{meta.threat_analysis_method}"
                ),
            ) from exc
    selected = await _prepare_resume_agent(scan_id, meta, current_user, claimed_execution_revision)
    checkpoint = capture_resume_checkpoint(scan, meta, processed_keys, plan)
    payload = await _resume_payload(scan_id, meta, selected, plan, checkpoint, server_url)
    revision, command = await claim_and_prepare_resume(
        scan_id, scan, meta, selected, plan, checkpoint, payload, server_url, claimed_execution_revision,
    )
    await dispatch_resume(scan_id, scan, current_user, selected, plan, checkpoint, command)
    return await _finish_resume(
        scan_id, scan, selected, plan, checkpoint, revision,
        fp_resume_count, claimed_execution_revision, server_url,
    )


async def resume_scan(
    scan_id: str,
    server_url: str,
    current_user: User = None,
) -> ScanStartResponse:
    return await _continue_scan(scan_id, server_url, current_user)


async def retry_incomplete_scan(
    scan_id: str,
    server_url: str,
    current_user: User = None,
) -> ScanStartResponse:
    """Compatibility alias for the unified continue action."""
    return await _continue_scan(scan_id, server_url, current_user)
