"""Scan creation services."""

from dataclasses import dataclass
from datetime import datetime, timezone
import secrets
import uuid
from backend.application import ApplicationError, get_runtime, get_scan_store, run_store_call
from backend.logger import get_logger
from backend.models import (
    AgentInfo,
    AgentRemoteConfig,
    CreateScanRequest,
    MiningEngineRunStatus,
    MultiVersionTarget,
    ScanItemStatus,
    ScanMeta,
    ScanStartResponse,
    ScanStatus,
    ScanVulnerabilityValidationConfig,
    ThreatAnalysisRunStatus,
    User,
)
from backend.scans.configuration import (
    _default_scan_name_base,
    _record_validator_catalog,
    _remember_scan_configuration,
    _resolve_scan_validation,
)
from backend.scans.creation_config import ResolvedScanConfiguration, resolve_creation_configuration
from backend.scans.feedback_selection import _selected_feedback_entries
from backend.store.base import DuplicateScanNameError

logger = get_logger(__name__)


@dataclass
class CreationAgent:
    agent_id: str
    selected_agent_key: str
    agent: AgentInfo
    managed_config: AgentRemoteConfig


@dataclass
class CreationIdentity:
    scan_id: str
    now: str
    requested_scan_name: str
    generated_name_base: str
    generated_name_seed: int
    scan_name: str
    product: str


async def _select_creation_agent(
    body: CreateScanRequest,
    current_user: User,
    enforce_agent_owner: bool,
) -> CreationAgent:
    from backend.agents.configuration import agent_config_has_explicit_model, get_scan_agent_config_async
    from backend.agents.runtime_updates import ensure_agent_accepting_tasks_async
    from backend.agents.directory import resolve_agent_connection_async, resolve_agent_id_connection_async

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
        agent = by_id[1] if by_id is not None else get_runtime().agents.registered_agents.get(agent_id)
        if agent is not None:
            selected_agent_key = agent.agent_key
    if agent is None:
        raise ApplicationError(status_code=404, detail="所选 Agent 不在线")

    # Verify the agent belongs to this user (or user is admin)
    if enforce_agent_owner and current_user.role != "admin" and agent.user_id != current_user.user_id:
        raise ApplicationError(status_code=403, detail="Agent does not belong to you")
    await ensure_agent_accepting_tasks_async(selected_agent_key)
    managed_config = await get_scan_agent_config_async(agent, selected_agent_key)
    if not agent_config_has_explicit_model(managed_config):
        raise ApplicationError(
            status_code=400,
            detail="所选客户端尚未配置启用的显式模型，请先在客户端配置页面手动添加模型",
        )
    return CreationAgent(
        agent_id=agent_id,
        selected_agent_key=selected_agent_key,
        agent=agent,
        managed_config=managed_config,
    )


def _creation_identity(body: CreateScanRequest, project_path: str) -> CreationIdentity:
    scan_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    requested_scan_name = str(body.scan_name or "").strip()
    generated_name_base = _default_scan_name_base(project_path)
    generated_name_seed = secrets.randbelow(0x10000)
    scan_name = (
        requested_scan_name
        if requested_scan_name
        else f"{generated_name_base}_{generated_name_seed:04x}"
    )
    product = str(body.product or "").strip()
    if str(body.validation_environment or "").strip():
        raise ApplicationError(
            status_code=422,
            detail="validation_environment 已废弃，请选择验证方法并填写 field 配置",
        )
    return CreationIdentity(
        scan_id=scan_id,
        now=now,
        requested_scan_name=requested_scan_name,
        generated_name_base=generated_name_base,
        generated_name_seed=generated_name_seed,
        scan_name=scan_name,
        product=product,
    )


async def _creation_validation(
    body: CreateScanRequest,
    identity: CreationIdentity,
    selected: CreationAgent,
) -> ScanVulnerabilityValidationConfig | None:
    selected_agent_key, managed_config = selected.selected_agent_key, selected.managed_config
    product = identity.product
    record = await run_store_call(
        get_scan_store(),
        "get_agent_record",
        selected_agent_key,
    )
    validation_config = _resolve_scan_validation(
        body.vulnerability_validation,
        product=product,
        catalog=_record_validator_catalog(record),
        policy=managed_config.vulnerability_validation,
    )

    return validation_config


async def _preflight_creation_paths(
    selected: CreationAgent,
    configuration: ResolvedScanConfiguration,
) -> None:
    from backend.agents.gateway import request_agent_scan_paths
    agent_id, agent = selected.agent_id, selected.agent
    multi_versions = configuration.multi_versions
    project_path = configuration.project_path
    code_scan_path = configuration.code_scan_path
    code_scan_paths = configuration.code_scan_paths
    # Resolve Agent-local files before persisting any scan or execution state.
    targets = [item.model_dump(mode="json") for item in multi_versions] if multi_versions else [{
        "project_path": project_path, "code_scan_path": code_scan_path,
        "code_scan_paths": code_scan_paths,
    }]
    checked_targets = await request_agent_scan_paths(agent_id, agent, targets)
    if multi_versions:
        multi_versions = [MultiVersionTarget(
            version_name=version.version_name, **checked,
        ) for version, checked in zip(multi_versions, checked_targets)]
    project_path = checked_targets[0]["project_path"]
    code_scan_path = checked_targets[0]["code_scan_path"]
    code_scan_paths = checked_targets[0]["code_scan_paths"]

    configuration.multi_versions = multi_versions
    configuration.project_path = project_path
    configuration.code_scan_path = code_scan_path
    configuration.code_scan_paths = code_scan_paths


def _creation_records(
    body: CreateScanRequest,
    current_user: User,
    selected: CreationAgent,
    configuration: ResolvedScanConfiguration,
    identity: CreationIdentity,
    validation_config: ScanVulnerabilityValidationConfig | None,
    public_access_token: str,
) -> tuple[ScanStatus, ScanMeta]:
    agent_id = selected.agent_id
    selected_agent_key = selected.selected_agent_key
    agent = selected.agent
    project_path = configuration.project_path
    code_scan_path = configuration.code_scan_path
    code_scan_paths = configuration.code_scan_paths
    multi_versions = configuration.multi_versions
    scan_mode = configuration.scan_mode
    threat_analysis_enabled = configuration.threat_analysis_enabled
    threat_analysis_method = configuration.threat_analysis_method
    threat_analysis_method_selection = configuration.threat_analysis_method_selection
    auto_fp_review = configuration.auto_fp_review
    fp_review_method = configuration.fp_review_method
    fp_review_method_selection = configuration.fp_review_method_selection
    validated_checker_names = configuration.validated_checker_names
    mining_engine_selections = configuration.mining_engine_selections
    code_graph_mcp = configuration.code_graph_mcp
    knowledge_base_mcp = configuration.knowledge_base_mcp
    scan_id = identity.scan_id
    now = identity.now
    scan_name = identity.scan_name
    product = identity.product
    scan = ScanStatus(
        scan_id=scan_id,
        project_id=scan_name,
        scan_name=scan_name,
        project_path=project_path,
        code_scan_path=code_scan_path,
        code_scan_paths=code_scan_paths,
        multi_versions=multi_versions,
        scan_mode=scan_mode,
        threat_analysis_enabled=threat_analysis_enabled,
        threat_analysis_method=threat_analysis_method,
        threat_analysis_method_selection=threat_analysis_method_selection,
        threat_analysis_run=(
            ThreatAnalysisRunStatus()
            if threat_analysis_enabled
            else None
        ),
        auto_fp_review=auto_fp_review,
        fp_review_method=fp_review_method,
        fp_review_method_selection=fp_review_method_selection,
        product=product,
        validation_environment="",
        code_graph_mcp_enabled=code_graph_mcp is not None,
        knowledge_base_enabled=knowledge_base_mcp is not None,
        vulnerability_validation_enabled=validation_config is not None,
        validation_method_id=(validation_config.method_id if validation_config else ""),
        validation_method_label=(validation_config.method_label if validation_config else ""),
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
        threat_analysis_method=threat_analysis_method,
        threat_analysis_method_selection=threat_analysis_method_selection,
        mining_engines=mining_engine_selections,
        auto_fp_review=auto_fp_review,
        fp_review_method=fp_review_method,
        fp_review_method_selection=fp_review_method_selection,
        feedback_ids=body.feedback_ids,
        agent_id=agent_id,
        agent_key=selected_agent_key,
        agent_name=agent.name,
        project_path=project_path,
        code_scan_path=code_scan_path,
        code_scan_paths=code_scan_paths,
        multi_versions=multi_versions,
        scan_name=scan_name,
        product=product,
        validation_environment="",
        knowledge_base_enabled=knowledge_base_mcp is not None,
        vulnerability_validation_enabled=validation_config is not None,
        validation_method_id=(validation_config.method_id if validation_config else ""),
        validation_method_label=(validation_config.method_label if validation_config else ""),
        user_id=current_user.user_id,
        public_access_token=public_access_token,
        code_graph_mcp=code_graph_mcp,
        knowledge_base_mcp=knowledge_base_mcp,
        vulnerability_validation=validation_config,
    )

    return scan, meta


async def _persist_creation(
    body: CreateScanRequest,
    current_user: User,
    identity: CreationIdentity,
    scan: ScanStatus,
    meta: ScanMeta,
) -> dict | None:
    scan_id = identity.scan_id
    requested_scan_name = identity.requested_scan_name
    generated_name_base = identity.generated_name_base
    generated_name_seed = identity.generated_name_seed
    scan_name = identity.scan_name
    store = get_scan_store()
    if body.review_note_ids:
        try:
            await run_store_call(store, "validate_review_note_ids", current_user.user_id, body.review_note_ids)
        except ValueError as exc:
            raise ApplicationError(status_code=422, detail=str(exc)) from exc
    for name_attempt in range(0x10000):
        if not requested_scan_name:
            scan_name = (
                f"{generated_name_base}_"
                f"{(generated_name_seed + name_attempt) & 0xFFFF:04x}"
            )
            scan.project_id = scan_name
            scan.scan_name = scan_name
            meta.scan_name = scan_name
        try:
            await run_store_call(store, "save_scan", scan, meta)
            break
        except DuplicateScanNameError as exc:
            if requested_scan_name:
                raise ApplicationError(
                    status_code=409,
                    detail=f"扫描名称「{requested_scan_name}」已存在，请修改后重试",
                ) from exc
    else:
        raise ApplicationError(
            status_code=409,
            detail=f"无法为项目「{generated_name_base}」生成不重复的扫描名称",
        )
    review_notes = None
    if body.review_notes_enabled or body.review_note_ids:
        try:
            review_notes = await run_store_call(
                store, "set_scan_review_notes", scan_id, current_user.user_id,
                body.review_notes_enabled, body.review_note_ids,
            )
        except ValueError as exc:
            # A selected note can be deleted after the initial validation.
            # This new scan has not been dispatched or exposed in local state.
            await run_store_call(store, "update_scan_progress", scan_id,
                                 status=ScanItemStatus.ERROR, error_message=str(exc))
            await run_store_call(store, "delete_scan", scan_id)
            raise ApplicationError(status_code=422, detail=str(exc)) from exc
    get_runtime().scans.running_scans[scan_id] = scan
    get_runtime().scans.scan_owners[scan_id] = current_user.user_id

    return review_notes


async def _dispatch_creation(
    body: CreateScanRequest,
    server_url: str,
    selected: CreationAgent,
    configuration: ResolvedScanConfiguration,
    identity: CreationIdentity,
    scan: ScanStatus,
    meta: ScanMeta,
    review_notes: dict | None,
    validation_config: ScanVulnerabilityValidationConfig | None,
) -> None:
    from backend.agents.configuration import agent_explicit_model_ids
    store = get_scan_store()
    agent_id = selected.agent_id
    selected_agent_key = selected.selected_agent_key
    agent = selected.agent
    managed_config = selected.managed_config
    project_path = configuration.project_path
    code_scan_path = configuration.code_scan_path
    code_scan_paths = configuration.code_scan_paths
    multi_versions = configuration.multi_versions
    scan_mode = configuration.scan_mode
    threat_analysis_enabled = configuration.threat_analysis_enabled
    threat_analysis_method = configuration.threat_analysis_method
    validated_checker_names = configuration.validated_checker_names
    checker_packages = configuration.checker_packages
    mining_engine_selections = configuration.mining_engine_selections
    code_graph_mcp = configuration.code_graph_mcp
    knowledge_base_mcp = configuration.knowledge_base_mcp
    scan_id = identity.scan_id
    scan_name = identity.scan_name
    product = identity.product
    scan_name = scan.scan_name
    # Dispatch to agent via WebSocket
    from backend.agents.artifacts import create_agent_task_runtime_update_payload_async
    from backend.agents.gateway import send_agent_command
    selected_feedback = await run_store_call(
        store,
        _selected_feedback_entries,
        scan_id,
        body.feedback_ids,
    )
    feedback_entries = [entry.model_dump() for entry in selected_feedback]
    execution_revision = await run_store_call(
        store,
        "begin_scan_execution",
        scan_id,
        agent_id=agent_id,
        agent_session_id=agent.agent_session_id,
    )
    scan.execution_revision = execution_revision
    command = {
        "type": "task",
        "scan_id": scan_id,
        "review_notes": review_notes,
        "execution_revision": execution_revision,
        "project_path": project_path,
        "code_scan_path": code_scan_path,
        "code_scan_paths": code_scan_paths,
        "multi_versions": [
            item.model_dump(mode="json") for item in multi_versions
        ],
        "checkers": validated_checker_names,
        "scan_mode": scan_mode,
        "threat_analysis_enabled": threat_analysis_enabled,
        "threat_analysis_method": threat_analysis_method,
        "scan_name": scan_name,
        "product": product,
        "validation_environment": "",
        "vulnerability_validation": (
            validation_config.model_dump(mode="json")
            if validation_config is not None
            else None
        ),
        "feedback_entries": feedback_entries,
        "checker_packages": checker_packages,
        "mining_engines": [
            item.model_dump(mode="json")
            for item in mining_engine_selections
        ],
        "codex_model_ids": agent_explicit_model_ids(managed_config),
        "code_graph_mcp_revision": meta.code_graph_mcp_revision,
        "code_graph_mcp": (
            code_graph_mcp.model_dump(mode="json")
            if code_graph_mcp is not None
            else None
        ),
        "knowledge_base_mcp": (
            knowledge_base_mcp.model_dump(mode="json")
            if knowledge_base_mcp is not None
            else None
        ),
        "agent_runtime_update": await create_agent_task_runtime_update_payload_async(
            server_url,
            selected_agent_key,
        ),
    }
    ok = await send_agent_command(agent_id, command)
    if not ok:
        await run_store_call(
            store,
            "update_scan_progress",
            scan_id,
            status=ScanItemStatus.ERROR,
            error_message="Agent not connected",
        )
        scan.status = ScanItemStatus.ERROR
        get_runtime().scans.running_scans.pop(scan_id, None)
        logger.error("Failed to dispatch scan %s: agent %s not connected", scan_id, agent_id)
        raise ApplicationError(status_code=502, detail="Agent not connected")


async def create_agent_scan(
    body: CreateScanRequest,
    server_url: str,
    current_user: User,
    *,
    checker_names: list[str] | None = None,
    public_access_token: str = "",
    enforce_agent_owner: bool = True,
) -> ScanStartResponse:
    """Resolve, preflight, persist and dispatch one new scan in that order."""
    selected = await _select_creation_agent(body, current_user, enforce_agent_owner)
    configuration = resolve_creation_configuration(body, selected.managed_config, current_user, checker_names)
    identity = _creation_identity(body, configuration.project_path)
    validation = await _creation_validation(body, identity, selected)
    await _preflight_creation_paths(selected, configuration)
    scan, meta = _creation_records(body, current_user, selected, configuration, identity, validation, public_access_token)
    review_notes = await _persist_creation(body, current_user, identity, scan, meta)
    await _dispatch_creation(body, server_url, selected, configuration, identity, scan, meta, review_notes, validation)
    await _remember_scan_configuration(
        user_id=current_user.user_id,
        agent_key=selected.selected_agent_key,
        product=identity.product,
        knowledge_base_mcp=configuration.knowledge_base_mcp,
        validation=validation,
    )
    logger.info(
        "Created scan %s for project '%s', dispatched to agent %s (%s)",
        scan.scan_id, scan.scan_name, selected.agent_id, selected.agent.ip,
    )
    return ScanStartResponse(scan_id=scan.scan_id)


async def create_scan(
    body: CreateScanRequest,
    server_url: str,
    current_user: User,
) -> ScanStartResponse:
    """Create a new scan and dispatch it to the specified agent daemon."""
    return await create_agent_scan(body, server_url, current_user)
