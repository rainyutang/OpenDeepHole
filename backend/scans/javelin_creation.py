"""Isolated scan creation pipeline for Java + Javelin scans."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from backend.application import ApplicationError, get_config, get_runtime, get_scan_store, run_store_call
from backend.logger import get_logger
from backend.models import (
    CreateScanRequest,
    FpReviewMethod,
    JAVELIN_CONTRACT_VERSION,
    JAVELIN_ENGINE_ID,
    JAVELIN_ENGINE_LABEL,
    JavelinScanConfig,
    MiningEngineRunStatus,
    MiningEngineSelection,
    ScanItemStatus,
    ScanMeta,
    ScanStartResponse,
    ScanStatus,
    User,
    has_javelin_engine,
)
from backend.scans.configuration import _validate_absolute_scan_path
from backend.scans.creation import (
    _creation_identity,
    _persist_creation,
    _select_creation_agent,
)
from backend.scans.javelin_sanitizer import (
    encrypt_secret_context,
    log_secret_context_audit,
)

logger = get_logger(__name__)


def is_javelin_creation_request(body: CreateScanRequest) -> bool:
    if body.language == "java":
        return True
    return has_javelin_engine(body.mining_engines)


async def create_javelin_scan(
    body: CreateScanRequest,
    server_url: str,
    current_user: User,
    *,
    public_access_token: str = "",
    enforce_agent_owner: bool = True,
) -> ScanStartResponse:
    """Validate feature gate + client capability, persist Java scan & javelin_audit_state, and dispatch."""
    cfg = get_config()
    if not cfg.javelin.enabled:
        raise ApplicationError(
            status_code=422,
            detail="当前服务端未开启 Javelin (Java) 漏洞挖掘开关（javelin.enabled=false）",
        )

    project_path = str(body.project_path or "").strip()
    if not project_path:
        raise ApplicationError(status_code=400, detail="project_path is required")
    _validate_absolute_scan_path(project_path, "项目总路径")
    if body.multi_versions:
        raise ApplicationError(status_code=422, detail="Javelin Java 扫描当前仅支持单目录项目范围")

    javelin_cfg = (body.javelin_config or JavelinScanConfig()).model_copy(deep=True)
    if javelin_cfg.mining_strategy == "api" and not javelin_cfg.api_inventory.strip():
        raise ApplicationError(status_code=422, detail="选择逐接口 API 审查策略时必须填写 API 审查清单")

    selected = await _select_creation_agent(body, current_user, enforce_agent_owner)
    store = get_scan_store()
    agent_meta = await run_store_call(store, "get_agent_javelin_metadata", selected.selected_agent_key)
    if agent_meta.get("decommissioned_at"):
        raise ApplicationError(status_code=409, detail="所选客户端已报废注销，无法派发新任务")

    cap = selected.agent.javelin or agent_meta.get("capability")
    if cap is None or not cap.supported:
        raise ApplicationError(
            status_code=409,
            detail="所选客户端不支持 Javelin 引擎，请升级客户端",
        )
    if cap.contract_version != JAVELIN_CONTRACT_VERSION:
        raise ApplicationError(
            status_code=409,
            detail=(
                f"客户端 Javelin 契约版本不匹配（client={cap.contract_version}, "
                f"server={JAVELIN_CONTRACT_VERSION}），拒绝派发任务"
            ),
        )
    if not cap.ready:
        reason = "；".join(cap.blockers) if cap.blockers else "Node.js >= 22.5.0 / ESM 依赖 / OpenCode 未就绪"
        raise ApplicationError(status_code=409, detail=f"所选客户端 Javelin 运行环境未就绪：{reason}")

    # Preflight single directory path on the target agent
    from backend.agents.gateway import request_agent_scan_paths

    code_scan_path = str(body.code_scan_path or "").strip() or project_path
    checked_targets = await request_agent_scan_paths(
        selected.agent_id,
        selected.agent,
        [{
            "project_path": project_path,
            "code_scan_path": code_scan_path,
            "code_scan_paths": [code_scan_path],
        }],
    )
    resolved_project_path = checked_targets[0]["project_path"]
    resolved_scan_path = checked_targets[0]["code_scan_path"]
    resolved_scan_paths = checked_targets[0]["code_scan_paths"]

    identity = _creation_identity(body, resolved_project_path)
    raw_secret_env = (
        javelin_cfg.runtime_testing.test_environment_context.strip()
        if javelin_cfg.runtime_testing.enabled
        else ""
    )
    public_javelin_cfg = javelin_cfg.public_copy()

    selection = MiningEngineSelection(
        engine_id=JAVELIN_ENGINE_ID,
        engine_label=JAVELIN_ENGINE_LABEL,
        enabled=True,
    )
    scan = ScanStatus(
        scan_id=identity.scan_id,
        project_id=identity.scan_name,
        scan_name=identity.scan_name,
        project_path=resolved_project_path,
        code_scan_path=resolved_scan_path,
        code_scan_paths=resolved_scan_paths,
        scan_mode="custom",
        threat_analysis_enabled=False,
        auto_resume_enabled=False,
        auto_fp_review=False,
        fp_review_method=FpReviewMethod.ADVERSARIAL.value,
        product=identity.product,
        scan_items=[],
        mining_engines=[selection],
        mining_engine_runs=[
            MiningEngineRunStatus(
                engine_id=JAVELIN_ENGINE_ID,
                engine_label=JAVELIN_ENGINE_LABEL,
            )
        ],
        created_at=identity.now,
        status=ScanItemStatus.PENDING,
        progress=0.0,
        total_candidates=0,
        processed_candidates=0,
        vulnerabilities=[],
        agent_name=selected.agent.name,
        agent_key=selected.selected_agent_key,
        agent_online=True,
        language="java",
        has_javelin=True,
        javelin_config=public_javelin_cfg,
    )
    meta = ScanMeta(
        scan_items=[],
        created_at=identity.now,
        scan_mode="custom",
        threat_analysis_enabled=False,
        mining_engines=[selection],
        auto_resume_enabled=False,
        auto_fp_review=False,
        fp_review_method=FpReviewMethod.ADVERSARIAL.value,
        feedback_ids=[],
        agent_id=selected.agent_id,
        agent_key=selected.selected_agent_key,
        agent_name=selected.agent.name,
        project_path=resolved_project_path,
        code_scan_path=resolved_scan_path,
        code_scan_paths=resolved_scan_paths,
        scan_name=identity.scan_name,
        product=identity.product,
        user_id=current_user.user_id,
        public_access_token=public_access_token,
        language="java",
        javelin_config=public_javelin_cfg,
    )

    await _persist_creation(body, current_user, identity, scan, meta)

    distributed = bool(getattr(store, "distributed", False))
    secret_ciphertext: bytes | None = None
    secret_meta: dict | None = None
    if raw_secret_env:
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        secret_ciphertext, secret_meta = encrypt_secret_context(
            {"test_environment_context": raw_secret_env},
            scan_id=scan.scan_id,
            expires_at=expires_at,
            config=cfg,
            distributed=distributed,
        )

    execution_revision = await run_store_call(
        store,
        "begin_scan_execution",
        scan.scan_id,
        agent_id=selected.agent_id,
        agent_session_id=selected.agent.agent_session_id,
    )
    scan.execution_revision = execution_revision
    audit_id = f"dh-{scan.scan_id}"
    product_id = "product-undefined"
    product_name = identity.product or "DeepHole"
    await run_store_call(
        store,
        "init_javelin_audit_state",
        scan_id=scan.scan_id,
        audit_id=audit_id,
        product_id=product_id,
        product_name=product_name,
        target_id=f"target-{scan.scan_id[:12]}",
        target_name=scan.scan_name,
        repository_id=f"repo-{scan.scan_id[:12]}",
        repository_name=scan.scan_name,
        mining_strategy=public_javelin_cfg.mining_strategy,
        execution_revision=execution_revision,
        secret_ciphertext=secret_ciphertext,
        secret_meta=secret_meta,
    )
    if secret_ciphertext is not None:
        log_secret_context_audit("SECRET_CONTEXT_STORED", scan_id=scan.scan_id, detail="runtime_testing_enabled")

    from backend.agents.artifacts import create_agent_task_runtime_update_payload_async
    from backend.agents.configuration import agent_explicit_model_ids
    from backend.agents.gateway import send_agent_command

    command = {
        "type": "task",
        "scan_id": scan.scan_id,
        "execution_revision": execution_revision,
        "language": "java",
        "project_path": resolved_project_path,
        "code_scan_path": resolved_scan_path,
        "code_scan_paths": resolved_scan_paths,
        "scan_name": scan.scan_name,
        "product": identity.product,
        "mining_engines": [selection.model_dump(mode="json")],
        "javelin_contract_version": JAVELIN_CONTRACT_VERSION,
        "javelin_audit_id": audit_id,
        "javelin_config": public_javelin_cfg.model_dump(mode="json"),
        "has_secret_context": secret_ciphertext is not None,
        "codex_model_ids": agent_explicit_model_ids(selected.managed_config),
        "agent_runtime_update": await create_agent_task_runtime_update_payload_async(
            server_url,
            selected.selected_agent_key,
        ),
    }
    try:
        ok = await send_agent_command(selected.agent_id, command)
    except Exception:
        logger.exception("Failed to dispatch Javelin scan %s via agent %s", scan.scan_id, selected.agent_id)
        ok = False
    if not ok:
        await run_store_call(
            store,
            "update_scan_progress",
            scan.scan_id,
            status=ScanItemStatus.ERROR,
            error_message="Agent not connected",
        )
        scan.status = ScanItemStatus.ERROR
        get_runtime().scans.running_scans.pop(scan.scan_id, None)
        get_runtime().scans.scan_owners.pop(scan.scan_id, None)
        raise ApplicationError(status_code=502, detail="Agent not connected")

    await run_store_call(
        store,
        "update_scan_progress",
        scan.scan_id,
        status=ScanItemStatus.AUDITING,
    )
    scan.status = ScanItemStatus.AUDITING
    logger.info(
        "Created Javelin Java scan %s ('%s'), dispatched to agent %s",
        scan.scan_id,
        scan.scan_name,
        selected.agent_id,
    )
    return ScanStartResponse(scan_id=scan.scan_id)
