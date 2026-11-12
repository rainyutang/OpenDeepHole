"""Scan configuration queries services."""

from deephole_client.scan_modes import (
    SCAN_MODE_CUSTOM,
    SCAN_MODE_MULTI_VERSION,
    SCAN_MODE_THREAT_ANALYSIS_ONLY,
    normalize_scan_mode,
)
from backend.application import ApplicationError, get_scan_store, run_store_call
from backend.models import (
    MiningEngineRequest,
    ScanConfigMemoryResponse,
    ScanCopyConfig,
    ScanKnowledgeBaseRequest,
    ScanVulnerabilityValidationRequest,
    User,
)
from backend.scans.access import _check_scan_owner


async def get_scan_config_memory(
    agent_key: str,
    current_user: User = None,
) -> ScanConfigMemoryResponse:
    from backend.agents.configuration import _authorize_agent_record

    store = get_scan_store()
    _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    raw = await run_store_call(
        store,
        "get_scan_config_memory",
        current_user.user_id,
        agent_key,
    ) or {}
    knowledge = raw.get("knowledge_base")
    validation = raw.get("validation_by_product")
    return ScanConfigMemoryResponse(
        knowledge_base=(dict(knowledge) if isinstance(knowledge, dict) else None),
        validation_by_product=(dict(validation) if isinstance(validation, dict) else {}),
    )


async def list_scan_validation_targets(
    _current_user: User = None,
) -> dict:
    """Retire the legacy server-side product/environment catalog."""
    raise ApplicationError(
        status_code=410,
        detail="验证环境目录已废弃，请使用所选客户端的验证方法目录",
    )


async def get_scan_copy_config(
    scan_id: str,
    current_user: User = None,
) -> ScanCopyConfig:
    """Read saved form values without creating a scan or resolving new defaults."""
    store = get_scan_store()
    meta = await run_store_call(store, "get_scan_meta", scan_id)
    if meta is None:
        raise ApplicationError(status_code=404, detail="Scan not found")
    await _check_scan_owner(scan_id, current_user)
    # Review notes and validation values remain private even to administrators
    # who may otherwise inspect another user's scan results.
    if not meta.user_id or meta.user_id != current_user.user_id:
        raise ApplicationError(status_code=403, detail="只能复制自己的扫描")

    missing = []
    for value, label in (
        (meta.agent_key, "客户端标识"),
        (meta.project_path, "项目总路径"),
        (meta.product, "产品"),
    ):
        if not value.strip():
            missing.append(label)
    try:
        mode = normalize_scan_mode(meta.scan_mode)
    except ValueError as exc:
        raise ApplicationError(status_code=409, detail="原扫描的模式无法用于创建扫描") from exc
    if mode == SCAN_MODE_THREAT_ANALYSIS_ONLY:
        mode = SCAN_MODE_CUSTOM
    if mode == SCAN_MODE_MULTI_VERSION and not 2 <= len(meta.multi_versions) <= 5:
        missing.append("多版本配置")
    knowledge = meta.knowledge_base_mcp
    if meta.knowledge_base_enabled and (knowledge is None or not knowledge.project_id):
        missing.append("知识库项目配置")
    validation = meta.vulnerability_validation
    if meta.vulnerability_validation_enabled and (validation is None or not validation.method_id):
        missing.append("漏洞验证配置")
    if meta.validation_environment:
        missing.append("旧版验证环境对应的验证方法配置")
    if mode == SCAN_MODE_CUSTOM:
        if meta.threat_analysis_enabled and not meta.threat_analysis_method:
            missing.append("威胁分析方法")
        if not meta.fp_review_method:
            missing.append("去误报方法")
        if not meta.threat_analysis_enabled and not any(item.enabled for item in meta.mining_engines):
            missing.append("漏洞挖掘引擎配置")
    if missing:
        raise ApplicationError(
            status_code=409,
            detail="原扫描缺少可复制的配置：" + "、".join(missing) + "，请使用普通新建扫描",
        )
    notes = await run_store_call(store, "get_scan_review_notes", scan_id)
    return ScanCopyConfig(
        agent_key=meta.agent_key,
        project_path=meta.project_path,
        code_scan_path=meta.code_scan_path,
        code_scan_paths=list(meta.code_scan_paths or [meta.code_scan_path or meta.project_path]),
        scan_mode=mode,
        product=meta.product,
        knowledge_base=ScanKnowledgeBaseRequest(
            enabled=meta.knowledge_base_enabled,
            project_id=knowledge.project_id if knowledge else "",
            project_name=knowledge.project_name if knowledge else "",
        ),
        vulnerability_validation=ScanVulnerabilityValidationRequest(
            enabled=meta.vulnerability_validation_enabled,
            method_id=validation.method_id if validation else "",
            values=dict(validation.values) if validation else {},
        ),
        code_graph_mcp=meta.code_graph_mcp.model_copy(deep=True) if meta.code_graph_mcp else None,
        review_notes_enabled=notes["enabled"],
        review_note_ids=notes["note_ids"],
        multi_versions=[
            item.model_copy(update={
                "code_scan_paths": list(item.code_scan_paths or [item.code_scan_path or item.project_path]),
            }, deep=True)
            for item in meta.multi_versions
        ],
        **({
            "threat_analysis_enabled": meta.threat_analysis_enabled,
            "threat_analysis_method": meta.threat_analysis_method,
            "mining_engines": [MiningEngineRequest(engine_id=item.engine_id) for item in meta.mining_engines if item.enabled],
            "auto_fp_review": meta.auto_fp_review,
            "fp_review_method": meta.fp_review_method,
        } if mode == SCAN_MODE_CUSTOM else {}),
    )
