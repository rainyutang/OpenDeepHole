"""Resolve a new scan's immutable configuration before Agent path probing."""

from dataclasses import dataclass
from deephole_client.scan_modes import (
    SCAN_MODE_MULTI_VERSION,
    SCAN_MODE_QUICK,
    SCAN_MODE_STANDARD,
    STATIC_ANALYSIS_ENGINE_IDS,
)
from backend.application import ApplicationError, get_config
from backend.models import (
    AgentMcpConfig,
    AgentRemoteConfig,
    CreateScanRequest,
    FpReviewMethodSelection,
    MiningEngineSelection,
    MultiVersionTarget,
    ThreatAnalysisMethodSelection,
    User,
)
from backend.scans.configuration import (
    _checker_packages_for,
    _globally_enabled_checker_names,
    _knowledge_base_mcp,
    _normalize_scan_mode,
    _normalized_code_scan_paths,
    _resolve_fp_review_method,
    _resolve_scan_mining_engines,
    _resolve_threat_analysis_enabled,
    _resolve_threat_analysis_method,
    _scan_code_graph_mcp,
    _validate_absolute_scan_path,
    _validated_checker_names,
    _validated_multi_versions,
)


@dataclass
class ResolvedScanConfiguration:
    project_path: str
    code_scan_path: str
    code_scan_paths: list[str]
    multi_versions: list[MultiVersionTarget]
    scan_mode: str
    threat_analysis_enabled: bool
    threat_analysis_method: str
    threat_analysis_method_selection: ThreatAnalysisMethodSelection
    auto_fp_review: bool
    fp_review_method: str
    fp_review_method_selection: FpReviewMethodSelection
    validated_checker_names: list[str]
    checker_packages: list[dict[str, str]]
    mining_engine_selections: list[MiningEngineSelection]
    code_graph_mcp: AgentMcpConfig | None
    knowledge_base_mcp: AgentMcpConfig | None


def resolve_creation_configuration(
    body: CreateScanRequest,
    managed_config: AgentRemoteConfig,
    current_user: User,
    checker_names: list[str] | None,
) -> ResolvedScanConfiguration:
    requested_scan_mode = _normalize_scan_mode(body.scan_mode)
    if requested_scan_mode == SCAN_MODE_MULTI_VERSION:
        # Both scan MCP bindings are single-project scoped. Multi-version
        # tasks use explicit read-only repository roots and file tools instead.
        code_graph_mcp = None
        knowledge_base_mcp = None
    else:
        code_graph_mcp = _scan_code_graph_mcp(body.code_graph_mcp)
        knowledge_base_mcp = _knowledge_base_mcp(body.knowledge_base)
    if (
        code_graph_mcp is not None
        and knowledge_base_mcp is not None
        and code_graph_mcp.name.strip().casefold()
        == knowledge_base_mcp.name.strip().casefold()
    ):
        raise ApplicationError(
            status_code=422,
            detail="代码图谱 MCP 与知识库 MCP 名称不能相同",
        )

    multi_versions = (
        _validated_multi_versions(body.multi_versions)
        if requested_scan_mode == SCAN_MODE_MULTI_VERSION
        else []
    )
    project_path = (
        multi_versions[0].project_path
        if multi_versions
        else body.project_path.strip()
    )
    if not project_path:
        raise ApplicationError(status_code=400, detail="project_path is required")
    code_scan_path = (
        multi_versions[0].code_scan_path
        if multi_versions
        else body.code_scan_path.strip() or project_path
    )
    _validate_absolute_scan_path(project_path, "项目总路径")
    code_scan_paths = (
        list(multi_versions[0].code_scan_paths) if multi_versions else
        _normalized_code_scan_paths(project_path, code_scan_path, body.code_scan_paths)
    )
    fixed_profile = requested_scan_mode in {
        SCAN_MODE_QUICK,
        SCAN_MODE_STANDARD,
    }
    if fixed_profile and body.threat_analysis_enabled is False:
        raise ApplicationError(
            status_code=422,
            detail="快速模式和标准模式固定启用威胁分析",
        )
    if fixed_profile and body.auto_fp_review is False:
        raise ApplicationError(
            status_code=422,
            detail="快速模式和标准模式固定启用自动去误报",
        )
    if (
        requested_scan_mode == SCAN_MODE_MULTI_VERSION
        and body.threat_analysis_enabled is True
    ):
        baseline_name = multi_versions[0].version_name if multi_versions else "基准版本"
        raise ApplicationError(
            status_code=422,
            detail=f"多版本测试模式由多版本引擎自行执行版本 {baseline_name} 的威胁分析",
        )
    if fixed_profile and (
        body.checkers is not None or checker_names is not None
    ):
        raise ApplicationError(
            status_code=422,
            detail="快速模式和标准模式的规则由高级配置决定",
        )
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
    scan_mode = requested_scan_mode
    requested_threat_analysis_method = body.threat_analysis_method
    if requested_scan_mode == SCAN_MODE_STANDARD:
        requested_threat_analysis_method = "deephole_compact_threat_analysis"
    elif requested_scan_mode == SCAN_MODE_MULTI_VERSION:
        requested_threat_analysis_method = "deephole_threat_analysis"
    elif fixed_profile:
        requested_threat_analysis_method = None
    threat_analysis_method, threat_analysis_method_selection = (
        _resolve_threat_analysis_method(requested_threat_analysis_method)
    )
    if (
        fixed_profile
        and body.threat_analysis_method is not None
        and str(body.threat_analysis_method).strip()
        != threat_analysis_method
    ):
        raise ApplicationError(
            status_code=422,
            detail="快速模式和标准模式固定使用默认威胁分析方法",
        )
    auto_fp_review = (
        True
        if fixed_profile
        else (
            body.auto_fp_review
            if body.auto_fp_review is not None
            else get_config().fp_review.auto_on_complete
        )
    )
    fp_review_method, fp_review_method_selection = _resolve_fp_review_method(
        None if fixed_profile else body.fp_review_method
    )
    if (
        fixed_profile
        and body.fp_review_method is not None
        and str(body.fp_review_method).strip() != fp_review_method
    ):
        raise ApplicationError(
            status_code=422,
            detail="快速模式和标准模式固定使用默认去误报方法",
        )
    globally_enabled_checkers = _globally_enabled_checker_names(
        managed_config,
        current_user,
        scan_mode,
    )
    requested_checkers = checker_names if checker_names is not None else body.checkers
    static_engine_enabled = any(
        item.enabled and item.engine_id in STATIC_ANALYSIS_ENGINE_IDS
        for item in mining_engine_selections
    )
    if not static_engine_enabled:
        validated_checker_names = []
        checker_packages = []
    else:
        if requested_checkers is None:
            selected_checkers = globally_enabled_checkers
        else:
            requested_valid = _validated_checker_names(
                requested_checkers,
                current_user,
            )
            enabled_set = set(globally_enabled_checkers)
            selected_checkers = [
                name for name in requested_valid if name in enabled_set
            ]
        validated_checker_names = (
            _validated_checker_names(selected_checkers, current_user)
            if selected_checkers
            else []
        )
        checker_packages = _checker_packages_for(validated_checker_names)
    return ResolvedScanConfiguration(
        project_path=project_path,
        code_scan_path=code_scan_path,
        code_scan_paths=code_scan_paths,
        multi_versions=multi_versions,
        scan_mode=scan_mode,
        threat_analysis_enabled=threat_analysis_enabled,
        threat_analysis_method=threat_analysis_method,
        threat_analysis_method_selection=threat_analysis_method_selection,
        auto_fp_review=auto_fp_review,
        fp_review_method=fp_review_method,
        fp_review_method_selection=fp_review_method_selection,
        validated_checker_names=validated_checker_names,
        checker_packages=checker_packages,
        mining_engine_selections=mining_engine_selections,
        code_graph_mcp=code_graph_mcp,
        knowledge_base_mcp=knowledge_base_mcp,
    )
