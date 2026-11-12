"""Scan configuration services."""

from deephole_client.scan_modes import (
    BUILTIN_PROFILE_ENGINE_IDS,
    OPT_IN_MINING_ENGINE_IDS,
    SCAN_MODE_CUSTOM,
    SCAN_MODE_MULTI_VERSION,
    SCAN_MODE_QUICK,
    SCAN_MODE_STANDARD,
    SCAN_MODE_THREAT_ANALYSIS_ONLY,
    THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS,
    component_scan_mode,
    normalize_scan_mode,
)
from pathlib import PurePosixPath, PureWindowsPath
import json
from backend.application import ApplicationError, get_scan_store, run_store_call
from backend.checker_sync import build_checker_packages
from backend.logger import get_logger
from backend.models import (
    AgentMcpConfig,
    AgentValidatorCatalog,
    AgentValidatorMethod,
    FpReviewMethodCatalog,
    FpReviewMethodSelection,
    MULTI_VERSION_ENGINE_LABEL,
    MiningEngineCatalog,
    MiningEngineRequest,
    MiningEngineSelection,
    MultiVersionTarget,
    ScanKnowledgeBaseRequest,
    ScanStatus,
    ScanVulnerabilityValidationConfig,
    ScanVulnerabilityValidationRequest,
    THREAT_AUDIT_ENGINE_LABEL,
    ThreatAnalysisMethodCatalog,
    ThreatAnalysisMethodSelection,
    User,
)
from backend.registry import CHECKER_VISIBILITY_ADMIN, refresh_registry

logger = get_logger(__name__)


_PREFERRED_THREAT_ANALYSIS_METHOD_ID = "opencode_lightweight_threat_analysis"


def _normalize_scan_mode(value: str | None) -> str:
    try:
        return normalize_scan_mode(value)
    except ValueError as exc:
        raise ApplicationError(status_code=400, detail=str(exc)) from exc


def _is_threat_analysis_only_mode(value: str | None) -> bool:
    return _normalize_scan_mode(value) == SCAN_MODE_THREAT_ANALYSIS_ONLY


def _validate_absolute_scan_path(value: str, label: str) -> None:
    # Paths belong to the Agent, which may use a different OS than the server.
    if not (PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute()):
        raise ApplicationError(
            status_code=422,
            detail=f"{label}必须填写绝对路径，不能使用相对路径",
        )


def _normalized_code_scan_paths(
    project_path: str, code_scan_path: str, code_scan_paths: list[str], *, prefix: str = "",
) -> list[str]:
    paths = list(dict.fromkeys(path.strip() for path in code_scan_paths if path.strip()))
    if not paths:
        paths = [code_scan_path.strip() or project_path]
    for path in paths:
        _validate_absolute_scan_path(path, f"{prefix}扫描模块路径")
    return paths


def _validated_multi_versions(
    values: list[MultiVersionTarget],
) -> list[MultiVersionTarget]:
    """Validate scan-local version targets without probing agent-local paths."""
    if not 2 <= len(values) <= 5:
        raise ApplicationError(
            status_code=422,
            detail="多版本测试模式需要配置 2 到 5 个版本",
        )
    normalized: list[MultiVersionTarget] = []
    seen_names: set[str] = set()
    for value in values:
        name = value.version_name.strip()
        project_path = value.project_path.strip()
        code_scan_path = value.code_scan_path.strip() or project_path
        if not name or not project_path:
            raise ApplicationError(
                status_code=422,
                detail="每个版本都必须填写版本名称和项目总路径",
            )
        _validate_absolute_scan_path(project_path, f"版本「{name}」的项目总路径")
        code_scan_paths = _normalized_code_scan_paths(
            project_path, code_scan_path, value.code_scan_paths, prefix=f"版本「{name}」的",
        )
        key = name.casefold()
        if key in seen_names:
            raise ApplicationError(
                status_code=422,
                detail=f"版本名称不能重复：{name}",
            )
        seen_names.add(key)
        normalized.append(MultiVersionTarget(
            version_name=name,
            project_path=project_path,
            code_scan_path=code_scan_path,
            code_scan_paths=code_scan_paths,
        ))
    return normalized


def _default_scan_name_base(project_path: str) -> str:
    normalized = str(project_path or "").strip().rstrip("/\\")
    if not normalized:
        return "scan"
    basename = normalized.replace("\\", "/").rsplit("/", 1)[-1].strip()
    if (
        not basename
        or basename in {".", ".."}
        or (len(basename) == 2 and basename[0].isalpha() and basename[1] == ":")
    ):
        return "scan"
    return basename


def _repository_mining_engine_catalog() -> MiningEngineCatalog:
    from deephole_client.vulnerability_mining import build_mining_engine_catalog

    return MiningEngineCatalog.model_validate(
        build_mining_engine_catalog()
    )


async def get_mining_engine_catalog(
    current_user: User = None,
) -> MiningEngineCatalog:
    """Return the mining engines shipped by this repository."""
    return _repository_mining_engine_catalog()


def _repository_fp_review_method_catalog() -> FpReviewMethodCatalog:
    from deephole_client.fp_review import build_fp_review_method_catalog

    return FpReviewMethodCatalog.model_validate(
        build_fp_review_method_catalog()
    )


async def get_fp_review_method_catalog(
    current_user: User = None,
) -> FpReviewMethodCatalog:
    """Return repository-owned false-positive review methods."""
    return _repository_fp_review_method_catalog()


def _repository_threat_analysis_method_catalog() -> ThreatAnalysisMethodCatalog:
    from deephole_client.threat_analysis import build_threat_analysis_method_catalog

    return ThreatAnalysisMethodCatalog.model_validate(
        build_threat_analysis_method_catalog()
    )


async def get_threat_analysis_method_catalog(
    current_user: User = None,
) -> ThreatAnalysisMethodCatalog:
    """Return repository-owned threat-analysis methods."""
    return _repository_threat_analysis_method_catalog()


def _resolve_threat_analysis_method(
    requested: str | None,
) -> tuple[str, ThreatAnalysisMethodSelection]:
    catalog = _repository_threat_analysis_method_catalog()
    available = {item.method_id: item for item in catalog.methods}
    requested_id = str(requested or "").strip()
    method_id = requested_id or _PREFERRED_THREAT_ANALYSIS_METHOD_ID
    selected = available.get(method_id)
    if selected is None:
        status_code = 500 if not requested_id else 400
        detail = f"Unknown threat-analysis method: {method_id}"
        if status_code == 500 and catalog.errors:
            detail += ": " + "; ".join(catalog.errors)
        raise ApplicationError(status_code=status_code, detail=detail)
    return selected.method_id, ThreatAnalysisMethodSelection(
        method_id=selected.method_id,
        method_label=selected.label,
        description=selected.description,
    )


def _hydrate_threat_analysis_method_selection(scan: ScanStatus) -> None:
    """Hydrate legacy scans while preserving unavailable method snapshots."""
    if scan.threat_analysis_method_selection is not None:
        return
    try:
        method_id, selection = _resolve_threat_analysis_method(
            scan.threat_analysis_method
        )
        scan.threat_analysis_method = method_id
    except ApplicationError:
        selection = ThreatAnalysisMethodSelection(
            method_id=scan.threat_analysis_method,
            method_label=scan.threat_analysis_method,
        )
    scan.threat_analysis_method_selection = selection


def _resolve_fp_review_method(
    requested: str | None,
) -> tuple[str, FpReviewMethodSelection]:
    catalog = _repository_fp_review_method_catalog()
    available = {item.method_id: item for item in catalog.methods}
    method_id = str(requested or "").strip()
    if not method_id:
        defaults = [item for item in catalog.methods if item.default]
        if len(defaults) != 1:
            detail = "; ".join(catalog.errors)
            raise ApplicationError(
                status_code=500,
                detail=(
                    "FP review method catalog must declare exactly one default"
                    + (f": {detail}" if detail else "")
                ),
            )
        selected = defaults[0]
    else:
        selected = available.get(method_id)
        if selected is None:
            raise ApplicationError(
                status_code=400,
                detail=f"Unknown FP review method: {method_id}",
            )
    selection = FpReviewMethodSelection(
        method_id=selected.method_id,
        method_label=selected.label,
        description=selected.description,
        stages=selected.stages,
    )
    return selected.method_id, selection


def _hydrate_fp_review_method_selection(
    scan: ScanStatus,
) -> None:
    """Hydrate legacy scans that predate persisted method metadata."""
    if scan.fp_review_method_selection is not None:
        return
    try:
        _, selection = _resolve_fp_review_method(scan.fp_review_method)
    except ApplicationError:
        selection = FpReviewMethodSelection(
            method_id=scan.fp_review_method,
            method_label=scan.fp_review_method,
            stages=[],
        )
    scan.fp_review_method_selection = selection


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
        raise ApplicationError(
            status_code=400,
            detail=(
                "Duplicate mining engines: "
                + ", ".join(sorted(duplicate_ids))
            ),
        )
    unknown = sorted(set(requested_by_id) - set(available))
    if unknown:
        raise ApplicationError(
            status_code=400,
            detail=(
                "Unknown mining engines: " + ", ".join(unknown)
            ),
        )

    if scan_mode == SCAN_MODE_MULTI_VERSION:
        engine = available.get("multi_version")
        if engine is None:
            raise ApplicationError(
                status_code=400,
                detail=f"{MULTI_VERSION_ENGINE_LABEL}不可用",
            )
        requested_ids = [item.engine_id.strip() for item in requested or []]
        if requested is not None and requested_ids != ["multi_version"]:
            raise ApplicationError(
                status_code=422,
                detail="多版本测试模式固定使用多版本代码漏洞挖掘引擎",
            )
        return [MiningEngineSelection(
            engine_id=engine.engine_id,
            engine_label=engine.label,
            enabled=True,
        )]

    if scan_mode in {SCAN_MODE_QUICK, SCAN_MODE_STANDARD}:
        missing = [
            engine_id
            for engine_id in BUILTIN_PROFILE_ENGINE_IDS
            if engine_id not in available
        ]
        if missing:
            raise ApplicationError(
                status_code=400,
                detail=(
                    "扫描模式所需漏洞挖掘引擎不可用: "
                    + ", ".join(missing)
                ),
            )
        requested_ids = [item.engine_id.strip() for item in requested or []]
        if requested is not None and set(requested_ids) != set(
            BUILTIN_PROFILE_ENGINE_IDS
        ):
            raise ApplicationError(
                status_code=422,
                detail="快速模式和标准模式固定启用两个内置漏洞挖掘引擎",
            )
        return [
            MiningEngineSelection(
                engine_id=engine_id,
                engine_label=available[engine_id].label,
                enabled=True,
            )
            for engine_id in BUILTIN_PROFILE_ENGINE_IDS
        ]

    # Keep old callers that only supplied scan_mode working exactly as before.
    # New callers send threat_analysis_enabled explicitly and may select no
    # mining engine for a real analysis-only scan.
    if (
        scan_mode == SCAN_MODE_THREAT_ANALYSIS_ONLY
        and threat_analysis_enabled is None
    ):
        threat_engine = available.get("threat_audit")
        if threat_engine is None:
            raise ApplicationError(
                status_code=400,
                detail=f"{THREAT_AUDIT_ENGINE_LABEL}不可用",
            )
        return [MiningEngineSelection(
            engine_id=threat_engine.engine_id,
            engine_label=threat_engine.label,
            enabled=True,
        )]

    if requested is None:
        selected_ids = [item.engine_id for item in catalog.engines if item.engine_id not in OPT_IN_MINING_ENGINE_IDS]
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
    dependent = next(
        (
            item
            for item in selections
            if item.engine_id in THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS
        ),
        None,
    )
    if dependent is not None and not effective_threat_analysis_enabled:
        raise ApplicationError(
            status_code=400,
            detail=f"{dependent.engine_label}要求本次扫描启用威胁分析",
        )
    if not selections and not effective_threat_analysis_enabled:
        raise ApplicationError(
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
    if scan_mode == SCAN_MODE_MULTI_VERSION:
        return False
    if scan_mode in {SCAN_MODE_QUICK, SCAN_MODE_STANDARD}:
        return True
    if requested is not None:
        return bool(requested)
    if scan_mode == SCAN_MODE_THREAT_ANALYSIS_ONLY:
        return True
    return any(
        item.enabled and item.engine_id in THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS
        for item in selections
    )


def _record_validator_catalog(record: dict | None) -> AgentValidatorCatalog:
    if not record:
        return AgentValidatorCatalog()
    try:
        raw = json.loads(str(record.get("validator_catalog_json") or "{}"))
        return AgentValidatorCatalog.model_validate(raw)
    except Exception as exc:
        logger.warning("Ignoring invalid validator catalog for scan creation: %s", exc)
        return AgentValidatorCatalog(errors=[str(exc)])


def _validator_method_for_scan(
    catalog: AgentValidatorCatalog,
    method_id: str,
    product: str,
) -> AgentValidatorMethod | None:
    normalized_method = str(method_id or "").strip()
    normalized_product = str(product or "").strip()
    return next(
        (
            method
            for method in catalog.methods
            if method.method_id == normalized_method
            and normalized_product in method.products
        ),
        None,
    )


def _validated_method_values(
    method: AgentValidatorMethod,
    values: dict[str, object],
) -> dict[str, object]:
    schemas = {field.key: field for field in method.fields}
    unknown = sorted(set(values) - set(schemas))
    if unknown:
        raise ApplicationError(
            status_code=422,
            detail=f"验证方法 {method.method_label} 包含未知字段：{', '.join(unknown)}",
        )
    result: dict[str, object] = {}
    for field in method.fields:
        value = values.get(field.key, field.default)
        if field.required and value in (None, ""):
            raise ApplicationError(
                status_code=422,
                detail=f"验证方法 {method.method_label} 缺少必填字段：{field.label}",
            )
        if value in (None, ""):
            result[field.key] = value
            continue
        try:
            if field.type == "integer":
                if isinstance(value, bool):
                    raise ValueError
                parsed: object = int(value)
            elif field.type == "number":
                if isinstance(value, bool):
                    raise ValueError
                parsed = float(value)
            elif field.type == "boolean":
                if not isinstance(value, bool):
                    raise ValueError
                parsed = value
            else:
                parsed = str(value)
        except (TypeError, ValueError):
            raise ApplicationError(
                status_code=422,
                detail=f"验证方法 {method.method_label} 的字段 {field.label} 类型无效",
            )
        if field.type == "select" and field.options and parsed not in {
            str(option) for option in field.options
        }:
            raise ApplicationError(
                status_code=422,
                detail=f"验证方法 {method.method_label} 的字段 {field.label} 选项无效",
            )
        if field.type in {"integer", "number"}:
            if field.min is not None and parsed < field.min:  # type: ignore[operator]
                raise ApplicationError(
                    status_code=422,
                    detail=f"验证方法 {method.method_label} 的字段 {field.label} 小于最小值",
                )
            if field.max is not None and parsed > field.max:  # type: ignore[operator]
                raise ApplicationError(
                    status_code=422,
                    detail=f"验证方法 {method.method_label} 的字段 {field.label} 大于最大值",
                )
        result[field.key] = parsed
    return result


def _resolve_scan_validation(
    request: ScanVulnerabilityValidationRequest,
    *,
    product: str,
    catalog: AgentValidatorCatalog,
    policy,
) -> ScanVulnerabilityValidationConfig | None:
    if not request.enabled:
        return None
    normalized_product = str(product or "").strip()
    if not normalized_product:
        raise ApplicationError(status_code=422, detail="启用漏洞验证前必须填写产品")
    method = _validator_method_for_scan(catalog, request.method_id, normalized_product)
    if method is None:
        raise ApplicationError(
            status_code=422,
            detail=f"所选客户端没有适用于产品 {normalized_product} 的验证方法 {request.method_id}",
        )
    return ScanVulnerabilityValidationConfig(
        method_id=method.method_id,
        method_label=method.method_label,
        description=method.description,
        values=_validated_method_values(method, dict(request.values)),
        policy=policy.model_copy(deep=True),
    )


def _knowledge_base_mcp(
    request: ScanKnowledgeBaseRequest,
) -> AgentMcpConfig | None:
    from backend.agents.configuration import _normalize_scan_knowledge_base_mcp

    return _normalize_scan_knowledge_base_mcp(
        enabled=request.enabled,
        project_id=request.project_id,
        project_name=request.project_name,
    )


def _scan_code_graph_mcp(
    request: AgentMcpConfig | None,
) -> AgentMcpConfig | None:
    from backend.agents.configuration import _normalize_scan_code_graph_mcp

    return _normalize_scan_code_graph_mcp(request)


async def _remember_scan_configuration(
    *,
    user_id: str,
    agent_key: str,
    product: str,
    knowledge_base_mcp: AgentMcpConfig | None,
    validation: ScanVulnerabilityValidationConfig | None,
) -> None:
    store = get_scan_store()
    current = await run_store_call(
        store,
        "get_scan_config_memory",
        user_id,
        agent_key,
    ) or {}
    memory = dict(current)
    if knowledge_base_mcp is not None:
        memory["knowledge_base"] = {
            "project_id": knowledge_base_mcp.project_id,
            "project_name": knowledge_base_mcp.project_name,
        }
    if validation is not None and product:
        raw_products = memory.get("validation_by_product")
        products = dict(raw_products) if isinstance(raw_products, dict) else {}
        raw_product = products.get(product)
        product_memory = dict(raw_product) if isinstance(raw_product, dict) else {}
        raw_methods = product_memory.get("values_by_method")
        methods = dict(raw_methods) if isinstance(raw_methods, dict) else {}
        methods[validation.method_id] = dict(validation.values)
        product_memory.update({
            "last_method_id": validation.method_id,
            "values_by_method": methods,
        })
        products[product] = product_memory
        memory["validation_by_product"] = products
    await run_store_call(
        store,
        "upsert_scan_config_memory",
        user_id,
        agent_key,
        memory,
    )


def _validated_checker_names(checkers: list[str], user: User) -> list[str]:
    """Refresh checker registry and validate requested scan checkers."""
    registry = refresh_registry()
    names = list(dict.fromkeys(checkers))

    unknown = [name for name in names if name not in registry]
    if unknown:
        raise ApplicationError(status_code=400, detail=f"Unknown checkers: {', '.join(unknown)}")

    admin_only = [
        name for name in names
        if registry[name].visibility == CHECKER_VISIBILITY_ADMIN and user.role != "admin"
    ]
    if admin_only:
        raise ApplicationError(status_code=403, detail=f"Checker is admin-only: {', '.join(admin_only)}")

    return names


def _globally_enabled_checker_names(
    managed_config,
    user: User,
    scan_mode: str = SCAN_MODE_CUSTOM,
) -> list[str]:
    registry = refresh_registry()
    profile = getattr(
        managed_config.checker_selection,
        component_scan_mode(scan_mode),
    )
    disabled = {
        str(name).strip()
        for name in profile.disabled_checkers
        if str(name).strip()
    }
    return [
        name
        for name, checker in registry.items()
        if name not in disabled
        and not (
            checker.visibility == CHECKER_VISIBILITY_ADMIN
            and user.role != "admin"
        )
    ]


def _checker_packages_for(names: list[str]) -> list[dict[str, str]]:
    registry = refresh_registry()
    missing = [name for name in names if name not in registry]
    if missing:
        raise ApplicationError(status_code=400, detail=f"Checker unavailable: {', '.join(missing)}")
    return build_checker_packages(registry, names)
