"""Scan metadata services."""

from backend.application import (
    ApplicationError,
    get_runtime,
    get_scan_store,
    publish as publish_scan_event,
    run_store_call,
)
from backend.models import (
    AgentMcpConfig,
    ScanCodeGraphResponse,
    ScanMetadataResponse,
    UpdateScanCodeGraphRequest,
    UpdateScanMetadataRequest,
    UpdateScanValidationTargetRequest,
    User,
)
from backend.scans.access import _check_scan_owner
from backend.scans.configuration import _scan_code_graph_mcp
from backend.scans.projection import _apply_scan_metadata
from backend.store.base import DuplicateScanNameError


async def update_scan_metadata(
    scan_id: str,
    body: UpdateScanMetadataRequest,
    current_user: User = None,
) -> ScanMetadataResponse:
    store = get_scan_store()
    if await run_store_call(store, "get_scan_meta", scan_id) is None:
        raise ApplicationError(status_code=404, detail="Scan not found")
    await _check_scan_owner(scan_id, current_user)
    try:
        metadata = await run_store_call(
            store,
            "update_scan_metadata",
            scan_id,
            **body.model_dump(exclude_unset=True),
        )
    except DuplicateScanNameError as exc:
        raise ApplicationError(
            status_code=409,
            detail=f"扫描名称「{body.scan_name}」已存在，请修改后重试",
        ) from exc
    if metadata is None:
        raise ApplicationError(status_code=404, detail="Scan not found")
    cached = get_runtime().scans.running_scans.get(scan_id)
    if cached is not None:
        _apply_scan_metadata(cached, metadata)
    publish_scan_event(scan_id, "resource_changed", {"resource": "metadata"})
    return metadata


async def update_scan_code_graph(
    scan_id: str,
    body: UpdateScanCodeGraphRequest,
    current_user: User = None,
) -> ScanCodeGraphResponse:
    from backend.code_graph import code_graph_response, sync_scan_code_graph

    store = get_scan_store()
    if await run_store_call(store, "get_scan_meta", scan_id) is None:
        raise ApplicationError(status_code=404, detail="Scan not found")
    await _check_scan_owner(scan_id, current_user)
    default_config = _scan_code_graph_mcp(AgentMcpConfig(enabled=True, transport="local"))
    try:
        meta = await run_store_call(store, "update_scan_code_graph", scan_id, body.enabled, default_config)
    except ValueError as exc:
        raise ApplicationError(status_code=422, detail=str(exc)) from exc
    if meta is None:
        raise ApplicationError(status_code=404, detail="Scan not found")
    cached = get_runtime().scans.running_scans.get(scan_id)
    if cached is not None:
        _apply_scan_metadata(cached, meta)
    publish_scan_event(scan_id, "resource_changed", {"resource": "code-graph"})
    message = await sync_scan_code_graph(scan_id)
    meta = await run_store_call(store, "get_scan_meta", scan_id)
    if meta is None:
        raise ApplicationError(status_code=404, detail="Scan not found")
    if cached is not None:
        _apply_scan_metadata(cached, meta)
    return code_graph_response(scan_id, meta, message)


async def update_scan_validation_target(
    scan_id: str,
    body: UpdateScanValidationTargetRequest,
    current_user: User = None,
) -> dict:
    """Reject legacy product/environment edits; scan configuration is immutable."""
    await _check_scan_owner(scan_id, current_user)
    del body
    raise ApplicationError(
        status_code=410,
        detail="历史扫描的产品与验证方法快照只读，请新建扫描后选择验证方法和 field 参数",
    )
