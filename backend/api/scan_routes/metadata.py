"""HTTP bindings for scan metadata."""

from fastapi import APIRouter, Depends
from backend.auth import get_current_user
from backend.models import (
    ScanCodeGraphResponse,
    ScanMetadataResponse,
    UpdateScanCodeGraphRequest,
    UpdateScanMetadataRequest,
    UpdateScanValidationTargetRequest,
    User,
)
from backend.report_routes import HistoricalReportRoute
from backend.scans import metadata as service

router = APIRouter(route_class=HistoricalReportRoute)


@router.patch(
    "/api/scan/{scan_id}/metadata",
    response_model=ScanMetadataResponse,
)
async def update_scan_metadata(
    scan_id: str,
    body: UpdateScanMetadataRequest,
    current_user: User = Depends(get_current_user),
) -> ScanMetadataResponse:
    return await service.update_scan_metadata(scan_id=scan_id, body=body, current_user=current_user)


@router.put("/api/scan/{scan_id}/code-graph", response_model=ScanCodeGraphResponse)
async def update_scan_code_graph(
    scan_id: str,
    body: UpdateScanCodeGraphRequest,
    current_user: User = Depends(get_current_user),
) -> ScanCodeGraphResponse:
    return await service.update_scan_code_graph(scan_id=scan_id, body=body, current_user=current_user)


@router.put("/api/scan/{scan_id}/validation-target")
async def update_scan_validation_target(
    scan_id: str,
    body: UpdateScanValidationTargetRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    'Reject legacy product/environment edits; scan configuration is immutable.'
    return await service.update_scan_validation_target(scan_id=scan_id, body=body, current_user=current_user)
