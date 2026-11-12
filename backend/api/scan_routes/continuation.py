"""HTTP bindings for scan continuation."""

from fastapi import APIRouter, Depends, Request
from backend.auth import get_current_user
from backend.models import ScanStartResponse, User
from backend.report_routes import HistoricalReportRoute
from backend.scans import continuation as service

router = APIRouter(route_class=HistoricalReportRoute)


@router.post("/api/scan/{scan_id}/resume", response_model=ScanStartResponse)
async def resume_scan(
    scan_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> ScanStartResponse:
    return await service.resume_scan(
        scan_id=scan_id,
        server_url=str(request.base_url).rstrip('/'),
        current_user=current_user,
    )


@router.post("/api/scan/{scan_id}/retry-incomplete", response_model=ScanStartResponse)
async def retry_incomplete_scan(
    scan_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> ScanStartResponse:
    'Compatibility alias for the unified continue action.'
    return await service.retry_incomplete_scan(
        scan_id=scan_id,
        server_url=str(request.base_url).rstrip('/'),
        current_user=current_user,
    )
