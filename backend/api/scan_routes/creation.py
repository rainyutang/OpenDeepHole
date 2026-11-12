"""HTTP bindings for scan creation."""

from fastapi import APIRouter, Depends, Request
from backend.auth import get_current_user
from backend.models import CreateScanRequest, ScanStartResponse, User
from backend.report_routes import HistoricalReportRoute
from backend.scans import creation as service

router = APIRouter(route_class=HistoricalReportRoute)


@router.post("/api/scan", response_model=ScanStartResponse)
async def create_scan(
    body: CreateScanRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> ScanStartResponse:
    'Create a new scan and dispatch it to the specified agent daemon.'
    return await service.create_scan(body=body, server_url=str(request.base_url).rstrip("/"), current_user=current_user)
