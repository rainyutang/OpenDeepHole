"""HTTP bindings for scan validation."""

from fastapi import APIRouter, Depends, Request
from backend.auth import get_current_user
from backend.models import User
from backend.report_routes import HistoricalReportRoute
from backend.scans import validation as service

router = APIRouter(route_class=HistoricalReportRoute)


@router.post("/api/scan/{scan_id}/vulnerability/{idx}/validation")
async def trigger_vulnerability_validation(
    scan_id: str,
    idx: int,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> dict:
    'Manually start Agent-side local validation for one confirmed vulnerability.'
    return await service.trigger_vulnerability_validation(
        scan_id=scan_id,
        idx=idx,
        server_url=str(request.base_url).rstrip('/'),
        current_user=current_user,
    )


@router.post("/api/scan/{scan_id}/vulnerability/{idx}/validation/stop")
async def stop_vulnerability_validation(
    scan_id: str,
    idx: int,
    current_user: User = Depends(get_current_user),
) -> dict:
    'Cancel Agent-side local validation for one vulnerability.'
    return await service.stop_vulnerability_validation(scan_id=scan_id, idx=idx, current_user=current_user)
