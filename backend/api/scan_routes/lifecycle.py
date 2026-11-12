"""HTTP bindings for scan lifecycle."""

from fastapi import APIRouter, Depends
from backend.auth import get_current_user
from backend.models import User
from backend.report_routes import HistoricalReportRoute
from backend.scans import lifecycle as service

router = APIRouter(route_class=HistoricalReportRoute)


@router.post("/api/scan/{scan_id}/stop")
async def stop_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    'Stop the main scan and every active false-positive review task.'
    return await service.stop_scan(scan_id=scan_id, current_user=current_user)


@router.delete("/api/scan/{scan_id}")
async def delete_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    'Queue an explicit deletion after database-atomic active-work checks.'
    return await service.delete_scan(scan_id=scan_id, current_user=current_user)
