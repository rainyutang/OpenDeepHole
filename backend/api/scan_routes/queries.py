"""HTTP bindings for scan queries."""

from fastapi import APIRouter, Depends, Query
from backend.auth import get_current_user
from backend.models import ScanOverview, ScanStatus, ScanSummary, ScanSummaryPage, User
from backend.report_routes import HistoricalReportRoute
from backend.scans import queries as service

router = APIRouter(route_class=HistoricalReportRoute)


@router.get("/api/scans", response_model=list[ScanSummary])
async def list_scans(current_user: User = Depends(get_current_user)) -> list[ScanSummary]:
    'Legacy unpaginated scan list retained for one Agent/UI release.'
    return await service.list_scans(current_user=current_user)


@router.get("/api/v2/scans", response_model=ScanSummaryPage)
async def list_scans_v2(
    limit: int = Query(50, ge=1, le=100),
    cursor: str | None = Query(None),
    current_user: User = Depends(get_current_user),
) -> ScanSummaryPage:
    'Return a bounded, stable page of scans visible to the current user.'
    return await service.list_scans_v2(limit=limit, cursor=cursor, current_user=current_user)


@router.get("/api/scan/{scan_id}", response_model=ScanStatus)
async def get_scan_status(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> ScanStatus:
    'Get the current status and results of a scan.'
    return await service.get_scan_status(scan_id=scan_id, current_user=current_user)


@router.get("/api/v2/scans/{scan_id}/overview", response_model=ScanOverview)
async def get_scan_overview_v2(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> ScanOverview:
    'Return frequently refreshed state without large result collections.'
    return await service.get_scan_overview_v2(scan_id=scan_id, current_user=current_user)
