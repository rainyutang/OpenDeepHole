"""HTTP bindings for scan results."""

from fastapi import APIRouter, Depends
from backend.auth import get_current_user
from backend.models import HistoryPattern, ThreatAuditTask, User
from backend.report_routes import HistoricalReportRoute
from backend.scans import results as service

router = APIRouter(route_class=HistoricalReportRoute)


@router.get("/api/scan/{scan_id}/git_history", response_model=list[HistoryPattern])
async def get_scan_git_history(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> list[HistoryPattern]:
    'Return the git-history security problem patterns mined for a scan.'
    return await service.get_scan_git_history(scan_id=scan_id, current_user=current_user)


@router.get("/api/scan/{scan_id}/threat-analysis", response_model=dict | None)
async def get_scan_threat_analysis(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    allow_missing: bool = False,
) -> dict | None:
    'Return the opaque threat-analysis artifact bundle for a scan.'
    return await service.get_scan_threat_analysis(
        scan_id=scan_id,
        current_user=current_user,
        allow_missing=allow_missing,
    )


@router.get("/api/scan/{scan_id}/threat-coverage", response_model=dict)
async def get_scan_threat_coverage(
    scan_id: str, current_user: User = Depends(get_current_user),
) -> dict:
    return await service.get_scan_threat_coverage(scan_id=scan_id, current_user=current_user)


@router.get("/api/scan/{scan_id}/threat-coverage/issues", response_model=dict)
async def get_scan_threat_coverage_issues(
    scan_id: str, current_user: User = Depends(get_current_user),
) -> dict:
    return await service.get_scan_threat_coverage_issues(scan_id=scan_id, current_user=current_user)


@router.get("/api/scan/{scan_id}/threat-audit-tasks", response_model=list[ThreatAuditTask])
async def get_scan_threat_audit_tasks(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> list[ThreatAuditTask]:
    'Return threat-analysis-derived audit tasks for a scan.'
    return await service.get_scan_threat_audit_tasks(scan_id=scan_id, current_user=current_user)
