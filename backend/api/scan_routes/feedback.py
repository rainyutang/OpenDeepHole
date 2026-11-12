"""HTTP bindings for scan feedback."""

from fastapi import APIRouter, Depends
from backend.auth import get_current_user
from backend.models import BatchMarkRequest, BatchUnmarkRequest, MarkRequest, UnmarkRequest, User
from backend.report_routes import HistoricalReportRoute
from backend.scans import feedback as service

router = APIRouter(route_class=HistoricalReportRoute)


@router.post("/api/scan/{scan_id}/mark")
async def mark_vulnerability(
    scan_id: str,
    body: MarkRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    'Mark a vulnerability with manual triage feedback.'
    return await service.mark_vulnerability(scan_id=scan_id, body=body, current_user=current_user)


@router.post("/api/scan/{scan_id}/unmark")
async def unmark_vulnerability(
    scan_id: str,
    body: UnmarkRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    "Clear a vulnerability's manual verdict and remove its generated feedback."
    return await service.unmark_vulnerability(scan_id=scan_id, body=body, current_user=current_user)


@router.post("/api/scan/{scan_id}/batch-mark")
async def batch_mark_vulnerabilities(
    scan_id: str,
    body: BatchMarkRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    'Batch-mark multiple vulnerabilities with manual triage feedback.'
    return await service.batch_mark_vulnerabilities(scan_id=scan_id, body=body, current_user=current_user)


@router.post("/api/scan/{scan_id}/batch-unmark")
async def batch_unmark_vulnerabilities(
    scan_id: str,
    body: BatchUnmarkRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    'Clear manual verdicts and remove generated feedback for multiple vulnerabilities.'
    return await service.batch_unmark_vulnerabilities(scan_id=scan_id, body=body, current_user=current_user)


@router.put("/api/scan/{scan_id}/feedback")
async def update_scan_feedback(
    scan_id: str,
    body: dict,
    current_user: User = Depends(get_current_user),
) -> dict:
    'Update the feedback entry IDs associated with a scan.'
    return await service.update_scan_feedback(scan_id=scan_id, body=body, current_user=current_user)
