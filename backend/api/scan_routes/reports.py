"""HTTP bindings for scan reports."""

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from backend.auth import get_current_user
from backend.models import User
from backend.report_routes import HistoricalReportRoute
from backend.scans import reports as service

router = APIRouter(route_class=HistoricalReportRoute)


@router.get("/api/scan/{scan_id}/report")
async def download_report(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> Response:
    'Download current FP-review-confirmed issues as a CSV report.'
    artifact = await service.download_report(scan_id=scan_id, current_user=current_user)
    return Response(content=artifact.content, media_type=artifact.media_type, headers=artifact.headers)


@router.get("/api/scan/{scan_id}/vulnerability/{idx}/report")
async def download_vulnerability_report(
    scan_id: str,
    idx: int,
    current_user: User = Depends(get_current_user),
) -> Response:
    "Download a single vulnerability's report (AI analysis + FP review) as Markdown."
    artifact = await service.download_vulnerability_report(scan_id=scan_id, idx=idx, current_user=current_user)
    return Response(content=artifact.content, media_type=artifact.media_type, headers=artifact.headers)


@router.get("/api/scan/{scan_id}/report.zip")
async def download_report_zip(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> Response:
    'Download current FP-review-confirmed issues as Markdown reports.'
    artifact = await service.download_report_zip(scan_id=scan_id, current_user=current_user)
    return Response(content=artifact.content, media_type=artifact.media_type, headers=artifact.headers)
