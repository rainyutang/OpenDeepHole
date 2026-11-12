"""HTTP bindings for scan fp review."""

from fastapi import APIRouter, Depends, Query, Request
from backend.auth import get_current_user
from backend.models import FpReviewJob, User
from backend.report_routes import HistoricalReportRoute
from backend.scans import fp_review as service

router = APIRouter(route_class=HistoricalReportRoute)


@router.post("/api/scan/{scan_id}/fp_review", response_model=dict)
async def trigger_fp_review(
    scan_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> dict:
    'Review unresolved findings, or rerun all after every finding is resolved.'
    return await service.trigger_fp_review(
        scan_id=scan_id,
        server_url=str(request.base_url).rstrip('/'),
        current_user=current_user,
    )


@router.post("/api/scan/{scan_id}/fp_review/stop")
async def stop_fp_review(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    'Cancel the latest running FP review job for a scan.'
    return await service.stop_fp_review(scan_id=scan_id, current_user=current_user)


@router.get("/api/scan/{scan_id}/fp_review", response_model=FpReviewJob)
async def get_fp_review(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> FpReviewJob:
    'Get the latest FP review job and results for a scan.'
    return await service.get_fp_review(scan_id=scan_id, current_user=current_user)


@router.get("/api/v2/scans/{scan_id}/fp-review/overview", response_model=FpReviewJob | None)
async def get_fp_review_overview_v2(
    scan_id: str, current_user: User = Depends(get_current_user), allow_missing: bool = False,
):
    return await service.get_fp_review_overview_v2(
        scan_id=scan_id,
        current_user=current_user,
        allow_missing=allow_missing,
    )


@router.get("/api/v2/scans/{scan_id}/fp-review/results")
async def get_fp_review_results_v2(scan_id: str, after: int = Query(-1, ge=-1),
                                    limit: int = Query(50, ge=1, le=100),
                                    current_user: User = Depends(get_current_user)):
    return await service.get_fp_review_results_v2(scan_id=scan_id, after=after, limit=limit, current_user=current_user)
