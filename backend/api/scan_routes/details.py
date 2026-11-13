"""HTTP bindings for scan details."""

from fastapi import APIRouter, Depends, Query
from typing import Annotated
from backend.auth import get_current_user
from backend.models import (
    CandidateAuditTaskResult,
    ScanCandidatePage,
    ScanEventPage,
    ThreatAuditTaskPage,
    ThreatAuditTaskResult,
    ThreatPatternAuditTaskDetail,
    ThreatPatternAuditTaskPage,
    User,
    VulnerabilityAuditSource,
    VulnerabilityPage,
    VulnerabilityValidationPage,
)
from backend.report_routes import HistoricalReportRoute
from backend.scans import details as service
from backend.task_kinds import TaskKind

router = APIRouter(route_class=HistoricalReportRoute)


@router.get("/api/v2/scans/{scan_id}/tasks")
async def get_scan_tasks_page(scan_id: str, cursor: str | None = None,
                              limit: int = Query(default=50, ge=1, le=100),
                              current_user: User = Depends(get_current_user),
                              task_name: str | None = None, task_kind: TaskKind | None = None) -> dict:
    return await service.get_scan_tasks_page(
        scan_id=scan_id,
        cursor=cursor,
        limit=limit,
        current_user=current_user,
        task_name=task_name,
        task_kind=task_kind,
    )


@router.get("/api/v2/scans/{scan_id}/tasks/{task_id}")
async def get_scan_task_detail(scan_id: str, task_id: str, revision: int | None = None,
                               record_id: str | None = None,
                               current_user: User = Depends(get_current_user)) -> dict:
    return await service.get_scan_task_detail(
        scan_id=scan_id,
        task_id=task_id,
        revision=revision,
        record_id=record_id,
        current_user=current_user,
    )


@router.get("/api/v2/scans/{scan_id}/details/{resource}/{index}")
async def get_scan_detail_item(scan_id: str, resource: str, index: int,
                                current_user: User = Depends(get_current_user), include_body: bool = True):
    return await service.get_scan_detail_item(
        scan_id=scan_id,
        resource=resource,
        index=index,
        current_user=current_user,
        include_body=include_body,
    )


@router.get(
    "/api/v2/scans/{scan_id}/candidates",
    response_model=ScanCandidatePage,
)
async def get_scan_candidates_v2(
    scan_id: str,
    limit: int = Query(50, ge=1, le=100),
    after: int = Query(-1, ge=-1),
    current_user: User = Depends(get_current_user),
) -> ScanCandidatePage:
    return await service.get_scan_candidates_v2(scan_id=scan_id, limit=limit, after=after, current_user=current_user)


@router.get(
    "/api/v2/scans/{scan_id}/vulnerabilities",
    response_model=VulnerabilityPage,
)
async def get_scan_vulnerabilities_v2(
    scan_id: str,
    limit: int = Query(50, ge=1, le=100),
    after: int = Query(-1, ge=-1),
    current_user: User = Depends(get_current_user),
) -> VulnerabilityPage:
    return await service.get_scan_vulnerabilities_v2(
        scan_id=scan_id,
        limit=limit,
        after=after,
        current_user=current_user,
    )


@router.get("/api/v2/scans/{scan_id}/events", response_model=ScanEventPage)
async def get_scan_events_v2(
    scan_id: str,
    limit: int = Query(50, ge=1, le=100),
    before: int | None = Query(None, ge=1),
    current_user: User = Depends(get_current_user),
) -> ScanEventPage:
    return await service.get_scan_events_v2(scan_id=scan_id, limit=limit, before=before, current_user=current_user)


@router.get(
    "/api/v2/scans/{scan_id}/candidate-audit-results",
    response_model=list[CandidateAuditTaskResult],
)
async def get_scan_candidate_audit_results_v2(
    scan_id: str,
    candidate_indexes: list[Annotated[int, Query(ge=0)]] = Query(..., min_length=1, max_length=100),
    current_user: User = Depends(get_current_user),
) -> list[CandidateAuditTaskResult]:
    return await service.get_scan_candidate_audit_results_v2(
        scan_id=scan_id,
        candidate_indexes=candidate_indexes,
        current_user=current_user,
    )


@router.get(
    "/api/v2/scans/{scan_id}/vulnerabilities/{idx}/audit-source",
    response_model=VulnerabilityAuditSource,
)
async def get_scan_vulnerability_audit_source_v2(
    scan_id: str,
    idx: int,
    current_user: User = Depends(get_current_user),
) -> VulnerabilityAuditSource:
    return await service.get_scan_vulnerability_audit_source_v2(scan_id=scan_id, idx=idx, current_user=current_user)


@router.get(
    "/api/v2/scans/{scan_id}/threat-audit-results",
    response_model=list[ThreatAuditTaskResult],
)
async def get_scan_threat_audit_results_v2(
    scan_id: str,
    task_ids: list[str] = Query(..., min_length=1, max_length=100),
    current_user: User = Depends(get_current_user),
) -> list[ThreatAuditTaskResult]:
    return await service.get_scan_threat_audit_results_v2(scan_id=scan_id, task_ids=task_ids, current_user=current_user)


@router.get(
    "/api/v2/scans/{scan_id}/threat-audit-tasks",
    response_model=ThreatAuditTaskPage,
)
async def get_scan_threat_audit_tasks_v2(
    scan_id: str,
    limit: int = Query(50, ge=1, le=100),
    cursor: str | None = Query(None),
    current_user: User = Depends(get_current_user),
) -> ThreatAuditTaskPage:
    return await service.get_scan_threat_audit_tasks_v2(
        scan_id=scan_id,
        limit=limit,
        cursor=cursor,
        current_user=current_user,
    )


@router.get(
    "/api/v2/scans/{scan_id}/threat-pattern-audit-results",
    response_model=list[ThreatAuditTaskResult],
)
async def get_scan_threat_pattern_audit_results_v2(
    scan_id: str,
    task_ids: list[str] = Query(..., min_length=1, max_length=100),
    current_user: User = Depends(get_current_user),
) -> list[ThreatAuditTaskResult]:
    return await service.get_scan_threat_pattern_audit_results_v2(
        scan_id=scan_id,
        task_ids=task_ids,
        current_user=current_user,
    )


@router.get(
    "/api/v2/scans/{scan_id}/threat-pattern-audit-tasks",
    response_model=ThreatPatternAuditTaskPage,
)
async def get_scan_threat_pattern_audit_tasks_v2(
    scan_id: str,
    limit: int = Query(50, ge=1, le=100),
    cursor: str | None = Query(None),
    current_user: User = Depends(get_current_user),
    engine_id: str | None = None,
    summary: bool = True,
) -> ThreatPatternAuditTaskPage:
    return await service.get_scan_threat_pattern_audit_tasks_v2(
        scan_id=scan_id,
        limit=limit,
        cursor=cursor,
        current_user=current_user,
        engine_id=engine_id,
        summary=summary,
    )


@router.get(
    "/api/v2/scans/{scan_id}/threat-pattern-audit-tasks/{task_id}",
    response_model=ThreatPatternAuditTaskDetail,
)
async def get_scan_threat_pattern_audit_task_v2(
    scan_id: str, task_id: str, current_user: User = Depends(get_current_user),
) -> ThreatPatternAuditTaskDetail:
    return await service.get_scan_threat_pattern_audit_task_v2(
        scan_id=scan_id,
        task_id=task_id,
        current_user=current_user,
    )


@router.get(
    "/api/v2/scans/{scan_id}/validations",
    response_model=VulnerabilityValidationPage,
)
async def get_scan_validations_v2(
    scan_id: str,
    limit: int = Query(50, ge=1, le=100),
    after: int = Query(-1, ge=-1),
    current_user: User = Depends(get_current_user),
) -> VulnerabilityValidationPage:
    return await service.get_scan_validations_v2(scan_id=scan_id, limit=limit, after=after, current_user=current_user)
