"""HTTP boundary for scan validation."""
from __future__ import annotations
from backend.models import AgentVulnerabilityValidationUpdate, AgentValidationDelta
from fastapi import APIRouter, Depends
from backend.report_routes import HistoricalReportRoute, ApplicationRoute
import backend.scans.ingestion.validation as service

router = APIRouter(prefix="/api/agent", route_class=HistoricalReportRoute)
public_router = APIRouter(route_class=ApplicationRoute)


@router.post('/scan/{scan_id}/validation')
async def agent_report_vulnerability_validation(
    scan_id: str,
    body: AgentVulnerabilityValidationUpdate,
) -> dict:
    'Agent pushes local validation script progress/results for one vulnerability.'
    return await service.agent_report_vulnerability_validation(scan_id=scan_id, body=body)


@router.post('/v2/scan/{scan_id}/validation')
async def agent_report_validation_delta(scan_id: str, body: AgentValidationDelta) -> dict:
    return await service.agent_report_validation_delta(scan_id=scan_id, body=body)
