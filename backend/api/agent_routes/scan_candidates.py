"""HTTP boundary for scan candidates."""
from __future__ import annotations
from backend.models import AgentCandidateAuditResult, AgentScanCandidateBatch, AgentScanCandidates
from fastapi import APIRouter, Depends
from backend.report_routes import HistoricalReportRoute, ApplicationRoute
import backend.scans.ingestion.candidates as service

router = APIRouter(prefix="/api/agent", route_class=HistoricalReportRoute)
public_router = APIRouter(route_class=ApplicationRoute)


@router.post('/scan/{scan_id}/candidates')
async def agent_report_scan_candidates(scan_id: str, body: AgentScanCandidates) -> dict:
    'Agent pushes the final static-analysis candidate list for a scan.'
    return await service.agent_report_scan_candidates(scan_id=scan_id, body=body)


@router.post('/v2/scan/{scan_id}/candidates')
async def agent_report_scan_candidates_v2(scan_id: str, body: AgentScanCandidateBatch) -> dict:
    'Persist one bounded candidate chunk without broadcasting the full list.'
    return await service.agent_report_scan_candidates_v2(scan_id=scan_id, body=body)


@router.post('/scan/{scan_id}/candidate-audit')
async def agent_report_candidate_audit(scan_id: str, body: AgentCandidateAuditResult) -> dict:
    'Upsert the one authoritative audit result owned by candidate_idx.'
    return await service.agent_report_candidate_audit(scan_id=scan_id, body=body)
