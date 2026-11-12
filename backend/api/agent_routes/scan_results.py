"""HTTP boundary for scan results."""
from __future__ import annotations
from backend.models import AgentVulnerabilityReconcile, Vulnerability
from fastapi import APIRouter, Depends
from backend.report_routes import HistoricalReportRoute, ApplicationRoute
import backend.scans.ingestion.results as service

router = APIRouter(prefix="/api/agent", route_class=HistoricalReportRoute)
public_router = APIRouter(route_class=ApplicationRoute)


@router.post('/scan/{scan_id}/vulnerability')
async def agent_report_vulnerability(
    scan_id: str,
    vuln: Vulnerability,
    provisional: bool=False,
    report_batch_id: str='',
    supports_fp_review_execution_revision: bool=False,
) -> dict:
    'Agent pushes a single vulnerability result immediately after auditing it.'
    return await service.agent_report_vulnerability(scan_id=scan_id, vuln=vuln, provisional=provisional, report_batch_id=report_batch_id, supports_fp_review_execution_revision=supports_fp_review_execution_revision)


@router.post('/scan/{scan_id}/vulnerabilities/reconcile')
async def agent_reconcile_vulnerabilities(scan_id: str, body: AgentVulnerabilityReconcile) -> dict:
    'Replace live engine batches with the authoritative post-run result list.'
    return await service.agent_reconcile_vulnerabilities(scan_id=scan_id, body=body)
