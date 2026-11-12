"""HTTP boundary for scan completion."""
from __future__ import annotations
from fastapi import Request, APIRouter, Depends
from fastapi.responses import Response
from backend.models import AgentScanFinish, AgentScanExecutionFailure, AgentScanFinishV2
from backend.report_routes import HistoricalReportRoute, ApplicationRoute
import backend.scans.ingestion.completion as service

router = APIRouter(prefix="/api/agent", route_class=HistoricalReportRoute)
public_router = APIRouter(route_class=ApplicationRoute)


@router.post('/scan/{scan_id}/execution-failed')
async def agent_scan_execution_failed(scan_id: str, body: AgentScanExecutionFailure) -> dict:
    return await service.agent_scan_execution_failed(scan_id=scan_id, body=body)


@router.post('/scan/{scan_id}/finish')
async def agent_finish_scan(scan_id: str, body: AgentScanFinish, request: Request) -> dict:
    'Agent pushes final results when the scan completes, errors, or is cancelled.'
    return await service.agent_finish_scan(scan_id=scan_id, body=body, server_url=str(request.base_url).rstrip('/'))


@router.post('/v2/scan/{scan_id}/finish')
async def agent_finish_scan_v2(scan_id: str, body: AgentScanFinishV2, request: Request) -> dict:
    'Finalize a v2 scan without resending every streamed finding.'
    return await service.agent_finish_scan_v2(scan_id=scan_id, body=body, server_url=str(request.base_url).rstrip('/'))


@router.get('/v2/resume-manifests/{token}')
async def agent_get_resume_manifest_v2(token: str) -> Response:
    'Return a durable resume payload outside the Agent WebSocket frame.'
    result = await service.agent_get_resume_manifest_v2(token=token)
    return Response(content=result.content, media_type=result.media_type, headers=result.headers)
