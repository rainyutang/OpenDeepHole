"""HTTP boundary for scan events."""
from __future__ import annotations
from backend.models import AgentScanEventBatch, ScanEvent
from fastapi import APIRouter, Depends
from backend.report_routes import HistoricalReportRoute, ApplicationRoute
import backend.scans.ingestion.events as service

router = APIRouter(prefix="/api/agent", route_class=HistoricalReportRoute)
public_router = APIRouter(route_class=ApplicationRoute)


@router.post('/scan/{scan_id}/event')
async def agent_scan_event(scan_id: str, event: ScanEvent) -> dict:
    'Agent pushes a progress event. Updates in-memory scan state and DB.'
    return await service.agent_scan_event(scan_id=scan_id, event=event)


@router.post('/v2/scan/{scan_id}/events')
async def agent_scan_events_v2(scan_id: str, body: AgentScanEventBatch) -> dict:
    'Persist a bounded event chunk in one transaction and one progress write.'
    return await service.agent_scan_events_v2(scan_id=scan_id, body=body)
