"""HTTP bindings for scan events."""

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from backend.report_routes import HistoricalReportRoute
from backend.scans import events as service

router = APIRouter(route_class=HistoricalReportRoute)


@router.get("/api/scan/{scan_id}/events")
async def scan_events_sse(
    scan_id: str,
    request: Request,
    token: str = Query(...),
) -> StreamingResponse:
    'SSE stream for real-time scan and FP review status updates.\n\n    The browser EventSource API does not support custom headers, so the\n    JWT is passed as a query parameter.\n    '
    events = await service.scan_events_sse(
        scan_id=scan_id,
        last_event_id_header=request.headers.get('last-event-id', ''),
        token=token,
    )
    return StreamingResponse(events, media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
