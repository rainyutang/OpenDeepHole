"""HTTP boundary for artifacts."""
from __future__ import annotations
from fastapi import Depends, Request, APIRouter
from fastapi.responses import Response
from backend.auth import get_current_user
from backend.models import User
from backend.report_routes import HistoricalReportRoute, ApplicationRoute
import backend.agents.artifacts as service

router = APIRouter(prefix="/api/agent", route_class=HistoricalReportRoute)
public_router = APIRouter(route_class=ApplicationRoute)


@router.get('/download')
async def agent_download(
    request: Request,
    current_user: User=Depends(get_current_user),
) -> Response:
    'Serve the agent package as a downloadable zip with server_url and owner_token pre-filled.'
    result = await service.agent_download(server_url=str(request.base_url).rstrip('/'), current_user=current_user)
    return Response(content=result.content, media_type=result.media_type, headers=result.headers)


@router.get('/runtime/manifest')
async def agent_runtime_manifest() -> dict:
    'Return the current server-side Agent runtime hash.'
    return await service.agent_runtime_manifest()


@router.get('/runtime/download')
async def agent_runtime_download(request: Request) -> Response:
    'Serve a short-lived Agent runtime update archive.'
    result = await service.agent_runtime_download(token=request.headers.get('X-Agent-Update-Token') or request.query_params.get('token') or '')
    return Response(content=result.content, media_type=result.media_type, headers=result.headers)
