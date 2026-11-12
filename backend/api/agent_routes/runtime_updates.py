"""HTTP boundary for runtime updates."""
from __future__ import annotations
from fastapi import Depends, Request, APIRouter
from backend.auth import get_current_user
from backend.models import User
from backend.report_routes import HistoricalReportRoute, ApplicationRoute
import backend.agents.runtime_updates as service

router = APIRouter(prefix="/api/agent", route_class=HistoricalReportRoute)
public_router = APIRouter(route_class=ApplicationRoute)


@public_router.post('/api/agent-configs/{agent_key}/runtime-update')
async def request_stable_agent_runtime_update(
    agent_key: str,
    request: Request,
    current_user: User=Depends(get_current_user),
) -> dict:
    return await service.request_stable_agent_runtime_update(agent_key=agent_key, server_url=str(request.base_url).rstrip('/'), current_user=current_user)
