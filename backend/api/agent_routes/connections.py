"""HTTP boundary for connections."""
from __future__ import annotations
from fastapi import Request, WebSocket, APIRouter, Depends
from backend.agents.schemas import _AgentRegisterBody
from backend.report_routes import HistoricalReportRoute, ApplicationRoute
from backend.api.dependencies import runtime_scope
import backend.agents.connections as service

router = APIRouter(prefix="/api/agent", route_class=HistoricalReportRoute)
public_router = APIRouter(route_class=ApplicationRoute)


@router.websocket('/ws', dependencies=[Depends(runtime_scope)])
async def agent_websocket(websocket: WebSocket) -> None:
    'Agent connects here and receives task/stop/resume commands.'
    return await service.agent_websocket(websocket=websocket)


@router.post('/register')
async def agent_register(body: _AgentRegisterBody, request: Request) -> dict:
    'Agent calls this on startup to get an agent_id. (Legacy HTTP mode)'
    return await service.agent_register(body=body, client_host=request.client.host if request.client else 'unknown')


@router.put('/heartbeat/{agent_id}')
async def agent_heartbeat(agent_id: str) -> dict:
    'Agent sends heartbeat every 30s to stay in the online list. (Legacy HTTP mode)'
    return await service.agent_heartbeat(agent_id=agent_id)


@router.delete('/{agent_id}')
async def agent_unregister(agent_id: str) -> dict:
    'Agent calls this on graceful shutdown.'
    return await service.agent_unregister(agent_id=agent_id)
