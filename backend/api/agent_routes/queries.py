"""HTTP boundary for queries."""
from __future__ import annotations
from typing import Optional
from fastapi import Depends, APIRouter
from backend.auth import get_current_user
from backend.models import AgentOpenCodePoolStatus, OpenCodePoolStatus, OpenCodeTaskReport, User
from backend.report_routes import HistoricalReportRoute, ApplicationRoute
import backend.agents.queries as service

router = APIRouter(prefix="/api/agent", route_class=HistoricalReportRoute)
public_router = APIRouter(route_class=ApplicationRoute)


@router.post('/{agent_id}/opencode-pool')
async def update_agent_opencode_pool(agent_id: str, status: OpenCodePoolStatus) -> dict:
    'Agent pushes its Agent-wide OpenCode model-pool status snapshot.'
    return await service.update_agent_opencode_pool(agent_id=agent_id, status=status)


@router.post('/{agent_id}/opencode-task-report')
async def report_agent_opencode_task(agent_id: str, body: OpenCodeTaskReport) -> dict:
    'Persist one terminal logical task without resending prior Session history.'
    return await service.report_agent_opencode_task(agent_id=agent_id, body=body)


@router.get('/{agent_id}/opencode-pool', response_model=AgentOpenCodePoolStatus)
async def get_agent_opencode_pool(
    agent_id: str,
    current_user: User=Depends(get_current_user),
) -> AgentOpenCodePoolStatus:
    'Return persisted per-model usage for one Agent plus current active tasks.'
    return await service.get_agent_opencode_pool(agent_id=agent_id, current_user=current_user)


@router.get('/agents')
async def list_agents_prefixed(current_user: User=Depends(get_current_user)) -> list:
    'Return all registered agents with online status (alias for /api/agents).'
    return await service.list_agents_prefixed(current_user=current_user)


@public_router.get('/api/agents')
async def list_agents(current_user: User=Depends(get_current_user)) -> list:
    'Return agents with online status. Admin sees all; users see only their own.\n\n    Online agents come first; each group retains registration order.\n    WebSocket agents: online = WebSocket connection is active.\n    Legacy HTTP agents: online = last heartbeat < 90 seconds ago.\n    '
    return await service.list_agents(current_user=current_user)


@router.get('/feedback')
async def agent_get_feedback(vuln_types: Optional[str]=None) -> list:
    'Return feedback entries for the agent to enrich SKILLs.'
    return await service.agent_get_feedback(vuln_types=vuln_types)
