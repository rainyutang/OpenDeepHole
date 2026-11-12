"""HTTP boundary for models."""
from __future__ import annotations
from fastapi import Depends, APIRouter
from backend.auth import get_current_user
from backend.models import User
from backend.agents.schemas import (
    _AgentApiTestRequest,
    _AgentApiTestResponse,
    _AgentOpenCodeModelsResponse,
)
from backend.report_routes import HistoricalReportRoute, ApplicationRoute
import backend.agents.models as service

router = APIRouter(prefix="/api/agent", route_class=HistoricalReportRoute)
public_router = APIRouter(route_class=ApplicationRoute)


@public_router.get('/api/agent-configs/{agent_key}/opencode-models', response_model=_AgentOpenCodeModelsResponse)
async def get_stable_agent_opencode_models(
    agent_key: str,
    refresh: bool=False,
    current_user: User=Depends(get_current_user),
) -> _AgentOpenCodeModelsResponse:
    "Resolve the Agent's current connection before listing Serve models."
    return await service.get_stable_agent_opencode_models(agent_key=agent_key, refresh=refresh, current_user=current_user)


@router.get('/{agent_id}/opencode/models', response_model=_AgentOpenCodeModelsResponse)
async def get_agent_opencode_models(
    agent_id: str,
    refresh: bool=False,
    current_user: User=Depends(get_current_user),
) -> _AgentOpenCodeModelsResponse:
    'Compatibility route for the current Agent session identifier.'
    return await service.get_agent_opencode_models(agent_id=agent_id, refresh=refresh, current_user=current_user)


@public_router.post('/api/agent-configs/{agent_key}/opencode-api-test', response_model=_AgentApiTestResponse)
async def test_stable_agent_opencode_api(
    agent_key: str,
    body: _AgentApiTestRequest,
    current_user: User=Depends(get_current_user),
) -> _AgentApiTestResponse:
    "Resolve a draft's credentials, then ask its Agent to make the request."
    return await service.test_stable_agent_opencode_api(agent_key=agent_key, body=body, current_user=current_user)
