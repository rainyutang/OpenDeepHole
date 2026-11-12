"""HTTP boundary for configuration."""
from __future__ import annotations
from fastapi import Depends, APIRouter
from backend.auth import get_current_user
from backend.models import AgentRemoteConfig, OpenCodeTokenUsage, User
from backend.agents.schemas import _AgentConfigWrite, _AgentLLMConfigStatus
from backend.report_routes import HistoricalReportRoute, ApplicationRoute
import backend.agents.configuration as service

router = APIRouter(prefix="/api/agent", route_class=HistoricalReportRoute)
public_router = APIRouter(route_class=ApplicationRoute)


@router.get('/{agent_id}/config')
async def get_agent_config(
    agent_id: str,
    current_user: User=Depends(get_current_user),
) -> AgentRemoteConfig:
    'Return the server-managed config for an agent (defaults if not yet saved).'
    return await service.get_agent_config(agent_id=agent_id, current_user=current_user)


@router.put('/{agent_id}/config')
async def update_agent_config(
    agent_id: str,
    body: _AgentConfigWrite,
    current_user: User=Depends(get_current_user),
) -> dict:
    'Compatibility route for saving the stable Agent-managed config.\n\n    The path may contain the current session id or the stable agent_key.  The\n    stored record is always keyed by IP + machine name identity.\n    '
    return await service.update_agent_config(agent_id=agent_id, body=body, current_user=current_user)


@public_router.get('/api/agent-configs/{agent_key}', response_model=AgentRemoteConfig)
async def get_stable_agent_config(
    agent_key: str,
    current_user: User=Depends(get_current_user),
) -> AgentRemoteConfig:
    return await service.get_stable_agent_config(agent_key=agent_key, current_user=current_user)


@public_router.get('/api/agent-configs/{agent_key}/opencode-usage', response_model=OpenCodeTokenUsage | None)
async def get_stable_agent_opencode_usage(
    agent_key: str,
    current_user: User=Depends(get_current_user),
) -> OpenCodeTokenUsage | None:
    return await service.get_stable_agent_opencode_usage(agent_key=agent_key, current_user=current_user)


@public_router.put('/api/agent-configs/{agent_key}')
async def update_stable_agent_config(
    agent_key: str,
    body: _AgentConfigWrite,
    current_user: User=Depends(get_current_user),
) -> dict:
    return await service.update_stable_agent_config(agent_key=agent_key, body=body, current_user=current_user)


@public_router.get('/api/agent-configs/{agent_key}/opencode-config-status', response_model=_AgentLLMConfigStatus)
async def get_stable_agent_opencode_config_status(
    agent_key: str,
    current_user: User=Depends(get_current_user),
) -> _AgentLLMConfigStatus:
    return await service.get_stable_agent_opencode_config_status(agent_key=agent_key, current_user=current_user)


@public_router.post('/api/agent-configs/{agent_key}/opencode-config-apply', response_model=_AgentLLMConfigStatus)
async def apply_stable_agent_opencode_config(
    agent_key: str,
    current_user: User=Depends(get_current_user),
) -> _AgentLLMConfigStatus:
    return await service.apply_stable_agent_opencode_config(agent_key=agent_key, current_user=current_user)
