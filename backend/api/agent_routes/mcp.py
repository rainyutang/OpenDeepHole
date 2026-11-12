"""HTTP boundary for mcp."""
from __future__ import annotations
from fastapi import Depends, APIRouter
from backend.auth import get_current_user
from backend.models import (
    AgentMcpConfig,
    AgentMcpProbeResult,
    AgentMcpStatusResponse,
    AgentValidatorCatalog,
    User,
)
from backend.report_routes import HistoricalReportRoute, ApplicationRoute
import backend.agents.mcp as service

router = APIRouter(prefix="/api/agent", route_class=HistoricalReportRoute)
public_router = APIRouter(route_class=ApplicationRoute)


@public_router.get('/api/agent-configs/{agent_key}/mcp-status', response_model=AgentMcpStatusResponse)
async def get_stable_agent_mcp_status(
    agent_key: str,
    current_user: User=Depends(get_current_user),
) -> AgentMcpStatusResponse:
    return await service.get_stable_agent_mcp_status(agent_key=agent_key, current_user=current_user)


@public_router.post('/api/agent-configs/{agent_key}/mcp-reload/{target}')
async def reload_stable_agent_mcp(
    agent_key: str,
    target: str,
    current_user: User=Depends(get_current_user),
) -> dict:
    return await service.reload_stable_agent_mcp(agent_key=agent_key, target=target, current_user=current_user)


@public_router.post('/api/agent-configs/{agent_key}/mcp-probe/{target}', response_model=AgentMcpProbeResult)
async def probe_stable_agent_mcp(
    agent_key: str,
    target: str,
    current_user: User=Depends(get_current_user),
    mcp_config: AgentMcpConfig | None=None,
) -> AgentMcpProbeResult:
    return await service.probe_stable_agent_mcp(agent_key=agent_key, target=target, current_user=current_user, mcp_config=mcp_config)


@public_router.get('/api/agent-configs/{agent_key}/validator-catalog', response_model=AgentValidatorCatalog)
async def get_stable_agent_validator_catalog(
    agent_key: str,
    product: str='',
    current_user: User=Depends(get_current_user),
) -> AgentValidatorCatalog:
    return await service.get_stable_agent_validator_catalog(agent_key=agent_key, product=product, current_user=current_user)


@public_router.get('/api/agent-configs/{agent_key}/validation-environments')
async def get_stable_agent_validation_environments(
    agent_key: str,
    product: str='',
    current_user: User=Depends(get_current_user),
) -> dict:
    return await service.get_stable_agent_validation_environments(agent_key=agent_key, product=product, current_user=current_user)
