"""HTTP bindings for scan configuration queries."""

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from backend.auth import get_current_user
from backend.models import ScanConfigMemoryResponse, ScanCopyConfig, User
from backend.report_routes import HistoricalReportRoute
from backend.scans import configuration_queries as service

router = APIRouter(route_class=HistoricalReportRoute)


@router.get(
    "/api/scan/config-memory/{agent_key}",
    response_model=ScanConfigMemoryResponse,
)
async def get_scan_config_memory(
    agent_key: str,
    current_user: User = Depends(get_current_user),
) -> ScanConfigMemoryResponse:
    return await service.get_scan_config_memory(agent_key=agent_key, current_user=current_user)


@router.get("/api/scan/validation-targets")
async def list_scan_validation_targets(
    _current_user: User = Depends(get_current_user),
) -> dict:
    'Retire the legacy server-side product/environment catalog.'
    return await service.list_scan_validation_targets(_current_user=_current_user)


@router.get("/api/scan/{scan_id}/copy-config", response_model=ScanCopyConfig)
async def get_scan_copy_config(
    scan_id: str,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> ScanCopyConfig:
    'Read saved form values without creating a scan or resolving new defaults.'
    result = await service.get_scan_copy_config(scan_id=scan_id, current_user=current_user)
    response.headers["Cache-Control"] = "no-store"
    return result
