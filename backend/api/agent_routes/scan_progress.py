"""HTTP boundary for scan progress."""
from __future__ import annotations
from backend.models import (
    AgentProcessedKeyBatch,
    MiningEngineRunStatus,
    OpenCodePoolStatus,
    ThreatAnalysisRunStatus,
)
from backend.agents.schemas import _IndexStatusBody, _StaticProgressBody
from fastapi import APIRouter, Depends
from backend.report_routes import HistoricalReportRoute, ApplicationRoute
import backend.scans.ingestion.progress as service

router = APIRouter(prefix="/api/agent", route_class=HistoricalReportRoute)
public_router = APIRouter(route_class=ApplicationRoute)


@router.post('/scan/{scan_id}/mining-engine-run')
async def agent_report_mining_engine_run(scan_id: str, body: MiningEngineRunStatus) -> dict:
    'Agent reports one isolated mining-engine lifecycle state.'
    return await service.agent_report_mining_engine_run(scan_id=scan_id, body=body)


@router.post('/scan/{scan_id}/threat-analysis-run')
async def agent_report_threat_analysis_run(scan_id: str, body: ThreatAnalysisRunStatus) -> dict:
    'Agent reports the standalone threat-analysis lifecycle state.'
    return await service.agent_report_threat_analysis_run(scan_id=scan_id, body=body)


@router.post('/scan/{scan_id}/processed')
async def agent_report_processed(scan_id: str, body: dict) -> dict:
    'Agent reports a terminal candidate checkpoint after each audit.'
    return await service.agent_report_processed(scan_id=scan_id, body=body)


@router.post('/v2/scan/{scan_id}/processed')
async def agent_report_processed_v2(scan_id: str, body: AgentProcessedKeyBatch) -> dict:
    return await service.agent_report_processed_v2(scan_id=scan_id, body=body)


@router.get('/scan/{scan_id}/processed')
async def agent_get_processed(scan_id: str) -> list:
    'Return all processed candidate keys for a scan (used by agent on resume).'
    return await service.agent_get_processed(scan_id=scan_id)


@router.get('/scan/{scan_id}/candidate-audits/processed')
async def agent_get_processed_candidate_indexes(scan_id: str) -> list[int]:
    'Return terminal candidate indexes for idx-based resume.'
    return await service.agent_get_processed_candidate_indexes(scan_id=scan_id)


@router.post('/scan/{scan_id}/index-status')
async def agent_push_index_status(scan_id: str, body: _IndexStatusBody) -> dict:
    'Agent pushes code-indexing progress. Stored in memory for frontend polling.'
    return await service.agent_push_index_status(scan_id=scan_id, body=body)


@router.post('/scan/{scan_id}/static-progress')
async def agent_push_static_progress(scan_id: str, body: _StaticProgressBody) -> dict:
    'Agent pushes static analysis progress (function/file counts).'
    return await service.agent_push_static_progress(scan_id=scan_id, body=body)


@router.post('/scan/{scan_id}/opencode-pool')
async def agent_push_opencode_pool(scan_id: str, body: OpenCodePoolStatus) -> dict:
    'Agent pushes the latest OpenCode model-pool status for one scan.'
    return await service.agent_push_opencode_pool(scan_id=scan_id, body=body)


@router.get('/scan/{scan_id}/index-status')
async def agent_get_index_status(scan_id: str) -> dict:
    'Return the current code-indexing progress for an agent scan.'
    return await service.agent_get_index_status(scan_id=scan_id)
