"""Agent HTTP routes for Javelin 5-channel ingestion & transient secret_context."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Header, Query

from backend.report_routes import HistoricalReportRoute
from backend.scans.ingestion import javelin as javelin_ingestion

router = APIRouter(prefix="/api/agent/scan/{scan_id}/javelin", route_class=HistoricalReportRoute)


@router.post("/state")
async def agent_javelin_state(
    scan_id: str,
    payload: dict[str, Any] = Body(...),
    x_agent_id: str = Header(default=""),
) -> dict[str, Any]:
    return await javelin_ingestion.ingest_javelin_state(scan_id, payload, agent_id=x_agent_id)


@router.post("/events")
async def agent_javelin_events(
    scan_id: str,
    payload: dict[str, Any] = Body(...),
    x_agent_id: str = Header(default=""),
) -> dict[str, Any]:
    return await javelin_ingestion.ingest_javelin_events(scan_id, payload, agent_id=x_agent_id)


@router.post("/task-board")
async def agent_javelin_task_board(
    scan_id: str,
    payload: dict[str, Any] = Body(...),
    x_agent_id: str = Header(default=""),
) -> dict[str, Any]:
    return await javelin_ingestion.ingest_javelin_task_board(scan_id, payload, agent_id=x_agent_id)


@router.post("/artifacts")
async def agent_javelin_artifacts(
    scan_id: str,
    payload: dict[str, Any] = Body(...),
    x_agent_id: str = Header(default=""),
) -> dict[str, Any]:
    return await javelin_ingestion.ingest_javelin_artifacts(scan_id, payload, agent_id=x_agent_id)


@router.post("/report/chunk")
async def agent_javelin_report_chunk(
    scan_id: str,
    payload: dict[str, Any] = Body(...),
    x_agent_id: str = Header(default=""),
) -> dict[str, Any]:
    return await javelin_ingestion.ingest_javelin_report_chunk(scan_id, payload, agent_id=x_agent_id)


@router.post("/report")
async def agent_javelin_report(
    scan_id: str,
    payload: dict[str, Any] = Body(...),
    x_agent_id: str = Header(default=""),
) -> dict[str, Any]:
    return await javelin_ingestion.ingest_javelin_report(scan_id, payload, agent_id=x_agent_id)


@router.get("/secret-context")
async def agent_javelin_get_secret_context(
    scan_id: str,
    execution_revision: int = Query(default=1, ge=1),
    agent_session_id: str = Query(default=""),
    x_agent_id: str = Header(default=""),
) -> dict[str, Any]:
    return await javelin_ingestion.fetch_agent_javelin_secret_context(
        scan_id,
        execution_revision=execution_revision,
        agent_id=x_agent_id,
        agent_session_id=agent_session_id,
    )


@router.post("/secret-context/ack")
async def agent_javelin_ack_secret_context(
    scan_id: str,
    payload: dict[str, Any] = Body(default_factory=dict),
    x_agent_id: str = Header(default=""),
) -> dict[str, Any]:
    return await javelin_ingestion.ack_agent_javelin_secret_context(
        scan_id,
        execution_revision=int(payload.get("execution_revision") or 1),
        agent_id=x_agent_id,
        agent_session_id=str(payload.get("agent_session_id") or ""),
    )
