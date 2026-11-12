"""HTTP bindings for scan fp review callbacks."""

from fastapi import APIRouter, Depends
from backend.models import (
    AgentFpReviewFinish,
    AgentFpReviewProgress,
    AgentFpReviewResult,
    AgentFpReviewStageOutput,
)
from backend.report_routes import HistoricalReportRoute
from backend.scans import fp_review_callbacks as service

router = APIRouter(route_class=HistoricalReportRoute)


@router.post("/api/scan/{scan_id}/fp_review/progress")
async def agent_fp_review_progress(scan_id: str, body: AgentFpReviewProgress) -> dict:
    'Agent reports which vulnerability is currently being reviewed.'
    return await service.agent_fp_review_progress(scan_id=scan_id, body=body)


@router.post("/api/scan/{scan_id}/fp_review/result")
async def agent_fp_review_result(scan_id: str, body: AgentFpReviewResult) -> dict:
    'Agent pushes a single FP review result.'
    return await service.agent_fp_review_result(scan_id=scan_id, body=body)


@router.post("/api/scan/{scan_id}/fp_review/stage-output")
async def agent_fp_review_stage_output(scan_id: str, body: AgentFpReviewStageOutput) -> dict:
    "Agent pushes one stage's Markdown output while FP review is running."
    return await service.agent_fp_review_stage_output(scan_id=scan_id, body=body)


@router.post("/api/scan/{scan_id}/fp_review/finish")
async def agent_fp_review_finish(scan_id: str, body: AgentFpReviewFinish) -> dict:
    'Agent signals the single-item FP review queue is complete.'
    return await service.agent_fp_review_finish(scan_id=scan_id, body=body)
