"""Application handling for Agent skill creation results."""

from datetime import datetime, timezone

from backend.application import get_runtime
from backend.models import SkillDraft


def handle_skill_create_result(payload: dict) -> None:
    """Record a result message sent by an Agent over WebSocket."""
    job_id = str(payload.get("request_id") or "")
    job = get_runtime().skill_jobs.get(job_id)
    if job is None:
        return

    status = "completed" if payload.get("ok") else "error"
    job.status = status
    job.updated_at = datetime.now(timezone.utc).isoformat()
    if status == "completed":
        draft_payload = payload.get("draft") or {}
        job.draft = SkillDraft(
            skill_md=str(draft_payload.get("skill_md") or ""),
            scenarios_md=str(draft_payload.get("scenarios_md") or ""),
            summary=str(draft_payload.get("summary") or ""),
        )
        job.error_message = ""
    else:
        job.error_message = str(payload.get("message") or "SKILL 创建失败")
    get_runtime().skill_jobs[job_id] = job
