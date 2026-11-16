"""Execution-scoped audit reports and lightweight collection invalidations."""

from pydantic import BaseModel, Field, field_validator


class PatternTaskReportIdentity(BaseModel):
    execution_revision: int = Field(gt=0, strict=True)
    report_agent_session_id: str = Field(min_length=1)
    report_sequence: int = Field(gt=0, strict=True)

    @field_validator("report_agent_session_id")
    @classmethod
    def nonblank_session(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("report_agent_session_id must not be blank")
        return value


def pattern_report_identity(body: dict) -> dict:
    fields = PatternTaskReportIdentity.model_fields
    if not any(key in body for key in fields):
        return {}
    return PatternTaskReportIdentity.model_validate(body).model_dump()


def publish_pattern_task_settlement(scan_id: str, engine_ids: list[str], execution_revision: int) -> None:
    if not engine_ids:
        return
    from backend.application import get_runtime, publish

    # Cached lists are not the authority for detail reads. Avoid loading every
    # task (and its report metadata) merely to announce a set-based update.
    cached = get_runtime().scans.running_scans.get(scan_id)
    if cached is not None and cached.execution_revision == execution_revision:
        cached.threat_pattern_audit_tasks = []
    publish(scan_id, "resource_changed", {
        "resource": "threat-pattern-audit-tasks",
        "change": "task_status",
        "engine_ids": sorted(set(engine_ids)),
        "execution_revision": execution_revision,
    })
