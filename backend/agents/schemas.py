"""Schemas services for Agent-backed scans."""

from __future__ import annotations
from backend.models import AgentRemoteConfig
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from backend.application import ApplicationError as HTTPException
from typing import Literal
from dataclasses import dataclass


@dataclass(frozen=True)
class _RuntimeDownload:
    runtime_hash: str
    archive_sha256: str
    manifest: dict
    data: bytes
    expires_at: float


class _AgentRegisterBody(BaseModel):
    port: int
    name: str = ""


class _AgentOpenCodeModelInfo(BaseModel):
    id: str
    model: str
    provider_id: str = ""
    model_id: str = ""
    name: str = ""


class _AgentOpenCodeModelsResponse(BaseModel):
    ok: bool
    message: str = ""
    models: list[_AgentOpenCodeModelInfo] = []


class _AgentConfigWrite(AgentRemoteConfig):
    """Keep Pydantic's malformed-input diagnostics from echoing credentials."""

    @model_validator(mode="wrap")
    @classmethod
    def _safe_validation_errors(cls, value, handler):
        try:
            return handler(value)
        except ValidationError as exc:
            errors = [
                {"type": item["type"], "loc": ["body", *item["loc"]], "msg": item["msg"]}
                for item in exc.errors(include_input=False, include_context=False)
            ]
            raise HTTPException(status_code=422, detail=errors) from None


class _AgentLLMConfigStatus(BaseModel):
    desired_revision: str = ""
    applied_revision: str = ""
    state: Literal["active", "draining", "applying", "failed", "unsupported", "offline"]
    active_tasks: int = 0
    error: str = ""


class _AgentApiTestRequest(BaseModel):
    provider_id: str
    provider: dict[str, object]
    model_id: str

    @model_validator(mode="wrap")
    @classmethod
    def _safe_validation_errors(cls, value, handler):
        try:
            return handler(value)
        except ValidationError as exc:
            errors = [
                {"type": item["type"], "loc": ["body", *item["loc"]], "msg": item["msg"]}
                for item in exc.errors(include_input=False, include_context=False)
            ]
            raise HTTPException(status_code=422, detail=errors) from None


class _AgentApiTestResponse(BaseModel):
    model_config = ConfigDict(strict=True)

    success: bool
    elapsed_ms: float = Field(ge=0, allow_inf_nan=False)
    http_status: int | None = Field(default=None, ge=100, le=599)
    category: str
    error: str = ""


class _IndexStatusBody(BaseModel):
    status: str           # "not_started" | "parsing" | "done" | "error" | "skipped"
    parsed_files: int = 0
    total_files: int = 0
    stage: str = ""
    stage_current: int = 0
    stage_total: int = 0
    stats: dict[str, int] | None = None
    error: str | None = None


class _StaticProgressBody(BaseModel):
    scanned: int = 0
    total: int = 0
    done: bool = False
