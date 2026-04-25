"""Pydantic models for API requests, responses, and internal data."""

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel


class ScanItemStatus(str, Enum):
    PENDING = "pending"
    ANALYZING = "analyzing"   # static analysis running
    AUDITING = "auditing"     # opencode AI analysis running
    COMPLETE = "complete"
    ERROR = "error"
    CANCELLED = "cancelled"


# --- Internal models ---

class Candidate(BaseModel):
    """A candidate vulnerability location found by static analysis."""
    file: str
    line: int
    function: str
    description: str
    vuln_type: str


class Vulnerability(BaseModel):
    """A confirmed or assessed vulnerability after AI analysis."""
    file: str
    line: int
    function: str
    vuln_type: str
    severity: str        # "high", "medium", "low"
    description: str
    ai_analysis: str
    confirmed: bool
    user_verdict: str | None = None          # "confirmed" | "false_positive" | None
    user_verdict_reason: str | None = None   # 用户填写的理由


# --- API request/response models ---

class CheckerInfo(BaseModel):
    """Info about an available checker, returned by GET /api/checkers."""
    name: str
    label: str
    description: str


class UploadResponse(BaseModel):
    project_id: str


class ScanRequest(BaseModel):
    project_id: str
    scan_items: list[str]


class ScanStartResponse(BaseModel):
    scan_id: str


class ScanEvent(BaseModel):
    """A timestamped event during the scan process."""
    timestamp: str
    phase: str            # "init", "mcp_ready", "static_analysis", "auditing", "complete", "error"
    message: str
    candidate_index: int | None = None

    @staticmethod
    def create(phase: str, message: str, candidate_index: int | None = None) -> "ScanEvent":
        return ScanEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            phase=phase,
            message=message,
            candidate_index=candidate_index,
        )


class MarkRequest(BaseModel):
    """Request to mark a vulnerability as confirmed or false positive."""
    index: int
    verdict: str        # "confirmed" | "false_positive"
    reason: str = ""

class SaveFalsePositiveRequest(BaseModel):
    """Request to save a false positive experience to the project SKILL."""
    index: int


class ScanStatus(BaseModel):
    scan_id: str
    project_id: str = ""
    status: ScanItemStatus
    progress: float            # 0.0 to 1.0
    total_candidates: int
    processed_candidates: int
    vulnerabilities: list[Vulnerability]
    events: list[ScanEvent] = []
    current_candidate: Candidate | None = None
    error_message: str | None = None
