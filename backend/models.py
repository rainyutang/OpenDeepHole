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
    feedback_ids: list[str] = []


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

class BatchMarkItem(BaseModel):
    """Single item in a batch mark request."""
    index: int
    verdict: str        # "confirmed" | "false_positive"
    reason: str = ""

class BatchMarkRequest(BaseModel):
    """Request to batch-mark multiple vulnerabilities."""
    items: list[BatchMarkItem]

class SaveFalsePositiveRequest(BaseModel):
    """Request to save a false positive experience to the project SKILL."""
    index: int


# --- Feedback models ---

class FeedbackEntry(BaseModel):
    """A user feedback entry stored in the experience database."""
    id: str
    project_id: str
    vuln_type: str
    verdict: str          # "confirmed" | "false_positive"
    file: str
    line: int
    function: str
    description: str
    reason: str = ""
    source_scan_id: str | None = None
    created_at: str
    updated_at: str


class FeedbackCreateRequest(BaseModel):
    """Request to create a new feedback entry."""
    project_id: str
    vuln_type: str
    verdict: str          # "confirmed" | "false_positive"
    file: str
    line: int
    function: str
    description: str
    reason: str = ""
    source_scan_id: str | None = None


class FeedbackUpdateRequest(BaseModel):
    """Request to update an existing feedback entry."""
    verdict: str | None = None
    reason: str | None = None


class ScanStatus(BaseModel):
    scan_id: str
    project_id: str = ""
    scan_items: list[str] = []
    created_at: str = ""
    status: ScanItemStatus
    progress: float            # 0.0 to 1.0
    total_candidates: int
    processed_candidates: int
    vulnerabilities: list[Vulnerability]
    events: list[ScanEvent] = []
    current_candidate: Candidate | None = None
    error_message: str | None = None
    feedback_ids: list[str] = []

    # 静态分析进度（按文件计）
    static_total_files: int = 0
    static_scanned_files: int = 0
    static_analysis_done: bool = False


# --- Agent API models ---

class AgentScanRegister(BaseModel):
    """Sent by the agent to register a new scan and receive a scan_id."""
    project_name: str
    scan_items: list[str]
    agent_version: str = ""


class AgentScanFinish(BaseModel):
    """Sent by the agent when the scan completes (success or error)."""
    vulnerabilities: list[Vulnerability]
    status: str                    # "complete" | "error"
    total_candidates: int
    processed_candidates: int
    error_message: str | None = None


class AgentInfo(BaseModel):
    """Info about a registered agent."""
    agent_id: str
    name: str
    ip: str
    port: int
    last_seen: str


class AgentLLMApiConfig(BaseModel):
    base_url: str = "https://api.anthropic.com"
    api_key: str = ""
    model: str = "claude-sonnet-4-6"
    temperature: float = 0.1
    timeout: int = 120
    max_retries: int = 3


class AgentOpenCodeConfig(BaseModel):
    executable: str = "opencode"
    model: str = ""
    timeout: int = 300


class AgentRemoteConfig(BaseModel):
    """Agent configuration managed from the server Web UI."""
    no_proxy: str = ""
    llm_api: AgentLLMApiConfig = AgentLLMApiConfig()
    opencode: AgentOpenCodeConfig = AgentOpenCodeConfig()


class CreateScanRequest(BaseModel):
    """Request to create a new scan via a registered agent."""
    agent_id: str
    project_path: str
    scan_name: str = ""
    checkers: list[str]
    feedback_ids: list[str] = []


class ScanMeta(BaseModel):
    """扫描元数据，记录扫描配置信息。"""
    scan_items: list[str]
    created_at: str
    feedback_ids: list[str] = []
    agent_id: str = ""
    project_path: str = ""
    scan_name: str = ""


class ScanSummary(BaseModel):
    """扫描列表的摘要信息。"""
    scan_id: str
    project_id: str
    status: ScanItemStatus
    created_at: str
    progress: float
    total_candidates: int
    processed_candidates: int
    vulnerability_count: int
    scan_items: list[str]
