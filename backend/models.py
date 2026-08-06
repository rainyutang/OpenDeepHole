"""Pydantic models for API requests, responses, and internal data."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic.json_schema import SkipJsonSchema


class ScanItemStatus(str, Enum):
    PENDING = "pending"
    ANALYZING = "analyzing"   # static analysis running
    AUDITING = "auditing"     # opencode AI analysis running
    COMPLETE = "complete"
    ERROR = "error"
    CANCELLED = "cancelled"


class FpReviewMethod(str, Enum):
    """False-positive review workflow selected when a scan is created."""

    ADVERSARIAL = "adversarial"
    FP_CHECK = "fp_check"


# --- User / Auth models ---

class User(BaseModel):
    user_id: str
    username: str
    role: str  # "admin" | "user"
    agent_token: str = ""
    created_at: str = ""


class UserInDB(User):
    password_hash: str


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    token: str
    user: User


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "user"


class RegisterRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class Announcement(BaseModel):
    announcement_id: str
    title: str
    content: str
    published: bool = False
    published_at: str = ""
    created_at: str = ""
    updated_at: str = ""


class AnnouncementCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    content: str = Field(min_length=1, max_length=4000)
    published: bool = False


class AnnouncementUpdateRequest(AnnouncementCreateRequest):
    pass


# --- Internal models ---

class Candidate(BaseModel):
    """A candidate vulnerability location found by static analysis."""
    file: str
    line: int
    function: str
    description: str
    vuln_type: str
    related_functions: list[str] = []
    metadata: dict = Field(default_factory=dict)


class ScanCandidate(Candidate):
    """A persisted static-analysis candidate for one scan."""
    idx: int


class OutputSource(BaseModel):
    """Metadata describing which runtime produced an AI-visible output."""
    agent_id: str = ""
    agent_name: str = ""
    agent_session_id: str = ""
    backend: str = ""              # "cli" | "api" | "system"
    tool: str = ""
    model_id: str = ""
    model: str = ""
    use_default_model: bool = False
    capability: str = ""
    required_capability: str = ""
    task_id: str = ""
    attempt: int = 0
    started_at: str = ""
    serve_session_id: str = ""


class CallChainEntry(BaseModel):
    """One function location in an externally reachable vulnerability path."""

    function: str
    file: str
    line: int = Field(ge=1)


class Vulnerability(BaseModel):
    """A confirmed or assessed vulnerability after AI analysis."""
    file: str
    line: int
    function: str
    call_chain: list[CallChainEntry | str] = []
    vuln_type: str
    severity: str        # "critical", "high", "medium", "low"
    description: str
    impact: str = ""
    vulnerable_code: str = ""
    attack_entry: str = ""
    root_cause: str = ""
    trigger_conditions: str = ""
    ai_analysis: str = ""                     # Legacy unstructured analysis
    vulnerability_report: str = ""            # Legacy/downstream Markdown report
    confirmed: bool
    ai_verdict: str = ""                     # "confirmed" | "not_confirmed" | "timeout" | "no_result" | "failed" | "filtered_same_pattern"
    failure_reason: str = ""                 # OpenCode/runner output for retryable failures
    user_verdict: str | None = None          # "confirmed" | "false_positive" | "pending_analysis" | None
    user_verdict_reason: str | None = None   # 用户填写的理由
    ticket_submitted: bool = False           # 是否已提问题单
    ticket_id: str = ""                      # 问题单号
    function_source: str = ""
    function_start_line: int | None = None
    audit_index: int | None = None           # Static candidate audit order; DB idx remains the API handle.
    variant_of: str = ""                     # 同类变体排查命中时，来源历史问题模式（根因摘要+出处提交/文件）
    analysis_source: str = "static_candidate"  # "static_candidate" | "threat_audit"
    engine_id: str = "static_candidate"
    engine_label: str = "静态规则扫描 + 候选点审计"
    source_task_id: str = ""
    threat_surface_node_id: str = ""
    threat_method_node_id: str = ""
    threat_code_path: str = ""
    output_source: OutputSource = Field(default_factory=OutputSource)


class MiningEngineRequest(BaseModel):
    """One mining engine explicitly selected for a new scan."""

    engine_id: str


class MiningEngineSelection(BaseModel):
    """Resolved immutable mining-engine snapshot stored on a scan."""

    engine_id: str
    engine_label: str
    enabled: bool = True


class MiningEngineRunStatus(BaseModel):
    """One engine's lifecycle state within a scan."""

    engine_id: str
    engine_label: str
    status: str = "pending"
    error_message: str = ""
    started_at: str = ""
    finished_at: str = ""


class ThreatAnalysisRunStatus(BaseModel):
    """Standalone threat-analysis lifecycle state within a scan."""

    status: str = "pending"
    error_message: str = ""
    started_at: str = ""
    finished_at: str = ""


class ThreatAnalysisMethodSelection(BaseModel):
    """Resolved immutable threat-analysis method snapshot stored on a scan."""

    method_id: str
    method_label: str
    description: str = ""


class ThreatAnalysisMethodCatalogItem(BaseModel):
    method_id: str
    label: str
    description: str


class ThreatAnalysisMethodCatalog(BaseModel):
    methods: list[ThreatAnalysisMethodCatalogItem] = []
    errors: list[str] = []
    updated_at: str = ""


class MiningEngineCatalogItem(BaseModel):
    engine_id: str
    label: str
    description: str
    fp_review: bool


class MiningEngineCatalog(BaseModel):
    engines: list[MiningEngineCatalogItem] = []
    errors: list[str] = []
    updated_at: str = ""


class FpReviewStageConfig(BaseModel):
    key: str
    label: str


class FpReviewMethodCatalogItem(BaseModel):
    method_id: str
    label: str
    description: str
    default: bool = False
    max_concurrency: int = 1
    stages: list[FpReviewStageConfig] = Field(default_factory=list)


class FpReviewMethodCatalog(BaseModel):
    methods: list[FpReviewMethodCatalogItem] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    updated_at: str = ""


class FpReviewMethodSelection(BaseModel):
    """Immutable method metadata captured when a scan is created."""

    method_id: str
    method_label: str
    description: str = ""
    stages: list[FpReviewStageConfig] = Field(default_factory=list)


# --- API request/response models ---

class CheckerInfo(BaseModel):
    """Info about an available checker, returned by GET /api/checkers."""
    name: str
    label: str
    description: str
    visibility: str = "public"
    category: str = "illegal_memory_use"
    category_label: str = "非法内存使用"
    modified_at: str = ""
    user_created: bool = False
    created_by_user_id: str = ""
    creator_username: str = ""
    can_delete: bool = False
    result_mode: str = "vulnerabilities"
    timeout_seconds: int | None = None
    model_capability: str = "any"


class CheckerCatalogItem(BaseModel):
    """Detailed checker/SKILL introduction for the checker catalog page."""
    name: str
    label: str
    description: str
    enabled: bool = True
    visibility: str = "public"
    category: str = "illegal_memory_use"
    category_label: str = "非法内存使用"
    modified_at: str = ""
    introduction: str = ""
    introduction_source: str = ""
    user_created: bool = False
    created_by_user_id: str = ""
    creator_username: str = ""
    can_delete: bool = False
    result_mode: str = "vulnerabilities"
    timeout_seconds: int | None = None
    model_capability: str = "any"


class SkillDraft(BaseModel):
    skill_md: str = ""
    scenarios_md: str = ""
    summary: str = ""


class SkillCreateRequest(BaseModel):
    agent_id: str = ""
    skill_id: str
    name: str
    description: str
    input: str
    timeout_seconds: int = 3600


class SkillCreateJob(BaseModel):
    job_id: str
    status: str
    skill_id: str = ""
    name: str
    description: str
    input: str = ""
    agent_id: str = ""
    agent_name: str = ""
    user_id: str = ""
    created_at: str = ""
    updated_at: str = ""
    error_message: str = ""
    draft: SkillDraft | None = None


class SkillImportFile(BaseModel):
    path: str
    content_b64: str


class SkillImportRequest(BaseModel):
    skill_md: str
    scenarios_md: str = ""
    timeout_seconds: int = 3600
    files: list[SkillImportFile] = []


class SkillImportResponse(BaseModel):
    ok: bool = True
    name: str


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
    """Request to mark a vulnerability with manual triage feedback."""
    index: int
    verdict: str        # "confirmed" | "false_positive" | "pending_analysis"
    reason: str = ""
    ticket_submitted: bool = False
    ticket_id: str = ""

class BatchMarkItem(BaseModel):
    """Single item in a batch mark request."""
    index: int
    verdict: str        # "confirmed" | "false_positive" | "pending_analysis"
    reason: str = ""
    ticket_submitted: bool = False
    ticket_id: str = ""

class BatchMarkRequest(BaseModel):
    """Request to batch-mark multiple vulnerabilities."""
    items: list[BatchMarkItem]

class UnmarkRequest(BaseModel):
    """Request to clear a vulnerability's manual verdict."""
    index: int

class BatchUnmarkRequest(BaseModel):
    """Request to clear manual verdicts for multiple vulnerabilities."""
    indices: list[int]

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
    ticket_submitted: bool = False
    ticket_id: str = ""
    function_source: str = ""
    function_start_line: int | None = None
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
    ticket_submitted: bool = False
    ticket_id: str = ""
    function_source: str = ""
    function_start_line: int | None = None
    source_scan_id: str | None = None


class FeedbackUpdateRequest(BaseModel):
    """Request to update an existing feedback entry."""
    verdict: str | None = None
    reason: str | None = None
    ticket_submitted: bool | None = None
    ticket_id: str | None = None


class SkillReport(BaseModel):
    id: int | None = None
    scan_id: str = ""
    checker_name: str
    filename: str
    title: str = ""
    content: str
    created_at: str = ""
    output_source: OutputSource = Field(default_factory=OutputSource)


class ThreatCodePath(BaseModel):
    path: str = ""
    description: str = ""


class ThreatAuditTask(BaseModel):
    """One audit task derived from an attack-tree threat-analysis result."""
    task_id: str
    scan_id: str = ""
    status: str = "pending"  # pending | queued | running | completed | failed | timeout | no_result | cancelled
    surface_node_id: str = ""
    surface_name: str = ""
    method_node_id: str = ""
    method_name: str = ""
    attack_goal: str = ""
    risk_id: str = ""
    risk_name: str = ""
    asset_id: str = ""
    asset_name: str = ""
    code_path: str = ""
    code_path_description: str = ""
    code_paths: list[ThreatCodePath] = []
    attack_path_id: str = ""
    attack_path_fingerprint: str = ""
    description: str = ""
    result_vuln_indexes: list[int] = []
    failure_reason: str = ""
    output_source: OutputSource = Field(default_factory=OutputSource)
    created_at: str = ""
    started_at: str = ""
    finished_at: str = ""
    updated_at: str = ""


class VulnerabilityValidation(BaseModel):
    """Runtime validation status and artifacts for one vulnerability."""
    scan_id: str = ""
    vuln_index: int
    status: str = "pending"              # pending | queued | running | verified | failed | error | timeout | skipped | cancelled
    running: bool = False
    product: str = ""
    validation_environment: str = ""
    validation_method_id: str = ""
    validation_method_label: str = ""
    validator_name: str = ""
    validation_success: bool | None = None
    is_problem: bool | None = None
    requires_human_intervention: bool | None = None
    validation_code: str = ""
    validation_output: str = ""
    intermediate_output: str = ""
    output_sections: list[dict] = []
    final_output: str = ""
    artifacts: list[dict] = []
    started_at: str = ""
    finished_at: str = ""
    updated_at: str = ""


class AgentModelTimeWindow(BaseModel):
    """One model availability window in the Agent's local timezone."""

    weekdays: list[int] = Field(default_factory=lambda: list(range(1, 8)))
    start: str = ""
    end: str = ""


class OpenCodePoolModelStats(BaseModel):
    id: str
    model: str = ""
    use_default_model: bool = False
    capability: str = ""
    weight: float = 1.0
    effective_weight: float = 1.0
    health_penalty_level: int = 0
    last_health_failure_at: str = ""
    last_health_failure_kind: str = ""
    max_concurrency: int = 1
    enabled: bool = True
    available: bool = True
    time_windows: list[dict[str, object]] = []
    queued: int = 0
    running: int = 0
    total: int = 0
    success: int = 0
    failure: int = 0
    timeout: int = 0
    cancelled: int = 0
    avg_duration_seconds: float = 0.0
    last_status: str = ""
    last_started_at: str = ""
    last_finished_at: str = ""
    active_tasks: list[dict] = []

    @model_validator(mode="before")
    @classmethod
    def default_effective_weight_to_configured_weight(cls, value):
        """Keep snapshots from older Agents compatible with health-aware UIs."""
        if isinstance(value, dict) and value.get("effective_weight") is None:
            value = {**value, "effective_weight": value.get("weight", 1.0)}
        return value


class OpenCodeTokenCounters(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    total_tokens: int = 0


class OpenCodeModelTokenUsage(OpenCodeTokenCounters):
    model: str = "unknown"


class OpenCodeTokenUsage(OpenCodeTokenCounters):
    complete: bool = True
    by_model: list[OpenCodeModelTokenUsage] = []


class OpenCodePoolStatus(BaseModel):
    scope_id: str = ""
    agent_name: str = ""
    agent_session_id: str = ""
    global_running: int = 0
    global_queued: int = 0
    total_tasks: int = 0
    completed_task_count: int = 0
    queued_tasks: list[dict] = []
    planned_tasks: list[dict] = []
    completed_tasks: list[dict] = []
    token_usage: OpenCodeTokenUsage | None = None
    models: list[OpenCodePoolModelStats] = []
    updated_at: str = ""


class AgentOpenCodePoolStatus(OpenCodePoolStatus):
    agent_id: str = ""
    online: bool = False


class ScanStatus(BaseModel):
    scan_id: str
    project_id: str = ""
    scan_mode: str = "full"
    threat_analysis_enabled: bool = False
    threat_analysis_method: str = "deephole_threat_analysis"
    threat_analysis_method_selection: ThreatAnalysisMethodSelection | None = None
    threat_analysis_run: ThreatAnalysisRunStatus | None = None
    auto_fp_review: bool = True
    fp_review_method: str = FpReviewMethod.ADVERSARIAL.value
    fp_review_method_selection: FpReviewMethodSelection | None = None
    product: str = ""
    validation_environment: str = ""
    knowledge_base_enabled: bool = False
    vulnerability_validation_enabled: bool = False
    validation_method_id: str = ""
    validation_method_label: str = ""
    scan_items: list[str] = []
    mining_engines: list[MiningEngineSelection] = []
    mining_engine_runs: list[MiningEngineRunStatus] = []
    created_at: str = ""
    status: ScanItemStatus
    progress: float            # 0.0 to 1.0
    total_candidates: int
    processed_candidates: int
    candidates: list[ScanCandidate] = []
    vulnerabilities: list[Vulnerability]
    skill_reports: list[SkillReport] = []
    threat_analysis: dict[str, Any] | None = None
    threat_audit_tasks: list[ThreatAuditTask] = []
    validations: list[VulnerabilityValidation] = []
    events: list[ScanEvent] = []
    current_candidate: Candidate | None = None
    error_message: str | None = None
    feedback_ids: list[str] = []
    retryable_candidates_count: int = 0
    continuable_task_count: int = 0
    can_continue: bool = False
    total_task_count: int = 0
    completed_task_count: int = 0
    opencode_pool: OpenCodePoolStatus | None = None

    # 静态分析进度（按文件计）
    static_total_files: int = 0
    static_scanned_files: int = 0
    static_analysis_done: bool = False

    # Agent 信息
    agent_name: str = ""
    agent_online: bool = False


class ScanDetailCounts(BaseModel):
    candidates: int = 0
    vulnerabilities: int = 0
    effective_issue_count: int = 0
    validated_issue_count: int = 0
    events: int = 0
    threat_audit_tasks: int = 0
    validations: int = 0
    skill_reports: int = 0


class ScanOverview(ScanStatus):
    """Lightweight scan state; large detail collections are returned separately."""
    detail_counts: ScanDetailCounts = ScanDetailCounts()


class ScanCandidatePage(BaseModel):
    items: list[ScanCandidate] = []
    next_cursor: int | None = None
    has_more: bool = False


class VulnerabilityPageItem(BaseModel):
    index: int
    vulnerability: Vulnerability


class VulnerabilityPage(BaseModel):
    items: list[VulnerabilityPageItem] = []
    next_cursor: int | None = None
    has_more: bool = False


class ScanEventPage(BaseModel):
    items: list[ScanEvent] = []
    next_cursor: int | None = None
    has_more: bool = False


class ThreatAuditTaskPage(BaseModel):
    items: list[ThreatAuditTask] = []
    next_cursor: str | None = None
    has_more: bool = False


class VulnerabilityValidationPage(BaseModel):
    items: list[VulnerabilityValidation] = []
    next_cursor: int | None = None
    has_more: bool = False


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


class AgentScanCandidates(BaseModel):
    """Sent by the agent after the final static candidate list is ready."""
    candidates: list[Candidate] = []


class AgentScanCandidateBatch(BaseModel):
    """Bounded v2 candidate chunk; offset is the persisted candidate index."""
    offset: int = Field(ge=0)
    candidates: list[Candidate] = Field(default_factory=list, max_length=500)
    reset: bool = False
    final: bool = False
    total: int | None = Field(default=None, ge=0)


class AgentScanEventBatch(BaseModel):
    events: list[ScanEvent] = Field(default_factory=list, max_length=500)


class AgentProcessedKey(BaseModel):
    file: str
    line: int
    function: str
    vuln_type: str


class AgentProcessedKeyBatch(BaseModel):
    items: list[AgentProcessedKey] = Field(default_factory=list, max_length=500)


class AgentScanFinishV2(BaseModel):
    """Lightweight terminal state; findings are streamed before this request."""
    status: str
    total_candidates: int = Field(ge=0)
    processed_candidates: int = Field(ge=0)
    error_message: str | None = None


class AgentVulnerabilityValidationUpdate(BaseModel):
    """Sent by the agent while a local vulnerability validation script runs."""
    vuln_index: int
    status: str = "pending"
    running: bool = False
    product: str = ""
    validation_environment: str = ""
    validation_method_id: str = ""
    validation_method_label: str = ""
    validator_name: str = ""
    validation_success: bool | None = None
    is_problem: bool | None = None
    requires_human_intervention: bool | None = None
    validation_code: str = ""
    validation_output: str = ""
    intermediate_output: str = ""
    output_sections: list[dict] = []
    final_output: str = ""
    artifacts: list[dict] = []
    started_at: str = ""
    finished_at: str = ""
    updated_at: str = ""


class AgentInfo(BaseModel):
    """Info about a registered agent."""
    agent_id: str
    agent_key: str = ""
    name: str
    machine_name: str = ""
    ip: str
    port: int = 0
    last_seen: str
    user_id: str = ""
    runtime_hash: str = ""
    agent_session_id: str = ""
    runtime_update_status: str = ""
    runtime_update_target_hash: str = ""
    runtime_update_error: str = ""
    accepting_tasks: bool = True
    has_explicit_model: bool = False
    protocol_version: int = 1


class AgentOpenCodeModelConfig(BaseModel):
    id: str = ""
    model: str = ""
    # Read-only compatibility for old agent.yaml files.  It is deliberately
    # omitted from managed config and never satisfies scan readiness.
    use_default_model: bool = Field(default=False, exclude=True)
    capability: str = "high"
    weight: float = 1.0
    max_concurrency: int = 1
    enabled: bool = True
    tool: str = ""
    executable: str = ""
    timeout: int | None = None
    max_retries: int | None = None
    time_windows: list[AgentModelTimeWindow] = []


class AgentOpenCodeConfig(BaseModel):
    tool: str = "nga"
    executable: str = "nga"
    model: str = ""
    timeout: int = 3600
    max_retries: int = 2
    serve_port: int | None = None
    models: list[AgentOpenCodeModelConfig] = []
    config_paths: list[str] = []
    proxy_url: str = ""
    no_proxy: str = ""


class AgentBaseConfig(BaseModel):
    tool: str = "nga"
    executable: str = "nga"
    no_proxy: str = "10.0.0.0/8"
    opencode_serve_port: int | None = Field(default=None, ge=1, le=65535)


class AgentModelPoolConfig(BaseModel):
    global_concurrency: int = 4
    models: list[AgentOpenCodeModelConfig] = []


class AgentModelTaskPolicy(BaseModel):
    required_capability: str = "high"
    timeout_seconds: int = 3600
    max_retries: int = 2

    @field_validator("required_capability", mode="before")
    @classmethod
    def _normalize_required_capability(cls, value: object) -> str:
        normalized = str(value or "").strip().lower()
        if normalized in {"medium", "high"}:
            return "high"
        if normalized in {"", "any", "low"}:
            return "low"
        raise ValueError("required_capability must be low or high")


class AgentMcpLocalConfig(BaseModel):
    executable: str = ""
    args: list[str] = []
    environment: dict[str, str] = {}


class AgentMcpRemoteConfig(BaseModel):
    url: str = ""
    headers: dict[str, str] = {}


class AgentMcpConfig(BaseModel):
    enabled: bool = False
    name: str = ""
    transport: str = "local"
    timeout_seconds: int = Field(
        default=300,
        gt=0,
        description=(
            "MCP request timeout in seconds; converted to OpenCode's "
            "millisecond timeout at runtime"
        ),
    )
    local: AgentMcpLocalConfig = AgentMcpLocalConfig()
    remote: AgentMcpRemoteConfig = AgentMcpRemoteConfig()


class AgentMcpProbeResult(BaseModel):
    target: str
    config_fingerprint: str = ""
    success: bool = False
    checked_at: str = ""
    transport: str = ""
    protocol: str = ""
    tool_names: list[str] = []
    tool_count: int = 0
    duration_ms: int = 0
    error: str = ""
    runtime_state: str = "next_task"
    active_sessions: int = 0


class AgentMcpRuntimeStatus(BaseModel):
    state: str = "unknown"
    config_fingerprint: str = ""
    updated_at: str = ""
    error: str = ""
    loaded_directories: int = 0
    total_directories: int = 0


class AgentMcpTargetStatus(BaseModel):
    enabled: bool = False
    stale: bool = False
    last_probe: AgentMcpProbeResult | None = None
    runtime: AgentMcpRuntimeStatus = AgentMcpRuntimeStatus()


class AgentMcpStatusResponse(BaseModel):
    agent_key: str
    online: bool = False
    product_info: AgentMcpTargetStatus = AgentMcpTargetStatus()


class AgentVulnerabilityValidationConfig(BaseModel):
    supported_vulnerability_types: list[str] = ["*"]
    concurrency: int = 1
    validation_max_retries: int = 0
    model_policy: AgentModelTaskPolicy = AgentModelTaskPolicy(
        required_capability="high",
        timeout_seconds=3600,
        max_retries=2,
    )


class AgentCheckerSelectionConfig(BaseModel):
    # Persist exclusions so newly discovered checkers are enabled by default.
    disabled_checkers: list[str] = []


class AgentValidatorField(BaseModel):
    key: str
    label: str = ""
    type: str = "string"
    required: bool = False
    default: object | None = None
    options: list[object] = []
    min: float | None = None
    max: float | None = None
    help: str = ""
    placeholder: str = ""


class AgentValidatorMethod(BaseModel):
    method_id: str
    method_label: str = ""
    description: str = ""
    products: list[str] = []
    fields: list[AgentValidatorField] = []


class AgentValidatorCatalog(BaseModel):
    methods: list[AgentValidatorMethod] = []
    errors: list[str] = []
    updated_at: str = ""


def _safe_policy_int(value: object, default: int, *, minimum: int) -> int:
    try:
        return max(minimum, int(value))
    except (TypeError, ValueError):
        return default


def _upgrade_agent_policy(
    value: object,
    *,
    default_retries: int = 2,
    migrate_threat_retry_default: bool = False,
) -> dict[str, object]:
    policy = dict(value) if isinstance(value, dict) else {}
    timeout = _safe_policy_int(policy.get("timeout_seconds"), 3600, minimum=1)
    if timeout == 1200:
        timeout = 3600
    retries = _safe_policy_int(
        policy.get("max_retries"),
        default_retries,
        minimum=0,
    )
    if migrate_threat_retry_default and retries == 3:
        retries = 2
    policy.update({
        "required_capability": "high",
        "timeout_seconds": timeout,
        "max_retries": retries,
    })
    return policy


def _upgrade_agent_v2_config(value: dict) -> dict:
    """Migrate managed v2 stage defaults without touching model rows."""
    migrated = copy.deepcopy(value)
    migrated["schema_version"] = 5
    base = migrated.get("base")
    if not isinstance(base, dict):
        base = {}
        migrated["base"] = base
    base.setdefault("opencode_serve_port", None)

    for key in ("vulnerability_mining", "false_positive"):
        migrated[key] = _upgrade_agent_policy(migrated.get(key))

    threat = migrated.get("threat_analysis")
    if not isinstance(threat, dict):
        threat = {}
        migrated["threat_analysis"] = threat
    threat["model_policy"] = _upgrade_agent_policy(
        threat.get("model_policy"),
        migrate_threat_retry_default=True,
    )
    # v5 deliberately resets the old per-environment policy because multiple
    # environments cannot be losslessly collapsed into one shared policy.
    migrated["vulnerability_validation"] = {}
    migrated.setdefault("checker_selection", {"disabled_checkers": []})
    return migrated


def _upgrade_agent_v3_or_v4_config(value: dict, *, drop_code_graph: bool) -> dict:
    """Move v3/v4 to v5 while preserving unrelated task policies."""
    migrated = copy.deepcopy(value)
    migrated["schema_version"] = 5
    migrated.pop("mining_engines", None)
    migrated.pop("product_info", None)
    if drop_code_graph:
        migrated.pop("code_graph", None)
    # The old value was keyed by environment and cannot be merged safely into
    # the one universal v5 policy.  Product direction explicitly resets it.
    migrated["vulnerability_validation"] = {}
    migrated.setdefault("checker_selection", {"disabled_checkers": []})
    return migrated


class AgentMemoryApiDiscoveryConfig(BaseModel):
    enabled: bool = True
    batch_size: int = 8
    timeout_seconds: int = 3600
    max_candidates: int = 200


class AgentGitHistoryConfig(BaseModel):
    enabled: bool = False
    max_commits: int = 200
    since: str = ""
    paths: str = ""
    variant_hunt: bool = True


class AgentThreatAnalysisConfig(BaseModel):
    enabled: bool = True
    model_policy: AgentModelTaskPolicy = AgentModelTaskPolicy(
        required_capability="high",
        timeout_seconds=3600,
        max_retries=2,
    )


class AgentPatternFilterConfig(BaseModel):
    enabled: bool = True
    scope: str = "directory"


class AgentRemoteConfig(BaseModel):
    """Agent configuration managed from the server Web UI."""
    schema_version: int = 5
    base: AgentBaseConfig = AgentBaseConfig()
    model_pool: AgentModelPoolConfig = AgentModelPoolConfig()
    threat_analysis: AgentThreatAnalysisConfig = AgentThreatAnalysisConfig()
    # v3 compatibility input only. Code graph MCPs are snapshotted per scan
    # from v4 onward and omitted from managed Agent output.
    code_graph: AgentMcpConfig = Field(
        default_factory=lambda: AgentMcpConfig(
            name="codegraph",
            local=AgentMcpLocalConfig(
                executable="codegraph",
                args=["serve", "--mcp"],
                environment={
                    "CODEGRAPH_MCP_TOOLS": "explore,node,search,callers,callees,impact,files,status",
                },
            ),
        ),
        exclude=True,
    )
    # v4 compatibility input only. Product knowledge is scan-specific in v5.
    product_info: AgentMcpConfig = Field(
        default_factory=lambda: AgentMcpConfig(name="product-info"),
        exclude=True,
    )
    vulnerability_mining: AgentModelTaskPolicy = AgentModelTaskPolicy()
    false_positive: AgentModelTaskPolicy = AgentModelTaskPolicy(
        required_capability="high",
    )
    vulnerability_validation: AgentVulnerabilityValidationConfig = AgentVulnerabilityValidationConfig()
    checker_selection: AgentCheckerSelectionConfig = AgentCheckerSelectionConfig()

    @model_validator(mode="before")
    @classmethod
    def _upgrade_legacy(cls, value):
        """Accept older/transient Agent payloads and emit the v5 contract."""
        if not isinstance(value, dict):
            return value
        if not value:
            return value
        value = copy.deepcopy(value)
        # Web-managed OpenCode JSONC was removed.  Accept old payloads during
        # rolling upgrades, but never expose or persist that custom layer.
        value.pop("opencode_config", None)
        try:
            schema_version = int(value.get("schema_version", 0) or 0)
        except (TypeError, ValueError):
            schema_version = 0
        if schema_version >= 5:
            migrated = value
            migrated["schema_version"] = 5
            migrated.pop("mining_engines", None)
            return migrated
        if schema_version >= 4:
            return _upgrade_agent_v3_or_v4_config(
                value,
                drop_code_graph=False,
            )
        if schema_version == 3:
            return _upgrade_agent_v3_or_v4_config(
                value,
                drop_code_graph=True,
            )
        if schema_version == 2 or "base" in value or "model_pool" in value:
            return _upgrade_agent_v2_config(value)
        legacy = dict(value)
        opencode = legacy.get("opencode") if isinstance(legacy.get("opencode"), dict) else {}
        fp_cli = legacy.get("fp_review_cli") if isinstance(legacy.get("fp_review_cli"), dict) else {}
        threat = legacy.get("threat_analysis") if isinstance(legacy.get("threat_analysis"), dict) else {}
        models = []
        for raw_model in opencode.get("models") or []:
            if not isinstance(raw_model, dict):
                continue
            migrated_model = dict(raw_model)
            if migrated_model.pop("use_default_model", False):
                migrated_model["model"] = ""
                migrated_model["enabled"] = False
            models.append(migrated_model)
        seen_ids = {str(item.get("id") or "") for item in models if isinstance(item, dict)}
        for item in fp_cli.get("models") or []:
            if not isinstance(item, dict):
                continue
            migrated = dict(item)
            if migrated.pop("use_default_model", False):
                migrated["model"] = ""
                migrated["enabled"] = False
            model_id = str(migrated.get("id") or "model")
            if model_id in seen_ids:
                model_id = f"fp-{model_id}"
            migrated["id"] = model_id
            if not any(
                isinstance(existing, dict)
                and str(existing.get("model") or "") == str(migrated.get("model") or "")
                and str(existing.get("tool") or "") == str(migrated.get("tool") or "")
                for existing in models
            ):
                models.append(migrated)
                seen_ids.add(model_id)
        timeout = _safe_policy_int(opencode.get("timeout"), 3600, minimum=1)
        if timeout == 1200:
            timeout = 3600
        retries = _safe_policy_int(opencode.get("max_retries"), 2, minimum=0)
        fp_timeout = _safe_policy_int(fp_cli.get("timeout"), timeout, minimum=1)
        if fp_timeout == 1200:
            fp_timeout = 3600
        fp_retries = _safe_policy_int(fp_cli.get("max_retries"), retries, minimum=0)
        migrated = {
            "schema_version": 2,
            "base": {
                "tool": opencode.get("tool", "nga"),
                "executable": opencode.get("executable", "nga"),
                "no_proxy": legacy.get("no_proxy") or opencode.get("no_proxy") or "10.0.0.0/8",
                "opencode_serve_port": None,
            },
            "model_pool": {
                "global_concurrency": legacy.get("opencode_concurrency", 4),
                "models": models,
            },
            "threat_analysis": {
                "enabled": threat.get("enabled", True),
                "model_policy": threat.get("model_policy"),
            },
            "product_info": {
                "enabled": False,
                "name": "product-info",
            },
            "vulnerability_mining": {
                "required_capability": "high",
                "timeout_seconds": timeout,
                "max_retries": retries,
            },
            "false_positive": {
                "required_capability": "high",
                "timeout_seconds": fp_timeout,
                "max_retries": fp_retries,
            },
            "vulnerability_validation": {},
            "checker_selection": {"disabled_checkers": []},
        }
        return _upgrade_agent_v2_config(migrated)

    @property
    def no_proxy(self) -> str:
        return self.base.no_proxy

    @property
    def opencode_concurrency(self) -> int:
        return self.model_pool.global_concurrency

    @property
    def opencode(self) -> AgentOpenCodeConfig:
        return AgentOpenCodeConfig(
            tool=self.base.tool,
            executable=self.base.executable,
            timeout=self.vulnerability_mining.timeout_seconds,
            max_retries=self.vulnerability_mining.max_retries,
            serve_port=self.base.opencode_serve_port,
            models=self.model_pool.models,
            no_proxy=self.base.no_proxy,
        )


class ScanKnowledgeBaseRequest(BaseModel):
    enabled: bool = False
    url: str = ""
    headers: dict[str, str] = {}


class ScanVulnerabilityValidationRequest(BaseModel):
    enabled: bool = False
    method_id: str = ""
    values: dict[str, object] = {}


class ScanVulnerabilityValidationConfig(BaseModel):
    enabled: bool = True
    method_id: str
    method_label: str = ""
    description: str = ""
    values: dict[str, object] = {}
    policy: AgentVulnerabilityValidationConfig = AgentVulnerabilityValidationConfig()


class ScanConfigMemoryResponse(BaseModel):
    knowledge_base: dict[str, object] | None = None
    validation_by_product: dict[str, dict[str, object]] = {}


class CreateScanRequest(BaseModel):
    """Request to create a new scan via a registered agent."""
    agent_key: str = ""
    agent_id: str = ""  # compatibility for older callers
    project_path: str
    code_scan_path: str = ""
    scan_name: str = ""
    scan_mode: str = "full"
    threat_analysis_enabled: bool | None = None
    threat_analysis_method: str | None = None
    product: str = ""
    knowledge_base: ScanKnowledgeBaseRequest = Field(
        default_factory=ScanKnowledgeBaseRequest
    )
    vulnerability_validation: ScanVulnerabilityValidationRequest = Field(
        default_factory=ScanVulnerabilityValidationRequest
    )
    # Read-only compatibility input. It cannot enable a new validation run.
    validation_environment: str = ""
    checkers: list[str] | None = None
    mining_engines: list[MiningEngineRequest] | None = None
    feedback_ids: list[str] = []
    code_graph_mcp: AgentMcpConfig | None = None
    auto_fp_review: bool | None = None
    fp_review_method: str | None = None


class ValidationTarget(BaseModel):
    validator_id: str
    product: str
    validation_environment: str
    timeout_seconds: int | None = None


class ScanValidationTargetList(BaseModel):
    targets: list[ValidationTarget]


class UpdateScanValidationTargetRequest(BaseModel):
    product: str = ""
    validation_environment: str = ""


class ScanMeta(BaseModel):
    """扫描元数据，记录扫描配置信息。"""
    scan_items: list[str]
    created_at: str
    scan_mode: str = "full"
    threat_analysis_enabled: bool = False
    threat_analysis_method: str = "deephole_threat_analysis"
    threat_analysis_method_selection: ThreatAnalysisMethodSelection | None = None
    mining_engines: list[MiningEngineSelection] = []
    feedback_ids: list[str] = []
    agent_id: str = ""
    agent_key: str = ""
    agent_name: str = ""
    project_path: str = ""
    code_scan_path: str = ""
    scan_name: str = ""
    auto_fp_review: bool = True
    fp_review_method: str = FpReviewMethod.ADVERSARIAL.value
    fp_review_method_selection: FpReviewMethodSelection | None = None
    product: str = ""
    validation_environment: str = ""
    knowledge_base_enabled: bool = False
    vulnerability_validation_enabled: bool = False
    validation_method_id: str = ""
    validation_method_label: str = ""
    user_id: str = ""
    public_access_token: str = ""
    # Stored for internal task dispatch only. Public scan responses must never
    # echo connection headers or environment values.
    code_graph_mcp: AgentMcpConfig | None = Field(
        default=None,
        exclude=True,
        repr=False,
    )
    knowledge_base_mcp: AgentMcpConfig | None = Field(
        default=None,
        exclude=True,
        repr=False,
    )
    vulnerability_validation: ScanVulnerabilityValidationConfig | None = Field(
        default=None,
        exclude=True,
        repr=False,
    )


class ScanSummary(BaseModel):
    """扫描列表的摘要信息。"""
    scan_id: str
    project_id: str
    scan_mode: str = "full"
    threat_analysis_enabled: bool = False
    scan_name: str = ""
    product: str = ""
    validation_environment: str = ""
    knowledge_base_enabled: bool = False
    vulnerability_validation_enabled: bool = False
    validation_method_id: str = ""
    validation_method_label: str = ""
    status: ScanItemStatus
    created_at: str
    progress: float
    total_candidates: int
    processed_candidates: int
    vulnerability_count: int
    human_confirmed_count: int = 0
    retryable_candidates_count: int = 0
    continuable_task_count: int = 0
    can_continue: bool = False
    total_task_count: int = 0
    completed_task_count: int = 0
    scan_items: list[str]
    user_id: str = ""
    username: str = ""
    agent_name: str = ""
    agent_online: bool = False
    # Internal lifecycle snapshots used to derive continuation capability for
    # list responses.  They are loaded with the summary row but never exposed
    # through the public response model.
    threat_analysis_run: SkipJsonSchema[
        ThreatAnalysisRunStatus | None
    ] = Field(
        default=None,
        exclude=True,
        repr=False,
    )
    mining_engines: SkipJsonSchema[list[MiningEngineSelection]] = Field(
        default_factory=list,
        exclude=True,
        repr=False,
    )
    mining_engine_runs: SkipJsonSchema[list[MiningEngineRunStatus]] = Field(
        default_factory=list,
        exclude=True,
        repr=False,
    )


class ScanSummaryPage(BaseModel):
    """Cursor-paginated scan history response used by the v2 frontend."""
    items: list[ScanSummary] = []
    next_cursor: str | None = None
    has_more: bool = False


# --- Admin dashboard models ---

class CheckerScanDashboardStats(BaseModel):
    """Per-checker stats for one scan shown in the admin checker dashboard."""
    scan_id: str
    project_id: str
    scan_name: str = ""
    project_path: str = ""
    product: str = ""
    status: ScanItemStatus
    created_at: str
    username: str = ""
    agent_name: str = ""
    static_issue_count: int = 0
    llm_issue_count: int = 0
    fp_review_issue_count: int = 0
    fp_review_false_positive_count: int = 0
    human_confirmed_count: int = 0
    human_false_positive_count: int = 0
    ticket_submitted_count: int = 0
    accuracy_basis_count: int = 0
    accuracy: float | None = None
    ticket_accuracy: float | None = None


class CheckerDashboardStats(BaseModel):
    """Aggregated stats for a checker/SKILL."""
    checker: str
    label: str
    description: str = ""
    scan_count: int = 0
    project_count: int = 0
    projects: list[str] = []
    static_issue_count: int = 0
    llm_issue_count: int = 0
    fp_review_issue_count: int = 0
    fp_review_false_positive_count: int = 0
    human_confirmed_count: int = 0
    human_false_positive_count: int = 0
    ticket_submitted_count: int = 0
    accuracy_basis_count: int = 0
    accuracy: float | None = None
    ticket_accuracy: float | None = None
    scans: list[CheckerScanDashboardStats] = []
    user_created: bool = False


class CheckerDashboardSummary(BaseModel):
    """Top-level summary for the caller-scoped result dashboard."""
    checker_count: int = 0
    scan_count: int = 0
    project_count: int = 0
    static_issue_count: int = 0
    llm_issue_count: int = 0
    fp_review_issue_count: int = 0
    fp_review_false_positive_count: int = 0
    total_issue_count: int = 0
    human_confirmed_count: int = 0
    ticket_submitted_count: int = 0
    accuracy_basis_count: int = 0
    accuracy: float | None = None
    ticket_accuracy: float | None = None


class CheckerDashboardAgentTokenUsage(BaseModel):
    """Token usage for scans assigned to one Agent in the dashboard scope."""
    agent_key: str = ""
    agent_name: str = ""
    machine_name: str = ""
    ip: str = ""
    owner_user_id: str = ""
    owner_username: str = ""
    scan_count: int = 0
    tracked_scan_count: int = 0
    usage: OpenCodeTokenUsage = Field(default_factory=OpenCodeTokenUsage)


class CheckerDashboardTokenUsage(BaseModel):
    """Token totals for every scan visible to the dashboard caller."""
    scan_count: int = 0
    tracked_scan_count: int = 0
    usage: OpenCodeTokenUsage = Field(default_factory=OpenCodeTokenUsage)
    agents: list[CheckerDashboardAgentTokenUsage] = Field(default_factory=list)


class CheckerDashboardResponse(BaseModel):
    """Checker dashboard response scoped to the authenticated caller."""
    summary: CheckerDashboardSummary
    checkers: list[CheckerDashboardStats]
    products: list[str] = Field(default_factory=list)
    has_unconfigured_product: bool = False
    token_usage: CheckerDashboardTokenUsage = Field(
        default_factory=CheckerDashboardTokenUsage,
    )


# --- Git history mining models ---

class HistoryPattern(BaseModel):
    """从 git 历史中挖掘出的一条「历史安全问题模式」。"""
    pattern: str                  # 根因 + 缺陷类型 + 触发条件的抽象描述
    source: str = ""              # 出处：提交短 hash + 标题
    lens_hint: str = ""           # memory | integer | race | injection | authn | crypto | dos | infoleak
    files: list[str] = []         # 涉及/出现的文件
    rationale: str = ""           # 判定理由 + 改动要点摘要


class AgentGitHistory(BaseModel):
    """Agent 上报某次扫描挖掘出的历史问题模式批次。"""
    patterns: list[HistoryPattern] = []


# --- FP Review models ---

class FpReviewStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    ERROR = "error"
    CANCELLED = "cancelled"


class FpReviewResult(BaseModel):
    """Per-vulnerability false-positive review result."""
    vuln_index: int           # index in the parent scan's vulnerability list
    verdict: str              # "tp" (true positive) | "fp" (false positive)
    severity: str = "low"     # "high" | "low"
    reason: str               # AI reasoning
    vulnerability_report: str = ""  # Markdown report for confirmed issues
    stage_outputs: dict[str, str] = {}
    match_reference: str = ""  # 命中历史问题模式或其它函数校验时，对应的修复/校验描述
    match_type: str = ""       # "history" | "validation" | ""（命中类型）
    stage_output_sources: dict[str, OutputSource] = Field(default_factory=dict)
    output_source: OutputSource = Field(default_factory=OutputSource)
    created_at: str


class FpReviewStageOutput(BaseModel):
    """Markdown output produced by one FP review stage."""
    review_id: str
    vuln_index: int
    stage: str
    markdown: str
    output_source: OutputSource = Field(default_factory=OutputSource)
    created_at: str
    updated_at: str


class FpReviewJob(BaseModel):
    """A false-positive review job for a scan."""
    review_id: str
    scan_id: str
    method: str = FpReviewMethod.ADVERSARIAL.value
    status: FpReviewStatus
    created_at: str
    total: int = 0
    processed: int = 0
    current_vuln_index: int | None = None
    current_vuln_indices: list[int] = []
    results: list[FpReviewResult] = []
    error_message: str | None = None


class FpReviewTriggerRequest(BaseModel):
    """Request body for POST /api/scan/{scan_id}/fp_review."""
    pass  # no extra fields needed for now


class AgentFpReviewResult(BaseModel):
    """Sent by the agent to push a single FP review result."""
    review_id: str
    vuln_index: int
    verdict: str       # "tp" | "fp"
    severity: str = "low"
    reason: str
    vulnerability_report: str = ""
    stage_outputs: dict[str, str] = {}
    match_reference: str = ""
    match_type: str = ""
    stage_output_sources: dict[str, OutputSource] = Field(default_factory=dict)
    output_source: OutputSource = Field(default_factory=OutputSource)


class AgentFpReviewStageOutput(BaseModel):
    """Sent by the agent when a stage Markdown output is ready."""
    review_id: str
    vuln_index: int
    stage: str
    markdown: str
    output_source: OutputSource = Field(default_factory=OutputSource)


class AgentFpReviewProgress(BaseModel):
    """Sent by the agent when it starts reviewing a vulnerability."""
    review_id: str
    vuln_index: int
    processed: int | None = None
    active_indices: list[int] | None = None  # all vuln indices being reviewed concurrently


class AgentFpReviewFinish(BaseModel):
    """Sent by the agent when the FP review job is complete."""
    review_id: str
    status: str        # "complete" | "error" | "cancelled"
    error_message: str | None = None
