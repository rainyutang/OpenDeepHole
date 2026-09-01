import type {
  Candidate,
  FpReviewJob,
  FpReviewResult,
  IndexedVulnerability,
  OpenCodeModelTokenUsage,
  OpenCodePoolModelStats,
  OpenCodePoolStatus,
  OpenCodeTokenUsage,
  ScanCandidate,
  ScanEvent,
  ScanItemStatus,
  ScanStatus,
  ThreatAuditTask,
  Vulnerability,
  VulnerabilityValidation,
} from "./types";

const SCAN_STATUSES = new Set<ScanItemStatus>([
  "pending",
  "analyzing",
  "auditing",
  "complete",
  "error",
  "cancelled",
]);

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function text(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function finiteNumber(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function nullableFiniteNumber(value: unknown): number | null {
  return value == null ? null : finiteNumber(value, 0);
}

function recordArray(value: unknown): Record<string, unknown>[] {
  if (!Array.isArray(value)) return [];
  if (value.every(isRecord)) return value as Record<string, unknown>[];
  return value.filter(isRecord);
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string");
}

function stringRecord(value: unknown): Record<string, string> | undefined {
  if (!isRecord(value)) return undefined;
  return Object.fromEntries(
    Object.entries(value).filter((entry): entry is [string, string] => typeof entry[1] === "string"),
  );
}

function normalizeCandidate(value: unknown, index?: number): Candidate | ScanCandidate {
  const raw = isRecord(value) ? value : {};
  const candidate = {
    ...raw,
    file: text(raw.file),
    line: finiteNumber(raw.line),
    function: text(raw.function),
    description: text(raw.description),
    vuln_type: text(raw.vuln_type),
    related_functions: stringArray(raw.related_functions),
    metadata: isRecord(raw.metadata) ? raw.metadata : undefined,
  };
  return index === undefined
    ? candidate as Candidate
    : {
        ...candidate,
        idx: finiteNumber(raw.idx, index),
        audit_state: ["pending", "running", "success", "failed"].includes(text(raw.audit_state))
          ? text(raw.audit_state) as ScanCandidate["audit_state"]
          : "pending",
        audit_result: isRecord(raw.audit_result)
          ? normalizeVulnerability(raw.audit_result)
          : null,
        vulnerability_idx: raw.vulnerability_idx == null
          ? null
          : finiteNumber(raw.vulnerability_idx),
        dedup_decision: isRecord(raw.dedup_decision) ? raw.dedup_decision : {},
        audit_updated_at: text(raw.audit_updated_at),
      } as ScanCandidate;
}

export function normalizeScanCandidate(value: unknown, index = 0): ScanCandidate {
  return normalizeCandidate(value, index) as ScanCandidate;
}

export function normalizeVulnerability(value: unknown): Vulnerability {
  const raw = isRecord(value) ? value : {};
  return {
    ...raw,
    file: text(raw.file),
    line: finiteNumber(raw.line),
    function: text(raw.function),
    call_chain: text(raw.call_chain),
    vuln_type: text(raw.vuln_type),
    severity: text(raw.severity),
    description: text(raw.description),
    impact: text(raw.impact),
    vulnerable_code: text(raw.vulnerable_code),
    attack_entry: text(raw.attack_entry),
    root_cause: text(raw.root_cause),
    trigger_conditions: text(raw.trigger_conditions),
    version_labels: stringArray(raw.version_labels),
    version_locations: recordArray(raw.version_locations).map((item) => ({
      version_name: text(item.version_name),
      project_path: text(item.project_path),
      code_scan_path: text(item.code_scan_path),
      file: text(item.file),
      line: finiteNumber(item.line),
      function: text(item.function),
    })),
    ai_analysis: text(raw.ai_analysis),
    vulnerability_report: text(raw.vulnerability_report),
    confirmed: raw.confirmed === true,
    provisional: raw.provisional === true,
  } as Vulnerability;
}

export function normalizeIndexedVulnerability(
  value: unknown,
  fallbackIndex: number,
): IndexedVulnerability | null {
  if (!isRecord(value)) return null;
  const rawIndex = value.vuln_index;
  const vulnIndex = Number.isInteger(rawIndex) && Number(rawIndex) >= 0
    ? Number(rawIndex)
    : fallbackIndex;
  if (!Number.isInteger(vulnIndex) || vulnIndex < 0) return null;
  return {
    ...normalizeVulnerability(value),
    vuln_index: vulnIndex,
  };
}

export function normalizeIndexedVulnerabilities(value: unknown): IndexedVulnerability[] {
  if (!Array.isArray(value)) return [];
  const byIndex = new Map<number, IndexedVulnerability>();
  value.forEach((item, index) => {
    const normalized = normalizeIndexedVulnerability(item, index);
    if (normalized) byIndex.set(normalized.vuln_index, normalized);
  });
  return [...byIndex.values()].sort((left, right) => left.vuln_index - right.vuln_index);
}

export function mergeIndexedVulnerabilities(
  existing: readonly IndexedVulnerability[],
  incoming: readonly { index: number; vulnerability: Vulnerability }[],
): IndexedVulnerability[] {
  const byIndex = new Map<number, IndexedVulnerability>();
  for (const vulnerability of existing) {
    if (!vulnerability || !Number.isInteger(vulnerability.vuln_index) || vulnerability.vuln_index < 0) continue;
    byIndex.set(vulnerability.vuln_index, vulnerability);
  }
  for (const item of incoming) {
    if (!Number.isInteger(item.index) || item.index < 0) continue;
    if (!isRecord(item.vulnerability)) continue;
    byIndex.set(item.index, {
      ...normalizeVulnerability(item.vulnerability),
      vuln_index: item.index,
    });
  }
  return [...byIndex.values()].sort((left, right) => left.vuln_index - right.vuln_index);
}

export function findIndexedVulnerability(
  vulnerabilities: readonly IndexedVulnerability[],
  vulnIndex: number,
): IndexedVulnerability | undefined {
  return vulnerabilities.find((vulnerability) => vulnerability.vuln_index === vulnIndex);
}

export function normalizeThreatTask(value: unknown): ThreatAuditTask {
  const raw = isRecord(value) ? value : {};
  return {
    ...raw,
    task_id: text(raw.task_id),
    status: text(raw.status),
    code_path: text(raw.code_path),
  } as ThreatAuditTask;
}

export function normalizeValidation(value: unknown): VulnerabilityValidation {
  const raw = isRecord(value) ? value : {};
  return {
    ...raw,
    vuln_index: finiteNumber(raw.vuln_index),
    status: text(raw.status),
    running: raw.running === true,
    validation_code: text(raw.validation_code),
    validation_output: text(raw.validation_output),
    intermediate_output: text(raw.intermediate_output),
    started_at: text(raw.started_at),
    finished_at: text(raw.finished_at),
    updated_at: text(raw.updated_at),
  } as VulnerabilityValidation;
}

export function normalizeFpReviewJob(value: unknown): FpReviewJob | null {
  if (!isRecord(value) || typeof value.review_id !== "string" || typeof value.scan_id !== "string") {
    return null;
  }
  const results = recordArray(value.results).map((item): FpReviewResult => ({
    ...item,
    vuln_index: finiteNumber(item.vuln_index),
    verdict: text(item.verdict, "uncertain") as FpReviewResult["verdict"],
    severity: text(item.severity, "low") as FpReviewResult["severity"],
    reason: text(item.reason),
    vulnerability_report: text(item.vulnerability_report),
    stage_outputs: stringRecord(item.stage_outputs),
    stage_output_sources: isRecord(item.stage_output_sources)
      ? item.stage_output_sources as FpReviewResult["stage_output_sources"]
      : undefined,
    created_at: text(item.created_at),
  }));
  return {
    ...value,
    review_id: value.review_id,
    scan_id: value.scan_id,
    method: text(value.method, "adversarial") as FpReviewJob["method"],
    status: text(value.status, "pending") as FpReviewJob["status"],
    created_at: text(value.created_at),
    total: finiteNumber(value.total),
    processed: finiteNumber(value.processed),
    current_vuln_index: value.current_vuln_index == null
      ? null
      : finiteNumber(value.current_vuln_index),
    current_vuln_indices: Array.isArray(value.current_vuln_indices)
      ? value.current_vuln_indices.filter((item): item is number => typeof item === "number" && Number.isFinite(item))
      : [],
    results,
    error_message: value.error_message == null ? null : text(value.error_message),
  } as FpReviewJob;
}

export function normalizeScanEvent(value: unknown): ScanEvent | null {
  if (!isRecord(value)) return null;
  if (
    typeof value.timestamp !== "string"
    || typeof value.phase !== "string"
    || typeof value.message !== "string"
  ) {
    return null;
  }
  return {
    timestamp: value.timestamp,
    phase: value.phase,
    message: value.message,
    candidate_index: nullableFiniteNumber(value.candidate_index),
  };
}

function normalizeTokenCounters(value: Record<string, unknown>) {
  return {
    input_tokens: finiteNumber(value.input_tokens),
    output_tokens: finiteNumber(value.output_tokens),
    reasoning_tokens: finiteNumber(value.reasoning_tokens),
    cache_read_tokens: finiteNumber(value.cache_read_tokens),
    cache_write_tokens: finiteNumber(value.cache_write_tokens),
    total_tokens: finiteNumber(value.total_tokens),
  };
}

function normalizeTokenUsage(value: unknown): OpenCodeTokenUsage | null {
  if (!isRecord(value)) return null;
  const byModel = recordArray(value.by_model).map((item): OpenCodeModelTokenUsage => ({
    ...normalizeTokenCounters(item),
    model: text(item.model),
  }));
  return {
    ...normalizeTokenCounters(value),
    complete: value.complete === true,
    by_model: byModel,
  };
}

function normalizePoolModel(value: Record<string, unknown>): OpenCodePoolModelStats {
  const windows = recordArray(value.time_windows).map((window) => ({
    weekdays: Array.isArray(window.weekdays)
      ? window.weekdays.filter((item): item is number => typeof item === "number" && Number.isFinite(item))
      : [],
    start: text(window.start),
    end: text(window.end),
  }));
  return {
    ...value,
    id: text(value.id),
    model: text(value.model),
    use_default_model: value.use_default_model === true,
    capability: text(value.capability),
    weight: finiteNumber(value.weight),
    effective_weight: finiteNumber(value.effective_weight),
    health_penalty_level: finiteNumber(value.health_penalty_level),
    last_health_failure_at: text(value.last_health_failure_at),
    last_health_failure_kind: text(value.last_health_failure_kind),
    max_concurrency: finiteNumber(value.max_concurrency),
    enabled: value.enabled === true,
    available: value.available === true,
    time_windows: windows,
    queued: finiteNumber(value.queued),
    running: finiteNumber(value.running),
    total: finiteNumber(value.total),
    success: finiteNumber(value.success),
    failure: finiteNumber(value.failure),
    timeout: finiteNumber(value.timeout),
    cancelled: finiteNumber(value.cancelled),
    avg_duration_seconds: finiteNumber(value.avg_duration_seconds),
    last_status: text(value.last_status),
    last_started_at: text(value.last_started_at),
    last_finished_at: text(value.last_finished_at),
    active_tasks: recordArray(value.active_tasks),
  };
}

export function normalizeOpenCodePool(value: unknown): OpenCodePoolStatus | null {
  if (value == null) return null;
  if (
    !isRecord(value)
    || typeof value.scope_id !== "string"
    || !Array.isArray(value.queued_tasks)
    || !Array.isArray(value.models)
  ) {
    return null;
  }
  return {
    ...value,
    scope_id: text(value.scope_id),
    agent_name: text(value.agent_name) || undefined,
    agent_session_id: text(value.agent_session_id) || undefined,
    global_running: finiteNumber(value.global_running),
    global_queued: finiteNumber(value.global_queued),
    total_tasks: finiteNumber(value.total_tasks),
    completed_task_count: finiteNumber(value.completed_task_count),
    planned_tasks: recordArray(value.planned_tasks),
    queued_tasks: recordArray(value.queued_tasks),
    completed_tasks: recordArray(value.completed_tasks),
    token_usage: normalizeTokenUsage(value.token_usage),
    models: recordArray(value.models).map(normalizePoolModel),
    updated_at: text(value.updated_at),
  } as OpenCodePoolStatus;
}

export function normalizeScanStatus(value: unknown): ScanStatus | null {
  if (
    !isRecord(value)
    || typeof value.scan_id !== "string"
    || !value.scan_id
    || !SCAN_STATUSES.has(value.status as ScanItemStatus)
  ) {
    return null;
  }
  const status = value.status as ScanItemStatus;
  const currentCandidate = value.current_candidate == null
    ? null
    : normalizeCandidate(value.current_candidate) as Candidate;
  return {
    ...value,
    scan_id: value.scan_id,
    project_id: text(value.project_id),
    project_path: text(value.project_path),
    code_scan_path: text(value.code_scan_path),
    multi_versions: recordArray(value.multi_versions).map((item) => ({
      version_name: text(item.version_name),
      project_path: text(item.project_path),
      code_scan_path: text(item.code_scan_path),
    })),
    scan_mode: text(value.scan_mode) || "full",
    threat_analysis_enabled: value.threat_analysis_enabled === true,
    threat_analysis_method: text(value.threat_analysis_method),
    product: text(value.product),
    validation_environment: text(value.validation_environment),
    code_graph_mcp_enabled: value.code_graph_mcp_enabled === true,
    knowledge_base_enabled: value.knowledge_base_enabled === true,
    vulnerability_validation_enabled: value.vulnerability_validation_enabled === true,
    validation_method_id: text(value.validation_method_id),
    validation_method_label: text(value.validation_method_label),
    scan_items: stringArray(value.scan_items),
    mining_engines: value.mining_engines === undefined
      ? undefined
      : recordArray(value.mining_engines).map((item) => ({
          ...item,
          engine_id: text(item.engine_id),
          engine_label: text(item.engine_label),
          enabled: item.enabled === true,
        })) as ScanStatus["mining_engines"],
    mining_engine_runs: recordArray(value.mining_engine_runs).map((item) => ({
      ...item,
      engine_id: text(item.engine_id),
      status: text(item.status),
    })) as ScanStatus["mining_engine_runs"],
    created_at: text(value.created_at),
    status,
    progress: finiteNumber(value.progress),
    total_candidates: finiteNumber(value.total_candidates),
    processed_candidates: finiteNumber(value.processed_candidates),
    candidates: Array.isArray(value.candidates)
      ? value.candidates.map((item, index) => normalizeCandidate(item, index) as ScanCandidate)
      : [],
    vulnerabilities: normalizeIndexedVulnerabilities(value.vulnerabilities),
    skill_reports: recordArray(value.skill_reports) as unknown as ScanStatus["skill_reports"],
    threat_audit_tasks: Array.isArray(value.threat_audit_tasks)
      ? value.threat_audit_tasks.map(normalizeThreatTask)
      : [],
    validations: Array.isArray(value.validations)
      ? value.validations.map(normalizeValidation)
      : [],
    events: Array.isArray(value.events)
      ? value.events.map(normalizeScanEvent).filter((item): item is ScanEvent => item !== null)
      : [],
    current_candidate: currentCandidate,
    error_message: value.error_message == null ? null : text(value.error_message),
    feedback_ids: stringArray(value.feedback_ids),
    retryable_candidates_count: finiteNumber(value.retryable_candidates_count),
    continuable_task_count: finiteNumber(value.continuable_task_count),
    can_continue: value.can_continue === true,
    fp_review_running: value.fp_review_running === true,
    total_task_count: finiteNumber(value.total_task_count),
    completed_task_count: finiteNumber(value.completed_task_count),
    opencode_pool: normalizeOpenCodePool(value.opencode_pool),
    static_total_files: finiteNumber(value.static_total_files),
    static_scanned_files: finiteNumber(value.static_scanned_files),
    static_analysis_done: value.static_analysis_done === true,
  } as ScanStatus;
}

export function sameOpenCodePoolSnapshot(
  left: OpenCodePoolStatus | null | undefined,
  right: OpenCodePoolStatus | null | undefined,
): boolean {
  if (left === right) return true;
  if (!left || !right) return left == null && right == null;
  return left.scope_id === right.scope_id
    && left.updated_at === right.updated_at
    && left.global_running === right.global_running
    && left.global_queued === right.global_queued
    && left.completed_task_count === right.completed_task_count
    && left.total_tasks === right.total_tasks;
}
