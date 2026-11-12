import { selectedScanPaths } from "../scanPaths";
import { normalizeScanProgressEstimate, selectScanProgressEstimate } from "../scanProgress";
import type { Candidate, ScanCandidate } from "../types/audit";
import type { ScanCodeGraphState, ScanEvent, ScanItemStatus, ScanStatus } from "../types/scans";
import { isRecord, text, finiteNumber, nullableFiniteNumber, recordArray, stringArray } from './record';
import { normalizeCandidate } from './candidates';
import { normalizeIndexedVulnerabilities, normalizeValidation } from './issues';
import { normalizePatternTask, mergePatternTasks, normalizeThreatTask } from './audit';
import { normalizeOpenCodePool, selectOpenCodePoolSnapshot } from './modelPool';

export const SCAN_STATUSES = new Set<ScanItemStatus>([
  "pending",
  "analyzing",
  "auditing",
  "complete",
  "error",
  "cancelled",
]);

export type ScanExecutionState = {
  execution_revision?: number | null;
  opencode_pool?: { execution_revision?: number } | null;
};

export function scanExecutionRevision(value: ScanExecutionState | null | undefined): number | undefined {
  return value?.execution_revision ?? value?.opencode_pool?.execution_revision;
}

export const progressFields = [
  "status", "error_message", "progress", "total_candidates", "processed_candidates",
  "static_total_files", "static_scanned_files", "static_analysis_done",
] as const;

export interface ScanMetadataState {
  scan_id: string;
  scan_name?: string;
  product?: string;
  metadata_revision?: number;
}

/** Labels have their own revision and must not gate newer runtime progress. */
export function mergeScanMetadata<T extends ScanMetadataState>(
  previous: ScanMetadataState | null | undefined,
  incoming: T,
): T {
  if (previous?.scan_id !== incoming.scan_id
    || (incoming.metadata_revision ?? 0) >= (previous.metadata_revision ?? 0)) return incoming;
  return {
    ...incoming,
    scan_name: previous.scan_name,
    product: previous.product,
    metadata_revision: previous.metadata_revision,
  };
}

export type CodeGraphSnapshot = Pick<ScanCodeGraphState, "scan_id"> & Partial<ScanCodeGraphState>;

/** CodeGraph changes and acknowledgements advance independently of scan execution. */
export function mergeScanCodeGraph<T extends CodeGraphSnapshot>(
  previous: CodeGraphSnapshot | null | undefined,
  incoming: T,
): T {
  if (previous?.scan_id !== incoming.scan_id) return incoming;
  if (previous.code_graph_mcp_revision == null && incoming.code_graph_mcp_revision == null) return incoming;
  const selected = (previous.code_graph_mcp_revision ?? 0) > (incoming.code_graph_mcp_revision ?? 0)
    ? previous : incoming;
  const revision = selected.code_graph_mcp_revision ?? 0;
  const applied = Math.max(previous.code_graph_mcp_applied_revision ?? 0, incoming.code_graph_mcp_applied_revision ?? 0);
  const syncStatus = applied >= revision ? "synced" : "pending";
  if (incoming.code_graph_mcp_enabled === selected.code_graph_mcp_enabled
    && incoming.code_graph_mcp_revision === revision
    && incoming.code_graph_mcp_applied_revision === applied
    && incoming.code_graph_mcp_sync_status === syncStatus) return incoming;
  return {
    ...incoming,
    code_graph_mcp_enabled: selected.code_graph_mcp_enabled,
    code_graph_mcp_revision: revision,
    code_graph_mcp_applied_revision: applied,
    code_graph_mcp_sync_status: syncStatus,
  };
}

/** Merge a GET without letting a response started before a live update undo it. */
export function mergeScanSnapshot(
  previous: ScanStatus | null,
  incoming: ScanStatus,
  requestedFrom?: ScanStatus | null,
): ScanStatus {
  if (previous?.scan_id !== incoming.scan_id) return incoming;
  if (isOlderScanExecution(previous, incoming)) return mergeScanCodeGraph(incoming, mergeScanMetadata(incoming, previous));
  const newerExecution = (scanExecutionRevision(incoming) ?? 0) > (scanExecutionRevision(previous) ?? 0);
  const updatedDuringRequest = requestedFrom !== undefined && !newerExecution && (
    requestedFrom?.scan_id !== previous.scan_id
    || scanExecutionRevision(requestedFrom) !== scanExecutionRevision(previous)
    || progressFields.some((key) => previous[key] !== requestedFrom?.[key])
  );
  const runtime = updatedDuringRequest ? previous : incoming;
  return mergeScanCodeGraph(previous, mergeScanMetadata(previous, {
    ...incoming,
    ...Object.fromEntries(progressFields.map((key) => [key, runtime[key]])),
    execution_revision: scanExecutionRevision(runtime) ?? scanExecutionRevision(previous),
    progress_estimate: selectScanProgressEstimate(previous.progress_estimate, incoming.progress_estimate,
      scanExecutionRevision(runtime) ?? scanExecutionRevision(previous)),
    progress: runtime.total_candidates > 0
      ? Math.min(1, Math.max(0, runtime.processed_candidates / runtime.total_candidates))
      : runtime.progress,
    ...(updatedDuringRequest ? {
      detail_counts: previous.detail_counts,
      retryable_candidates_count: previous.retryable_candidates_count,
      continuable_task_count: previous.continuable_task_count,
      can_continue: previous.can_continue,
    } : {}),
    opencode_pool: selectOpenCodePoolSnapshot(previous.opencode_pool, incoming.opencode_pool, {
      allowClear: incoming.opencode_pool === null && !updatedDuringRequest
        && ["complete", "error", "cancelled"].includes(incoming.status),
    }),
    // Overview snapshots omit artifacts; null does not delete a loaded result.
    threat_analysis: incoming.threat_analysis ?? previous.threat_analysis,
    threat_pattern_audit_tasks: mergePatternTasks(previous.threat_pattern_audit_tasks ?? [], incoming.threat_pattern_audit_tasks ?? []),
  }));
}

export function mergeScanOverview(
  previous: ScanStatus | null, incoming: ScanStatus, requestedFrom?: ScanStatus | null,
): ScanStatus {
  const merged = mergeScanSnapshot(previous, incoming, requestedFrom);
  if (!previous || previous.scan_id !== incoming.scan_id || merged === previous) return merged;
  return {
    ...merged,
    candidates: previous.candidates,
    vulnerabilities: previous.vulnerabilities,
    skill_reports: previous.skill_reports,
    threat_audit_tasks: previous.threat_audit_tasks,
    threat_pattern_audit_tasks: previous.threat_pattern_audit_tasks,
    validations: previous.validations,
    events: previous.events,
    detail_pages: previous.detail_pages,
  };
}

export function isOlderScanExecution(
  current: ScanExecutionState | null | undefined,
  incoming: ScanExecutionState | null | undefined,
): boolean {
  const revision = scanExecutionRevision(incoming);
  return revision !== undefined && revision < (scanExecutionRevision(current) ?? 0);
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
    execution_revision: nullableFiniteNumber(value.execution_revision) ?? undefined,
    scan_name: text(value.scan_name) || text(value.project_id),
    metadata_revision: Math.max(0, nullableFiniteNumber(value.metadata_revision) ?? 0),
    project_id: text(value.project_id),
    project_path: text(value.project_path),
    code_scan_path: text(value.code_scan_path),
    code_scan_paths: selectedScanPaths(value),
    multi_versions: recordArray(value.multi_versions).map((item) => ({
      version_name: text(item.version_name),
      project_path: text(item.project_path),
      code_scan_path: text(item.code_scan_path),
      code_scan_paths: selectedScanPaths(item),
    })),
    scan_mode: text(value.scan_mode) || "full",
    threat_analysis_enabled: value.threat_analysis_enabled === true,
    threat_analysis_method: text(value.threat_analysis_method),
    product: text(value.product),
    validation_environment: text(value.validation_environment),
    code_graph_mcp_enabled: value.code_graph_mcp_enabled === true,
    code_graph_mcp_revision: Math.max(0, finiteNumber(value.code_graph_mcp_revision)),
    code_graph_mcp_applied_revision: Math.max(0, finiteNumber(value.code_graph_mcp_applied_revision)),
    code_graph_mcp_sync_status: finiteNumber(value.code_graph_mcp_applied_revision) < finiteNumber(value.code_graph_mcp_revision)
      ? "pending" : "synced",
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
      total_candidates: nullableFiniteNumber(item.total_candidates),
      processed_candidates: nullableFiniteNumber(item.processed_candidates),
    })) as ScanStatus["mining_engine_runs"],
    created_at: text(value.created_at),
    status,
    progress: finiteNumber(value.progress),
    progress_estimate: normalizeScanProgressEstimate(value.progress_estimate),
    total_candidates: finiteNumber(value.total_candidates),
    processed_candidates: finiteNumber(value.processed_candidates),
    candidates: Array.isArray(value.candidates)
      ? value.candidates.map((item, index) => normalizeCandidate(item, index) as ScanCandidate)
      : [],
    vulnerabilities: normalizeIndexedVulnerabilities(value.vulnerabilities),
    skill_reports: recordArray(value.skill_reports) as unknown as ScanStatus["skill_reports"],
    threat_pattern_audit_tasks: Array.isArray(value.threat_pattern_audit_tasks)
      ? value.threat_pattern_audit_tasks.map(normalizePatternTask) : [],
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
