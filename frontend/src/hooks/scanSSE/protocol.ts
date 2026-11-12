import type { ScanDetailResource } from "../../scanResourceRefresh";
import { isRecord } from "../../scanRuntime/record";
import { normalizeScanEvent } from "../../scanRuntime/scanSnapshots";
import type { FpReviewJob, FpReviewMethod, FpReviewStatus } from "../../types/fpReview";
import type { IndexStatus, ScanEvent, ScanStatus } from "../../types/scans";
import type { MiningEngineRunStatus } from "../../types/mining";
import type { OpenCodeCompletedTask } from "../../types/modelPool";
import type { OutputSource, Vulnerability, VulnerabilityValidation } from "../../types/issues";
import type { ScanCandidate, ThreatAuditTask, ThreatPatternAuditTask } from "../../types/audit";
import type { ThreatAnalysis, ThreatAnalysisRunStatus } from "../../types/threatAnalysis";

export const SCAN_STATUSES = new Set(["pending", "analyzing", "auditing", "complete", "error", "cancelled"]);

export const FP_REVIEW_STATUSES = new Set(["pending", "running", "complete", "error", "cancelled"]);

/* ------------------------------------------------------------------ */
/*  SSE event payload types (mirror backend publish() shapes)          */
/* ------------------------------------------------------------------ */

export interface ScanStatusEvent {
  execution_revision?: number;
  status: string | null;
  progress: number | null;
  progress_estimate?: ScanStatus["progress_estimate"];
  total_candidates: number | null;
  processed_candidates: number | null;
  static_total_files?: number | null;
  static_scanned_files?: number | null;
  static_analysis_done?: boolean | null;
  error_message?: string | null;
  opencode_pool?: ScanStatus["opencode_pool"];
}

export interface OpenCodeTaskReportEvent {
  task?: OpenCodeCompletedTask;
  task_id?: string;
  revision?: number;
  completed_task_count: number;
  total_tasks: number;
}

export interface ScanVulnerabilityEvent {
  index: number;
  vulnerability: Vulnerability;
}

export interface ScanVulnerabilitiesChangedEvent {
  count: number;
}

export interface ScanCandidatesEvent {
  candidates: ScanCandidate[];
}

export interface ScanCandidatesChangedEvent {
  offset: number;
  count: number;
  total_candidates: number;
  final: boolean;
}

export interface ScanCandidateAuditEvent {
  candidate: ScanCandidate;
}

export interface ScanEventPayload {
  event: ScanEvent;
}

export interface ScanFinishEvent {
  execution_revision?: number;
  status: string;
  error_message: string | null;
}

export interface FpReviewStartedEvent {
  review_id: string;
  status: FpReviewStatus;
  total: number;
  processed?: number;
  method?: FpReviewMethod;
}

export interface FpReviewProgressEvent {
  review_id: string;
  vuln_index: number;
  active_indices?: number[] | null;
  processed?: number | null;
  total: number;
}

export interface FpReviewResultEvent {
  review_id: string;
  vuln_index: number;
  verdict: "tp" | "fp";
  severity: "high" | "medium" | "low";
  reason: string;
  vulnerability_report?: string;
  stage_outputs?: Record<string, string>;
  match_reference?: string;
  match_type?: string;
  stage_output_sources?: Record<string, OutputSource>;
  output_source?: OutputSource;
}

export interface FpReviewStageOutputEvent {
  review_id: string;
  vuln_index: number;
  stage: string;
  markdown: string;
  output_source?: OutputSource;
}

export interface FpReviewFinishEvent {
  review_id: string;
  status: FpReviewStatus;
  error_message: string | null;
  method?: FpReviewMethod;
}

export interface VulnerabilityValidationEvent {
  validation: VulnerabilityValidation;
}

export interface ThreatAnalysisEvent {
  analysis: ThreatAnalysis;
}

export interface ThreatAnalysisRunEvent {
  run: ThreatAnalysisRunStatus;
}

export interface ThreatAuditTaskEvent {
  task: ThreatAuditTask;
}

export interface MiningEngineRunEvent {
  run: MiningEngineRunStatus;
  runs: MiningEngineRunStatus[];
}

/* ------------------------------------------------------------------ */
/*  Handler map                                                        */
/* ------------------------------------------------------------------ */

export interface ScanSSEHandlers {
  onDetailRefreshState?: (resources: readonly ScanDetailResource[], refreshing: boolean) => void;
  onStateRefresh?: () => void;
  onScanStatus?: (data: ScanStatusEvent) => void;
  onOpenCodeTaskReport?: (data: OpenCodeTaskReportEvent) => void;
  onScanCandidates?: (data: ScanCandidatesEvent) => void;
  onScanCandidatesChanged?: (data: ScanCandidatesChangedEvent) => void;
  onScanCandidateAudit?: (data: ScanCandidateAuditEvent) => void;
  onScanVulnerability?: (data: ScanVulnerabilityEvent) => void;
  onScanVulnerabilitiesChanged?: (data: ScanVulnerabilitiesChangedEvent) => void;
  onScanEvent?: (data: ScanEventPayload) => void;
  onScanEvents?: (events: ScanEvent[]) => void;
  onScanFinish?: (data: ScanFinishEvent) => void;
  onFpReviewStarted?: (data: FpReviewStartedEvent) => void;
  onFpReviewProgress?: (data: FpReviewProgressEvent) => void;
  onFpReviewStageOutput?: (data: FpReviewStageOutputEvent) => void;
  onFpReviewResult?: (data: FpReviewResultEvent) => void;
  onFpReviewFinish?: (data: FpReviewFinishEvent) => void;
  onVulnerabilityValidation?: (data: VulnerabilityValidationEvent) => void;
  onThreatAnalysis?: (data: ThreatAnalysisEvent) => void;
  onThreatAnalysisRefresh?: (force?: boolean) => void;
  onThreatCoverageRefresh?: () => void;
  onCoverageIssuesRefresh?: () => void;
  onThreatAnalysisRun?: (data: ThreatAnalysisRunEvent) => void;
  onThreatAuditTask?: (data: ThreatAuditTaskEvent) => void;
  onThreatPatternAuditTask?: (data: { task: ThreatPatternAuditTask }) => void;
  onMiningEngineRun?: (data: MiningEngineRunEvent) => void;
  onIndexStatus?: (data: IndexStatus) => void;
}

/* ------------------------------------------------------------------ */
/*  Full-state refresh helpers (used on connect and reconnect)         */
/* ------------------------------------------------------------------ */

export interface SSEStateSetters {
  getScan: () => ScanStatus | null;
  getFpReview: () => FpReviewJob | null;
  setScan: React.Dispatch<React.SetStateAction<ScanStatus | null>>;
  setFpReview: React.Dispatch<React.SetStateAction<FpReviewJob | null>>;
  setIndexStatus: React.Dispatch<React.SetStateAction<IndexStatus | null>>;
}

export function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

export function isString(value: unknown): value is string {
  return typeof value === "string";
}

export function isRecordArray(value: unknown): boolean {
  return Array.isArray(value) && value.every(isRecord);
}

export function isCandidate(value: unknown): boolean {
  return isRecord(value)
    && isString(value.file)
    && isFiniteNumber(value.line)
    && isString(value.function)
    && isString(value.description)
    && isString(value.vuln_type);
}

export function isVulnerability(value: unknown): boolean {
  return isCandidate(value)
    && isRecord(value)
    && isString(value.severity)
    && isString(value.ai_analysis);
}

export function isValidPayload(eventType: string, value: unknown): value is Record<string, unknown> {
  if (!isRecord(value)) return false;
  switch (eventType) {
    case "scan_status":
      return (value.status == null || (isString(value.status) && SCAN_STATUSES.has(value.status)))
        && (value.execution_revision == null || isFiniteNumber(value.execution_revision))
        && (value.progress == null || isFiniteNumber(value.progress))
        && (value.total_candidates == null || isFiniteNumber(value.total_candidates))
        && (value.processed_candidates == null || isFiniteNumber(value.processed_candidates))
        && (value.static_total_files == null || isFiniteNumber(value.static_total_files))
        && (value.static_scanned_files == null || isFiniteNumber(value.static_scanned_files))
        && (value.static_analysis_done == null || typeof value.static_analysis_done === "boolean")
        && (value.opencode_pool === undefined || value.opencode_pool === null || isRecord(value.opencode_pool));
    case "opencode_task_report":
      return (isString(value.task_id) || isRecord(value.task) && isString(value.task.task_id))
        && isFiniteNumber(value.completed_task_count)
        && isFiniteNumber(value.total_tasks);
    case "scan_candidates":
      return Array.isArray(value.candidates) && value.candidates.every(isCandidate);
    case "scan_candidates_changed":
      return isFiniteNumber(value.offset)
        && isFiniteNumber(value.count)
        && isFiniteNumber(value.total_candidates)
        && typeof value.final === "boolean";
    case "scan_candidate_audit":
      return isCandidate(value.candidate);
    case "scan_vulnerability":
      return Number.isInteger(value.index) && Number(value.index) >= 0 && isVulnerability(value.vulnerability);
    case "scan_vulnerabilities_changed":
      return Number.isInteger(value.count) && Number(value.count) >= 0;
    case "scan_event":
      return normalizeScanEvent(value.event) !== null;
    case "scan_finish":
      return isString(value.status) && SCAN_STATUSES.has(value.status)
        && (value.error_message == null || isString(value.error_message));
    case "fp_review_started":
      return isString(value.review_id)
        && isString(value.status)
        && FP_REVIEW_STATUSES.has(value.status)
        && isFiniteNumber(value.total)
        && (value.processed == null || isFiniteNumber(value.processed));
    case "fp_review_progress":
      return isString(value.review_id)
        && isFiniteNumber(value.vuln_index)
        && isFiniteNumber(value.total)
        && (value.processed == null || isFiniteNumber(value.processed))
        && (value.active_indices == null
          || (Array.isArray(value.active_indices) && value.active_indices.every(isFiniteNumber)));
    case "fp_review_stage_output":
      return isString(value.review_id)
        && isFiniteNumber(value.vuln_index)
        && isString(value.stage)
        && isString(value.markdown);
    case "fp_review_result":
      return isString(value.review_id)
        && isFiniteNumber(value.vuln_index)
        && (value.verdict === "tp" || value.verdict === "fp")
        && (value.severity === "high" || value.severity === "medium" || value.severity === "low")
        && isString(value.reason)
        && (value.stage_outputs === undefined || isRecord(value.stage_outputs))
        && (value.stage_output_sources === undefined || isRecord(value.stage_output_sources));
    case "fp_review_finish":
      return isString(value.review_id)
        && isString(value.status)
        && FP_REVIEW_STATUSES.has(value.status)
        && (value.error_message == null || isString(value.error_message));
    case "vulnerability_validation":
      return isRecord(value.validation) && isFiniteNumber(value.validation.vuln_index);
    case "threat_analysis":
      return isRecord(value.analysis);
    case "file_inventory":
      return isString(value.snapshot_id) && isString(value.status);
    case "threat_analysis_run":
      return isRecord(value.run) && isString(value.run.status);
    case "threat_pattern_audit_task":
      return isRecord(value.task)
        && isString(value.task.task_id)
        && isString(value.task.status)
        && isString(value.task.module_name)
        && Array.isArray(value.task.code_paths)
        && value.task.code_paths.every((path) => isRecord(path) && isString(path.path));
    case "threat_audit_task":
      return isRecord(value.task)
        && isString(value.task.task_id)
        && isString(value.task.status)
        && isString(value.task.code_path);
    case "mining_engine_run":
      return isRecord(value.run) && isRecordArray(value.runs);
    case "index_status":
      return isString(value.status);
    default:
      return false;
  }
}
