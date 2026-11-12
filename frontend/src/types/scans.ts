import type { Candidate, ScanCandidate, ThreatAuditTask, ThreatPatternAuditTask } from "./audit";
import type { SkillReport } from "./checkers";
import type { FpReviewMethod, FpReviewMethodSelection } from "./fpReview";
import type { IndexedVulnerability, VulnerabilityValidation } from "./issues";
import type { MiningEngineRunStatus, MiningEngineSelection } from "./mining";
import type { OpenCodePoolStatus } from "./modelPool";
import type { ThreatAnalysis, ThreatAnalysisMethodSelection, ThreatAnalysisRunStatus } from "./threatAnalysis";

export type ScanItemStatus =
  | "pending"
  | "analyzing"
  | "auditing"
  | "complete"
  | "error"
  | "cancelled";

export interface UploadResponse {
  project_id: string;
}

export interface ScanStartResponse {
  scan_id: string;
}

export interface ScanStopResponse {
  ok: boolean;
  main_scan_stopped: boolean;
  agent_stop_state: "not_required" | "confirmed" | "pending";
  fp_review_ids: string[];
}

export interface HistoryPattern {
  pattern: string;
  source: string;
  lens_hint: string;
  files: string[];
  rationale: string;
}

export interface ScanEvent {
  timestamp: string;
  phase: string;
  message: string;
  candidate_index: number | null;
}

export interface ScanCodeGraphState {
  scan_id: string;
  code_graph_mcp_enabled: boolean;
  code_graph_mcp_revision: number;
  code_graph_mcp_applied_revision: number;
  code_graph_mcp_sync_status: "synced" | "pending";
  sync_message?: string;
}

export interface ScanProgressEstimate {
  progress: number;
  remaining_seconds: number | null;
  state: "ready" | "estimating" | "unavailable" | "complete";
  calculated_at: string;
  execution_revision: number;
  active: boolean;
}

export interface ScanStatus {
  scan_id: string;
  can_copy_scan?: boolean;
  execution_revision?: number;
  scan_name: string;
  metadata_revision: number;
  project_id: string;
  project_path: string;
  code_scan_path: string;
  code_scan_paths?: string[];
  multi_versions?: ScanVersionTarget[];
  scan_mode?: string;
  threat_analysis_enabled: boolean;
  threat_analysis_method: string;
  threat_analysis_method_selection?: ThreatAnalysisMethodSelection | null;
  threat_analysis_run?: ThreatAnalysisRunStatus | null;
  auto_fp_review?: boolean;
  fp_review_method?: FpReviewMethod;
  fp_review_method_selection?: FpReviewMethodSelection | null;
  product: string;
  validation_environment: string;
  code_graph_mcp_enabled: boolean;
  code_graph_mcp_revision?: number;
  code_graph_mcp_applied_revision?: number;
  code_graph_mcp_sync_status?: "synced" | "pending";
  knowledge_base_enabled: boolean;
  vulnerability_validation_enabled: boolean;
  validation_method_id: string;
  validation_method_label: string;
  scan_items: string[];
  mining_engines?: MiningEngineSelection[];
  mining_engine_runs?: MiningEngineRunStatus[];
  created_at: string;
  status: ScanItemStatus;
  progress: number;
  progress_estimate?: ScanProgressEstimate;
  total_candidates: number;
  processed_candidates: number;
  candidates: ScanCandidate[];
  vulnerabilities: IndexedVulnerability[];
  skill_reports: SkillReport[];
  threat_analysis?: ThreatAnalysis | null;
  threat_audit_tasks?: ThreatAuditTask[];
  threat_pattern_audit_tasks?: ThreatPatternAuditTask[];
  validations?: VulnerabilityValidation[];
  events: ScanEvent[];
  current_candidate: Candidate | null;
  error_message: string | null;
  feedback_ids: string[];
  retryable_candidates_count: number;
  continuable_task_count: number;
  can_continue: boolean;
  fp_review_running: boolean;
  total_task_count: number;
  completed_task_count: number;
  opencode_pool?: OpenCodePoolStatus | null;

  // 静态分析进度
  static_total_files: number;
  static_scanned_files: number;
  static_analysis_done: boolean;

  // Agent 信息
  agent_name?: string;
  agent_online?: boolean;

  detail_counts?: ScanDetailCounts;
  detail_pages?: ScanDetailPages;
}

export interface ScanVersionTarget {
  version_name: string;
  project_path: string;
  code_scan_path: string;
  code_scan_paths?: string[];
}

export interface ScanDetailCounts {
  candidates: number;
  candidate_audit_pending?: number;
  candidate_audit_queued?: number;
  candidate_audit_running?: number;
  candidate_audit_success?: number;
  candidate_audit_failed?: number;
  vulnerabilities: number;
  effective_issue_count?: number;
  human_confirmed_issue_count?: number;
  validated_issue_count?: number;
  events: number;
  threat_audit_tasks: number;
  threat_audit_current?: number;
  threat_audit_pending?: number;
  threat_audit_queued?: number;
  threat_audit_running?: number;
  threat_audit_completed?: number;
  threat_audit_failed?: number;
  threat_audit_cancelled?: number;
  threat_audit_superseded?: number;
  threat_pattern_audit_tasks?: number;
  threat_pattern_audit_by_engine?: Record<string, {
    tasks: number; current: number; pending: number; queued: number; running: number;
    completed: number; failed: number; cancelled: number; superseded: number;
  }>;
  threat_pattern_audit_current?: number;
  threat_pattern_audit_pending?: number;
  threat_pattern_audit_queued?: number;
  threat_pattern_audit_running?: number;
  threat_pattern_audit_completed?: number;
  threat_pattern_audit_failed?: number;
  threat_pattern_audit_cancelled?: number;
  threat_pattern_audit_superseded?: number;

  validations: number;
  skill_reports: number;
}

export interface ScanDetailPages {
  candidates_next_cursor: number | null;
  vulnerabilities_next_cursor: number | null;
  events_next_cursor: number | null;
  threat_tasks_next_cursor: string | null;
  pattern_tasks_next_cursor?: string | null;
  validations_next_cursor: number | null;
}

export interface ScanEventPage {
  items: ScanEvent[];
  next_cursor: number | null;
  has_more: boolean;
}

export interface CodeIndexStats {
  files: number;
  functions: number;
  structs: number;
  global_variables: number;
  function_calls: number;
  global_variable_references: number;
}

export interface IndexStatus {
  status: "not_started" | "parsing" | "done" | "error" | "skipped" | "unknown";
  parsed_files?: number;
  total_files?: number;
  stage?: string;
  stage_current?: number;
  stage_total?: number;
  stats?: CodeIndexStats;
  error?: string;
}

export interface ScanSummary {
  scan_id: string;
  project_id: string;
  scan_mode?: string;
  threat_analysis_enabled: boolean;
  scan_name: string;
  metadata_revision: number;
  product: string;
  validation_environment: string;
  knowledge_base_enabled: boolean;
  vulnerability_validation_enabled: boolean;
  validation_method_id: string;
  validation_method_label: string;
  status: ScanItemStatus;
  created_at: string;
  progress: number;
  total_candidates: number;
  processed_candidates: number;
  vulnerability_count: number;
  human_confirmed_count: number;
  suspected_issue_count: number;
  confirmed_vulnerability_count: number;
  fp_review_running: boolean;
  retryable_candidates_count: number;
  continuable_task_count: number;
  can_continue: boolean;
  total_task_count: number;
  completed_task_count: number;
  scan_items: string[];
  user_id?: string;
  username?: string;
  agent_name?: string;
  agent_online?: boolean;
}

export interface ScanMetadata {
  scan_id: string;
  scan_name: string;
  product: string;
  metadata_revision: number;
}

export interface ScanMetadataUpdate {
  scan_name?: string;
  product?: string;
}

export interface ScanSummaryPage {
  items: ScanSummary[];
  next_cursor: string | null;
  has_more: boolean;
}

export interface ScanConfigMemory {
  knowledge_base: { project_id?: string; project_name?: string } | null;
  validation_by_product: Record<string, {
    last_method_id?: string;
    values_by_method?: Record<string, Record<string, unknown>>;
  }>;
}
