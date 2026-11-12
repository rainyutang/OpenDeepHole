import type { OutputSource, Vulnerability } from "./issues";
import type { ThreatCodePath } from "./threatAnalysis";

export interface ThreatAuditTask {
  engine_id?: string;
  iteration?: number;
  parent_task_id?: string;
  has_more_findings?: boolean | null;
  followup_clues?: string;
  task_id: string;
  scan_id?: string;
  status: string;
  surface_node_id?: string;
  surface_name?: string;
  method_node_id?: string;
  method_name?: string;
  attack_goal?: string;
  risk_id?: string;
  risk_name?: string;
  asset_id?: string;
  asset_name?: string;
  code_path: string;
  code_path_description?: string;
  code_paths?: ThreatCodePath[];
  attack_path_id?: string;
  attack_path_fingerprint?: string;
  description?: string;
  result_vuln_indexes?: number[];
  failure_reason?: string;
  output_source?: OutputSource;
  created_at?: string;
  started_at?: string;
  finished_at?: string;
  updated_at?: string;
}

export interface ThreatPatternAuditTask {
  /** Derived by the detail endpoint; omitted from summary rows and persistence. */
  next_task_id?: string;
  engine_id?: string;
  iteration?: number;
  parent_task_id?: string;
  has_more_findings?: boolean | null;
  followup_clues?: string;
  task_id: string;
  scan_id?: string;
  status: string;
  module_name: string;
  pattern_id: string;
  pattern_name: string;
  code_paths?: ThreatCodePath[];
  description?: string;
  result_vuln_indexes?: number[];
  failure_reason?: string;
  output_source?: OutputSource;
  created_at?: string;
  started_at?: string;
  finished_at?: string;
  updated_at?: string;
}

export interface ThreatPatternAuditTaskPage {
  items: ThreatPatternAuditTask[];
  next_cursor: string | null;
  has_more: boolean;
}

export interface ThreatAuditFindingSummary {
  vuln_index: number;
  vuln_type: string;
  severity: string;
  description: string;
  file: string;
  line: number;
  function: string;
  verdict: "confirmed" | "false_positive" | "unreviewed" | "not_confirmed";
  verdict_source: "human" | "fp_review" | "audit";
}

export interface ThreatAuditTaskResult {
  task_id: string;
  findings: ThreatAuditFindingSummary[];
  confirmed_issue_count: number;
  association_complete: boolean;
}

export interface CandidateAuditTaskResult {
  candidate_index: number;
  findings: ThreatAuditFindingSummary[];
  confirmed_issue_count: number;
  association_complete: boolean;
}

export interface VulnerabilityAuditSource {
  vuln_index: number;
  status: "resolved" | "missing" | "ambiguous" | "unsupported";
  kind: "threat_audit" | "threat_pattern_audit" | "static_candidate" | null;
  pattern_task: ThreatPatternAuditTask | null;
  threat_task: ThreatAuditTask | null;
  candidate: ScanCandidate | null;
}

export interface Candidate {
  file: string;
  line: number;
  function: string;
  description: string;
  vuln_type: string;
  related_functions?: string[];
  metadata?: Record<string, unknown>;
}

export interface ScanCandidate extends Candidate {
  idx: number;
  audit_state: "pending" | "queued" | "running" | "success" | "failed";
  audit_result?: Vulnerability | null;
  vulnerability_idx?: number | null;
  dedup_decision?: Record<string, unknown>;
  audit_updated_at?: string;
}

export interface ScanCandidatePage {
  items: ScanCandidate[];
  next_cursor: number | null;
  has_more: boolean;
}

export interface ThreatAuditTaskPage {
  items: ThreatAuditTask[];
  next_cursor: string | null;
  has_more: boolean;
}
