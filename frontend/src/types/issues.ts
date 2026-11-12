export type UserFeedbackVerdict = "confirmed" | "false_positive" | "pending_analysis";

export type FeedbackEntryVerdict = "confirmed" | "false_positive";

export interface OutputSource {
  agent_id?: string;
  agent_name?: string;
  agent_session_id?: string;
  backend?: "cli" | "api" | "system" | "" | string;
  tool?: string;
  model_id?: string;
  model?: string;
  use_default_model?: boolean;
  capability?: string;
  required_capability?: string;
  task_id?: string;
  attempt?: number;
  started_at?: string;
  serve_session_id?: string;
}

export interface Vulnerability {
  file: string;
  line: number;
  function: string;
  call_chain?: string;
  vuln_type: string;
  severity: string;
  description: string;
  impact?: string;
  vulnerable_code?: string;
  remediation?: string;
  attack_entry?: string;
  root_cause?: string;
  trigger_conditions?: string;
  ai_analysis: string;
  vulnerability_report?: string;
  confirmed: boolean;
  ai_verdict?: "confirmed" | "not_confirmed" | "timeout" | "no_result" | "failed" | "filtered_same_pattern" | "";
  failure_reason?: string;
  user_verdict?: UserFeedbackVerdict | null;
  user_verdict_reason?: string | null;
  ticket_submitted?: boolean;
  ticket_id?: string;
  function_source?: string;
  function_start_line?: number | null;
  audit_index?: number | null;
  variant_of?: string;
  analysis_source?: "static_candidate" | "threat_audit" | string;
  engine_id?: string;
  engine_label?: string;
  source_task_id?: string;
  threat_surface_node_id?: string;
  threat_method_node_id?: string;
  threat_code_path?: string;
  version_labels?: string[];
  version_locations?: VersionVulnerabilityLocation[];
  provisional?: boolean;
  output_source?: OutputSource;
}

export interface VersionVulnerabilityLocation {
  version_name: string;
  project_path?: string;
  code_scan_path?: string;
  file?: string;
  line?: number;
  function?: string;
}

/** Frontend scan-detail record with the stable backend vulnerability index. */
export interface IndexedVulnerability extends Vulnerability {
  vuln_index: number;
}

export interface VulnerabilityValidation {
  scan_id?: string;
  execution_revision?: number;
  execution_agent_session_id?: string;
  vuln_index: number;
  status: string;
  running: boolean;
  product?: string;
  validation_environment?: string;
  validation_method_id?: string;
  validation_method_label?: string;
  validator_name?: string;
  validation_success?: boolean | null;
  is_problem?: boolean | null;
  requires_human_intervention?: boolean | null;
  validation_code: string;
  validation_output: string;
  intermediate_output: string;
  output_sections?: ValidationOutputSection[];
  final_output?: string;
  artifacts?: ValidationArtifact[];
  started_at: string;
  finished_at: string;
  updated_at: string;
}

export interface ValidationArtifact {
  title?: string;
  name: string;
  kind?: string;
  content?: string;
  path?: string;
  updated_at?: string;
}

export interface ValidationOutputSection {
  title: string;
  content: string;
  updated_at?: string;
}

export interface VulnerabilityPageItem {
  index: number;
  vulnerability: Vulnerability;
}

export interface VulnerabilityPage {
  items: VulnerabilityPageItem[];
  next_cursor: number | null;
  has_more: boolean;
}

export interface VulnerabilityValidationPage {
  items: VulnerabilityValidation[];
  next_cursor: number | null;
  has_more: boolean;
}

export interface FeedbackEntry {
  id: string;
  project_id: string;
  vuln_type: string;
  verdict: FeedbackEntryVerdict;
  file: string;
  line: number;
  function: string;
  description: string;
  reason: string;
  ticket_submitted: boolean;
  ticket_id: string;
  function_source: string;
  function_start_line: number | null;
  source_scan_id: string | null;
  created_at: string;
  updated_at: string;
}
