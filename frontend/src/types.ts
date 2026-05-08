export type ScanItemStatus =
  | "pending"
  | "analyzing"
  | "auditing"
  | "complete"
  | "error"
  | "cancelled";

export interface CheckerInfo {
  name: string;
  label: string;
  description: string;
}

export interface UploadResponse {
  project_id: string;
}

export interface ScanStartResponse {
  scan_id: string;
}

export interface Vulnerability {
  file: string;
  line: number;
  function: string;
  vuln_type: string;
  severity: string;
  description: string;
  ai_analysis: string;
  confirmed: boolean;
  user_verdict?: "confirmed" | "false_positive" | null;
  user_verdict_reason?: string | null;
}

export interface Candidate {
  file: string;
  line: number;
  function: string;
  description: string;
  vuln_type: string;
}

export interface ScanEvent {
  timestamp: string;
  phase: string;
  message: string;
  candidate_index: number | null;
}

export interface ScanStatus {
  scan_id: string;
  project_id: string;
  scan_items: string[];
  created_at: string;
  status: ScanItemStatus;
  progress: number;
  total_candidates: number;
  processed_candidates: number;
  vulnerabilities: Vulnerability[];
  events: ScanEvent[];
  current_candidate: Candidate | null;
  error_message: string | null;
  feedback_ids: string[];

  // 静态分析进度
  static_total_files: number;
  static_scanned_files: number;
  static_analysis_done: boolean;
}

export interface FeedbackEntry {
  id: string;
  project_id: string;
  vuln_type: string;
  verdict: "confirmed" | "false_positive";
  file: string;
  line: number;
  function: string;
  description: string;
  reason: string;
  source_scan_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface ScanSummary {
  scan_id: string;
  project_id: string;
  status: ScanItemStatus;
  created_at: string;
  progress: number;
  total_candidates: number;
  processed_candidates: number;
  vulnerability_count: number;
  scan_items: string[];
}

export interface AgentInfo {
  agent_id: string;
  name: string;
  ip: string;
  port: number;
  last_seen: string;
  online: boolean;
}

export interface AgentLLMApiConfig {
  base_url: string;
  api_key: string;
  model: string;
  temperature: number;
  timeout: number;
  max_retries: number;
}

export interface AgentOpenCodeConfig {
  executable: string;
  model: string;
  timeout: number;
}

export interface AgentRemoteConfig {
  no_proxy: string;
  llm_api: AgentLLMApiConfig;
  opencode: AgentOpenCodeConfig;
}
