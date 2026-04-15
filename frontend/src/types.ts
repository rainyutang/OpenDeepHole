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
  status: ScanItemStatus;
  progress: number;
  total_candidates: number;
  processed_candidates: number;
  vulnerabilities: Vulnerability[];
  events: ScanEvent[];
  current_candidate: Candidate | null;
  error_message: string | null;
}
