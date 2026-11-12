import type { OpenCodeTokenUsage } from "./modelPool";
import type { ScanItemStatus } from "./scans";

export interface CheckerScanDashboardStats {
  scan_id: string;
  project_id: string;
  scan_name: string;
  project_path: string;
  product: string;
  status: ScanItemStatus;
  created_at: string;
  username: string;
  agent_name: string;
  static_issue_count: number;
  llm_issue_count: number;
  fp_review_issue_count: number;
  fp_review_false_positive_count: number;
  human_confirmed_count: number;
  human_false_positive_count: number;
  ticket_submitted_count: number;
  accuracy_basis_count: number;
  accuracy: number | null;
  ticket_accuracy: number | null;
}

export interface CheckerDashboardStats {
  checker: string;
  label: string;
  description: string;
  scan_count: number;
  project_count: number;
  projects: string[];
  static_issue_count: number;
  llm_issue_count: number;
  fp_review_issue_count: number;
  fp_review_false_positive_count: number;
  human_confirmed_count: number;
  human_false_positive_count: number;
  ticket_submitted_count: number;
  accuracy_basis_count: number;
  accuracy: number | null;
  ticket_accuracy: number | null;
  scans: CheckerScanDashboardStats[];
  user_created: boolean;
}

export interface CheckerDashboardSummary {
  checker_count: number;
  scan_count: number;
  project_count: number;
  static_issue_count: number;
  llm_issue_count: number;
  fp_review_issue_count: number;
  fp_review_false_positive_count: number;
  suspected_issue_count: number;
  total_issue_count: number;
  human_confirmed_count: number;
  ticket_submitted_count: number;
  accuracy_basis_count: number;
  accuracy: number | null;
  ticket_accuracy: number | null;
}

export interface CheckerDashboardAgentTokenUsage {
  agent_key: string;
  agent_name: string;
  machine_name: string;
  ip: string;
  owner_user_id: string;
  owner_username: string;
  scan_count: number;
  tracked_scan_count: number;
  usage: OpenCodeTokenUsage;
}

export interface CheckerDashboardTokenUsage {
  scan_count: number;
  tracked_scan_count: number;
  usage: OpenCodeTokenUsage;
  agents: CheckerDashboardAgentTokenUsage[];
}

export interface CheckerDashboardResponse {
  summary: CheckerDashboardSummary;
  checkers: CheckerDashboardStats[];
  products: string[];
  has_unconfigured_product: boolean;
  token_usage: CheckerDashboardTokenUsage;
}
