import type { IndexedVulnerability, OutputSource } from "./issues";

export type FpReviewStatus = "pending" | "running" | "complete" | "error" | "cancelled";

export type FpReviewMethod = string;

export interface FpReviewStageConfig {
  key: string;
  label: string;
}

export interface FpReviewMethodCatalogItem {
  method_id: string;
  label: string;
  description: string;
  default: boolean;
  max_concurrency: number;
  stages: FpReviewStageConfig[];
}

export interface FpReviewMethodCatalog {
  methods: FpReviewMethodCatalogItem[];
  errors: string[];
  updated_at: string;
}

export interface FpReviewMethodSelection {
  method_id: string;
  method_label: string;
  description: string;
  stages: FpReviewStageConfig[];
}

export interface FpReviewResult {
  review_id?: string;
  execution_revision?: number;
  pending_stage_outputs?: Record<string, string>;
  vuln_index: number;
  verdict: "tp" | "fp" | "uncertain";
  severity: "high" | "medium" | "low";
  reason: string;
  vulnerability_report: string;
  stage_outputs?: Record<string, string>;
  stage_output_sources?: Record<string, OutputSource>;
  output_source?: OutputSource;
  match_reference?: string;
  match_type?: "history" | "validation" | "" | string;
  created_at: string;
}

export interface FpReviewJob {
  execution_revision?: number;
  result_counts?: { tp: number; fp: number; unresolved: number };
  next_cursor?: number | null;
  result_vulnerabilities?: IndexedVulnerability[];
  review_id: string;
  scan_id: string;
  method: FpReviewMethod;
  status: FpReviewStatus;
  created_at: string;
  total: number;
  processed: number;
  current_vuln_index: number | null;
  current_vuln_indices?: number[];
  results: FpReviewResult[];
  error_message: string | null;
}
