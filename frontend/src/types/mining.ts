export interface MiningEngineRequest {
  engine_id: string;
}

export interface MiningEngineSelection {
  engine_id: string;
  engine_label: string;
  enabled: boolean;
}

export interface StaticAnalysisError {
  checker_name: string;
  checker_label?: string;
  error: string;
  exit_code?: number | null;
  version_name?: string;
}

export interface MiningEngineRunStatus {
  engine_id: string;
  engine_label: string;
  status: "pending" | "running" | "success" | "error" | "cancelled" | "skipped" | string;
  error_message: string;
  started_at: string;
  finished_at: string;
  total_candidates?: number | null;
  processed_candidates?: number | null;
  static_analysis_errors?: StaticAnalysisError[];
}

export interface MiningEngineCatalogItem {
  engine_id: string;
  label: string;
  description: string;
  fp_review: boolean;
  requires_codex: boolean;
}

export interface MiningEngineCatalog {
  engines: MiningEngineCatalogItem[];
  errors: string[];
  updated_at: string;
}
