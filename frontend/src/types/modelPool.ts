export interface AgentModelTimeWindow {
  weekdays: number[];
  start: string;
  end: string;
}

export interface OpenCodePoolModelStats {
  id: string;
  model: string;
  use_default_model: boolean;
  capability: string;
  weight: number;
  effective_weight: number;
  health_penalty_level: number;
  last_health_failure_at: string;
  last_health_failure_kind: string;
  max_concurrency: number;
  enabled: boolean;
  available: boolean;
  time_windows: AgentModelTimeWindow[];
  queued: number;
  running: number;
  total: number;
  success: number;
  failure: number;
  timeout: number;
  cancelled: number;
  avg_duration_seconds: number;
  last_status: string;
  last_started_at: string;
  last_finished_at: string;
  active_tasks: Record<string, unknown>[];
}

export interface OpenCodeTokenCounters {
  input_tokens: number;
  output_tokens: number;
  reasoning_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  total_tokens: number;
}

export interface OpenCodeModelTokenUsage extends OpenCodeTokenCounters {
  model: string;
}

export interface OpenCodeCategoryTokenUsage extends OpenCodeTokenCounters {
  category: string;
  label: string;
  complete: boolean;
}

export interface OpenCodeTokenUsage extends OpenCodeTokenCounters {
  complete: boolean;
  by_model: OpenCodeModelTokenUsage[];
  by_category?: OpenCodeCategoryTokenUsage[];
}

export interface OpenCodeSessionEvent {
  sequence: number;
  phase: "business" | "json_format" | "json_retry" | "validation_retry";
  session_id: string;
  session_attempt: number;
  retry_ordinal?: number;
  retry_total?: number;
  outcome: "success" | "failure" | "timeout" | "cancelled" | "invalid_output";
  model_id?: string;
  model?: string;
  failure_kind?: string;
  failure_reason?: string;
  started_at?: string;
  finished_at?: string;
  duration_seconds?: number;
}

export interface OpenCodeCompletedTask extends Record<string, unknown> {
  failure_kind?: string;
  failure_reason?: string;
  serve_session_id?: string;
  session_events?: OpenCodeSessionEvent[];
}

export interface OpenCodePoolStatus {
  scope_id: string;
  agent_name?: string;
  agent_session_id?: string;
  execution_revision?: number;
  global_running: number;
  global_queued: number;
  total_tasks: number;
  completed_task_count: number;
  queued_tasks: Record<string, unknown>[];
  planned_tasks?: Record<string, unknown>[];
  completed_tasks?: OpenCodeCompletedTask[];
  token_usage?: OpenCodeTokenUsage | null;
  models: OpenCodePoolModelStats[];
  updated_at: string;
  details_truncated?: boolean;
}

export interface AgentOpenCodePoolStatus extends OpenCodePoolStatus {
  agent_id: string;
  online: boolean;
}
