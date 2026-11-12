import type { AgentModelTimeWindow } from "./modelPool";

export interface AgentInfo {
  agent_id: string;
  agent_key: string;
  user_id?: string;
  owner_username?: string;
  name: string;
  machine_name: string;
  ip: string;
  port?: number;
  last_seen: string;
  online: boolean;
  agent_session_id?: string;
  runtime_hash?: string;
  runtime_update_status?: "" | "pending" | "updating" | "failed";
  runtime_update_target_hash?: string;
  runtime_update_error?: string;
  accepting_tasks?: boolean;
  has_explicit_model: boolean;
}

export interface AgentRuntimeManifest {
  hash: string;
}

export interface AgentRuntimeUpdateResponse {
  status: "up_to_date" | "pending" | "updating" | "failed";
  target_hash: string;
  message: string;
}

export interface AgentOpenCodeModelConfig {
  id: string;
  model: string;
  capability: "low" | "medium" | "high" | string;
  weight: number;
  max_concurrency: number;
  enabled: boolean;
  timeout?: number | null;
  idle_timeout?: number | null;
  max_retries?: number | null;
  time_windows?: AgentModelTimeWindow[];
}

export interface AgentBaseConfig {
  tool: "opencode";
  executable: string;
  no_proxy: string;
  opencode_serve_port: number | null;
}

export interface AgentModelPoolConfig {
  models: AgentOpenCodeModelConfig[];
}

export interface AgentModelTaskPolicy {
  required_capability: "low" | "high";
  timeout_seconds: number;
  idle_timeout_seconds: number;
  json_correction_timeout_seconds: number;
  validation_retry_timeout_seconds: number;
  max_retries: number;
}

export interface AgentMiningTaskPolicy extends AgentModelTaskPolicy {
  threat_audit_timeout_seconds: number;
  candidate_audit_timeout_seconds: number;
  vulnerability_dedup_timeout_seconds: number;
}

export interface AgentMcpConfig {
  enabled: boolean;
  name: string;
  transport: "local" | "remote" | string;
  timeout_seconds: number;
  local: { executable: string; args: string[]; environment: Record<string, string> };
  remote: { url: string; headers: Record<string, string> };
}

export interface AgentThreatAnalysisConfig {
  enabled: boolean;
  model_policy: AgentModelTaskPolicy;
}

export interface AgentVulnerabilityValidationConfig {
  supported_vulnerability_types: string[];
  concurrency: number;
  validation_max_retries: number;
  model_policy: AgentModelTaskPolicy;
}

export interface AgentModeCheckerSelectionConfig {
  disabled_checkers: string[];
}

export interface AgentCheckerSelectionConfig {
  quick: AgentModeCheckerSelectionConfig;
  standard: AgentModeCheckerSelectionConfig;
  custom: AgentModeCheckerSelectionConfig;
}

export interface AgentValidatorField {
  key: string;
  label: string;
  type: "string" | "integer" | "number" | "boolean" | "select" | "secret" | string;
  required: boolean;
  default?: unknown;
  options: unknown[];
  min?: number | null;
  max?: number | null;
  help?: string;
  placeholder?: string;
}

export interface AgentValidatorMethod {
  method_id: string;
  method_label: string;
  description: string;
  products: string[];
  fields: AgentValidatorField[];
}

export interface AgentValidatorCatalog {
  methods: AgentValidatorMethod[];
  errors: string[];
  updated_at: string;
}

export interface AgentLlmModelConfig {
  previous_id?: string;
  name?: string;
  limit?: { context?: number; output?: number; input?: number };
  headers?: Record<string, string | null>;
}

export interface AgentLlmProviderConfig {
  previous_id?: string;
  name?: string;
  npm: "@ai-sdk/openai-compatible";
  options: {
    baseURL: string;
    apiKey?: string | null;
    apiKey_set?: boolean;
    headers?: Record<string, string | null>;
    timeout?: number;
    chunkTimeout?: number;
  };
  models: Record<string, AgentLlmModelConfig>;
}

export interface AgentOpenCodeConfigStatus {
  desired_revision: string;
  applied_revision: string;
  state: "active" | "draining" | "applying" | "failed" | "unsupported" | "offline";
  active_tasks: number;
  error: string;
}

export interface AgentOpenCodeApiTestRequest {
  provider_id: string;
  provider: AgentLlmProviderConfig;
  model_id: string;
}

export interface AgentOpenCodeApiTestResult {
  success: boolean;
  elapsed_ms: number;
  http_status: number | null;
  category: string;
  error: string;
}

export interface AgentRemoteConfig {
  schema_version: 11;
  llm_providers: Record<string, AgentLlmProviderConfig>;
  base: AgentBaseConfig;
  model_pool: AgentModelPoolConfig;
  threat_analysis: AgentThreatAnalysisConfig;
  vulnerability_mining: AgentMiningTaskPolicy;
  false_positive: AgentModelTaskPolicy;
  vulnerability_validation: AgentVulnerabilityValidationConfig;
  checker_selection: AgentCheckerSelectionConfig;
}

export type AgentMcpTarget = "product_info";

export type AgentMcpProbeTarget = AgentMcpTarget | "scan_code_graph" | "scan_knowledge_base";

export type AgentMcpRuntimeState = "active" | "reload_pending" | "next_task";

export interface AgentMcpLiveRuntimeStatus {
  state: "connected" | "applying" | "failed" | "needs_auth" | "needs_client_registration" | "disabled" | "next_session" | "offline" | "unknown" | string;
  config_fingerprint: string;
  updated_at: string;
  error: string;
  loaded_directories: number;
  total_directories: number;
}

export interface AgentMcpProbeResult {
  target: AgentMcpProbeTarget;
  config_fingerprint: string;
  success: boolean;
  checked_at: string;
  transport: string;
  protocol: string;
  tool_names: string[];
  tool_count: number;
  duration_ms: number;
  error: string;
  runtime_state: AgentMcpRuntimeState;
  active_sessions: number;
  projects: KnowledgeBaseProject[];
  current_project: KnowledgeBaseProject | null;
  session_project: KnowledgeBaseProject | null;
}

export interface KnowledgeBaseProject {
  id: string;
  name: string;
  path: string;
  current: boolean;
}

export interface AgentMcpTargetStatus {
  enabled: boolean;
  stale: boolean;
  last_probe: AgentMcpProbeResult | null;
  runtime: AgentMcpLiveRuntimeStatus;
}

export interface AgentMcpStatusResponse {
  agent_key: string;
  online: boolean;
  product_info: AgentMcpTargetStatus;
}

export interface AgentOpenCodeModelListItem {
  id: string;
  model: string;
  provider_id: string;
  model_id: string;
  name?: string;
}

export interface AgentOpenCodeModelsResult {
  ok: boolean;
  message: string;
  models: AgentOpenCodeModelListItem[];
}
