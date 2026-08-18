// --- Auth ---

export interface User {
  user_id: string;
  username: string;
  role: "admin" | "user";
  agent_token: string;
  created_at: string;
}

export interface TokenResponse {
  token: string;
  user: User;
}

export interface Announcement {
  announcement_id: string;
  title: string;
  content: string;
  published: boolean;
  published_at: string;
  created_at: string;
  updated_at: string;
}

// --- Scan ---

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
  visibility: "public" | "admin";
  category: string;
  category_label: string;
  modified_at: string;
  user_created: boolean;
  created_by_user_id: string;
  creator_username: string;
  can_delete: boolean;
  result_mode: string;
  timeout_seconds?: number | null;
  model_capability?: "any" | "low" | "medium" | "high" | string;
}

export interface CheckerCatalogItem {
  name: string;
  label: string;
  description: string;
  enabled: boolean;
  visibility: "public" | "admin";
  category: string;
  category_label: string;
  modified_at: string;
  introduction: string;
  introduction_source: string;
  user_created: boolean;
  created_by_user_id: string;
  creator_username: string;
  can_delete: boolean;
  result_mode: string;
  timeout_seconds?: number | null;
  model_capability?: "any" | "low" | "medium" | "high" | string;
}

export interface SkillDraft {
  skill_md: string;
  scenarios_md: string;
  summary: string;
}

export interface SkillCreateJob {
  job_id: string;
  status: "pending" | "running" | "completed" | "error";
  skill_id: string;
  name: string;
  description: string;
  input: string;
  agent_id: string;
  agent_name: string;
  user_id: string;
  created_at: string;
  updated_at: string;
  error_message: string;
  draft: SkillDraft | null;
}

export interface SkillImportFile {
  path: string;
  content_b64: string;
}

export interface UploadResponse {
  project_id: string;
}

export interface ScanStartResponse {
  scan_id: string;
}

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
  output_source?: OutputSource;
}

export interface VulnerabilityValidation {
  scan_id?: string;
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

export interface HistoryPattern {
  pattern: string;
  source: string;
  lens_hint: string;
  files: string[];
  rationale: string;
}

export interface SkillReport {
  id?: number | null;
  scan_id: string;
  checker_name: string;
  filename: string;
  title: string;
  content: string;
  created_at: string;
  output_source?: OutputSource;
}

export interface ThreatCodePath {
  path: string;
  description: string;
}

export interface NativeThreatValueAsset {
  "资产名": string;
  "资产类别": string;
  "资产描述": string;
  "攻击损失": string;
  "判断为价值资产的原因": string;
}

export interface NativeThreatHighRiskModule {
  "模块名称": string;
  "代码目录": string | string[];
  "面临威胁": string;
  "是否外部暴露面": string;
  "判断为高风险模块的原因": string;
  [key: string]: unknown;
}

export interface NativeThreatTreeNode {
  node_id: string;
  node_type: string;
  node_name: string;
  description: string;
  module_name: string | null;
  is_high_risk_module: boolean;
  external_exposure: boolean;
  external_interface_description: string | null;
}

export interface NativeThreatAttackPattern {
  pattern_id: string;
  pattern_name: string;
  association_description: string;
}

export interface NativeThreatAttackPath {
  path_id: string;
  path_name: string;
  node_ids: string[];
  edge_ids: string[];
  path_description: string;
  related_high_risk_modules: Array<{
    module_name: string;
    node_id: string;
    external_exposure: boolean;
    path_role: string;
    association_description: string;
  }>;
  attack_patterns: NativeThreatAttackPattern[];
}

export interface NativeThreatAttackTree {
  tree_id: string;
  value_asset: {
    asset_name: string;
    asset_category: string;
    asset_description: string;
    attack_loss: string;
  };
  nodes: NativeThreatTreeNode[];
  edges: Array<{
    edge_id: string;
    source_node_id: string;
    target_node_id: string;
    influence_type: string;
    description: string;
  }>;
  attack_paths: NativeThreatAttackPath[];
}

export interface ThreatAnalysisArtifact<T = unknown> {
  path: string;
  content: T;
}

export interface ThreatAnalysis {
  entrypoint_result: {
    result: boolean;
    value_asset_path?: string;
    attack_tree_path?: string;
    high_risk_modules_path?: string;
    [key: string]: unknown;
  };
  artifacts: Record<string, ThreatAnalysisArtifact | undefined> & {
    value_asset_path?: ThreatAnalysisArtifact<NativeThreatValueAsset[]>;
    high_risk_modules_path?: ThreatAnalysisArtifact<NativeThreatHighRiskModule[]>;
    attack_tree_path?: ThreatAnalysisArtifact<{ attack_trees: NativeThreatAttackTree[] }>;
  };
}

export interface ThreatAuditTask {
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
}

export interface ScanEvent {
  timestamp: string;
  phase: string;
  message: string;
  candidate_index: number | null;
}

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

export interface OpenCodeTokenUsage extends OpenCodeTokenCounters {
  complete: boolean;
  by_model: OpenCodeModelTokenUsage[];
}

export interface OpenCodePoolStatus {
  scope_id: string;
  agent_name?: string;
  agent_session_id?: string;
  global_running: number;
  global_queued: number;
  total_tasks: number;
  completed_task_count: number;
  queued_tasks: Record<string, unknown>[];
  planned_tasks?: Record<string, unknown>[];
  completed_tasks?: Record<string, unknown>[];
  token_usage?: OpenCodeTokenUsage | null;
  models: OpenCodePoolModelStats[];
  updated_at: string;
}

export interface AgentOpenCodePoolStatus extends OpenCodePoolStatus {
  agent_id: string;
  online: boolean;
}

export interface ScanStatus {
  scan_id: string;
  project_id: string;
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
  total_candidates: number;
  processed_candidates: number;
  candidates: ScanCandidate[];
  vulnerabilities: Vulnerability[];
  skill_reports: SkillReport[];
  threat_analysis?: ThreatAnalysis | null;
  threat_audit_tasks?: ThreatAuditTask[];
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

export interface ScanDetailCounts {
  candidates: number;
  vulnerabilities: number;
  effective_issue_count?: number;
  validated_issue_count?: number;
  events: number;
  threat_audit_tasks: number;
  validations: number;
  skill_reports: number;
}

export interface ScanDetailPages {
  candidates_next_cursor: number | null;
  vulnerabilities_next_cursor: number | null;
  events_next_cursor: number | null;
  threat_tasks_next_cursor: string | null;
  validations_next_cursor: number | null;
}

export interface ScanCandidatePage {
  items: ScanCandidate[];
  next_cursor: number | null;
  has_more: boolean;
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

export interface ScanEventPage {
  items: ScanEvent[];
  next_cursor: number | null;
  has_more: boolean;
}

export interface ThreatAuditTaskPage {
  items: ThreatAuditTask[];
  next_cursor: string | null;
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

export interface CodeIndexStats {
  files: number;
  functions: number;
  structs: number;
  global_variables: number;
  function_calls: number;
  global_variable_references: number;
}

export interface IndexStatus {
  status: "not_started" | "parsing" | "done" | "error" | "unknown";
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

export interface ScanSummaryPage {
  items: ScanSummary[];
  next_cursor: string | null;
  has_more: boolean;
}

export interface AgentInfo {
  agent_id: string;
  agent_key: string;
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
  global_concurrency: number;
  models: AgentOpenCodeModelConfig[];
}

export interface AgentModelTaskPolicy {
  required_capability: "low" | "high";
  timeout_seconds: number;
  max_retries: number;
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

export interface MiningEngineRequest {
  engine_id: string;
}

export interface MiningEngineSelection {
  engine_id: string;
  engine_label: string;
  enabled: boolean;
}

export interface MiningEngineRunStatus {
  engine_id: string;
  engine_label: string;
  status: "pending" | "running" | "success" | "error" | "cancelled" | "skipped" | string;
  error_message: string;
  started_at: string;
  finished_at: string;
}

export interface ThreatAnalysisRunStatus {
  status: "pending" | "running" | "success" | "error" | "cancelled" | string;
  error_message: string;
  started_at: string;
  finished_at: string;
}

export interface ThreatAnalysisMethodSelection {
  method_id: string;
  method_label: string;
  description: string;
}

export interface ThreatAnalysisMethodCatalogItem {
  method_id: string;
  label: string;
  description: string;
}

export interface ThreatAnalysisMethodCatalog {
  methods: ThreatAnalysisMethodCatalogItem[];
  errors: string[];
  updated_at: string;
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

export interface AgentRemoteConfig {
  schema_version: 7;
  base: AgentBaseConfig;
  model_pool: AgentModelPoolConfig;
  threat_analysis: AgentThreatAnalysisConfig;
  vulnerability_mining: AgentModelTaskPolicy;
  false_positive: AgentModelTaskPolicy;
  vulnerability_validation: AgentVulnerabilityValidationConfig;
  checker_selection: AgentCheckerSelectionConfig;
}

export type AgentMcpTarget = "product_info";
export type AgentMcpProbeTarget = AgentMcpTarget | "scan_code_graph" | "scan_knowledge_base";

export interface ScanConfigMemory {
  knowledge_base: { project_id?: string; project_name?: string } | null;
  validation_by_product: Record<string, {
    last_method_id?: string;
    values_by_method?: Record<string, Record<string, unknown>>;
  }>;
}
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

// --- Caller-scoped result dashboard ---

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
