import axios from "axios";
import type { AgentInfo, AgentMcpConfig, AgentMcpProbeResult, AgentMcpStatusResponse, AgentMcpTarget, AgentOpenCodeModelsResult, AgentOpenCodePoolStatus, AgentRemoteConfig, AgentRuntimeManifest, AgentRuntimeUpdateResponse, AgentValidatorCatalog, Announcement, CheckerCatalogItem, CheckerDashboardResponse, CheckerInfo, FeedbackEntry, FpReviewJob, FpReviewMethod, FpReviewMethodCatalog, HistoryPattern, IndexStatus, MiningEngineCatalog, MiningEngineRequest, ScanCandidatePage, ScanConfigMemory, ScanEventPage, ScanStatus, ScanStartResponse, ScanSummary, ScanSummaryPage, SkillCreateJob, SkillImportFile, SkillReport, ThreatAnalysisMethodCatalog, ThreatAuditTaskPage, TokenResponse, User, UserFeedbackVerdict, VulnerabilityPage, VulnerabilityValidationPage } from "../types";
import {
  isRecord,
  normalizeFpReviewJob,
  normalizeScanCandidate,
  normalizeScanEvent,
  normalizeScanStatus,
  normalizeThreatTask,
  normalizeValidation,
  normalizeVulnerability,
} from "../scanRuntime";

export const api = axios.create({ baseURL: "/" });

let publicScanAccess: { scanId: string; token: string } | null = null;

export function setPublicScanAccess(access: { scanId: string; token: string } | null): void {
  publicScanAccess = access;
}

export function isPublicScan(scanId: string): boolean {
  return !!publicScanAccess && publicScanAccess.scanId === scanId && !!publicScanAccess.token;
}

export function publicParams(): { token: string } | undefined {
  return publicScanAccess ? { token: publicScanAccess.token } : undefined;
}

export function publicScanPath(path: string): string {
  if (!publicScanAccess) return path;
  return `/api/public/scans/${publicScanAccess.scanId}${path}`;
}

// Attach JWT token to all requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("auth_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// On 401, clear token so the UI can redirect to login
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem("auth_token");
      localStorage.removeItem("auth_user");
      window.dispatchEvent(new Event("auth_expired"));
    }
    return Promise.reject(error);
  },
);

// --- Auth ---

export async function login(username: string, password: string): Promise<TokenResponse> {
  const { data } = await api.post<TokenResponse>("/api/auth/login", { username, password });
  localStorage.setItem("auth_token", data.token);
  localStorage.setItem("auth_user", JSON.stringify(data.user));
  return data;
}

export async function register(username: string, password: string): Promise<TokenResponse> {
  const { data } = await api.post<TokenResponse>("/api/auth/register", { username, password });
  localStorage.setItem("auth_token", data.token);
  localStorage.setItem("auth_user", JSON.stringify(data.user));
  return data;
}

export function logout(): void {
  localStorage.removeItem("auth_token");
  localStorage.removeItem("auth_user");
}

export function getStoredUser(): User | null {
  const raw = localStorage.getItem("auth_user");
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export function isAuthenticated(): boolean {
  return !!localStorage.getItem("auth_token");
}

// --- Announcements ---

export async function getAnnouncements(): Promise<Announcement[]> {
  const { data } = await api.get<Announcement[]>("/api/announcements", {
    params: { limit: 3 },
  });
  return data;
}

export async function getAdminAnnouncements(): Promise<Announcement[]> {
  const { data } = await api.get<Announcement[]>("/api/admin/announcements");
  return data;
}

export async function createAnnouncement(
  title: string,
  content: string,
  published: boolean,
): Promise<Announcement> {
  const { data } = await api.post<Announcement>("/api/admin/announcements", {
    title,
    content,
    published,
  });
  return data;
}

export async function updateAnnouncement(
  announcementId: string,
  title: string,
  content: string,
  published: boolean,
): Promise<Announcement> {
  const { data } = await api.put<Announcement>(
    `/api/admin/announcements/${announcementId}`,
    { title, content, published },
  );
  return data;
}

export async function deleteAnnouncement(announcementId: string): Promise<void> {
  await api.delete(`/api/admin/announcements/${announcementId}`);
}

export async function getCurrentUser(): Promise<User> {
  const { data } = await api.get<User>("/api/auth/me");
  return data;
}

export async function changePassword(oldPassword: string, newPassword: string): Promise<void> {
  await api.put("/api/auth/password", { old_password: oldPassword, new_password: newPassword });
}

export async function listUsers(): Promise<User[]> {
  const { data } = await api.get<User[]>("/api/auth/users");
  return data;
}

export async function createUser(username: string, password: string, role: string): Promise<User> {
  const { data } = await api.post<User>("/api/auth/users", { username, password, role });
  return data;
}

export async function deleteUser(userId: string): Promise<void> {
  await api.delete(`/api/auth/users/${userId}`);
}

export async function getCheckers(): Promise<CheckerInfo[]> {
  if (publicScanAccess) {
    const { data } = await api.get<CheckerInfo[]>(
      publicScanPath("/checkers"),
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.get<CheckerInfo[]>("/api/checkers");
  return data;
}

export async function getCheckerCatalog(): Promise<CheckerCatalogItem[]> {
  const { data } = await api.get<CheckerCatalogItem[]>("/api/checkers/catalog");
  return data;
}

export async function createSkill(body: {
  agent_id?: string;
  skill_id: string;
  name: string;
  description: string;
  input: string;
  timeout_seconds: number;
}): Promise<SkillCreateJob> {
  const { data } = await api.post<SkillCreateJob>("/api/skills/create", body);
  return data;
}

export async function deleteSkill(skillId: string): Promise<void> {
  await api.delete(`/api/skills/${skillId}`);
}

export async function getSkillCreateJob(jobId: string): Promise<SkillCreateJob> {
  const { data } = await api.get<SkillCreateJob>(`/api/skills/create/${jobId}`);
  return data;
}

export async function importSkill(jobId: string, body: {
  skill_md: string;
  scenarios_md?: string;
  timeout_seconds: number;
  files?: SkillImportFile[];
}): Promise<{ ok: boolean; name: string }> {
  const { data } = await api.post<{ ok: boolean; name: string }>(
    `/api/skills/create/${jobId}/import`,
    body,
  );
  return data;
}

export async function getSkillReports(
  scanId: string,
  checkerName?: string,
): Promise<SkillReport[]> {
  const params = checkerName ? { checker_name: checkerName } : undefined;
  if (isPublicScan(scanId)) {
    const { data } = await api.get<{ reports: SkillReport[] }>(
      publicScanPath("/skill-reports"),
      { params: { ...publicParams(), ...(params ?? {}) } },
    );
    return data.reports;
  }
  const { data } = await api.get<{ reports: SkillReport[] }>(
    `/api/scan/${scanId}/skill-reports`,
    { params },
  );
  return data.reports;
}

export async function getAgents(): Promise<AgentInfo[]> {
  const { data } = await api.get<AgentInfo[]>("/api/agents");
  return data;
}

export async function getAgentRuntimeManifest(): Promise<AgentRuntimeManifest> {
  const { data } = await api.get<AgentRuntimeManifest>("/api/agent/runtime/manifest");
  return data;
}

export async function requestAgentRuntimeUpdate(
  agentKey: string,
): Promise<AgentRuntimeUpdateResponse> {
  const { data } = await api.post<AgentRuntimeUpdateResponse>(
    `/api/agent-configs/${agentKey}/runtime-update`,
  );
  return data;
}

export async function getIndexStatus(projectId: string): Promise<IndexStatus> {
  const { data } = await api.get<IndexStatus>(`/api/project/${projectId}/index-status`);
  return data;
}

export async function getAgentIndexStatus(scanId: string): Promise<IndexStatus> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<IndexStatus>(
      publicScanPath("/index-status"),
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.get<IndexStatus>(`/api/agent/scan/${scanId}/index-status`);
  return data;
}

export async function startScan(
  projectId: string,
  scanItems: string[],
  feedbackIds: string[] = [],
): Promise<ScanStartResponse> {
  const { data } = await api.post<ScanStartResponse>("/api/scan", {
    project_id: projectId,
    scan_items: scanItems,
    feedback_ids: feedbackIds,
  });
  return data;
}

export async function createScan(body: {
  agent_key: string;
  project_path: string;
  code_scan_path?: string;
  scan_name: string;
  scan_mode?: string;
  threat_analysis_enabled?: boolean;
  threat_analysis_method?: string;
  product?: string;
  knowledge_base?: { enabled: boolean; project_id: string; project_name: string };
  vulnerability_validation?: { enabled: boolean; method_id: string; values: Record<string, unknown> };
  checkers?: string[];
  mining_engines?: MiningEngineRequest[];
  feedback_ids?: string[];
  code_graph_mcp?: AgentMcpConfig | null;
  auto_fp_review?: boolean;
  fp_review_method?: FpReviewMethod;
}): Promise<ScanStartResponse> {
  const { data } = await api.post<ScanStartResponse>("/api/scan", body);
  return data;
}

export async function getScanStatus(scanId: string): Promise<ScanStatus> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<unknown>(
      publicScanPath(""),
      { params: publicParams() },
    );
    const normalized = normalizeScanStatus(data);
    if (!normalized || normalized.scan_id !== scanId) {
      throw new Error("扫描状态响应无效");
    }
    return normalized;
  }
  const [overview, candidates, vulnerabilities, events, threatTasks, validations] = await Promise.all([
    getScanOverview(scanId),
    getScanCandidatesPage(scanId),
    getScanVulnerabilitiesPage(scanId),
    getScanEventsPage(scanId),
    getScanThreatTasksPage(scanId),
    getScanValidationsPage(scanId),
  ]);
  const indexedVulnerabilities = vulnerabilities.items.map((item) => item.vulnerability);
  const normalized = normalizeScanStatus({
    ...overview,
    total_candidates: Math.max(
      overview.total_candidates,
      overview.detail_counts?.candidates ?? 0,
    ),
    candidates: candidates.items,
    vulnerabilities: indexedVulnerabilities,
    events: events.items,
    threat_audit_tasks: threatTasks.items,
    validations: validations.items,
    detail_pages: {
      candidates_next_cursor: candidates.next_cursor,
      vulnerabilities_next_cursor: vulnerabilities.next_cursor,
      events_next_cursor: events.next_cursor,
      threat_tasks_next_cursor: threatTasks.next_cursor,
      validations_next_cursor: validations.next_cursor,
    },
  });
  if (!normalized || normalized.scan_id !== scanId) {
    throw new Error("扫描状态响应无效");
  }
  return normalized;
}

export async function getScanOverview(scanId: string): Promise<ScanStatus> {
  const { data } = await api.get<unknown>(`/api/v2/scans/${scanId}/overview`);
  const normalized = normalizeScanStatus(data);
  if (!normalized || normalized.scan_id !== scanId) {
    throw new Error("扫描概览响应无效");
  }
  return normalized;
}

export async function getScanCandidatesPage(
  scanId: string,
  after?: number | null,
  signal?: AbortSignal,
): Promise<ScanCandidatePage> {
  const { data } = await api.get<unknown>(`/api/v2/scans/${scanId}/candidates`, {
    params: after == null ? undefined : { after },
    signal,
  });
  if (!isRecord(data) || !Array.isArray(data.items)) throw new Error("候选点分页响应无效");
  return {
    items: data.items.map((item, index) => normalizeScanCandidate(item, index)),
    next_cursor: typeof data.next_cursor === "number" ? data.next_cursor : null,
    has_more: data.has_more === true,
  };
}

export async function getScanVulnerabilitiesPage(
  scanId: string,
  after?: number | null,
  signal?: AbortSignal,
): Promise<VulnerabilityPage> {
  const { data } = await api.get<unknown>(`/api/v2/scans/${scanId}/vulnerabilities`, {
    params: after == null ? undefined : { after },
    signal,
  });
  if (!isRecord(data) || !Array.isArray(data.items)) throw new Error("漏洞分页响应无效");
  return {
    items: data.items.flatMap((item) => {
      if (!isRecord(item) || !Number.isInteger(item.index) || Number(item.index) < 0) return [];
      return [{ index: Number(item.index), vulnerability: normalizeVulnerability(item.vulnerability) }];
    }),
    next_cursor: typeof data.next_cursor === "number" ? data.next_cursor : null,
    has_more: data.has_more === true,
  };
}

export async function getScanEventsPage(
  scanId: string,
  before?: number | null,
  signal?: AbortSignal,
): Promise<ScanEventPage> {
  const { data } = await api.get<unknown>(`/api/v2/scans/${scanId}/events`, {
    params: before == null ? undefined : { before },
    signal,
  });
  if (!isRecord(data) || !Array.isArray(data.items)) throw new Error("日志分页响应无效");
  return {
    items: data.items.map(normalizeScanEvent).filter((item): item is NonNullable<typeof item> => item !== null),
    next_cursor: typeof data.next_cursor === "number" ? data.next_cursor : null,
    has_more: data.has_more === true,
  };
}

export async function getScanThreatTasksPage(
  scanId: string,
  cursor?: string | null,
  signal?: AbortSignal,
): Promise<ThreatAuditTaskPage> {
  const { data } = await api.get<unknown>(`/api/v2/scans/${scanId}/threat-audit-tasks`, {
    params: cursor ? { cursor } : undefined,
    signal,
  });
  if (!isRecord(data) || !Array.isArray(data.items)) throw new Error("威胁审计任务分页响应无效");
  return {
    items: data.items.map(normalizeThreatTask),
    next_cursor: typeof data.next_cursor === "string" ? data.next_cursor : null,
    has_more: data.has_more === true,
  };
}

export async function getScanValidationsPage(
  scanId: string,
  after?: number | null,
  signal?: AbortSignal,
): Promise<VulnerabilityValidationPage> {
  const { data } = await api.get<unknown>(`/api/v2/scans/${scanId}/validations`, {
    params: after == null ? undefined : { after },
    signal,
  });
  if (!isRecord(data) || !Array.isArray(data.items)) throw new Error("漏洞验证分页响应无效");
  return {
    items: data.items.map(normalizeValidation),
    next_cursor: typeof data.next_cursor === "number" ? data.next_cursor : null,
    has_more: data.has_more === true,
  };
}

export async function stopScan(scanId: string): Promise<void> {
  if (isPublicScan(scanId)) {
    await api.post(publicScanPath("/stop"), null, { params: publicParams() });
    return;
  }
  await api.post(`/api/scan/${scanId}/stop`);
}

export type ReportValidationState = "unverified" | "running" | "verified";
export type ReportFpReviewState = "no_conclusion" | "tp" | "fp";

export interface ScanReportFilters {
  showAll: boolean;
  severity?: string;
  vulnType?: string;
  engineId?: string;
  validationState?: ReportValidationState;
  fpReviewState?: ReportFpReviewState;
}

function scanReportParams(filters?: ScanReportFilters): Record<string, string | boolean> | undefined {
  if (!filters) return undefined;
  return {
    filtered: true,
    show_all: filters.showAll,
    ...(filters.severity ? { severity: filters.severity } : {}),
    ...(filters.vulnType ? { vuln_type: filters.vulnType } : {}),
    ...(filters.engineId ? { engine_id: filters.engineId } : {}),
    ...(filters.validationState ? { validation_state: filters.validationState } : {}),
    ...(filters.fpReviewState ? { fp_review_state: filters.fpReviewState } : {}),
  };
}

export async function downloadScanReport(scanId: string, filters?: ScanReportFilters): Promise<Blob> {
  const params = scanReportParams(filters);
  if (isPublicScan(scanId)) {
    const { data } = await api.get<Blob>(
      publicScanPath("/report"),
      { params: { ...(publicParams() ?? {}), ...(params ?? {}) }, responseType: "blob" },
    );
    return data;
  }
  const { data } = await api.get<Blob>(`/api/scan/${scanId}/report`, { params, responseType: "blob" });
  return data;
}

export async function downloadVulnerabilityReport(scanId: string, idx: number): Promise<Blob> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<Blob>(
      publicScanPath(`/vulnerability/${idx}/report`),
      { params: publicParams(), responseType: "blob" },
    );
    return data;
  }
  const { data } = await api.get<Blob>(
    `/api/scan/${scanId}/vulnerability/${idx}/report`,
    { responseType: "blob" },
  );
  return data;
}

export async function triggerVulnerabilityValidation(scanId: string, idx: number): Promise<{ ok: boolean; vuln_index: number }> {
  if (isPublicScan(scanId)) {
    const { data } = await api.post<{ ok: boolean; vuln_index: number }>(
      publicScanPath(`/vulnerability/${idx}/validation`),
      null,
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.post<{ ok: boolean; vuln_index: number }>(
    `/api/scan/${scanId}/vulnerability/${idx}/validation`,
  );
  return data;
}

export async function stopVulnerabilityValidation(scanId: string, idx: number): Promise<{ ok: boolean; vuln_index: number; status: string }> {
  if (isPublicScan(scanId)) {
    const { data } = await api.post<{ ok: boolean; vuln_index: number; status: string }>(
      publicScanPath(`/vulnerability/${idx}/validation/stop`),
      null,
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.post<{ ok: boolean; vuln_index: number; status: string }>(
    `/api/scan/${scanId}/vulnerability/${idx}/validation/stop`,
  );
  return data;
}

export async function downloadScanReportZip(scanId: string): Promise<Blob> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<Blob>(
      publicScanPath("/report.zip"),
      { params: publicParams(), responseType: "blob" },
    );
    return data;
  }
  const { data } = await api.get<Blob>(`/api/scan/${scanId}/report.zip`, { responseType: "blob" });
  return data;
}

export async function markVulnerability(
  scanId: string,
  index: number,
  verdict: UserFeedbackVerdict,
  reason: string,
  ticketSubmitted = false,
  ticketId = "",
): Promise<{ ok: boolean; feedback_id: string | null; removed_feedback_ids: string[] }> {
  if (isPublicScan(scanId)) {
    const { data } = await api.post(
      publicScanPath("/mark"),
      {
        index,
        verdict,
        reason,
        ticket_submitted: ticketSubmitted,
        ticket_id: ticketSubmitted ? ticketId : "",
      },
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.post(`/api/scan/${scanId}/mark`, {
    index,
    verdict,
    reason,
    ticket_submitted: ticketSubmitted,
    ticket_id: ticketSubmitted ? ticketId : "",
  });
  return data;
}

export async function unmarkVulnerability(
  scanId: string,
  index: number,
): Promise<{ ok: boolean; removed_feedback_ids: string[] }> {
  if (isPublicScan(scanId)) {
    const { data } = await api.post(
      publicScanPath("/unmark"),
      { index },
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.post(`/api/scan/${scanId}/unmark`, { index });
  return data;
}

export async function batchMarkVulnerabilities(
  scanId: string,
  items: Array<{ index: number; verdict: UserFeedbackVerdict; reason: string }>,
): Promise<{ ok: boolean; feedback_ids: string[]; removed_feedback_ids: string[] }> {
  if (isPublicScan(scanId)) {
    const { data } = await api.post(
      publicScanPath("/batch-mark"),
      { items },
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.post(`/api/scan/${scanId}/batch-mark`, { items });
  return data;
}

export async function batchUnmarkVulnerabilities(
  scanId: string,
  indices: number[],
): Promise<{ ok: boolean; removed_feedback_ids: string[] }> {
  if (isPublicScan(scanId)) {
    const { data } = await api.post(
      publicScanPath("/batch-unmark"),
      { indices },
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.post(`/api/scan/${scanId}/batch-unmark`, { indices });
  return data;
}

export async function saveFalsePositive(
  scanId: string,
  index: number,
): Promise<void> {
  await api.post(`/api/scan/${scanId}/save-fp`, { index });
}

// --- Feedback CRUD ---

export async function listFeedback(
  vulnType?: string,
  projectId?: string,
): Promise<FeedbackEntry[]> {
  const params: Record<string, string> = {};
  if (vulnType) params.vuln_type = vulnType;
  if (projectId) params.project_id = projectId;
  if (publicScanAccess) {
    params.token = publicScanAccess.token;
    const { data } = await api.get<FeedbackEntry[]>(
      publicScanPath("/feedback"),
      { params },
    );
    return data;
  }
  const { data } = await api.get<FeedbackEntry[]>("/api/feedback", { params });
  return data;
}

export async function createFeedback(body: {
  project_id: string;
  vuln_type: string;
  verdict: string;
  file: string;
  line: number;
  function: string;
  description: string;
  reason?: string;
  ticket_submitted?: boolean;
  ticket_id?: string;
  function_source?: string;
  function_start_line?: number | null;
  source_scan_id?: string;
}): Promise<FeedbackEntry> {
  if (publicScanAccess) {
    const { data } = await api.post<FeedbackEntry>(
      publicScanPath("/feedback"),
      body,
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.post<FeedbackEntry>("/api/feedback", body);
  return data;
}

export async function updateFeedback(
  feedbackId: string,
  body: { verdict?: string; reason?: string; ticket_submitted?: boolean; ticket_id?: string },
): Promise<FeedbackEntry> {
  if (publicScanAccess) {
    const { data } = await api.put<FeedbackEntry>(
      publicScanPath(`/feedback/${feedbackId}`),
      body,
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.put<FeedbackEntry>(`/api/feedback/${feedbackId}`, body);
  return data;
}

export async function deleteFeedback(feedbackId: string): Promise<void> {
  if (publicScanAccess) {
    await api.delete(publicScanPath(`/feedback/${feedbackId}`), { params: publicParams() });
    return;
  }
  await api.delete(`/api/feedback/${feedbackId}`);
}

export async function updateScanFeedback(
  scanId: string,
  feedbackIds: string[],
): Promise<void> {
  if (isPublicScan(scanId)) {
    await api.put(
      publicScanPath("/feedback"),
      { feedback_ids: feedbackIds },
      { params: publicParams() },
    );
    return;
  }
  await api.put(`/api/scan/${scanId}/feedback`, { feedback_ids: feedbackIds });
}

export async function getSkillContent(
  scanId: string,
  vulnType: string,
): Promise<string> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<{ vuln_type: string; content: string }>(
      publicScanPath(`/skill/${vulnType}`),
      { params: publicParams() },
    );
    return data.content;
  }
  const { data } = await api.get<{ vuln_type: string; content: string }>(
    `/api/scan/${scanId}/skill/${vulnType}`,
  );
  return data.content;
}

export async function getScans(): Promise<ScanSummary[]> {
  const { data } = await api.get<ScanSummary[]>("/api/scans");
  return data;
}

export async function getScansPage(
  limit = 50,
  cursor?: string | null,
): Promise<ScanSummaryPage> {
  const { data } = await api.get<ScanSummaryPage>("/api/v2/scans", {
    params: { limit, ...(cursor ? { cursor } : {}) },
  });
  return data;
}

export async function resumeScan(scanId: string): Promise<ScanStartResponse> {
  const { data } = await api.post<ScanStartResponse>(`/api/scan/${scanId}/resume`);
  return data;
}

export async function deleteScan(scanId: string): Promise<void> {
  await api.delete(`/api/scan/${scanId}`);
}

export async function getCheckerDashboard(product?: string): Promise<CheckerDashboardResponse> {
  const params = product ? { product } : undefined;
  const { data } = await api.get<CheckerDashboardResponse>("/api/checker-dashboard", { params });
  return data;
}

// --- Agent config ---

export async function getAgentConfig(agentKey: string): Promise<AgentRemoteConfig> {
  const { data } = await api.get<AgentRemoteConfig>(`/api/agent-configs/${agentKey}`);
  return data;
}

export async function getAgentOpenCodePool(agentId: string): Promise<AgentOpenCodePoolStatus> {
  const { data } = await api.get<AgentOpenCodePoolStatus>(`/api/agent/${agentId}/opencode-pool`);
  return data;
}

export async function getAgentOpenCodeModels(agentId: string, refresh = false): Promise<AgentOpenCodeModelsResult> {
  const { data } = await api.get<AgentOpenCodeModelsResult>(
    `/api/agent/${agentId}/opencode/models`,
    { params: { refresh } },
  );
  return data;
}

export async function updateAgentConfig(agentKey: string, config: AgentRemoteConfig): Promise<void> {
  await api.put(`/api/agent-configs/${agentKey}`, config);
}

export async function getAgentMcpStatus(agentKey: string): Promise<AgentMcpStatusResponse> {
  const { data } = await api.get<AgentMcpStatusResponse>(
    `/api/agent-configs/${agentKey}/mcp-status`,
  );
  return data;
}

export async function probeAgentMcp(agentKey: string, target: AgentMcpTarget): Promise<AgentMcpProbeResult> {
  const { data } = await api.post<AgentMcpProbeResult>(
    `/api/agent-configs/${agentKey}/mcp-probe/${target}`,
  );
  return data;
}

export async function probeScanCodeGraphMcp(
  agentKey: string,
  config: AgentMcpConfig,
): Promise<AgentMcpProbeResult> {
  const { data } = await api.post<AgentMcpProbeResult>(
    `/api/agent-configs/${agentKey}/mcp-probe/scan_code_graph`,
    config,
  );
  return data;
}

export async function probeScanKnowledgeBaseMcp(
  agentKey: string,
): Promise<AgentMcpProbeResult> {
  const { data } = await api.post<AgentMcpProbeResult>(
    `/api/agent-configs/${agentKey}/mcp-probe/scan_knowledge_base`,
  );
  return data;
}

export async function getScanConfigMemory(agentKey: string): Promise<ScanConfigMemory> {
  const { data } = await api.get<ScanConfigMemory>(
    `/api/scan/config-memory/${encodeURIComponent(agentKey)}`,
  );
  return data;
}

export async function reloadAgentMcp(agentKey: string, target: AgentMcpTarget): Promise<void> {
  await api.post(`/api/agent-configs/${agentKey}/mcp-reload/${target}`);
}

export async function getAgentValidatorCatalog(agentKey: string, product = ""): Promise<AgentValidatorCatalog> {
  const { data } = await api.get<AgentValidatorCatalog>(
    `/api/agent-configs/${agentKey}/validator-catalog`,
    { params: product ? { product } : undefined },
  );
  return data;
}

export async function getMiningEngineCatalog(): Promise<MiningEngineCatalog> {
  const { data } = await api.get<MiningEngineCatalog>("/api/mining-engines");
  return data;
}

export async function getThreatAnalysisMethodCatalog(): Promise<ThreatAnalysisMethodCatalog> {
  const { data } = await api.get<ThreatAnalysisMethodCatalog>("/api/threat-analysis-methods");
  return data;
}

export async function getFpReviewMethodCatalog(): Promise<FpReviewMethodCatalog> {
  const { data } = await api.get<FpReviewMethodCatalog>("/api/fp-review-methods");
  return data;
}

// --- FP Review ---

export function scanSSEUrl(scanId: string): string {
  const base = window.location.origin;
  if (isPublicScan(scanId) && publicScanAccess) {
    return `${base}/api/public/scans/${scanId}/events?token=${encodeURIComponent(publicScanAccess.token)}`;
  }
  const token = localStorage.getItem("auth_token") || "";
  return `${base}/api/scan/${scanId}/events?token=${encodeURIComponent(token)}`;
}

export async function triggerFpReview(scanId: string): Promise<{
  ok: boolean;
  review_id: string;
  status?: FpReviewJob["status"];
  total?: number;
  processed?: number;
  method?: FpReviewJob["method"];
}> {
  if (isPublicScan(scanId)) {
    const { data } = await api.post(publicScanPath("/fp_review"), null, { params: publicParams() });
    return data;
  }
  const { data } = await api.post(`/api/scan/${scanId}/fp_review`);
  return data;
}

export async function stopFpReview(scanId: string): Promise<{ ok: boolean; review_id: string }> {
  if (isPublicScan(scanId)) {
    const { data } = await api.post(publicScanPath("/fp_review/stop"), null, { params: publicParams() });
    return data;
  }
  const { data } = await api.post(`/api/scan/${scanId}/fp_review/stop`);
  return data;
}

export async function getFpReview(scanId: string): Promise<FpReviewJob> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<unknown>(
      publicScanPath("/fp_review"),
      { params: publicParams() },
    );
    const normalized = normalizeFpReviewJob(data);
    if (!normalized || normalized.scan_id !== scanId) throw new Error("去误报状态响应无效");
    return normalized;
  }
  const { data } = await api.get<unknown>(`/api/scan/${scanId}/fp_review`);
  const normalized = normalizeFpReviewJob(data);
  if (!normalized || normalized.scan_id !== scanId) throw new Error("去误报状态响应无效");
  return normalized;
}

export async function getScanGitHistory(scanId: string): Promise<HistoryPattern[]> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<HistoryPattern[]>(
      publicScanPath("/git_history"),
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.get<HistoryPattern[]>(`/api/scan/${scanId}/git_history`);
  return data;
}

export async function getFpReviewSkill(scanId: string): Promise<string> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<{ content: string }>(
      publicScanPath("/fp-review/skill"),
      { params: publicParams() },
    );
    return data.content;
  }
  const { data } = await api.get<{ content: string }>(`/api/scan/${scanId}/fp-review/skill`);
  return data.content;
}
