import axios from "axios";
import type { AgentInfo, AgentRemoteConfig, CheckerInfo, FeedbackEntry, FpReviewJob, IndexStatus, ScanStatus, ScanStartResponse, ScanSummary } from "../types";

const api = axios.create({ baseURL: "/" });

export async function getCheckers(): Promise<CheckerInfo[]> {
  const { data } = await api.get<CheckerInfo[]>("/api/checkers");
  return data;
}

export async function getAgents(): Promise<AgentInfo[]> {
  const { data } = await api.get<AgentInfo[]>("/api/agents");
  return data;
}

export async function getIndexStatus(projectId: string): Promise<IndexStatus> {
  const { data } = await api.get<IndexStatus>(`/api/project/${projectId}/index-status`);
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
  agent_id: string;
  project_path: string;
  scan_name: string;
  checkers: string[];
  feedback_ids?: string[];
}): Promise<ScanStartResponse> {
  const { data } = await api.post<ScanStartResponse>("/api/scan", body);
  return data;
}

export async function getScanStatus(scanId: string): Promise<ScanStatus> {
  const { data } = await api.get<ScanStatus>(`/api/scan/${scanId}`);
  return data;
}

export async function stopScan(scanId: string): Promise<void> {
  await api.post(`/api/scan/${scanId}/stop`);
}

export function getReportUrl(scanId: string): string {
  return `/api/scan/${scanId}/report`;
}

export async function markVulnerability(
  scanId: string,
  index: number,
  verdict: string,
  reason: string,
): Promise<{ ok: boolean; feedback_id: string }> {
  const { data } = await api.post(`/api/scan/${scanId}/mark`, { index, verdict, reason });
  return data;
}

export async function batchMarkVulnerabilities(
  scanId: string,
  items: Array<{ index: number; verdict: string; reason: string }>,
): Promise<{ ok: boolean; feedback_ids: string[] }> {
  const { data } = await api.post(`/api/scan/${scanId}/batch-mark`, { items });
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
  source_scan_id?: string;
}): Promise<FeedbackEntry> {
  const { data } = await api.post<FeedbackEntry>("/api/feedback", body);
  return data;
}

export async function updateFeedback(
  feedbackId: string,
  body: { verdict?: string; reason?: string },
): Promise<FeedbackEntry> {
  const { data } = await api.put<FeedbackEntry>(`/api/feedback/${feedbackId}`, body);
  return data;
}

export async function deleteFeedback(feedbackId: string): Promise<void> {
  await api.delete(`/api/feedback/${feedbackId}`);
}

export async function updateScanFeedback(
  scanId: string,
  feedbackIds: string[],
): Promise<void> {
  await api.put(`/api/scan/${scanId}/feedback`, { feedback_ids: feedbackIds });
}

export async function getSkillContent(
  scanId: string,
  vulnType: string,
): Promise<string> {
  const { data } = await api.get<{ vuln_type: string; content: string }>(
    `/api/scan/${scanId}/skill/${vulnType}`,
  );
  return data.content;
}

export async function getScans(): Promise<ScanSummary[]> {
  const { data } = await api.get<ScanSummary[]>("/api/scans");
  return data;
}

export async function resumeScan(scanId: string): Promise<ScanStartResponse> {
  const { data } = await api.post<ScanStartResponse>(`/api/scan/${scanId}/resume`);
  return data;
}

export async function deleteScan(scanId: string): Promise<void> {
  await api.delete(`/api/scan/${scanId}`);
}

// --- Agent config ---

export async function getAgentConfig(agentId: string): Promise<AgentRemoteConfig> {
  const { data } = await api.get<AgentRemoteConfig>(`/api/agent/${agentId}/config`);
  return data;
}

export async function updateAgentConfig(agentId: string, config: AgentRemoteConfig): Promise<void> {
  await api.put(`/api/agent/${agentId}/config`, config);
}

// --- FP Review ---

export async function triggerFpReview(scanId: string): Promise<{ ok: boolean; review_id: string }> {
  const { data } = await api.post(`/api/scan/${scanId}/fp_review`);
  return data;
}

export async function getFpReview(scanId: string): Promise<FpReviewJob> {
  const { data } = await api.get<FpReviewJob>(`/api/scan/${scanId}/fp_review`);
  return data;
}
