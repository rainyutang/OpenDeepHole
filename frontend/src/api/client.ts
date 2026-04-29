import axios from "axios";
import type { CheckerInfo, FeedbackEntry, ScanStatus, ScanStartResponse, ScanSummary, UploadResponse } from "../types";

const api = axios.create({ baseURL: "/" });

export async function getCheckers(): Promise<CheckerInfo[]> {
  const { data } = await api.get<CheckerInfo[]>("/api/checkers");
  return data;
}

export async function uploadSource(file: File): Promise<UploadResponse> {
  const form = new FormData();
  form.append("file", file);
  const { data } = await api.post<UploadResponse>("/api/upload", form);
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
