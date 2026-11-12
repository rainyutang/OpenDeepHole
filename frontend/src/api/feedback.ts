import type { FeedbackEntry } from "../types/issues";
import { isPublicScan, publicParams, publicScanAccess, publicScanPath } from "./accessPolicy";
import { api } from "./transport";

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
