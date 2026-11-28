import type { ThreatAuditTaskResult } from "../types/audit";
import type {
  RedlineAuditTask,
  RedlineAuditTaskPage,
  RedlineImportResponse,
  RedlineItem,
  RedlineItemInput,
  RedlineListResponse,
  RedlineSummaryResponse,
} from "../types/redlines";
import { isPublicScan, publicParams, scanV2Path } from "./accessPolicy";
import { SCAN_READ_TIMEOUT_MS, api } from "./transport";

export async function getRedlineSummary(signal?: AbortSignal): Promise<RedlineSummaryResponse> {
  const { data } = await api.get<RedlineSummaryResponse>("/api/redlines/summary", { signal });
  return data;
}

export async function listAdminRedlines(
  params?: { keyword?: string; category?: string; enabled?: boolean },
  signal?: AbortSignal,
): Promise<RedlineListResponse> {
  const query: Record<string, string | boolean> = {};
  if (params?.keyword?.trim()) query.keyword = params.keyword.trim();
  if (params?.category?.trim()) query.category = params.category.trim();
  if (typeof params?.enabled === "boolean") query.enabled = params.enabled;
  const { data } = await api.get<RedlineListResponse>("/api/admin/redlines", { params: query, signal });
  return data;
}

export async function createAdminRedline(body: RedlineItemInput): Promise<RedlineItem> {
  const { data } = await api.post<RedlineItem>("/api/admin/redlines", body);
  return data;
}

export async function updateAdminRedline(
  itemId: string,
  body: Partial<RedlineItemInput>,
): Promise<RedlineItem> {
  const { data } = await api.put<RedlineItem>(`/api/admin/redlines/${encodeURIComponent(itemId)}`, body);
  return data;
}

export async function deleteAdminRedline(itemId: string): Promise<{ ok: boolean; item_id: string }> {
  const { data } = await api.delete<{ ok: boolean; item_id: string }>(
    `/api/admin/redlines/${encodeURIComponent(itemId)}`,
  );
  return data;
}

export async function batchSetAdminRedlinesEnabled(
  itemIds: string[],
  enabled: boolean,
): Promise<{ updated: number; total_count: number; enabled_count: number }> {
  const { data } = await api.post<{ updated: number; total_count: number; enabled_count: number }>(
    "/api/admin/redlines/batch-enabled",
    { item_ids: itemIds, enabled },
  );
  return data;
}

export async function batchDeleteAdminRedlines(
  itemIds: string[],
): Promise<{ deleted: number; total_count: number; enabled_count: number }> {
  const { data } = await api.post<{ deleted: number; total_count: number; enabled_count: number }>(
    "/api/admin/redlines/batch-delete",
    { item_ids: itemIds },
  );
  return data;
}

export async function importAdminRedlinesExcel(
  file: File,
  mode: "upsert" | "replace" = "upsert",
): Promise<RedlineImportResponse> {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("mode", mode);
  const { data } = await api.post<RedlineImportResponse>("/api/admin/redlines/import", formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data;
}

export async function downloadAdminRedlineTemplate(): Promise<Blob> {
  const { data } = await api.get<Blob>("/api/admin/redlines/template", {
    responseType: "blob",
  });
  return data;
}

export async function getScanRedlineAuditTasksPage(
  scanId: string,
  cursor?: string | null,
  signal?: AbortSignal,
  limit = 100,
  redlineItemId?: string,
): Promise<RedlineAuditTaskPage> {
  const { data } = await api.get<RedlineAuditTaskPage>(scanV2Path(scanId, "/redline-audit-tasks"), {
    params: {
      ...(isPublicScan(scanId) ? publicParams() : {}),
      limit,
      ...(cursor ? { cursor } : {}),
      ...(redlineItemId ? { redline_item_id: redlineItemId } : {}),
    },
    signal,
    timeout: SCAN_READ_TIMEOUT_MS,
  });
  return data;
}

export async function getScanRedlineAuditTaskDetail(
  scanId: string,
  taskId: string,
  signal?: AbortSignal,
): Promise<RedlineAuditTask> {
  const { data } = await api.get<RedlineAuditTask>(
    scanV2Path(scanId, `/redline-audit-tasks/${encodeURIComponent(taskId)}`),
    {
      params: isPublicScan(scanId) ? publicParams() : undefined,
      signal,
      timeout: SCAN_READ_TIMEOUT_MS,
    },
  );
  return data;
}

export async function getScanRedlineAuditResults(
  scanId: string,
  taskIds: string[],
  signal?: AbortSignal,
): Promise<ThreatAuditTaskResult[]> {
  if (taskIds.length === 0) return [];
  const { data } = await api.get<ThreatAuditTaskResult[]>(scanV2Path(scanId, "/redline-audit-results"), {
    params: {
      ...(isPublicScan(scanId) ? publicParams() : {}),
      task_ids: taskIds,
    },
    paramsSerializer: { indexes: null },
    signal,
    timeout: SCAN_READ_TIMEOUT_MS,
  });
  return data;
}
