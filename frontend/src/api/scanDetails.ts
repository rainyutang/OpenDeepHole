import type { ScanCandidatePage } from "../types/audit";
import type { ScanEventPage } from "../types/scans";
import { isRecord } from "../scanRuntime/record";
import { normalizeScanCandidate } from "../scanRuntime/candidates";
import { normalizeScanEvent } from "../scanRuntime/scanSnapshots";
import { isPublicScan, publicParams, scanV2Path } from "./accessPolicy";
import { SCAN_READ_TIMEOUT_MS, api } from "./transport";

export async function getScanTasksPage(scanId: string, cursor?: string | null, taskName?: string, signal?: AbortSignal) {
  const { data } = await api.get<{ items: Record<string, unknown>[]; next_cursor: string | null }>(
    scanV2Path(scanId, "/tasks"), { params: { ...(isPublicScan(scanId) ? publicParams() : {}), cursor, limit: 50, task_name: taskName }, signal, timeout: SCAN_READ_TIMEOUT_MS },
  );
  return data;
}

export async function getScanTaskDetail(scanId: string, task: Record<string, unknown>, signal?: AbortSignal) {
  const { data } = await api.get<Record<string, unknown>>(
    scanV2Path(scanId, `/tasks/${encodeURIComponent(String(task.task_id))}`),
    { params: { ...(isPublicScan(scanId) ? publicParams() : {}), revision: task.revision, record_id: task.record_id }, signal, timeout: SCAN_READ_TIMEOUT_MS },
  );
  return data;
}

export async function getScanCandidatesPage(
  scanId: string,
  after?: number | null,
  signal?: AbortSignal,
): Promise<ScanCandidatePage> {
  const { data } = await api.get<unknown>(scanV2Path(scanId, "/candidates"), {
    params: { ...(isPublicScan(scanId) ? publicParams() : {}), ...(after == null ? {} : { after }) },
    signal, timeout: SCAN_READ_TIMEOUT_MS,
  });
  if (!isRecord(data) || !Array.isArray(data.items)) throw new Error("候选点分页响应无效");
  return {
    items: data.items.map((item, index) => normalizeScanCandidate(item, index)),
    next_cursor: typeof data.next_cursor === "number" ? data.next_cursor : null,
    has_more: data.has_more === true,
  };
}

export async function getScanEventsPage(
  scanId: string,
  before?: number | null,
  signal?: AbortSignal,
): Promise<ScanEventPage> {
  const { data } = await api.get<unknown>(scanV2Path(scanId, "/events"), {
    params: { ...(isPublicScan(scanId) ? publicParams() : {}), ...(before == null ? {} : { before }) },
    signal, timeout: SCAN_READ_TIMEOUT_MS,
  });
  if (!isRecord(data) || !Array.isArray(data.items)) throw new Error("日志分页响应无效");
  return {
    items: data.items.map(normalizeScanEvent).filter((item): item is NonNullable<typeof item> => item !== null),
    next_cursor: typeof data.next_cursor === "number" ? data.next_cursor : null,
    has_more: data.has_more === true,
  };
}

export async function getScanDetailItem(scanId: string, resource: string, index: number, includeBody = true, signal?: AbortSignal) {
  const { data } = await api.get(scanV2Path(scanId, `/details/${resource}/${index}`), {
    params: { ...(isPublicScan(scanId) ? publicParams() : {}), include_body: includeBody },
    signal, timeout: SCAN_READ_TIMEOUT_MS,
  });
  return data;
}
