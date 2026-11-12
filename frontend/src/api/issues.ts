import type { UserFeedbackVerdict, VulnerabilityPage, VulnerabilityValidationPage } from "../types/issues";
import { isRecord } from "../scanRuntime/record";
import { normalizeValidation, normalizeVulnerability } from "../scanRuntime/issues";
import { isPublicScan, publicParams, publicScanPath, scanV2Path } from "./accessPolicy";
import { SCAN_READ_TIMEOUT_MS, api } from "./transport";

export async function getScanVulnerabilitiesPage(
  scanId: string,
  after?: number | null,
  signal?: AbortSignal,
  limit?: number,
): Promise<VulnerabilityPage> {
  const publicScan = isPublicScan(scanId);
  const { data } = await api.get<unknown>(
    publicScan
      ? publicScanPath("/vulnerabilities")
      : `/api/v2/scans/${scanId}/vulnerabilities`,
    {
      params: {
        ...(publicScan ? publicParams() : {}),
        ...(after == null ? {} : { after }),
        ...(limit == null ? {} : { limit }),
      },
      signal, timeout: SCAN_READ_TIMEOUT_MS,
    },
  );
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

export async function getScanValidationsPage(
  scanId: string,
  after?: number | null,
  signal?: AbortSignal,
): Promise<VulnerabilityValidationPage> {
  const { data } = await api.get<unknown>(scanV2Path(scanId, "/validations"), {
    params: { ...(isPublicScan(scanId) ? publicParams() : {}), ...(after == null ? {} : { after }) },
    signal, timeout: SCAN_READ_TIMEOUT_MS,
  });
  if (!isRecord(data) || !Array.isArray(data.items)) throw new Error("漏洞验证分页响应无效");
  return {
    items: data.items.map(normalizeValidation),
    next_cursor: typeof data.next_cursor === "number" ? data.next_cursor : null,
    has_more: data.has_more === true,
  };
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
