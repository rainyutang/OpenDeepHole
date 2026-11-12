import axios from "axios";
import type { FpReviewJob, FpReviewMethodCatalog } from "../types/fpReview";
import type { IndexedVulnerability } from "../types/issues";
import { normalizeFpReviewJob } from "../scanRuntime/audit";
import { normalizeVulnerability } from "../scanRuntime/issues";
import { isPublicScan, publicParams, publicScanPath, scanV2Path } from "./accessPolicy";
import { isMissingOptionalResult } from "./errors";
import { getScanDetailItem } from "./scanDetails";
import { SCAN_READ_TIMEOUT_MS, api } from "./transport";

export async function getFpReviewMethodCatalog(): Promise<FpReviewMethodCatalog> {
  const { data } = await api.get<FpReviewMethodCatalog>("/api/fp-review-methods");
  return data;
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

export async function getFpReviewOverview(scanId: string, signal?: AbortSignal): Promise<FpReviewJob | null> {
  const { data } = await api.get(scanV2Path(scanId, "/fp-review/overview"), {
    params: { ...(isPublicScan(scanId) ? publicParams() : {}), allow_missing: true },
    signal, timeout: SCAN_READ_TIMEOUT_MS,
  }).catch((error) => {
    if (isMissingOptionalResult(error, ["No FP review found", "No FP review found for this scan"])) return { data: null };
    throw error;
  });
  if (data === null) return null;
  const job = normalizeFpReviewJob(data);
  if (!job || job.scan_id !== scanId) throw new Error("去误报状态响应无效");
  return job;
}

export async function getScanFpReviewResult(scanId: string, index: number, signal?: AbortSignal) {
  if (!Number.isInteger(index) || index < 0) throw new Error("问题索引无效");
  const data = await getScanDetailItem(scanId, "fp-review", index, true, signal).catch((error) => {
    if (axios.isAxiosError(error) && error.response?.status === 404) throw new Error("未找到对应的去误报记录");
    throw error;
  });
  if (!data || data.vuln_index !== index || !["tp", "fp", "uncertain"].includes(data.verdict)) {
    throw new Error("去误报详情响应无效");
  }
  return normalizeFpReviewJob({ review_id: "", scan_id: scanId, results: [data] })!.results[0];
}

export async function getFpReviewResultsPage(scanId: string, after = -1, limit = 50, signal?: AbortSignal) {
  const { data } = await api.get(scanV2Path(scanId, "/fp-review/results"), {
    params: { ...(isPublicScan(scanId) ? publicParams() : {}), after, limit },
    signal, timeout: SCAN_READ_TIMEOUT_MS,
  });
  const normalized = normalizeFpReviewJob({ review_id: "", scan_id: scanId, results: data.items });
  return {
    items: normalized?.results ?? [],
    vulnerabilities: (data.vulnerabilities ?? []).map((v: unknown) => normalizeVulnerability(v)) as IndexedVulnerability[],
    next_cursor: data.next_cursor as number | null,
    has_more: Boolean(data.has_more),
  };
}

export async function getFpReview(scanId: string): Promise<FpReviewJob | null> {
  const job = await getFpReviewOverview(scanId);
  if (!job) return null;
  const page = await getFpReviewResultsPage(scanId);
  return { ...job, results: page.items, next_cursor: page.next_cursor, result_vulnerabilities: page.vulnerabilities };
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
