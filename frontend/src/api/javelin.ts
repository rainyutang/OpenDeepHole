import { isPublicScan, publicParams, publicScanAccess } from "./accessPolicy";
import { SCAN_READ_TIMEOUT_MS, api } from "./transport";

export interface JavelinCoverageTaskRef {
  task_id: string;
  title: string;
  kind: string;
  domain: string;
  status: string;
}

export interface JavelinCoverageFileItem {
  file_id: string;
  path: string;
  size: number;
  eligible: boolean;
  language: string;
  status: "covered" | "pending" | "uncovered" | "out_of_scope";
  task_count: number;
  finding_count: number;
  tasks: JavelinCoverageTaskRef[];
}

export interface JavelinFileCoverageResponse {
  audit_id: string;
  scan_id: string;
  execution_revision: number;
  baseline_ready: boolean;
  summary: {
    total_files: number;
    eligible_files: number;
    covered_files: number;
    pending_files: number;
    uncovered_files: number;
    coverage_percent: number;
  };
  total: number;
  offset: number;
  limit: number;
  next_offset: number | null;
  items: JavelinCoverageFileItem[];
}

export function javelinScanApiBase(scanId: string): string {
  const encoded = encodeURIComponent(scanId);
  if (isPublicScan(scanId) && publicScanAccess) {
    const kind = publicScanAccess.kind === "shared" ? "shared" : "public";
    return `/api/${kind}/scans/${encoded}/javelin`;
  }
  return `/api/v2/scans/${encoded}/javelin`;
}

export async function controlJavelinScan(
  scanId: string,
  action: "pause" | "resume" | "cancel" | "dispatch" | "recover",
): Promise<{ ok: boolean; action?: string; queued_offline?: boolean; execution_revision?: number }> {
  const { data } = await api.post(`/api/v2/scans/${encodeURIComponent(scanId)}/javelin/actions`, { action });
  return data;
}

export async function getJavelinFileCoverage(
  scanId: string,
  params: { q?: string; status?: string; offset?: number; limit?: number } = {},
  signal?: AbortSignal,
): Promise<JavelinFileCoverageResponse> {
  const base = javelinScanApiBase(scanId);
  const { data } = await api.get<JavelinFileCoverageResponse>(`${base}/file-coverage`, {
    params: { ...(publicParams() || {}), ...params },
    signal,
    timeout: SCAN_READ_TIMEOUT_MS,
  });
  return data;
}

export async function decommissionAgent(agentKey: string): Promise<{ ok: boolean; converged_scan_ids: string[] }> {
  const { data } = await api.post(`/api/agents/${encodeURIComponent(agentKey)}/decommission`);
  return data;
}
