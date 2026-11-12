import type { AgentMcpConfig } from "../types/agents";
import type { FpReviewMethod } from "../types/fpReview";
import type { MiningEngineCatalog, MiningEngineRequest } from "../types/mining";
import type {
  HistoryPattern,
  IndexStatus,
  ScanCodeGraphState,
  ScanMetadata,
  ScanMetadataUpdate,
  ScanStartResponse,
  ScanStopResponse,
  ScanSummary,
  ScanSummaryPage,
} from "../types/scans";
import type { ThreatAnalysisMethodCatalog } from "../types/threatAnalysis";
import { isPublicScan, publicParams, publicScanPath } from "./accessPolicy";
import { SCAN_READ_TIMEOUT_MS, api } from "./transport";

export async function getIndexStatus(projectId: string): Promise<IndexStatus> {
  const { data } = await api.get<IndexStatus>(`/api/project/${projectId}/index-status`);
  return data;
}

export async function getAgentIndexStatus(scanId: string, signal?: AbortSignal): Promise<IndexStatus> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<IndexStatus>(
      publicScanPath("/index-status"),
      { params: publicParams(), signal, timeout: SCAN_READ_TIMEOUT_MS },
    );
    return data;
  }
  const { data } = await api.get<IndexStatus>(`/api/agent/scan/${scanId}/index-status`, { signal, timeout: SCAN_READ_TIMEOUT_MS });
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

export interface CreateScanInput {
  agent_key: string;
  project_path: string;
  code_scan_path?: string;
  code_scan_paths?: string[];
  scan_name: string;
  scan_mode?: string;
  threat_analysis_enabled?: boolean;
  threat_analysis_method?: string;
  product: string;
  knowledge_base?: { enabled: boolean; project_id: string; project_name: string };
  vulnerability_validation?: { enabled: boolean; method_id: string; values: Record<string, unknown> };
  checkers?: string[];
  mining_engines?: MiningEngineRequest[];
  feedback_ids?: string[];
  code_graph_mcp?: AgentMcpConfig | null;
  auto_fp_review?: boolean;
  fp_review_method?: FpReviewMethod;
  review_notes_enabled?: boolean;
  review_note_ids?: string[];
  multi_versions?: Array<{
    version_name: string;
    project_path: string;
    code_scan_path?: string;
    code_scan_paths?: string[];
  }>;
}

type ProfileFields = "threat_analysis_enabled" | "threat_analysis_method" | "mining_engines" | "auto_fp_review" | "fp_review_method";

export type ScanCopyConfig = Omit<CreateScanInput, ProfileFields> & {
  [K in ProfileFields]?: CreateScanInput[K] | null;
};

export async function getScanCopyConfig(scanId: string, signal?: AbortSignal): Promise<ScanCopyConfig> {
  const { data } = await api.get<ScanCopyConfig>(`/api/scan/${encodeURIComponent(scanId)}/copy-config`, { signal });
  return data;
}

export async function createScan(body: CreateScanInput): Promise<ScanStartResponse> {
  const { data } = await api.post<ScanStartResponse>("/api/scan", body);
  return data;
}

export async function stopScan(scanId: string): Promise<ScanStopResponse> {
  if (isPublicScan(scanId)) {
    const { data } = await api.post<ScanStopResponse>(
      publicScanPath("/stop"),
      null,
      { params: publicParams() },
    );
    return data;
  }
  const { data } = await api.post<ScanStopResponse>(`/api/scan/${scanId}/stop`);
  return data;
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

export async function updateScanMetadata(scanId: string, body: ScanMetadataUpdate): Promise<ScanMetadata> {
  if (isPublicScan(scanId)) throw new Error("当前访问方式不支持编辑扫描名称");
  const { data } = await api.patch<ScanMetadata>(`/api/scan/${scanId}/metadata`, body);
  return data;
}

export async function updateScanCodeGraph(scanId: string, enabled: boolean): Promise<ScanCodeGraphState> {
  if (isPublicScan(scanId)) throw new Error("当前访问方式不支持编辑 CodeGraph 配置");
  const { data } = await api.put<ScanCodeGraphState>(`/api/scan/${scanId}/code-graph`, { enabled });
  return data;
}

export async function createScanShare(scanId: string): Promise<string> {
  const { data } = await api.post<{ scan_id: string; token: string }>(`/api/scan/${scanId}/share`);
  const url = new URL(window.location.href);
  url.pathname = `/shared-scan/${encodeURIComponent(data.scan_id)}/overview`;
  url.search = new URLSearchParams({ token: data.token }).toString();
  url.hash = "";
  return url.toString();
}

export async function revokeScanShare(scanId: string): Promise<void> {
  await api.delete(`/api/scan/${scanId}/share`);
}

export async function getMiningEngineCatalog(): Promise<MiningEngineCatalog> {
  const { data } = await api.get<MiningEngineCatalog>("/api/mining-engines");
  return data;
}

export async function getThreatAnalysisMethodCatalog(): Promise<ThreatAnalysisMethodCatalog> {
  const { data } = await api.get<ThreatAnalysisMethodCatalog>("/api/threat-analysis-methods");
  return data;
}

export async function getScanGitHistory(scanId: string): Promise<HistoryPattern[]> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<HistoryPattern[]>(
      publicScanPath("/git_history"),
      { params: publicParams(), timeout: SCAN_READ_TIMEOUT_MS },
    );
    return data;
  }
  const { data } = await api.get<HistoryPattern[]>(`/api/scan/${scanId}/git_history`, { timeout: SCAN_READ_TIMEOUT_MS });
  return data;
}
