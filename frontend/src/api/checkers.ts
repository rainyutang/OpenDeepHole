import type { CheckerCatalogItem, CheckerInfo, SkillCreateJob, SkillImportFile, SkillReport } from "../types/checkers";
import type { CheckerDashboardResponse, CheckerScanDashboardStats } from "../types/dashboard";
import { isPublicScan, publicParams, publicScanAccess, publicScanPath } from "./accessPolicy";
import { api } from "./transport";

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

export async function getCheckerDashboard(product?: string): Promise<CheckerDashboardResponse> {
  const params = product ? { product } : undefined;
  const { data } = await api.get<CheckerDashboardResponse>("/api/v2/checker-dashboard", { params });
  return data;
}

export async function getCheckerScansPage(checker: string, product?: string, cursor?: string | null) {
  const { data } = await api.get<{ items: CheckerScanDashboardStats[]; next_cursor: string | null }>(
    `/api/v2/checker-dashboard/${encodeURIComponent(checker)}/scans`, { params: { product, cursor, limit: 50 } },
  );
  return data;
}
