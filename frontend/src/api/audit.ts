import type {
  CandidateAuditTaskResult,
  ThreatAuditTaskPage,
  ThreatAuditTaskResult,
  ThreatPatternAuditTask,
  ThreatPatternAuditTaskPage,
  VulnerabilityAuditSource,
} from "../types/audit";
import { isRecord } from "../scanRuntime/record";
import { normalizePatternTask, normalizeThreatTask } from "../scanRuntime/audit";
import { normalizeScanCandidate } from "../scanRuntime/candidates";
import { isPublicScan, publicParams, publicScanPath, scanV2Path } from "./accessPolicy";
import { SCAN_READ_TIMEOUT_MS, api } from "./transport";

export async function getScanThreatAuditResults(scanId: string, taskIds: string[], signal?: AbortSignal) {
  return getAuditTaskResults(scanId, taskIds, "threat-audit", signal);
}

export async function getScanThreatPatternAuditResults(scanId: string, taskIds: string[], signal?: AbortSignal) {
  return getAuditTaskResults(scanId, taskIds, "threat-pattern-audit", signal);
}

async function getAuditTaskResults(
  scanId: string,
  taskIds: string[],
  kind: "threat-audit" | "threat-pattern-audit",
  signal?: AbortSignal,
): Promise<ThreatAuditTaskResult[]> {
  const ids = [...new Set(taskIds)];
  if (ids.length === 0) return [];
  if (ids.length > 100) throw new Error("每次最多读取 100 个审计任务结果");
  const params = new URLSearchParams();
  ids.forEach((id) => params.append("task_ids", id));
  const publicAccess = isPublicScan(scanId);
  if (publicAccess) params.set("token", publicParams()!.token);
  const { data } = await api.get<ThreatAuditTaskResult[]>(
    publicAccess
      ? publicScanPath(`/${kind}-results`)
      : `/api/v2/scans/${scanId}/${kind}-results`,
    { params, signal, timeout: SCAN_READ_TIMEOUT_MS },
  );
  if (!Array.isArray(data) || data.length !== ids.length || data.some((item) => (
    !isRecord(item) || !ids.includes(item.task_id) || !validAuditResult(item)
  )) || new Set(data.map((item) => item.task_id)).size !== ids.length) {
    throw new Error("审计结果响应无效");
  }
  return data;
}

export async function getScanCandidateAuditResults(
  scanId: string,
  candidateIndexes: number[],
  signal?: AbortSignal,
): Promise<CandidateAuditTaskResult[]> {
  const indexes = [...new Set(candidateIndexes)];
  if (indexes.length === 0) return [];
  if (indexes.length > 100 || indexes.some((index) => !Number.isInteger(index) || index < 0)) {
    throw new Error("每次最多读取 100 个有效候选点索引");
  }
  const params = new URLSearchParams();
  indexes.forEach((index) => params.append("candidate_indexes", String(index)));
  const publicAccess = isPublicScan(scanId);
  if (publicAccess) params.set("token", publicParams()!.token);
  const { data } = await api.get<CandidateAuditTaskResult[]>(
    publicAccess ? publicScanPath("/candidate-audit-results") : `/api/v2/scans/${scanId}/candidate-audit-results`,
    { params, signal, timeout: SCAN_READ_TIMEOUT_MS },
  );
  if (!Array.isArray(data) || data.length !== indexes.length || data.some((item) => (
    !isRecord(item) || !indexes.includes(item.candidate_index)
    || !validAuditResult(item)
  )) || new Set(data.map((item) => item.candidate_index)).size !== indexes.length) {
    throw new Error("候选点审计结果响应无效");
  }
  return data;
}

function validAuditResult(item: Record<string, unknown>): boolean {
  return Array.isArray(item.findings)
    && Number.isInteger(item.confirmed_issue_count) && Number(item.confirmed_issue_count) >= 0
    && typeof item.association_complete === "boolean"
    && item.findings.every((finding) => (
      isRecord(finding) && Number.isInteger(finding.vuln_index) && Number(finding.vuln_index) >= 0
      && typeof finding.description === "string"
      && ["confirmed", "false_positive", "unreviewed", "not_confirmed"].includes(String(finding.verdict))
      && ["human", "fp_review", "audit"].includes(String(finding.verdict_source))
    ));
}

export async function getScanVulnerabilityAuditSource(
  scanId: string,
  index: number,
  signal?: AbortSignal,
): Promise<VulnerabilityAuditSource> {
  if (!Number.isInteger(index) || index < 0) throw new Error("问题索引无效");
  const publicAccess = isPublicScan(scanId);
  const suffix = `/vulnerabilities/${index}/audit-source`;
  const { data } = await api.get<VulnerabilityAuditSource>(
    publicAccess ? publicScanPath(suffix) : `/api/v2/scans/${scanId}${suffix}`,
    { params: publicAccess ? publicParams() : undefined, signal, timeout: SCAN_READ_TIMEOUT_MS },
  );
  if (!isRecord(data) || data.vuln_index !== index
    || !["resolved", "missing", "ambiguous", "unsupported"].includes(data.status)
    || ![null, "threat_audit", "threat_pattern_audit", "static_candidate"].includes(data.kind)
    || (data.status === "resolved" && (
      (data.kind === "threat_audit" && (!isRecord(data.threat_task)
        || !data.threat_task.task_id || data.threat_task.scan_id !== scanId))
      || (data.kind === "threat_pattern_audit" && (!isRecord(data.pattern_task)
        || !data.pattern_task.task_id || data.pattern_task.scan_id !== scanId))
      || (data.kind === "static_candidate" && (!isRecord(data.candidate)
        || !Number.isInteger(data.candidate.idx) || data.candidate.idx < 0))
      || data.kind === null
    ))) {
    throw new Error("审计来源响应无效");
  }
  return {
    ...data,
    threat_task: data.threat_task ? normalizeThreatTask(data.threat_task) : null,
    pattern_task: data.pattern_task ? normalizePatternTask(data.pattern_task) : null,
    candidate: data.candidate ? normalizeScanCandidate(data.candidate, data.candidate.idx) : null,
  };
}

export async function getScanThreatTasksPage(
  scanId: string,
  cursor?: string | null,
  signal?: AbortSignal,
): Promise<ThreatAuditTaskPage> {
  const { data } = await api.get<unknown>(scanV2Path(scanId, "/threat-audit-tasks"), {
    params: { ...(isPublicScan(scanId) ? publicParams() : {}), ...(cursor ? { cursor } : {}) },
    signal, timeout: SCAN_READ_TIMEOUT_MS,
  });
  if (!isRecord(data) || !Array.isArray(data.items)) throw new Error("威胁审计任务分页响应无效");
  return {
    items: data.items.map(normalizeThreatTask),
    next_cursor: typeof data.next_cursor === "string" ? data.next_cursor : null,
    has_more: data.has_more === true,
  };
}

export async function getScanPatternTasksPage(
  scanId: string,
  cursor?: string | null,
  signal?: AbortSignal,
  engineId?: string,
): Promise<ThreatPatternAuditTaskPage> {
  const { data } = await api.get<unknown>(scanV2Path(scanId, "/threat-pattern-audit-tasks"), {
    params: { ...(isPublicScan(scanId) ? publicParams() : {}), ...(cursor ? { cursor } : {}),
      ...(engineId ? { engine_id: engineId, summary: true } : {}) },
    signal, timeout: SCAN_READ_TIMEOUT_MS,
  });
  if (!isRecord(data) || !Array.isArray(data.items)) throw new Error("攻击模式审计任务分页响应无效");
  return {
    items: data.items.map(normalizePatternTask),
    next_cursor: typeof data.next_cursor === "string" ? data.next_cursor : null,
    has_more: data.has_more === true,
  };
}

export async function getScanPatternTaskDetail(scanId: string, taskId: string, signal?: AbortSignal): Promise<ThreatPatternAuditTask> {
  const { data } = await api.get<unknown>(scanV2Path(scanId, `/threat-pattern-audit-tasks/${encodeURIComponent(taskId)}`), {
    params: isPublicScan(scanId) ? publicParams() : undefined,
    signal, timeout: SCAN_READ_TIMEOUT_MS,
  });
  if (!isRecord(data) || data.task_id !== taskId || data.scan_id !== scanId) throw new Error("攻击模式审计详情响应无效");
  return normalizePatternTask(data);
}
