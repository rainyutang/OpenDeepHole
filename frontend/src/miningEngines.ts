export const STATIC_CANDIDATE_ENGINE_ID = "static_candidate";
export const STATIC_CANDIDATE_ENGINE_LABEL = "DeepHole基于代码风险点的漏洞挖掘引擎";
export const THREAT_AUDIT_ENGINE_ID = "threat_audit";
export const THREAT_AUDIT_ENGINE_LABEL = "DeepHole基于攻击威胁的漏洞挖掘引擎";
export const THREAT_PATTERN_AUDIT_ENGINE_ID = "threat_pattern_audit";
export const THREAT_PATTERN_AUDIT_ENGINE_LABEL = "DeepHole基于攻击模式的漏洞挖掘引擎";
export const MULTI_VERSION_ENGINE_ID = "multi_version";
export const MULTI_VERSION_ENGINE_LABEL = "DeepHole多版本代码漏洞挖掘引擎";

export const THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS = new Set([
  THREAT_AUDIT_ENGINE_ID,
  THREAT_PATTERN_AUDIT_ENGINE_ID,
]);
export const STATIC_ANALYSIS_ENGINE_IDS = new Set([
  STATIC_CANDIDATE_ENGINE_ID,
  MULTI_VERSION_ENGINE_ID,
]);

const BUILTIN_MINING_ENGINE_LABELS: Record<string, string> = {
  [STATIC_CANDIDATE_ENGINE_ID]: STATIC_CANDIDATE_ENGINE_LABEL,
  [THREAT_AUDIT_ENGINE_ID]: THREAT_AUDIT_ENGINE_LABEL,
  [THREAT_PATTERN_AUDIT_ENGINE_ID]: THREAT_PATTERN_AUDIT_ENGINE_LABEL,
  [MULTI_VERSION_ENGINE_ID]: MULTI_VERSION_ENGINE_LABEL,
};

export function miningEngineRequiresThreatAnalysis(engineId: string): boolean {
  return THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS.has(engineId);
}

export function miningEngineRequiresCodeIndex(engineId: string): boolean {
  return STATIC_ANALYSIS_ENGINE_IDS.has(engineId);
}

export function canonicalMiningEngineLabel(engineId: string, label = ""): string {
  return BUILTIN_MINING_ENGINE_LABELS[engineId] ?? label.trim();
}

export function formatMiningEngineAuditProgress(run: {
  total_candidates?: number | null;
  processed_candidates?: number | null;
} | null | undefined): string | null {
  const rawTotal = run?.total_candidates;
  const rawProcessed = run?.processed_candidates;
  if (
    typeof rawTotal !== "number"
    || !Number.isFinite(rawTotal)
    || typeof rawProcessed !== "number"
    || !Number.isFinite(rawProcessed)
  ) {
    return null;
  }
  const total = Math.max(0, Math.trunc(rawTotal));
  const processed = Math.min(total, Math.max(0, Math.trunc(rawProcessed)));
  return `${processed}/${total} 已审计`;
}

export function threatPatternAuditFlowDetail(run: {
  status?: string;
  error_message?: string;
  started_at?: string;
  total_candidates?: number | null;
  processed_candidates?: number | null;
} | null | undefined, threatAnalysisReady: boolean): string {
  const progress = formatMiningEngineAuditProgress(run);
  if (progress) return progress;
  if (run?.error_message) return run.error_message;
  if (["success", "error", "cancelled", "skipped"].includes(
    String(run?.status || "").toLowerCase(),
  )) {
    return "历史扫描无进度数据";
  }
  if (run?.started_at) return "正在统计审计任务";
  return threatAnalysisReady ? "等待启动" : "等待威胁分析完成";
}
