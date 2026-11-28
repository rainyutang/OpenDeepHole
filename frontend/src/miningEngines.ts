export const STATIC_CANDIDATE_ENGINE_ID = "static_candidate";
export const STATIC_CANDIDATE_ENGINE_LABEL = "DeepHole基于代码风险点的漏洞挖掘引擎";
export const THREAT_AUDIT_ENGINE_ID = "threat_audit";
export const THREAT_AUDIT_ENGINE_LABEL = "DeepHole基于攻击威胁的漏洞挖掘引擎";
export const THREAT_PATTERN_AUDIT_ENGINE_ID = "threat_pattern_audit";
export const THREAT_PATTERN_AUDIT_ENGINE_LABEL = "DeepHole基于攻击模式的漏洞挖掘引擎";
export const THREAT_PATTERN_ITERATIVE_ENGINE_ID = "threat_pattern_iterative_audit";
export const THREAT_PATTERN_ITERATIVE_ENGINE_LABEL = "DeepHole基于攻击模式的迭代漏洞挖掘引擎";
export function isPatternAuditEngine(engineId: string): boolean {
  return engineId === THREAT_PATTERN_AUDIT_ENGINE_ID || engineId === THREAT_PATTERN_ITERATIVE_ENGINE_ID;
}

export const STANDARD_DEFAULT_MINING_ENGINE_IDS = new Set([
  STATIC_CANDIDATE_ENGINE_ID,
  THREAT_PATTERN_ITERATIVE_ENGINE_ID,
]);

export function miningEngineSelectedByDefault(engineId: string): boolean {
  return STANDARD_DEFAULT_MINING_ENGINE_IDS.has(engineId);
}
export const MULTI_VERSION_ENGINE_ID = "multi_version";
export const MULTI_VERSION_ENGINE_LABEL = "DeepHole多版本代码漏洞挖掘引擎";
export const REDLINE_AUDIT_ENGINE_ID = "redline_audit";
export const REDLINE_AUDIT_ENGINE_LABEL = "DeepHole网络安全红线排查引擎";

export function isRedlineAuditEngine(engineId: string): boolean {
  return engineId === REDLINE_AUDIT_ENGINE_ID;
}

export const THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS = new Set([
  THREAT_AUDIT_ENGINE_ID,
  THREAT_PATTERN_AUDIT_ENGINE_ID,
  THREAT_PATTERN_ITERATIVE_ENGINE_ID,
]);
export const STATIC_ANALYSIS_ENGINE_IDS = new Set([
  STATIC_CANDIDATE_ENGINE_ID,
  MULTI_VERSION_ENGINE_ID,
]);

const BUILTIN_MINING_ENGINE_LABELS: Record<string, string> = {
  [STATIC_CANDIDATE_ENGINE_ID]: STATIC_CANDIDATE_ENGINE_LABEL,
  [THREAT_AUDIT_ENGINE_ID]: THREAT_AUDIT_ENGINE_LABEL,
  [THREAT_PATTERN_AUDIT_ENGINE_ID]: THREAT_PATTERN_AUDIT_ENGINE_LABEL,
  [THREAT_PATTERN_ITERATIVE_ENGINE_ID]: THREAT_PATTERN_ITERATIVE_ENGINE_LABEL,
  [MULTI_VERSION_ENGINE_ID]: MULTI_VERSION_ENGINE_LABEL,
  [REDLINE_AUDIT_ENGINE_ID]: REDLINE_AUDIT_ENGINE_LABEL,
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

export interface PatternAuditEngineCounts {
  tasks?: number;
  current: number;
  completed: number;
  failed?: number;
  cancelled?: number;
  pending?: number;
  queued?: number;
  running?: number;
  superseded?: number;
}

export function formatPatternAuditTaskProgress(
  counts: PatternAuditEngineCounts | null | undefined,
): string | null {
  if (!counts) return null;
  const rawTasks = counts.tasks ?? counts.current;
  if (typeof rawTasks !== "number" || !Number.isFinite(rawTasks) || rawTasks <= 0) {
    return null;
  }
  const total = Math.max(0, Math.trunc(counts.current));
  const completed = Math.min(total, Math.max(0, Math.trunc(counts.completed)));
  const failed = Math.max(0, Math.trunc(counts.failed ?? 0));
  return failed > 0
    ? `${completed}/${total} 已审计 · ${failed} 未成功`
    : `${completed}/${total} 已审计`;
}

export function threatPatternAuditFlowDetail(run: {
  status?: string;
  error_message?: string;
  started_at?: string;
  total_candidates?: number | null;
  processed_candidates?: number | null;
} | null | undefined, threatAnalysisReady: boolean, taskCounts?: PatternAuditEngineCounts | null): string {
  const taskProgress = formatPatternAuditTaskProgress(taskCounts);
  if (taskProgress) return taskProgress;
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

export function redlineAuditFlowDetail(
  run: {
    status?: string;
    error_message?: string;
    started_at?: string;
    total_candidates?: number | null;
    processed_candidates?: number | null;
  } | null | undefined,
  counts?: {
    redline_audit_items_total?: number;
    redline_audit_items_completed?: number;
    redline_audit_items_failed?: number;
    redline_audit_findings?: number;
  } | null,
  snapshotItemCount = 0,
): string {
  const total = Math.max(0, Math.trunc(counts?.redline_audit_items_total ?? snapshotItemCount ?? 0));
  if (total > 0) {
    const completed = Math.min(total, Math.max(0, Math.trunc(counts?.redline_audit_items_completed ?? 0)));
    const failed = Math.max(0, Math.trunc(counts?.redline_audit_items_failed ?? 0));
    const findings = Math.max(0, Math.trunc(counts?.redline_audit_findings ?? 0));
    const parts = [`${completed}/${total} 红线完成`];
    if (findings > 0) parts.push(`${findings} 问题`);
    if (failed > 0) parts.push(`${failed} 失败`);
    return parts.join(" · ");
  }
  const progress = formatMiningEngineAuditProgress(run);
  if (progress) return progress;
  if (run?.error_message) return run.error_message;
  if (run?.started_at) return "正在排查网络安全红线";
  return "等待启动";
}
