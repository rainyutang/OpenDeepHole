import { isEffectiveFpReviewResult } from "../../../fpReview";
import {
  canonicalMiningEngineLabel,
  isPatternAuditEngine,
  miningEngineRequiresCodeIndex,
  STATIC_CANDIDATE_ENGINE_LABEL,
  STATIC_CANDIDATE_ENGINE_ID as STATIC_ENGINE_ID,
  THREAT_AUDIT_ENGINE_LABEL,
  THREAT_AUDIT_ENGINE_ID as THREAT_ENGINE_ID,
  THREAT_PATTERN_AUDIT_ENGINE_ID as THREAT_PATTERN_ENGINE_ID,
  THREAT_PATTERN_ITERATIVE_ENGINE_ID,
} from "../../../miningEngines";
import type { Candidate, ThreatAuditTask } from "../../../types/audit";
import type { CodeIndexStats, IndexStatus, ScanEvent, ScanStatus as ScanStatusType } from "../../../types/scans";
import type { FpReviewJob, FpReviewMethod, FpReviewMethodSelection } from "../../../types/fpReview";
import type { MiningEngineRunStatus, MiningEngineSelection } from "../../../types/mining";
import type { OpenCodePoolStatus, OpenCodeTokenUsage } from "../../../types/modelPool";
import type { OutputSource, Vulnerability } from "../../../types/issues";
import type { ThreatAnalysis } from "../../../types/threatAnalysis";
import { poolTaskName, poolTaskType } from "../../modelPool/presentation";
import { getThreatAnalysisResultCounts, isThreatAnalysisResultReady } from "../../threatAnalysis/analysisModel";
import type { CheckerDisplayMetadata, FlowNodeStatus } from "./types";

export const MAX_LOG_LINES = 200;

export const STATIC_CANDIDATE_PAGE_SIZE = 20;

export const FP_REVIEW_PAGE_SIZE = 20;

export const SCAN_QUEUE_PAGE_SIZE = 12;

const AGENT_DISCONNECT_ERROR = "Agent 断开连接";

const FINAL_USER_VERDICTS = new Set(["confirmed", "false_positive"]);

const ACTIVE_THREAT_TASK_STATUSES = new Set(["pending", "queued", "running", "analyzing", "auditing"]);

// Read-only compatibility for model-pool snapshots saved before task types were merged.
const LEGACY_VULNERABILITY_MINING_TASK_TYPES = new Set([
  "audit",
  "project_audit",
  "sensitive_clear",
  "report_audit",
  "threat_audit",
]);

export const THREAT_AUDIT_PAGE_SIZE = 20;

export function hasOutputSource(source?: OutputSource | null): boolean {
  return Boolean(source && (source.agent_name || source.agent_id || source.model || source.model_id || source.tool));
}

export function fpReviewMethodLabel(
  method?: FpReviewMethod | null,
  selection?: FpReviewMethodSelection | null,
): string {
  if (selection && selection.method_id === method) return selection.method_label;
  return method || "去误报复核";
}

export function formatOutputSource(source?: OutputSource | null): string {
  if (!hasOutputSource(source)) return "";
  const agent = source?.agent_name || source?.agent_id || "未知 Agent";
  const tool = source?.tool || source?.backend || "AI";
  const model = source?.model
    || (source?.use_default_model ? "CLI 默认模型" : (source?.model_id || "默认模型"));
  const modelId = source?.model_id && source.model_id !== model ? `${source.model_id} / ${model}` : model;
  return `${agent} · ${tool} · ${modelId}`;
}

export function isAgentDisconnectError(message: string | null | undefined): boolean {
  return !!message && message.includes(AGENT_DISCONNECT_ERROR);
}

export function hasFinalUserVerdict(vuln: { user_verdict?: string | null; }): boolean {
  return FINAL_USER_VERDICTS.has(vuln.user_verdict || "");
}

export function percent(current: number, total: number): number {
  if (!total || total <= 0) return 0;
  return Math.max(0, Math.min(100, Math.round((current / total) * 100)));
}

export function taskTokenUsage(task: Record<string, unknown>): OpenCodeTokenUsage | null {
  const value = task.token_usage;
  return value && typeof value === "object" ? value as OpenCodeTokenUsage : null;
}

function scanEventMatches(event: ScanEvent, phases: string[]): boolean {
  return phases.includes(event.phase);
}

export function filterEvents(events: ScanEvent[], phases: string[]): ScanEvent[] {
  return events.filter((event) => scanEventMatches(event, phases));
}

export function hasEvent(events: ScanEvent[], phases: string[]): boolean {
  return events.some((event) => scanEventMatches(event, phases));
}

export function isAiConfirmed(vuln: { ai_verdict?: string; confirmed?: boolean; }): boolean {
  return vuln.ai_verdict === "confirmed" || (!vuln.ai_verdict && !!vuln.confirmed);
}

export {
  vulnerabilityTypeLabel,
  vulnerabilityLocation,
  vulnerabilityFunctionLabel,
} from "../../issues/model";

export function checkerChineseLabel(checker: CheckerDisplayMetadata): string {
  const label = checker.label.trim();
  const localizedParts = label
    .split(/\s*\/\s*/)
    .map((part) => part.trim())
    .filter(Boolean);
  return [...localizedParts].reverse().find((part) => /[\u3400-\u9fff]/.test(part))
    || label
    || checker.name.toUpperCase();
}

export function isStaticCandidateVulnerability(vuln: Vulnerability): boolean {
  return (vuln.analysis_source || "static_candidate") === "static_candidate";
}

export function isStaticCandidate(item: Candidate): boolean {
  return String(item.vuln_type || "").toLowerCase() !== "threat_audit"
    && String(item.metadata?.source || "").toLowerCase() !== "threat_analysis";
}

function finalReviewedIssueIndices(fpReview: FpReviewJob | null): Set<number> {
  const latestResults = new Map(
    (fpReview?.results ?? []).map((result) => [result.vuln_index, result]),
  );
  return new Set(
    [...latestResults.entries()]
      .filter(([, result]) => isEffectiveFpReviewResult(result) && result.verdict === "tp")
      .map(([index]) => index),
  );
}

export function finalReviewedIssueCount(fpReview: FpReviewJob | null): number {
  return fpReview?.result_counts?.tp ?? finalReviewedIssueIndices(fpReview).size;
}

export function isValidationTerminalStatus(status: string): boolean {
  return ["verified", "success", "failed", "error", "timeout", "cancelled", "skipped"].includes(status);
}

export function humanConfirmedIssueCount(scan: ScanStatusType, fpReview: FpReviewJob | null): number {
  if (scan.detail_counts?.human_confirmed_issue_count != null) return scan.detail_counts.human_confirmed_issue_count;
  const issueIndices = finalReviewedIssueIndices(fpReview);
  return scan.vulnerabilities.filter((vuln) => (
    issueIndices.has(vuln.vuln_index) && vuln.user_verdict === "confirmed"
  )).length;
}

export function scanEventKey(item: ScanEvent): string {
  return [
    item.timestamp,
    item.phase,
    item.message,
    item.candidate_index ?? "",
  ].join("\u0000");
}

export function mergeRecentScanEvents(existing: ScanEvent[], incoming: ScanEvent[]): ScanEvent[] {
  if (incoming.length === 0) return existing;
  const keys = new Set(existing.map(scanEventKey));
  const next = [...existing];
  for (const event of incoming) {
    const key = scanEventKey(event);
    if (keys.has(key)) continue;
    keys.add(key);
    next.push(event);
  }
  if (next.length === existing.length) return existing;
  return next.slice(-MAX_LOG_LINES);
}

export function isActiveThreatAuditStatus(status: string | null | undefined): boolean {
  return ACTIVE_THREAT_TASK_STATUSES.has(String(status || "").trim().toLowerCase());
}

function isSupersededThreatAuditStatus(status: string | null | undefined): boolean {
  return String(status || "").trim().toLowerCase() === "superseded";
}

export function currentThreatAuditTasks(tasks: ThreatAuditTask[]): ThreatAuditTask[] {
  return tasks.filter((task) => !isSupersededThreatAuditStatus(task.status));
}

export function effectiveMiningEngines(scan: ScanStatusType): MiningEngineSelection[] {
  const selected = (scan.mining_engines ?? [])
    .filter((item) => item.enabled)
    .map((item) => ({
      ...item,
      engine_label: canonicalMiningEngineLabel(item.engine_id, item.engine_label),
    }));
  if (scan.mining_engines !== undefined) return selected;
  const threat = {
    engine_id: THREAT_ENGINE_ID,
    engine_label: THREAT_AUDIT_ENGINE_LABEL,
    enabled: true,
  };
  if (scan.scan_mode === "threat_analysis_only") return [threat];
  return [
    {
      engine_id: STATIC_ENGINE_ID,
      engine_label: STATIC_CANDIDATE_ENGINE_LABEL,
      enabled: true,
    },
    threat,
  ];
}

export function isThreatAnalysisSelected(scan: ScanStatusType): boolean {
  return scan.threat_analysis_enabled || scan.scan_mode === "threat_analysis_only";
}

export function threatAnalysisMethodLabel(scan: ScanStatusType): string {
  const snapshot = scan.threat_analysis_method_selection;
  if (snapshot?.method_label) return snapshot.method_label;
  if (scan.threat_analysis_method === "deephole_threat_analysis") {
    return "DeepHole威胁分析";
  }
  return scan.threat_analysis_method || "威胁分析";
}

export function threatAnalysisFlowStatus(scan: ScanStatusType): FlowNodeStatus {
  if (!isThreatAnalysisSelected(scan)) return "disabled";
  if (isThreatAnalysisResultReady(scan.threat_analysis)) return "done";
  const status = scan.threat_analysis_run?.status;
  if (status === "running") return "running";
  if (status === "error") return "error";
  if (status === "cancelled") return "cancelled";
  if (status === "skipped") return "skipped";
  if (status === "success") return "done";
  return "pending";
}

export function miningEngineRun(
  scan: ScanStatusType,
  engineId: string,
): MiningEngineRunStatus | null {
  return (scan.mining_engine_runs ?? []).find((item) => item.engine_id === engineId) ?? null;
}

export function engineFlowStatus(run: MiningEngineRunStatus | null): FlowNodeStatus {
  if (!run) return "unknown";
  if (run.status === "running") return "running";
  if (run.status === "success") return run.static_analysis_errors?.length ? "warning" : "done";
  if (run.status === "error") return "error";
  if (run.status === "cancelled") return "cancelled";
  if (run.status === "skipped") return "skipped";
  if (run.status === "pending") return "pending";
  return "unknown";
}

export function threatAuditFlowStatus(
  scan: ScanStatusType,
  run: MiningEngineRunStatus | null,
): FlowNodeStatus {
  const tasks = currentThreatAuditTasks(scan.threat_audit_tasks ?? []);
  const counts = scan.detail_counts;
  const runStatus = engineFlowStatus(run);
  if (scan.status === "cancelled" && runStatus !== "done") return "cancelled";
  const active = counts?.threat_audit_running
    ?? tasks.filter((task) => ["running", "analyzing", "auditing"].includes(
      String(task.status || "").toLowerCase(),
    )).length;
  const pending = counts?.threat_audit_pending ?? 0;
  const queued = counts?.threat_audit_queued
    ?? tasks.filter((task) => String(task.status || "").toLowerCase() === "queued").length;
  if (active > 0) return "running";
  if (queued > 0) return "queued";
  const failed = counts?.threat_audit_failed ?? tasks.filter((task) =>
    ["failed", "failure", "error", "timeout", "no_result"].includes(String(task.status || "").toLowerCase()),
  ).length;
  const cancelled = counts?.threat_audit_cancelled ?? tasks.filter(
    (task) => String(task.status || "").toLowerCase() === "cancelled",
  ).length;
  const completed = counts?.threat_audit_completed
    ?? tasks.filter((task) => task.status === "completed").length;
  const currentTotal = counts?.threat_audit_current ?? tasks.length;
  if (currentTotal > 0 && pending === 0 && completed + failed + cancelled >= currentTotal) {
    if (runStatus === "error") return "error";
    if (cancelled === currentTotal) return "cancelled";
    return failed > 0 || cancelled > 0 ? "warning" : "done";
  }
  if (scan.threat_analysis && runStatus === "running") return "running";
  if (scan.threat_analysis && runStatus === "done") return "done";
  if (scan.threat_analysis && ["error", "cancelled", "skipped"].includes(runStatus)) return runStatus;
  if (scan.threat_analysis && !run && scan.status === "complete") return "done";
  return runStatus === "error" || runStatus === "cancelled" ? runStatus : "pending";
}

function isVulnerabilityMiningPoolTask(task: Record<string, unknown>): boolean {
  const type = poolTaskType(task);
  return type === "vulnerability_mining"
    || LEGACY_VULNERABILITY_MINING_TASK_TYPES.has(type);
}

export function isThreatAuditPoolTask(task: Record<string, unknown>): boolean {
  const type = poolTaskType(task);
  if (type === "threat_audit") return true;
  return type === "vulnerability_mining"
    && poolTaskName(task).startsWith("threat-audit-");
}

export function isThreatPatternAuditPoolTask(task: Record<string, unknown>, engineId?: string): boolean {
  if (poolTaskType(task) !== "vulnerability_mining") return false;
  const actualEngine = String(task.mining_engine_id || "") || (poolTaskName(task).startsWith("threat-pattern-iterative-audit-")
    ? THREAT_PATTERN_ITERATIVE_ENGINE_ID : poolTaskName(task).startsWith("threat-pattern-audit-") ? THREAT_PATTERN_ENGINE_ID : "");
  return isPatternAuditEngine(actualEngine) && (!engineId || actualEngine === engineId);
}

function isVulnerabilityDedupPoolTask(task: Record<string, unknown>): boolean {
  return poolTaskType(task) === "vulnerability_mining"
    && poolTaskName(task).startsWith("vulnerability-dedup-");
}

export function isCandidateAuditPoolTask(task: Record<string, unknown>): boolean {
  return isVulnerabilityMiningPoolTask(task)
    && !isThreatAuditPoolTask(task)
    && !isThreatPatternAuditPoolTask(task)
    && !isVulnerabilityDedupPoolTask(task);
}

function isThreatPoolTask(task: Record<string, unknown>): boolean {
  return poolTaskType(task) === "threat_analysis" || isThreatAuditPoolTask(task);
}

function hasActiveThreatPoolWork(pool: OpenCodePoolStatus | null | undefined): boolean {
  if (!pool) return false;
  if ((pool.planned_tasks ?? []).some(isThreatPoolTask)) return true;
  if ((pool.queued_tasks ?? []).some(isThreatPoolTask)) return true;
  return (pool.models ?? []).some((model) => (model.active_tasks ?? []).some(isThreatPoolTask));
}

export function hasActiveThreatWork(scan: ScanStatusType): boolean {
  return (scan.threat_audit_tasks ?? []).some((task) => isActiveThreatAuditStatus(task.status))
    || hasActiveThreatPoolWork(scan.opencode_pool);
}

export function threatAnalysisSummary(analysis: ThreatAnalysis): string {
  if (!analysis.artifacts || !analysis.entrypoint_result) {
    return "不支持的威胁分析格式";
  }
  const counts = getThreatAnalysisResultCounts(analysis);
  return `${counts.valueAssets} 价值资产 · ${counts.highRiskModules} 高风险模块 · ${counts.internalNodes} 内部节点 · ${counts.attackTrees} 攻击树`;
}

export function currentStageLabel(scan: ScanStatusType, events: ScanEvent[]): string {
  if (scan.status === "error") return "异常中断";
  if (scan.status === "cancelled") return "已取消";
  const runningEngines = effectiveMiningEngines(scan)
    .map((engine) => ({
      engine,
      run: miningEngineRun(scan, engine.engine_id),
    }))
    .filter((item) => item.run?.status === "running");
  if ((scan.threat_audit_tasks ?? []).some((task) => isActiveThreatAuditStatus(task.status))) {
    return `漏洞挖掘 / ${THREAT_AUDIT_ENGINE_LABEL}`;
  }
  if (runningEngines.length > 1) {
    return `漏洞挖掘 / ${runningEngines.length} 个引擎并行`;
  }
  if (runningEngines.length === 1) {
    const running = runningEngines[0];
    if (running.engine.engine_id === THREAT_ENGINE_ID) {
      return `漏洞挖掘 / ${THREAT_AUDIT_ENGINE_LABEL}`;
    }
    return `漏洞挖掘 / ${running.engine.engine_label}`;
  }
  if (scan.threat_analysis_run?.status === "running" && !isThreatAnalysisResultReady(scan.threat_analysis)) {
    return "威胁分析 / 攻击树分析";
  }
  if (scan.status === "complete") return "完成";
  const latest = [...events].reverse().find((event) => event.phase !== "opencode_output");
  if (latest?.phase === "fp_review") {
    return `漏洞挖掘 / ${fpReviewMethodLabel(scan.fp_review_method, scan.fp_review_method_selection)}`;
  }
  if (latest?.phase === "variant_hunt") return "威胁分析 / 历史同类问题挖掘";
  if (latest?.phase === "threat_analysis") return "威胁分析 / 攻击树分析";
  if (latest?.phase === "threat_audit") return `漏洞挖掘 / ${THREAT_AUDIT_ENGINE_LABEL}`;
  if (latest?.phase === "git_history") return "威胁分析 / Git 历史问题分析";
  if (latest?.phase === "auditing") return `漏洞挖掘 / ${STATIC_CANDIDATE_ENGINE_LABEL} / 候选点 AI 审计`;
  if (latest?.phase === "static_analysis") return `漏洞挖掘 / ${STATIC_CANDIDATE_ENGINE_LABEL} / 静态分析`;
  if (latest?.phase === "code_graph_build") return "底层能力 / 代码图谱构建";
  if (latest?.phase === "mcp_ready" || latest?.phase === "init") return "底层能力 / 扫描准备";
  if (scan.status === "auditing") return `漏洞挖掘 / ${STATIC_CANDIDATE_ENGINE_LABEL} / 候选点 AI 审计`;
  if (scan.status === "analyzing") return `漏洞挖掘 / ${STATIC_CANDIDATE_ENGINE_LABEL} / 静态分析`;
  return "等待启动";
}

export function taskStateLabel(done: boolean, running: boolean, failed = false): string {
  if (failed) return "异常";
  if (done) return "完成";
  if (running) return "进行中";
  return "等待";
}

export function formatIndexProgress(indexStatus: IndexStatus | null, scan: ScanStatusType): {
  current: number;
  total: number;
  done: boolean;
  running: boolean;
  failed: boolean;
  skipped: boolean;
  stage: string;
  stageCurrent: number;
  stageTotal: number;
  stats?: CodeIndexStats;
} {
  const status = indexStatus?.status ?? "unknown";
  const skipped = status === "skipped" || !effectiveMiningEngines(scan).some(
    (engine) => miningEngineRequiresCodeIndex(engine.engine_id),
  );
  const statsFiles = indexStatus?.stats?.files ?? 0;
  const total = indexStatus?.total_files || statsFiles || scan.static_total_files || 0;
  let current = indexStatus?.parsed_files ?? scan.static_scanned_files ?? 0;
  const failed = !skipped && status === "error";
  const running = !skipped && status === "parsing";
  const done = !skipped && !running && (
    status === "done"
    || scan.static_analysis_done
    || (indexStatus == null && (scan.static_total_files > 0 || scan.status === "complete"))
  );
  if (done && total > 0 && current === 0) current = total;
  return {
    current,
    total,
    done,
    running,
    failed,
    skipped,
    stage: indexStatus?.stage ?? "",
    stageCurrent: indexStatus?.stage_current ?? 0,
    stageTotal: indexStatus?.stage_total ?? 0,
    stats: indexStatus?.stats,
  };
}
