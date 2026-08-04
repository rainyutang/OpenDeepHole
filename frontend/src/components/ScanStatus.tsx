import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { getScanStatus, getScanCandidatesPage, getScanEventsPage, getScanThreatTasksPage, getScanValidationsPage, getScanVulnerabilitiesPage, stopScan, resumeScan, downloadScanReportZip, getCheckers, updateScanFeedback, getSkillContent, triggerFpReview, stopFpReview, getFpReview, getFpReviewSkill, getScanGitHistory, getSkillReports, getAgentIndexStatus, triggerVulnerabilityValidation, stopVulnerabilityValidation } from "../api/client";
import { getScanThreatAnalysis, ThreatAnalysisPanel } from "../features/threatAnalysis";
import type { Candidate, CodeIndexStats, FpReviewJob, FpReviewMethod, FpReviewMethodSelection, FpReviewStageConfig, HistoryPattern, IndexStatus, ScanItemStatus, ScanStatus as ScanStatusType, ScanEvent, CheckerInfo, SkillReport, OpenCodePoolStatus, OpenCodeTokenUsage, ScanCandidate, Vulnerability, OutputSource, ThreatAnalysis, ThreatAuditTask, VulnerabilityValidation, MiningEngineRunStatus, MiningEngineSelection } from "../types";
import { useScanSSE } from "../hooks/useScanSSE";
import type { ScanSSEHandlers, SSEStateSetters } from "../hooks/useScanSSE";
import { isEffectiveFpReviewResult, isFpReviewNonProblem } from "../fpReview";
import VulnerabilityList from "./VulnerabilityList";
import FeedbackManager from "./FeedbackManager";
import { ThemeToggle } from "./ThemeToggle";

const MAX_LOG_LINES = 200;
const STATIC_CANDIDATE_PAGE_SIZE = 20;
const SCAN_QUEUE_PAGE_SIZE = 12;
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
const STATIC_ENGINE_ID = "static_candidate";
const THREAT_ENGINE_ID = "threat_audit";
const THREAT_AUDIT_PAGE_SIZE = 20;

type MainTab = "overview" | "index" | "static" | "threat" | "mining" | "validation" | "fp_review" | "issues";
type TaskTone = "slate" | "cyan" | "amber" | "green" | "red" | "purple" | "blue";
type ScanQueueTaskStatus = "planned" | "queued" | "running" | "success" | "failure" | "timeout" | "cancelled" | "unknown";
type FlowNodeId = "index" | "static" | "threat" | "fp_review" | "validation" | `engine:${string}`;
type FlowNodeStatus = "pending" | "running" | "done" | "warning" | "error" | "cancelled" | "skipped" | "unknown";

interface ScanQueueTask {
  id: string;
  status: ScanQueueTaskStatus;
  modelId: string;
  scopeId: string;
  task: Record<string, unknown>;
  timestamp: string;
}

function hasOutputSource(source?: OutputSource | null): boolean {
  return Boolean(source && (source.agent_name || source.agent_id || source.model || source.model_id || source.tool));
}

function fpReviewMethodLabel(
  method?: FpReviewMethod | null,
  selection?: FpReviewMethodSelection | null,
): string {
  if (selection && selection.method_id === method) return selection.method_label;
  return method || "去误报复核";
}

function formatOutputSource(source?: OutputSource | null): string {
  if (!hasOutputSource(source)) return "";
  const agent = source?.agent_name || source?.agent_id || "未知 Agent";
  const tool = source?.tool || source?.backend || "AI";
  const model = source?.model
    || (source?.use_default_model ? "CLI 默认模型" : (source?.model_id || "默认模型"));
  const modelId = source?.model_id && source.model_id !== model ? `${source.model_id} / ${model}` : model;
  return `${agent} · ${tool} · ${modelId}`;
}

function isAgentDisconnectError(message: string | null | undefined): boolean {
  return !!message && message.includes(AGENT_DISCONNECT_ERROR);
}

function hasFinalUserVerdict(vuln: { user_verdict?: string | null }): boolean {
  return FINAL_USER_VERDICTS.has(vuln.user_verdict || "");
}

function percent(current: number, total: number): number {
  if (!total || total <= 0) return 0;
  return Math.max(0, Math.min(100, Math.round((current / total) * 100)));
}

function formatTokenCount(value: number): string {
  return new Intl.NumberFormat("zh-CN").format(value || 0);
}

function taskTokenUsage(task: Record<string, unknown>): OpenCodeTokenUsage | null {
  const value = task.token_usage;
  return value && typeof value === "object" ? value as OpenCodeTokenUsage : null;
}

function scanEventMatches(event: ScanEvent, phases: string[]): boolean {
  return phases.includes(event.phase);
}

function filterEvents(events: ScanEvent[], phases: string[]): ScanEvent[] {
  return events.filter((event) => scanEventMatches(event, phases));
}

function hasEvent(events: ScanEvent[], phases: string[]): boolean {
  return events.some((event) => scanEventMatches(event, phases));
}

function isAiConfirmed(vuln: { ai_verdict?: string; confirmed?: boolean }): boolean {
  return vuln.ai_verdict === "confirmed" || (!vuln.ai_verdict && !!vuln.confirmed);
}

function vulnerabilityTypeLabel(vuln: Vulnerability): string {
  return vuln.vuln_type?.trim() || "未知类型";
}

function vulnerabilityLocation(vuln: Vulnerability, short = false): string {
  const file = vuln.file?.trim();
  const fileLabel = file
    ? (short ? file.split("/").pop() || file : file)
    : "未知文件";
  return `${fileLabel}:${vuln.line > 0 ? vuln.line : "未知行号"}`;
}

function vulnerabilityFunctionLabel(vuln: Vulnerability): string {
  return vuln.function?.trim() || "未知函数";
}

function isStaticCandidateVulnerability(vuln: Vulnerability): boolean {
  return (vuln.analysis_source || "static_candidate") === "static_candidate";
}

function isStaticCandidate(item: Candidate): boolean {
  return item.vuln_type.toLowerCase() !== "threat_audit"
    && String(item.metadata?.source || "").toLowerCase() !== "threat_analysis";
}

function effectiveIssueCount(scan: ScanStatusType, fpReview: FpReviewJob | null): number {
  const fpMap = new Map(
    (fpReview?.results ?? [])
      .filter(isEffectiveFpReviewResult)
      .map((result) => [result.vuln_index, result]),
  );
  return scan.vulnerabilities.filter((vuln, index) => {
    if (!isAiConfirmed(vuln)) return false;
    if (isFpReviewNonProblem(fpMap.get(index))) return false;
    return true;
  }).length;
}

function issueItems(scan: ScanStatusType, fpReview: FpReviewJob | null): { vuln: Vulnerability; index: number }[] {
  const fpMap = new Map(
    (fpReview?.results ?? [])
      .filter(isEffectiveFpReviewResult)
      .map((result) => [result.vuln_index, result]),
  );
  return scan.vulnerabilities
    .map((vuln, index) => ({ vuln, index }))
    .filter(({ vuln, index }) => isAiConfirmed(vuln) && !isFpReviewNonProblem(fpMap.get(index)));
}

function isValidationTerminalStatus(status: string): boolean {
  return ["verified", "success", "failed", "error", "timeout", "cancelled", "skipped"].includes(status);
}

function validatedIssueCount(scan: ScanStatusType, fpReview: FpReviewJob | null): number {
  const validationMap = new Map((scan.validations ?? []).map((item) => [item.vuln_index, item]));
  return issueItems(scan, fpReview).filter(({ index }) => {
    const validation = validationMap.get(index);
    return Boolean(validation && !validation.running && isValidationTerminalStatus(validation.status));
  }).length;
}

function candidateKey(item: Pick<Candidate, "file" | "line" | "function" | "vuln_type">): string {
  return `${item.file}\u0000${item.line}\u0000${item.function}\u0000${item.vuln_type}`;
}

function isActiveThreatAuditStatus(status: string | null | undefined): boolean {
  return ACTIVE_THREAT_TASK_STATUSES.has(String(status || "").trim().toLowerCase());
}

function effectiveMiningEngines(scan: ScanStatusType): MiningEngineSelection[] {
  const selected = (scan.mining_engines ?? []).filter((item) => item.enabled);
  if (scan.mining_engines !== undefined) return selected;
  const threat = {
    engine_id: THREAT_ENGINE_ID,
    engine_label: "威胁审计",
    enabled: true,
  };
  if (scan.scan_mode === "threat_analysis_only") return [threat];
  return [
    {
      engine_id: STATIC_ENGINE_ID,
      engine_label: "静态规则扫描 + 候选点审计",
      enabled: true,
    },
    threat,
  ];
}

function isThreatAnalysisSelected(scan: ScanStatusType): boolean {
  return scan.threat_analysis_enabled || scan.scan_mode === "threat_analysis_only";
}

function threatAnalysisFlowStatus(scan: ScanStatusType): FlowNodeStatus {
  if (!isThreatAnalysisSelected(scan)) return "skipped";
  if (scan.threat_analysis) return "done";
  const status = scan.threat_analysis_run?.status;
  if (status === "running") return "running";
  if (status === "success") return "done";
  if (status === "error") return "error";
  if (status === "cancelled") return "cancelled";
  if (status === "skipped") return "skipped";
  return "pending";
}

function miningEngineRun(
  scan: ScanStatusType,
  engineId: string,
): MiningEngineRunStatus | null {
  return (scan.mining_engine_runs ?? []).find((item) => item.engine_id === engineId) ?? null;
}

function engineFlowStatus(run: MiningEngineRunStatus | null): FlowNodeStatus {
  if (!run) return "unknown";
  if (run.status === "running") return "running";
  if (run.status === "success") return "done";
  if (run.status === "error") return "error";
  if (run.status === "cancelled") return "cancelled";
  if (run.status === "skipped") return "skipped";
  if (run.status === "pending") return "pending";
  return "unknown";
}

function terminalThreatTaskStatus(status: string): boolean {
  return ["completed", "failed", "failure", "error", "timeout", "no_result", "cancelled"].includes(
    String(status || "").trim().toLowerCase(),
  );
}

function threatAuditFlowStatus(
  scan: ScanStatusType,
  run: MiningEngineRunStatus | null,
): FlowNodeStatus {
  const tasks = scan.threat_audit_tasks ?? [];
  if (tasks.some((task) => isActiveThreatAuditStatus(task.status))) return "running";
  const runStatus = engineFlowStatus(run);
  const failed = tasks.filter((task) =>
    ["failed", "failure", "error", "timeout", "no_result"].includes(String(task.status || "").toLowerCase()),
  ).length;
  const cancelled = tasks.filter(
    (task) => String(task.status || "").toLowerCase() === "cancelled",
  ).length;
  if (tasks.length > 0 && tasks.every((task) => terminalThreatTaskStatus(task.status))) {
    if (runStatus === "error") return "error";
    if (cancelled === tasks.length) return "cancelled";
    return failed > 0 || cancelled > 0 ? "warning" : "done";
  }
  if (scan.threat_analysis && runStatus === "running") return "running";
  if (scan.threat_analysis && runStatus === "done") return "done";
  if (scan.threat_analysis && ["error", "cancelled", "skipped"].includes(runStatus)) return runStatus;
  if (scan.threat_analysis && !run && scan.status === "complete") return "done";
  return runStatus === "error" || runStatus === "cancelled" ? runStatus : "pending";
}

function poolTaskType(task: Record<string, unknown>): string {
  const direct = String(task.task_type || "").trim();
  if (direct) return direct.toLowerCase();
  const context = task.context;
  if (context && typeof context === "object") {
    return String((context as Record<string, unknown>).task_type || "").trim().toLowerCase();
  }
  return "";
}

function poolTaskName(task: Record<string, unknown>): string {
  const direct = String(task.task_name || "").trim();
  if (direct) return direct.toLowerCase();
  const context = task.context;
  if (context && typeof context === "object") {
    return String((context as Record<string, unknown>).task_name || "").trim().toLowerCase();
  }
  return "";
}

function isVulnerabilityMiningPoolTask(task: Record<string, unknown>): boolean {
  const type = poolTaskType(task);
  return type === "vulnerability_mining"
    || LEGACY_VULNERABILITY_MINING_TASK_TYPES.has(type);
}

function isThreatAuditPoolTask(task: Record<string, unknown>): boolean {
  const type = poolTaskType(task);
  if (type === "threat_audit") return true;
  return type === "vulnerability_mining"
    && poolTaskName(task).startsWith("threat-audit-");
}

function isCandidateAuditPoolTask(task: Record<string, unknown>): boolean {
  return isVulnerabilityMiningPoolTask(task) && !isThreatAuditPoolTask(task);
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

function hasActiveThreatWork(scan: ScanStatusType): boolean {
  return (scan.threat_audit_tasks ?? []).some((task) => isActiveThreatAuditStatus(task.status))
    || hasActiveThreatPoolWork(scan.opencode_pool);
}

function threatAnalysisSummary(analysis: ThreatAnalysis): string {
  if (!analysis.artifacts || !analysis.entrypoint_result) {
    return "不支持的威胁分析格式";
  }
  const assets = analysis.artifacts.value_asset_path?.content;
  const treeDocument = analysis.artifacts.attack_tree_path?.content;
  const trees = (
    treeDocument
    && typeof treeDocument === "object"
    && Array.isArray((treeDocument as { attack_trees?: unknown }).attack_trees)
  )
    ? (treeDocument as { attack_trees: unknown[] }).attack_trees
    : [];
  return `${Array.isArray(assets) ? assets.length : 0} 资产 · ${trees.length} 攻击树`;
}

function currentStageLabel(scan: ScanStatusType, events: ScanEvent[]): string {
  if (scan.status === "error") return "异常中断";
  if (scan.status === "cancelled") return "已取消";
  const runningEngines = effectiveMiningEngines(scan)
    .map((engine) => ({
      engine,
      run: miningEngineRun(scan, engine.engine_id),
    }))
    .filter((item) => item.run?.status === "running");
  if ((scan.threat_audit_tasks ?? []).some((task) => isActiveThreatAuditStatus(task.status))) {
    return "漏洞挖掘 / 威胁审计";
  }
  if (runningEngines.length > 1) {
    return `漏洞挖掘 / ${runningEngines.length} 个引擎并行`;
  }
  if (runningEngines.length === 1) {
    const running = runningEngines[0];
    if (running.engine.engine_id === THREAT_ENGINE_ID) {
      return "漏洞挖掘 / 威胁审计";
    }
    return `漏洞挖掘 / ${running.engine.engine_label}`;
  }
  if (scan.threat_analysis_run?.status === "running") return "威胁分析 / 攻击树分析";
  if (scan.status === "complete") return "完成";
  const latest = [...events].reverse().find((event) => event.phase !== "opencode_output");
  if (latest?.phase === "fp_review") {
    return `漏洞挖掘 / ${fpReviewMethodLabel(scan.fp_review_method, scan.fp_review_method_selection)}`;
  }
  if (latest?.phase === "variant_hunt") return "威胁分析 / 历史同类问题挖掘";
  if (latest?.phase === "threat_analysis") return "威胁分析 / 攻击树分析";
  if (latest?.phase === "threat_audit") return "漏洞挖掘 / 威胁审计";
  if (latest?.phase === "git_history") return "威胁分析 / Git 历史问题分析";
  if (latest?.phase === "auditing") return "漏洞挖掘 / 候选点 AI 审计";
  if (latest?.phase === "static_analysis") return "静态分析 / 规则扫描";
  if (latest?.phase === "code_graph_build") return "底层能力 / 代码图谱构建";
  if (latest?.phase === "mcp_ready" || latest?.phase === "init") return "底层能力 / 扫描准备";
  if (scan.status === "auditing") return "漏洞挖掘 / 候选点 AI 审计";
  if (scan.status === "analyzing") return "静态分析 / 规则扫描";
  return "等待启动";
}

function taskStateLabel(done: boolean, running: boolean, failed = false): string {
  if (failed) return "异常";
  if (done) return "完成";
  if (running) return "进行中";
  return "等待";
}

function formatIndexProgress(indexStatus: IndexStatus | null, scan: ScanStatusType): {
  current: number;
  total: number;
  done: boolean;
  running: boolean;
  failed: boolean;
  stage: string;
  stageCurrent: number;
  stageTotal: number;
  stats?: CodeIndexStats;
} {
  const status = indexStatus?.status ?? "unknown";
  const statsFiles = indexStatus?.stats?.files ?? 0;
  const total = indexStatus?.total_files || statsFiles || scan.static_total_files || 0;
  let current = indexStatus?.parsed_files ?? scan.static_scanned_files ?? 0;
  const failed = status === "error";
  const running = status === "parsing";
  const done = !running && (
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
    stage: indexStatus?.stage ?? "",
    stageCurrent: indexStatus?.stage_current ?? 0,
    stageTotal: indexStatus?.stage_total ?? 0,
    stats: indexStatus?.stats,
  };
}

interface Props {
  scanId: string;
  onBack: () => void;
}

export default function ScanStatus({ scanId, onBack }: Props) {
  const [scan, setScan] = useState<ScanStatusType | null>(null);
  const [activeTab, setActiveTab] = useState<MainTab>("overview");
  const [activeEngineId, setActiveEngineId] = useState("");
  const [stopping, setStopping] = useState(false);
  const [continuing, setContinuing] = useState(false);
  const [exportingZip, setExportingZip] = useState(false);
  const [logOpen, setLogOpen] = useState(false);
  const [modelPoolOpen, setModelPoolOpen] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [lastSeenEvents, setLastSeenEvents] = useState(0);
  const logRef = useRef<HTMLDivElement>(null);

  // Feedback panel state
  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const [checkers, setCheckers] = useState<CheckerInfo[]>([]);
  const [selectedFeedbackIds, setSelectedFeedbackIds] = useState<Set<string> | null>(null);

  // SKILL preview state
  const [skillOpen, setSkillOpen] = useState(false);
  const [skillType, setSkillType] = useState<string | null>(null);
  const [skillContent, setSkillContent] = useState("");
  const [skillLoading, setSkillLoading] = useState(false);

  // Markdown reports generated by user-created SKILLs
  const [reportsOpen, setReportsOpen] = useState(false);
  const [reports, setReports] = useState<SkillReport[]>([]);
  const [reportsLoading, setReportsLoading] = useState(false);
  const [activeReportIndex, setActiveReportIndex] = useState(0);

  // FP review state
  const [fpReview, setFpReview] = useState<FpReviewJob | null>(null);
  const [fpReviewLoading, setFpReviewLoading] = useState(false);
  const [fpReviewStopping, setFpReviewStopping] = useState(false);
  const [launchingValidations, setLaunchingValidations] = useState<Set<number>>(new Set());
  const [stoppingValidations, setStoppingValidations] = useState<Set<number>>(new Set());

  // Code indexing progress
  const [indexStatus, setIndexStatus] = useState<IndexStatus | null>(null);

  // Git history mined patterns
  const [gitHistory, setGitHistory] = useState<HistoryPattern[]>([]);
  const [threatAnalysisLoading, setThreatAnalysisLoading] = useState(false);

  const completeButThreatActive = Boolean(scan && scan.status === "complete" && hasActiveThreatWork(scan));
  const isRunning = scan && (
    scan.status === "pending"
    || scan.status === "analyzing"
    || scan.status === "auditing"
    || completeButThreatActive
  );
  const isDone = scan && (
    scan.status === "error"
    || scan.status === "cancelled"
    || (scan.status === "complete" && !completeButThreatActive)
  );

  useEffect(() => {
    getCheckers().then(setCheckers).catch(() => {});
  }, []);

  // Initial full-state hydration on mount
  useEffect(() => {
    getScanStatus(scanId)
      .then((data) => {
        setScan(data);
        if (selectedFeedbackIds === null && data.feedback_ids) {
          setSelectedFeedbackIds(new Set(data.feedback_ids));
        }
      })
      .catch(() => {});
    getFpReview(scanId)
      .then(setFpReview)
      .catch(() => {});
    getAgentIndexStatus(scanId)
      .then(setIndexStatus)
      .catch(() => {});
    getScanGitHistory(scanId)
      .then(setGitHistory)
      .catch(() => {});
    setThreatAnalysisLoading(true);
    getScanThreatAnalysis(scanId)
      .then((analysis) => {
        setScan((prev) => prev ? { ...prev, threat_analysis: analysis } : prev);
      })
      .catch(() => {})
      .finally(() => setThreatAnalysisLoading(false));
  }, [scanId]);

  // SSE event handlers — update state incrementally
  const sseHandlers = useMemo<ScanSSEHandlers>(() => ({
    onScanStatus: (data) => {
      setScan((prev) => {
        if (!prev) return prev;
        const patch: Partial<ScanStatusType> = {};
        if (data.status != null) patch.status = data.status as ScanItemStatus;
        if (data.progress != null) patch.progress = data.progress;
        if (data.total_candidates != null) patch.total_candidates = data.total_candidates;
        if (data.processed_candidates != null) patch.processed_candidates = data.processed_candidates;
        if (data.static_total_files != null) patch.static_total_files = data.static_total_files;
        if (data.static_scanned_files != null) patch.static_scanned_files = data.static_scanned_files;
        if (data.static_analysis_done != null) patch.static_analysis_done = data.static_analysis_done;
        if (data.opencode_pool !== undefined) patch.opencode_pool = data.opencode_pool;
        return { ...prev, ...patch };
      });
    },
    onScanCandidates: (data) => {
      setScan((prev) => prev ? { ...prev, candidates: data.candidates, total_candidates: data.candidates.length } : prev);
    },
    onScanCandidatesChanged: (data) => {
      if (!data.final) return;
      getScanCandidatesPage(scanId)
        .then((page) => {
          setScan((prev) => prev ? {
            ...prev,
            candidates: page.items,
            total_candidates: data.total_candidates,
            detail_pages: {
              candidates_next_cursor: page.next_cursor,
              vulnerabilities_next_cursor: prev.detail_pages?.vulnerabilities_next_cursor ?? null,
              events_next_cursor: prev.detail_pages?.events_next_cursor ?? null,
              threat_tasks_next_cursor: prev.detail_pages?.threat_tasks_next_cursor ?? null,
              validations_next_cursor: prev.detail_pages?.validations_next_cursor ?? null,
            },
          } : prev);
        })
        .catch(() => {});
    },
    onScanVulnerability: (data) => {
      setScan((prev) => {
        if (!prev) return prev;
        const vulns = [...prev.vulnerabilities];
        vulns[data.index] = data.vulnerability;
        return { ...prev, vulnerabilities: vulns };
      });
    },
    onVulnerabilityValidation: (data) => {
      setLaunchingValidations((prev) => {
        if (!prev.has(data.validation.vuln_index)) return prev;
        const next = new Set(prev);
        next.delete(data.validation.vuln_index);
        return next;
      });
      setStoppingValidations((prev) => {
        if (!prev.has(data.validation.vuln_index)) return prev;
        const next = new Set(prev);
        next.delete(data.validation.vuln_index);
        return next;
      });
      setScan((prev) => {
        if (!prev) return prev;
        const validations = [...(prev.validations ?? [])];
        const existingIndex = validations.findIndex((item) => item.vuln_index === data.validation.vuln_index);
        if (existingIndex >= 0) {
          validations[existingIndex] = data.validation;
        } else {
          validations.push(data.validation);
          validations.sort((a, b) => a.vuln_index - b.vuln_index);
        }
        return { ...prev, validations };
      });
    },
    onThreatAnalysis: (data) => {
      setThreatAnalysisLoading(false);
      setScan((prev) => prev ? { ...prev, threat_analysis: data.analysis } : prev);
    },
    onThreatAnalysisRun: (data) => {
      if (["success", "error", "cancelled"].includes(data.run.status)) {
        setThreatAnalysisLoading(false);
      }
      setScan((prev) => prev ? { ...prev, threat_analysis_run: data.run } : prev);
    },
    onThreatAuditTask: (data) => {
      setScan((prev) => {
        if (!prev) return prev;
        const tasks = [...(prev.threat_audit_tasks ?? [])];
        const existing = tasks.findIndex((task) => task.task_id === data.task.task_id);
        if (existing >= 0) {
          tasks[existing] = data.task;
        } else {
          tasks.push(data.task);
        }
        tasks.sort((a, b) => String(a.created_at || "").localeCompare(String(b.created_at || "")) || a.task_id.localeCompare(b.task_id));
        return { ...prev, threat_audit_tasks: tasks };
      });
    },
    onMiningEngineRun: (data) => {
      setScan((prev) => prev ? {
        ...prev,
        mining_engine_runs: data.runs,
      } : prev);
    },
    onScanEvent: (data) => {
      setScan((prev) => {
        if (!prev) return prev;
        const events = [...prev.events, data.event].slice(-MAX_LOG_LINES);
        return { ...prev, events };
      });
    },
    onScanFinish: (data) => {
      setScan((prev) =>
        prev ? { ...prev, status: data.status as ScanItemStatus, error_message: data.error_message } : prev,
      );
    },
    onFpReviewStarted: (data) => {
      setFpReview((prev) => ({
        review_id: data.review_id,
        scan_id: scanId,
        method: data.method ?? prev?.method ?? "adversarial",
        status: data.status,
        total: data.total,
        processed: data.processed ?? 0,
        current_vuln_index: null,
        current_vuln_indices: [],
        results: prev?.results ?? [],
        error_message: null,
        created_at: prev?.created_at ?? new Date().toISOString(),
      }));
    },
    onFpReviewProgress: (data) => {
      setFpReview((prev) => {
        if (!prev || prev.review_id !== data.review_id) return prev;
        return {
          ...prev,
          status: "running",
          processed: data.processed ?? prev.processed,
          current_vuln_index: data.vuln_index,
          current_vuln_indices: data.active_indices ?? [data.vuln_index],
          total: data.total,
        };
      });
    },
    onFpReviewStageOutput: (data) => {
      setFpReview((prev) => {
        if (!prev || prev.review_id !== data.review_id) return prev;
        const results = [...prev.results];
        const existingIndex = results.findIndex((result) => result.vuln_index === data.vuln_index);
        if (existingIndex >= 0) {
          const existing = results[existingIndex];
          results[existingIndex] = {
            ...existing,
            stage_outputs: {
              ...(existing.stage_outputs ?? {}),
              [data.stage]: data.markdown,
            },
            stage_output_sources: {
              ...(existing.stage_output_sources ?? {}),
              [data.stage]: data.output_source ?? {},
            },
          };
        } else {
          results.push({
            vuln_index: data.vuln_index,
            verdict: "uncertain",
            severity: "low",
            reason: "",
            vulnerability_report: "",
            stage_outputs: { [data.stage]: data.markdown },
            stage_output_sources: { [data.stage]: data.output_source ?? {} },
            created_at: new Date().toISOString(),
          });
        }
        return { ...prev, status: "running", results };
      });
    },
    onFpReviewResult: (data) => {
      setFpReview((prev) => {
        if (!prev || prev.review_id !== data.review_id) return prev;
        const existing = prev.results.find((result) => result.vuln_index === data.vuln_index);
        const newResult = {
          vuln_index: data.vuln_index,
          verdict: data.verdict,
          severity: data.severity,
          reason: data.reason,
          vulnerability_report: data.vulnerability_report ?? "",
          stage_outputs: {
            ...(existing?.stage_outputs ?? {}),
            ...(data.stage_outputs ?? {}),
          },
          match_reference: data.match_reference ?? existing?.match_reference ?? "",
          match_type: data.match_type ?? existing?.match_type ?? "",
          stage_output_sources: {
            ...(existing?.stage_output_sources ?? {}),
            ...(data.stage_output_sources ?? {}),
          },
          output_source: data.output_source ?? existing?.output_source,
          created_at: new Date().toISOString(),
        };
        return {
          ...prev,
          status: "running",
          results: [
            ...prev.results.filter((result) => result.vuln_index !== data.vuln_index),
            newResult,
          ],
        };
      });
    },
    onFpReviewFinish: (data) => {
      setFpReview((prev) => {
        if (!prev || prev.review_id !== data.review_id) return prev;
        return {
          ...prev,
          status: data.status,
          error_message: data.error_message,
          current_vuln_index: null,
          current_vuln_indices: [],
        };
      });
    },
    onIndexStatus: (data) => {
      setIndexStatus(data);
      const totalFiles = data.total_files || data.stats?.files || 0;
      const parsedFiles = data.status === "done" && (data.parsed_files ?? 0) === 0
        ? totalFiles
        : data.parsed_files;
      if (totalFiles > 0 && parsedFiles != null) {
        setScan((prev) => prev ? {
          ...prev,
          static_total_files: totalFiles,
          static_scanned_files: parsedFiles,
        } : prev);
      }
    },
  }), [scanId]);

  const sseStateSetters = useMemo<SSEStateSetters>(() => ({
    setScan,
    setFpReview,
    setIndexStatus,
  }), []);

  useScanSSE(scanId, sseHandlers, sseStateSetters);

  const handleFpReview = async () => {
    setFpReviewLoading(true);
    try {
      const started = await triggerFpReview(scanId);
      setFpReview((prev) => ({
        review_id: started.review_id,
        scan_id: scanId,
        method: started.method ?? prev?.method ?? scan?.fp_review_method ?? "adversarial",
        status: started.status ?? "running",
        total: started.total ?? 0,
        processed: started.processed ?? 0,
        current_vuln_index: null,
        current_vuln_indices: [],
        results: prev?.results ?? [],
        error_message: null,
        created_at: prev?.created_at ?? new Date().toISOString(),
      }));
    } catch (err: unknown) {
      const msg = err && typeof err === "object" && "response" in err
        ? (err as { response: { data: { detail: string } } }).response?.data?.detail
        : "触发失败";
      alert(`AI去误报失败：${msg || "未知错误"}`);
    } finally {
      setFpReviewLoading(false);
    }
  };

  const handleTriggerValidation = async (index: number) => {
    setLaunchingValidations((prev) => new Set(prev).add(index));
    try {
      await triggerVulnerabilityValidation(scanId, index);
    } catch (err: unknown) {
      const response = (err as { response?: { data?: { detail?: string } } }).response;
      const msg = response?.data?.detail || (err instanceof Error ? err.message : "未知错误");
      alert(`启动漏洞验证失败：${msg}`);
      setLaunchingValidations((prev) => {
        const next = new Set(prev);
        next.delete(index);
        return next;
      });
    }
  };

  const handleStopValidation = async (index: number) => {
    setStoppingValidations((prev) => new Set(prev).add(index));
    try {
      await stopVulnerabilityValidation(scanId, index);
    } catch (err: unknown) {
      const response = (err as { response?: { data?: { detail?: string } } }).response;
      const msg = response?.data?.detail || (err instanceof Error ? err.message : "未知错误");
      alert(`停止漏洞验证失败：${msg}`);
      setStoppingValidations((prev) => {
        const next = new Set(prev);
        next.delete(index);
        return next;
      });
    }
  };

  const handleStopFpReview = async () => {
    setFpReviewStopping(true);
    try {
      await stopFpReview(scanId);
      const job = await getFpReview(scanId);
      setFpReview(job);
    } catch (err: unknown) {
      const msg = err && typeof err === "object" && "response" in err
        ? (err as { response: { data: { detail: string } } }).response?.data?.detail
        : "停止失败";
      alert(`停止AI复核失败：${msg || "未知错误"}`);
    } finally {
      setFpReviewStopping(false);
    }
  };

  const handleStop = async () => {
    setStopping(true);
    try {
      await stopScan(scanId);
      const next = await getScanStatus(scanId);
      setScan(next);
    } catch {
      // The next poll can still reconcile an Agent-side stop.
    } finally {
      setStopping(false);
    }
  };

  const handleContinue = async () => {
    setContinuing(true);
    try {
      await resumeScan(scanId);
      const next = await getScanStatus(scanId);
      setScan(next);
    } catch (err: unknown) {
      const msg = err && typeof err === "object" && "response" in err
        ? (err as { response: { data: { detail: string } } }).response?.data?.detail
        : "续扫失败";
      alert(`续扫失败：${msg || "未知错误"}`);
    } finally {
      setContinuing(false);
    }
  };

  const handleLoadMoreDetails = async () => {
    const cursors = scan?.detail_pages;
    if (!scan || !cursors || detailLoading) return;
    setDetailLoading(true);
    try {
      const [candidatePage, vulnerabilityPage, eventPage, threatTaskPage, validationPage] = await Promise.all([
        cursors.candidates_next_cursor == null
          ? Promise.resolve(null)
          : getScanCandidatesPage(scanId, cursors.candidates_next_cursor),
        cursors.vulnerabilities_next_cursor == null
          ? Promise.resolve(null)
          : getScanVulnerabilitiesPage(scanId, cursors.vulnerabilities_next_cursor),
        cursors.events_next_cursor == null
          ? Promise.resolve(null)
          : getScanEventsPage(scanId, cursors.events_next_cursor),
        cursors.threat_tasks_next_cursor == null
          ? Promise.resolve(null)
          : getScanThreatTasksPage(scanId, cursors.threat_tasks_next_cursor),
        cursors.validations_next_cursor == null
          ? Promise.resolve(null)
          : getScanValidationsPage(scanId, cursors.validations_next_cursor),
      ]);
      setScan((previous) => {
        if (!previous) return previous;

        const candidates = [...previous.candidates];
        const candidateIndexes = new Set(candidates.map((item) => item.idx));
        for (const item of candidatePage?.items ?? []) {
          if (!candidateIndexes.has(item.idx)) candidates.push(item);
        }
        candidates.sort((left, right) => left.idx - right.idx);

        const vulnerabilities = [...previous.vulnerabilities];
        for (const item of vulnerabilityPage?.items ?? []) {
          vulnerabilities[item.index] = item.vulnerability;
        }

        const eventKey = (item: ScanEvent) => [
          item.timestamp,
          item.phase,
          item.message,
          item.candidate_index ?? "",
        ].join("\u0000");
        const existingEventKeys = new Set(previous.events.map(eventKey));
        const olderEvents = (eventPage?.items ?? []).filter(
          (item) => !existingEventKeys.has(eventKey(item)),
        );

        const threatTasks = [...(previous.threat_audit_tasks ?? [])];
        const threatTaskIds = new Set(threatTasks.map((item) => item.task_id));
        for (const item of threatTaskPage?.items ?? []) {
          if (!threatTaskIds.has(item.task_id)) threatTasks.push(item);
        }

        const validations = [...(previous.validations ?? [])];
        const validationIndexes = new Set(validations.map((item) => item.vuln_index));
        for (const item of validationPage?.items ?? []) {
          if (!validationIndexes.has(item.vuln_index)) validations.push(item);
        }
        validations.sort((left, right) => left.vuln_index - right.vuln_index);

        return {
          ...previous,
          candidates,
          vulnerabilities,
          events: [...olderEvents, ...previous.events],
          threat_audit_tasks: threatTasks,
          validations,
          detail_pages: {
            candidates_next_cursor: candidatePage
              ? candidatePage.next_cursor
              : cursors.candidates_next_cursor,
            vulnerabilities_next_cursor: vulnerabilityPage
              ? vulnerabilityPage.next_cursor
              : cursors.vulnerabilities_next_cursor,
            events_next_cursor: eventPage
              ? eventPage.next_cursor
              : cursors.events_next_cursor,
            threat_tasks_next_cursor: threatTaskPage
              ? threatTaskPage.next_cursor
              : cursors.threat_tasks_next_cursor,
            validations_next_cursor: validationPage
              ? validationPage.next_cursor
              : cursors.validations_next_cursor,
          },
        };
      });
    } catch {
      // Keep already loaded detail pages; the user can retry.
    } finally {
      setDetailLoading(false);
    }
  };

  const handleExportZip = async () => {
    if (!scan) return;
    setExportingZip(true);
    try {
      const blob = await downloadScanReportZip(scan.scan_id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `scan-${scan.scan_id}-report.zip`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "未知错误";
      alert(`导出报告失败：${msg}`);
    } finally {
      setExportingZip(false);
    }
  };

  // Handle feedback selection change — update backend and refresh skills
  const handleFeedbackChange = async (ids: Set<string>) => {
    setSelectedFeedbackIds(ids);
    setScan((prev) => prev ? { ...prev, feedback_ids: [...ids] } : prev);
    try {
      await updateScanFeedback(scanId, [...ids]);
      // Refresh SKILL preview if it's currently open
      if (skillOpen && skillType) {
        const content = skillType === "__fp_review__"
          ? await getFpReviewSkill(scanId)
          : await getSkillContent(scanId, skillType);
        setSkillContent(content);
      }
    } catch {
      // ignore
    }
  };

  const addSelectedFeedbackIds = async (feedbackIds: string[]) => {
    if (feedbackIds.length === 0) return;
    const next = new Set(selectedFeedbackIds ?? scan?.feedback_ids ?? []);
    for (const id of feedbackIds) next.add(id);
    await handleFeedbackChange(next);
  };

  const removeSelectedFeedbackIds = async (feedbackIds: string[]) => {
    if (feedbackIds.length === 0) return;
    const next = new Set(selectedFeedbackIds ?? scan?.feedback_ids ?? []);
    for (const id of feedbackIds) next.delete(id);
    setSelectedFeedbackIds(next);
    setScan((prev) => prev ? { ...prev, feedback_ids: [...next] } : prev);
  };

  const handleFlowNodeClick = (node: FlowNodeId) => {
    if (node === "index") {
      setActiveTab("index");
      return;
    }
    if (node === "static") {
      setActiveTab("static");
      return;
    }
    if (node === "threat") {
      setActiveTab("threat");
      return;
    }
    if (node === "validation") {
      setActiveTab("validation");
      return;
    }
    if (node === "fp_review") {
      setActiveTab("fp_review");
      return;
    }
    const engineId = node.slice("engine:".length);
    setActiveEngineId(engineId);
    setActiveTab("mining");
  };

  const loadSkill = async (vulnType: string) => {
    setSkillType(vulnType);
    setSkillLoading(true);
    try {
      const content = await getSkillContent(scanId, vulnType);
      setSkillContent(content);
    } catch {
      setSkillContent("加载失败");
    } finally {
      setSkillLoading(false);
    }
  };

  const loadFpReviewSkill = async () => {
    setSkillType("__fp_review__");
    setSkillLoading(true);
    try {
      const content = await getFpReviewSkill(scanId);
      setSkillContent(content);
    } catch {
      setSkillContent("加载失败");
    } finally {
      setSkillLoading(false);
    }
  };

  const loadSkillReports = async () => {
    setReportsOpen(true);
    setReportsLoading(true);
    try {
      const next = await getSkillReports(scanId);
      setReports(next);
      setActiveReportIndex(0);
    } catch {
      setReports([]);
    } finally {
      setReportsLoading(false);
    }
  };

  // Compute log event count for scroll/unseen tracking
  const logEventCount = scan?.events.length ?? 0;

  // Auto-scroll log
  useEffect(() => {
    if (logRef.current && logOpen) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logEventCount, logOpen]);

  // Track unseen events
  useEffect(() => {
    if (logOpen) {
      setLastSeenEvents(logEventCount);
    }
  }, [logOpen, logEventCount]);

  if (!scan) {
    return (
      <div className="relative min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
        <div className="absolute right-4 top-4">
          <ThemeToggle />
        </div>
        <div role="status" aria-label="加载扫描详情" className="page-spinner w-5 h-5 border-2 rounded-full animate-spin" />
      </div>
    );
  }

  const pct = Math.round(scan.progress * 100);
  const allLogEvents = scan.events;
  const truncated = allLogEvents.length > MAX_LOG_LINES;
  const logEvents = truncated ? allLogEvents.slice(-MAX_LOG_LINES) : allLogEvents;
  const unseenCount = allLogEvents.length - lastSeenEvents;
  const feedbackCount = selectedFeedbackIds?.size ?? scan.feedback_ids?.length ?? 0;
  const agentDisconnectError = isAgentDisconnectError(scan.error_message);
  const staleAgentDisconnectError = scan.status === "cancelled" && agentDisconnectError && !!scan.agent_online;
  const visibleErrorMessage = staleAgentDisconnectError ? null : scan.error_message;
  const isFpReviewing = fpReview?.status === "running" || fpReview?.status === "pending";
  const fpIndicesSource = !isFpReviewing
    ? []
    : fpReview?.current_vuln_indices?.length
    ? fpReview.current_vuln_indices
    : fpReview?.current_vuln_index != null
    ? [fpReview.current_vuln_index]
    : [];
  const currentFpReviewIndices = new Set(fpIndicesSource.filter((i) => i >= 0));
  const currentFpReviewTargets = [...currentFpReviewIndices]
    .sort((a, b) => a - b)
    .map((i) => scan.vulnerabilities[i])
    .filter(Boolean);
  const reportCheckers = checkers.filter(
    (checker) => scan.scan_items.includes(checker.name) && checker.result_mode === "markdown_reports",
  );
  const hasReportModeSkill = reportCheckers.length > 0 || (scan.skill_reports?.length ?? 0) > 0;
  const displayedReports = reports.length > 0 ? reports : (scan.skill_reports ?? []);
  const activeReport = displayedReports[activeReportIndex] ?? displayedReports[0];
  const continuableCount = scan.continuable_task_count || 0;
  const issueCount = effectiveIssueCount(scan, fpReview);
  const verifiedIssueCount = validatedIssueCount(scan, fpReview);
  const variantIssueCount = scan.vulnerabilities.filter((v) => v.variant_of).length;
  const showGitHistoryStages = gitHistory.length > 0
    || variantIssueCount > 0
    || hasEvent(scan.events, ["git_history", "variant_hunt"]);
  const indexProgress = formatIndexProgress(indexStatus, scan);
  const selectedEngines = effectiveMiningEngines(scan);
  const activeEngine = selectedEngines.find((item) => item.engine_id === activeEngineId) ?? null;
  const threatAnalysisEvents = filterEvents(scan.events, ["threat_analysis"]);
  const threatAuditEvents = filterEvents(scan.events, ["threat_audit"]);
  const miningEvents = filterEvents(scan.events, ["auditing", "fp_review", "opencode_output"]);
  const selectedFpReviewMethod = fpReview?.method ?? scan.fp_review_method ?? "adversarial";
  const selectedFpReviewSelection = scan.fp_review_method_selection?.method_id === selectedFpReviewMethod
    ? scan.fp_review_method_selection
    : null;
  const selectedFpReviewStages = selectedFpReviewSelection?.stages ?? [];
  const validationEvents = filterEvents(scan.events, ["validation"]);
  const hasMoreDetailPages = Boolean(
    scan.detail_pages && Object.values(scan.detail_pages).some((value) => value != null),
  );
  const issuesView = (
    <VulnerabilityList
      scanId={scanId}
      vulnerabilities={scan.vulnerabilities}
      events={scan.events}
      isScanning={!!isRunning}
      totalCandidates={scan.total_candidates}
      processedCandidates={scan.processed_candidates}
      fpReview={fpReview}
      fpReviewStages={selectedFpReviewStages}
      currentFpReviewIndices={currentFpReviewIndices}
      fpReviewRunning={isFpReviewing}
      validations={scan.validations ?? []}
      validatingIndices={launchingValidations}
      stoppingValidationIndices={stoppingValidations}
      agentOnline={!!scan.agent_online}
      enableCsvExport
      onTriggerValidation={handleTriggerValidation}
      onStopValidation={handleStopValidation}
      onFeedbackCreated={addSelectedFeedbackIds}
      onFeedbackRemoved={removeSelectedFeedbackIds}
      onVulnMarked={() => {
        if (skillOpen && skillType) {
          if (skillType === "__fp_review__") {
            getFpReviewSkill(scanId).then(setSkillContent).catch(() => {});
          } else {
            getSkillContent(scanId, skillType).then(setSkillContent).catch(() => {});
          }
        }
      }}
    />
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex flex-col">
      {/* Top bar */}
      <div className="bg-slate-800/80 backdrop-blur border-b border-slate-700 px-4 py-4 sm:px-6">
        <div className="mb-3 flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between">
          <div className="flex min-w-0 flex-wrap items-center gap-x-4 gap-y-2">
            <button
              onClick={onBack}
              className="flex items-center gap-1 rounded-md text-sm text-slate-400 transition-colors hover:text-slate-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400/70 motion-reduce:transition-none"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
              返回
            </button>
            <h1 className="text-lg font-bold text-white">OpenDeepHole</h1>
            <span className="text-sm text-slate-400">
              {scan.status === "cancelled"
                ? (agentDisconnectError ? (scan.agent_online ? "扫描已中断" : "Agent 断开，已中断") : "已取消")
                : scan.status === "error" ? "扫描异常"
                  : isRunning ? "扫描中..." : isDone ? "扫描完成" : "扫描中..."}
            </span>
            {scan.agent_name && (
              <span className="flex items-center gap-1.5 text-sm text-slate-400 border-l border-slate-600 pl-4">
                <span
                  className={`w-2 h-2 rounded-full flex-shrink-0 ${
                    scan.agent_online ? "bg-green-400" : "bg-slate-500"
                  }`}
                />
                Agent: {scan.agent_name}
                {!scan.agent_online && (
                  <span className="text-xs text-slate-500">(离线)</span>
                )}
              </span>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2 xl:max-w-[72%] xl:justify-end">
            <ThemeToggle />
            {/* Feedback button with count badge */}
            <button
              onClick={() => setFeedbackOpen(true)}
              className="px-3 py-1.5 text-sm font-medium text-slate-300 border border-slate-600 rounded-lg hover:bg-slate-700 transition-colors flex items-center gap-1.5"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
              </svg>
              误报屏蔽规则
              {feedbackCount > 0 && (
                <span className="bg-blue-500 text-white text-xs rounded-full px-1.5 py-0.5 min-w-[1.25rem] text-center">
                  {feedbackCount}
                </span>
              )}
            </button>
            <button
              onClick={() => {
                setSkillOpen(true);
                if (!skillType && scan.scan_items.length > 0) {
                  loadSkill(scan.scan_items[0]);
                }
              }}
              className="px-3 py-1.5 text-sm font-medium text-slate-300 border border-slate-600 rounded-lg hover:bg-slate-700 transition-colors flex items-center gap-1.5"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
              </svg>
              SKILL 预览
            </button>
            <button
              onClick={() => setModelPoolOpen(true)}
              className="px-3 py-1.5 text-sm font-medium text-cyan-300 border border-cyan-500/40 rounded-lg hover:bg-cyan-500/10 transition-colors flex items-center gap-1.5"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 19V5m0 14h16M8 15V9m4 6V7m4 8v-4" />
              </svg>
              模型看板
              {(scan.opencode_pool?.global_running ?? 0) > 0 && (
                <span className="text-xs text-cyan-100">{scan.opencode_pool?.global_running}</span>
              )}
            </button>
            {hasReportModeSkill && (
              <button
                onClick={loadSkillReports}
                className="px-3 py-1.5 text-sm font-medium text-purple-300 border border-purple-500/40 rounded-lg hover:bg-purple-500/10 transition-colors flex items-center gap-1.5"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                SKILL 报告
                {(scan.skill_reports?.length ?? 0) > 0 && (
                  <span className="text-xs text-purple-200">{scan.skill_reports.length}</span>
                )}
              </button>
            )}
            {(() => {
              const confirmedVulns = scan.vulnerabilities.filter(
                (v) => (v.ai_verdict === "confirmed" || (!v.ai_verdict && v.confirmed))
                  && !hasFinalUserVerdict(v)
              ).length;
              const canTrigger = confirmedVulns > 0;
              const isReviewing = fpReview?.status === "running" || fpReview?.status === "pending";
              if (!canTrigger) return null;
              return (
                <>
                  <button
                    onClick={handleFpReview}
                    disabled={!canTrigger || fpReviewLoading || !!isReviewing}
                    className="px-3 py-1.5 text-sm font-medium text-amber-400 border border-amber-500/50 rounded-lg hover:bg-amber-500/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-1.5"
                    title={!canTrigger ? "需要存在 LLM 正报才可使用" : "使用 AI 对已确认漏洞逐条进行误报复核"}
                  >
                    {isReviewing ? (
                      <>
                        <div className="w-3 h-3 border border-amber-500/30 border-t-amber-400 rounded-full animate-spin" />
                        复核中 {fpReview!.processed}/{fpReview!.total}
                      </>
                    ) : fpReviewLoading ? (
                      <>
                        <div className="w-3 h-3 border border-amber-500/30 border-t-amber-400 rounded-full animate-spin" />
                        启动中...
                      </>
                    ) : (
                      <>
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        AI去误报
                        {fpReview?.status === "complete" && (
                          <span className="text-xs text-green-400 ml-0.5">✓</span>
                        )}
                        {fpReview?.status === "cancelled" && (
                          <span className="text-xs text-amber-300 ml-0.5">已停止</span>
                        )}
                      </>
                    )}
                  </button>
                  {isReviewing && (
                    <button
                      onClick={handleStopFpReview}
                      disabled={fpReviewStopping}
                      className="px-3 py-1.5 text-sm font-medium text-red-400 border border-red-500/50 rounded-lg hover:bg-red-500/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                      title="停止当前AI去误报复核"
                    >
                      {fpReviewStopping ? "停止中..." : "停止复核"}
                    </button>
                  )}
                </>
              );
            })()}
            {isDone && (
              <>
                {scan.can_continue && (
                  <button
                    onClick={handleContinue}
                    disabled={continuing || !scan.agent_online}
                    title={!scan.agent_online ? "Agent 离线，无法续扫" : `续扫 ${continuableCount} 个任务`}
                    className="px-3 py-1.5 text-sm font-medium text-amber-300 border border-amber-500/50 rounded-lg hover:bg-amber-500/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    {continuing ? "启动中..." : "续扫"}
                  </button>
                )}
              </>
            )}
            {isDone && (
              <button
                onClick={handleExportZip}
                disabled={exportingZip}
                className="px-3 py-1.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed rounded-lg transition-colors"
              >
                {exportingZip ? "导出中..." : "导出报告"}
              </button>
            )}
            {isRunning && (
              <button
                onClick={handleStop}
                disabled={stopping}
                className="px-3 py-1.5 text-sm font-medium text-red-400 border border-red-500/50 rounded-lg hover:bg-red-500/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {stopping ? "停止中..." : "停止扫描"}
              </button>
            )}
          </div>
        </div>

        <ProcessFlowNav
          scan={scan}
          indexProgress={indexProgress}
          fpReview={fpReview}
          activeTab={activeTab}
          activeEngineId={activeEngineId}
          issueCount={issueCount}
          verifiedIssueCount={verifiedIssueCount}
          threatAnalysisLoading={threatAnalysisLoading}
          isDone={!!isDone}
          isFpReviewing={isFpReviewing}
          onNodeClick={handleFlowNodeClick}
          onHome={() => setActiveTab("overview")}
          onIssues={() => setActiveTab("issues")}
        />

        {/* Error */}
        {visibleErrorMessage && (
          <div className={`mt-3 rounded-lg border p-2.5 text-sm ${
            scan.status === "complete"
              ? "border-amber-500/30 bg-amber-500/10 text-amber-300"
              : "border-red-500/30 bg-red-500/10 text-red-400"
          }`}>
            {visibleErrorMessage}
          </div>
        )}
      </div>

      {/* Main content */}
      <div className="flex-1 overflow-auto px-4 py-4 sm:px-6">
        {hasMoreDetailPages && (
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-blue-500/30 bg-blue-500/10 px-4 py-3 text-sm text-blue-100">
            <span>
              当前按页展示详情，已加载 {scan.candidates.length} 个候选点、
              {scan.vulnerabilities.filter(Boolean).length} 条漏洞结果和 {scan.events.length} 条日志。
            </span>
            <button
              type="button"
              onClick={handleLoadMoreDetails}
              disabled={detailLoading}
              className="rounded-md border border-blue-400/40 px-3 py-1.5 text-xs font-medium text-blue-100 transition-colors hover:bg-blue-400/10 disabled:opacity-50"
            >
              {detailLoading ? "加载中..." : "继续加载详情"}
            </button>
          </div>
        )}
        {activeTab === "overview" && (
          <ScanOverview
            scan={scan}
            issueCount={issueCount}
            continuableCount={continuableCount}
            variantIssueCount={variantIssueCount}
            gitHistoryCount={gitHistory.length}
            showGitHistoryStages={showGitHistoryStages}
            currentStage={currentStageLabel(scan, scan.events)}
            indexProgress={indexProgress}
            pct={pct}
            isRunning={!!isRunning}
            isDone={!!isDone}
            fpReview={fpReview}
            isFpReviewing={isFpReviewing}
            currentFpReviewTargets={currentFpReviewTargets}
            hasReportModeSkill={hasReportModeSkill}
            verifiedIssueCount={verifiedIssueCount}
            onNavigate={setActiveTab}
          />
        )}
        {activeTab === "index" && (
          <TaskPanel
            title="代码图谱构建"
            status={taskStateLabel(indexProgress.done, indexProgress.running, indexProgress.failed)}
            tone={indexProgress.failed ? "red" : indexProgress.done ? "green" : indexProgress.running ? "blue" : "slate"}
            summary="作为扫描底层能力，为静态分析、威胁分析和漏洞挖掘提供调用关系与代码上下文。"
          >
            <CallGraphBuildPanel
              indexStatus={indexStatus}
              indexProgress={indexProgress}
              events={filterEvents(scan.events, ["init", "code_graph_build"])}
            />
          </TaskPanel>
        )}
        {activeTab === "static" && (
          <StaticTaskPanel
            scan={scan}
            indexProgress={indexProgress}
            candidates={scan.candidates ?? []}
            vulnerabilities={scan.vulnerabilities}
            validations={scan.validations ?? []}
            currentCandidate={scan.current_candidate}
            processedCandidates={scan.processed_candidates}
            events={filterEvents(scan.events, ["static_analysis"])}
          />
        )}
        {activeTab === "threat" && isThreatAnalysisSelected(scan) && (
          <ThreatAnalysisPanel
            analysis={scan.threat_analysis ?? null}
            events={threatAnalysisEvents}
            loading={(threatAnalysisLoading || scan.threat_analysis_run?.status === "running") && !scan.threat_analysis}
            isDone={!!isDone}
          />
        )}
        {activeTab === "threat" && !isThreatAnalysisSelected(scan) && (
          <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-6 text-sm text-slate-400">
            本次扫描未选择威胁分析。
          </div>
        )}
        {activeTab === "mining" && activeEngine?.engine_id === STATIC_ENGINE_ID && (
          <AuditTaskPanel
            scan={scan}
            pct={pct}
            currentCandidate={scan.current_candidate}
            events={filterEvents(miningEvents, ["auditing", "opencode_output"])}
            pool={scan.opencode_pool ?? null}
          />
        )}
        {activeTab === "mining" && activeEngine?.engine_id === THREAT_ENGINE_ID && (
          <ThreatAuditPanel
            scan={scan}
            events={threatAuditEvents}
          />
        )}
        {activeTab === "mining" && activeEngine && ![STATIC_ENGINE_ID, THREAT_ENGINE_ID].includes(activeEngine.engine_id) && (
          <GenericEnginePanel
            engine={activeEngine}
            run={miningEngineRun(scan, activeEngine.engine_id)}
          >
            <VulnerabilityList
              scanId={scanId}
              vulnerabilities={scan.vulnerabilities}
              events={scan.events}
              isScanning={!!isRunning}
              totalCandidates={scan.total_candidates}
              processedCandidates={scan.processed_candidates}
              fpReview={fpReview}
              currentFpReviewIndices={currentFpReviewIndices}
              fpReviewRunning={isFpReviewing}
              validations={scan.validations ?? []}
              validatingIndices={launchingValidations}
              stoppingValidationIndices={stoppingValidations}
              agentOnline={!!scan.agent_online}
              fixedEngineId={activeEngine.engine_id}
              onTriggerValidation={handleTriggerValidation}
              onStopValidation={handleStopValidation}
              onFeedbackCreated={addSelectedFeedbackIds}
              onFeedbackRemoved={removeSelectedFeedbackIds}
            />
          </GenericEnginePanel>
        )}
        {activeTab === "mining" && !activeEngine && (
          <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-6 text-sm text-slate-400">
            {selectedEngines.length > 0 ? "请从流程图中选择一个漏洞挖掘引擎。" : "本次扫描未选择漏洞挖掘引擎。"}
          </div>
        )}
        {activeTab === "validation" && (
          <ValidationPanel
            vulnerabilities={scan.vulnerabilities}
            validations={scan.validations ?? []}
            stoppingValidationIndices={stoppingValidations}
            events={validationEvents}
            onStopValidation={handleStopValidation}
          />
        )}
        {activeTab === "fp_review" && (
          <FpReviewPanel
            vulnerabilities={scan.vulnerabilities}
            fpReview={fpReview}
            methodLabel={fpReviewMethodLabel(selectedFpReviewMethod, selectedFpReviewSelection)}
            methodDescription={selectedFpReviewSelection?.description ?? "按漏洞粒度逐条执行去误报复核。"}
            stages={selectedFpReviewStages}
            isFpReviewing={isFpReviewing}
            loading={fpReviewLoading}
            stopping={fpReviewStopping}
            events={filterEvents(miningEvents, ["fp_review", "opencode_output"])}
            onTrigger={handleFpReview}
            onStop={handleStopFpReview}
          />
        )}
        {activeTab === "issues" && issuesView}
      </div>

      {/* Log floating button */}
      <button
        onClick={() => { setLogOpen(true); setLastSeenEvents(logEvents.length); }}
        className="fixed bottom-6 right-6 px-4 py-2.5 bg-slate-700 hover:bg-slate-600 text-slate-300 text-sm font-medium rounded-full shadow-lg border border-slate-600 transition-colors z-40 flex items-center gap-2"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
        日志
        {unseenCount > 0 && (
          <span className="bg-blue-500 text-white text-xs rounded-full px-1.5 py-0.5 min-w-[1.25rem] text-center">
            {unseenCount > 99 ? "99+" : unseenCount}
          </span>
        )}
      </button>

      {/* Log slide-over panel */}
      {logOpen && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-black/30 z-40"
            onClick={() => setLogOpen(false)}
          />
          {/* Panel */}
          <div className="fixed right-0 top-0 bottom-0 w-[32rem] max-w-full bg-slate-900 border-l border-slate-700 z-50 flex flex-col shadow-2xl">
            <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
              <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
                处理日志
              </h3>
              <button
                onClick={() => setLogOpen(false)}
                className="text-slate-500 hover:text-slate-300 transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div
              ref={logRef}
              className="flex-1 overflow-y-auto p-3 space-y-1 font-mono text-xs"
            >
              {logEvents.length === 0 ? (
                <p className="text-slate-500">等待事件...</p>
              ) : (
                <>
                  {truncated && (
                    <p className="text-slate-600 text-center py-1 border-b border-slate-700/50 mb-1">
                      ... 已省略 {allLogEvents.length - MAX_LOG_LINES} 条早期日志 ...
                    </p>
                  )}
                  {logEvents.map((event, i) => (
                    <EventLine key={i} event={event} />
                  ))}
                </>
              )}
            </div>
          </div>
        </>
      )}

      {/* Feedback Manager Panel */}
      {feedbackOpen && scan.project_id && (
        <FeedbackManager
          checkers={checkers.filter((c) => scan.scan_items.includes(c.name))}
          initialTypes={scan.scan_items}
          scanId={scanId}
          projectId={scan.project_id}
          selectedIds={selectedFeedbackIds ?? new Set(scan.feedback_ids)}
          onSelectionChange={handleFeedbackChange}
          onFeedbackCreated={addSelectedFeedbackIds}
          onClose={() => setFeedbackOpen(false)}
        />
      )}

      {/* OpenCode model pool dashboard */}
      {modelPoolOpen && (
        <>
          <div
            className="fixed inset-0 bg-black/30 z-40"
            onClick={() => setModelPoolOpen(false)}
          />
          <div className="fixed right-0 top-0 bottom-0 w-[60rem] max-w-full bg-slate-900 border-l border-slate-700 z-50 flex flex-col shadow-2xl">
            <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
              <div>
                <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
                  OpenCode 模型看板
                </h3>
                <p className="text-xs text-slate-500 mt-1">
                  {scan.opencode_pool?.updated_at
                    ? `最后更新：${formatDateTime(scan.opencode_pool.updated_at)}`
                    : "当前扫描尚未产生 OpenCode 模型池统计"}
                </p>
              </div>
              <button
                onClick={() => setModelPoolOpen(false)}
                className="text-slate-500 hover:text-slate-300 transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <ModelPoolDashboard pool={scan.opencode_pool ?? null} />
          </div>
        </>
      )}

      {/* SKILL Preview Panel */}
      {skillOpen && (
        <>
          <div
            className="fixed inset-0 bg-black/30 z-40"
            onClick={() => setSkillOpen(false)}
          />
          <div className="fixed right-0 top-0 bottom-0 w-[40rem] max-w-full bg-slate-900 border-l border-slate-700 z-50 flex flex-col shadow-2xl">
            <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
              <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
                SKILL 预览
              </h3>
              <button
                onClick={() => setSkillOpen(false)}
                className="text-slate-500 hover:text-slate-300 transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            {/* Type tabs */}
            <div className="flex gap-1.5 px-4 py-2.5 border-b border-slate-700/50 overflow-x-auto">
              {scan.scan_items.map((item) => (
                <button
                  key={item}
                  onClick={() => loadSkill(item)}
                  className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap ${
                    skillType === item
                      ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
                      : "text-slate-400 border-slate-700 hover:bg-slate-800"
                  }`}
                >
                  {item.toUpperCase()}
                </button>
              ))}
              <button
                onClick={() => loadFpReviewSkill()}
                className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap ${
                  skillType === "__fp_review__"
                    ? "bg-amber-500/20 text-amber-400 border-amber-500/30"
                    : "text-slate-400 border-slate-700 hover:bg-slate-800"
                }`}
              >
                FP REVIEW
              </button>
            </div>
            {/* Content */}
            <div className="flex-1 overflow-y-auto p-4">
              {skillLoading ? (
                <div className="flex items-center gap-2 text-xs text-slate-500">
                  <div className="w-3 h-3 border border-slate-600 border-t-blue-400 rounded-full animate-spin" />
                  加载中...
                </div>
              ) : (
                <pre className="text-xs text-slate-400 whitespace-pre-wrap leading-relaxed font-mono">
                  {skillContent}
                </pre>
              )}
            </div>
          </div>
        </>
      )}

      {/* Markdown report panel */}
      {reportsOpen && (
        <>
          <div
            className="fixed inset-0 bg-black/30 z-40"
            onClick={() => setReportsOpen(false)}
          />
          <div className="fixed right-0 top-0 bottom-0 w-[52rem] max-w-full bg-slate-900 border-l border-slate-700 z-50 flex flex-col shadow-2xl">
            <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
              <div>
                <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
                  SKILL 报告
                </h3>
                <p className="text-xs text-slate-500 mt-1">
                  {isRunning ? "报告型 SKILL 正在运行或等待同步" : `已同步 ${displayedReports.length} 个 Markdown 报告`}
                </p>
              </div>
              <button
                onClick={() => setReportsOpen(false)}
                className="text-slate-500 hover:text-slate-300 transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="flex min-h-0 flex-1">
              <div className="w-64 shrink-0 border-r border-slate-800 p-3 overflow-y-auto">
                {reportsLoading ? (
                  <div className="flex items-center gap-2 text-xs text-slate-500">
                    <div className="w-3 h-3 border border-slate-600 border-t-purple-400 rounded-full animate-spin" />
                    加载中...
                  </div>
                ) : displayedReports.length === 0 ? (
                  <div className="rounded border border-slate-800 bg-slate-950 px-3 py-4 text-xs text-slate-500">
                    暂无报告
                  </div>
                ) : (
                  <div className="space-y-2">
                    {displayedReports.map((report, index) => (
                      <button
                        key={`${report.checker_name}-${report.filename}-${index}`}
                        onClick={() => setActiveReportIndex(index)}
                        className={`w-full rounded-lg border px-3 py-2 text-left transition-colors ${
                          index === activeReportIndex
                            ? "border-purple-500/50 bg-purple-500/10"
                            : "border-slate-800 bg-slate-950 hover:border-slate-700"
                        }`}
                      >
                        <div className="text-xs font-semibold text-slate-200 truncate">{report.title || report.filename}</div>
                        <div className="mt-1 text-[11px] text-slate-500 font-mono truncate">{report.checker_name}/{report.filename}</div>
                        {hasOutputSource(report.output_source) && (
                          <div className="mt-1 text-[11px] text-cyan-300 truncate">{formatOutputSource(report.output_source)}</div>
                        )}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <div className="min-w-0 flex-1 overflow-y-auto p-5">
                {activeReport ? (
                  <>
                    {hasOutputSource(activeReport.output_source) && (
                      <div
                        className="mb-3 rounded border border-cyan-500/20 bg-cyan-500/5 px-3 py-2 text-xs text-cyan-200"
                        title={[
                          activeReport.output_source?.agent_id ? `Agent ID: ${activeReport.output_source.agent_id}` : "",
                          activeReport.output_source?.agent_session_id ? `Session: ${activeReport.output_source.agent_session_id}` : "",
                          activeReport.output_source?.task_id ? `Task: ${activeReport.output_source.task_id}` : "",
                        ].filter(Boolean).join("\n")}
                      >
                        输出来源：{formatOutputSource(activeReport.output_source)}
                      </div>
                    )}
                    <MarkdownContent content={activeReport.content} />
                  </>
                ) : (
                  <div className="text-sm text-slate-500">选择左侧报告查看内容</div>
                )}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

interface FlowNodeView {
  id: FlowNodeId;
  label: string;
  detail: string;
  status: FlowNodeStatus;
  active: boolean;
  tone: TaskTone;
}

function ProcessFlowNav({
  scan,
  indexProgress,
  fpReview,
  activeTab,
  activeEngineId,
  issueCount,
  verifiedIssueCount,
  threatAnalysisLoading,
  isDone,
  isFpReviewing,
  onNodeClick,
  onHome,
  onIssues,
}: {
  scan: ScanStatusType;
  indexProgress: ReturnType<typeof formatIndexProgress>;
  fpReview: FpReviewJob | null;
  activeTab: MainTab;
  activeEngineId: string;
  issueCount: number;
  verifiedIssueCount: number;
  threatAnalysisLoading: boolean;
  isDone: boolean;
  isFpReviewing: boolean;
  onNodeClick: (node: FlowNodeId) => void;
  onHome: () => void;
  onIssues: () => void;
}) {
  const engines = effectiveMiningEngines(scan);
  const candidates = scan.candidates ?? [];
  const candidateCount = candidates.length || scan.total_candidates || scan.vulnerabilities.length;
  const staticSelected = engines.some((engine) => engine.engine_id === STATIC_ENGINE_ID);
  const staticRun = miningEngineRun(scan, STATIC_ENGINE_ID);
  const staticRunning = staticSelected && scan.status === "analyzing" && !scan.static_analysis_done;
  const staticDone = staticSelected && (
    scan.static_analysis_done
    || candidateCount > 0
    || scan.status === "auditing"
    || staticRun?.status === "success"
    || (scan.status === "complete" && staticRun?.status !== "error")
  );
  const threatSelected = isThreatAnalysisSelected(scan);
  const validations = scan.validations ?? [];
  const confirmedCount = scan.vulnerabilities.filter((vuln) => isAiConfirmed(vuln)).length;
  const fpReviewTargetCount = scan.vulnerabilities.filter(isAiConfirmed).length;
  const validationRunningCount = validations.filter((item) =>
    item.running || item.status === "queued" || item.status === "running" || item.status === "pending",
  ).length;
  const validationDoneCount = validations.filter((item) => !item.running && isValidationTerminalStatus(item.status)).length;
  const validationDone = confirmedCount > 0 && validationDoneCount >= confirmedCount;
  const fpReviewDone = fpReview?.status === "complete";
  const fpReviewProcessed = fpReview?.processed ?? 0;
  const fpReviewTotal = fpReview?.total ?? 0;

  const validationDetail = confirmedCount > 0
    ? `${validationRunningCount} 运行 · ${validationDoneCount}/${confirmedCount} 完成`
    : "等待确认问题";
  const indexNode: FlowNodeView = {
    id: "index",
    label: "代码图谱构建",
    detail: indexProgress.total > 0
      ? `${indexProgress.current}/${indexProgress.total} 文件`
      : "为全流程提供调用关系与代码上下文",
    status: indexProgress.failed
      ? "error"
      : indexProgress.done
        ? "done"
        : indexProgress.running
          ? "running"
          : scan.status === "cancelled"
            ? "cancelled"
            : "pending",
    active: activeTab === "index",
    tone: "blue",
  };
  const staticNodeStatus: FlowNodeStatus = !staticSelected
    ? "skipped"
    : staticDone
      ? "done"
      : staticRunning
        ? "running"
        : staticRun?.status === "error"
          ? "error"
          : staticRun?.status === "cancelled" || scan.status === "cancelled"
            ? "cancelled"
            : "pending";
  const staticNode: FlowNodeView = {
    id: "static",
    label: "静态分析",
    detail: !staticSelected
      ? "本次扫描未选择静态候选引擎"
      : candidateCount > 0
        ? `${candidateCount} 个候选点`
        : scan.static_total_files > 0
          ? `${scan.static_scanned_files}/${scan.static_total_files} 文件`
          : "等待静态规则扫描",
    status: staticNodeStatus,
    active: activeTab === "static",
    tone: "cyan",
  };
  const threatTasks = scan.threat_audit_tasks ?? [];
  const completedThreatTasks = threatTasks.filter((task) => task.status === "completed").length;
  const failedThreatTasks = threatTasks.filter((task) =>
    ["failed", "failure", "error", "timeout", "no_result"].includes(String(task.status || "").toLowerCase()),
  ).length;
  const activeThreatTasks = threatTasks.filter((task) => isActiveThreatAuditStatus(task.status)).length;
  let threatAnalysisStatus = threatAnalysisFlowStatus(scan);
  if (
    threatAnalysisStatus === "pending"
    && (threatAnalysisLoading || (!isDone && hasEvent(scan.events, ["threat_analysis"])))
  ) {
    threatAnalysisStatus = "running";
  }
  const threatAnalysisNode: FlowNodeView = {
    id: "threat",
    label: "威胁分析",
    detail: scan.threat_analysis
      ? threatAnalysisSummary(scan.threat_analysis)
      : !threatSelected
        ? "本次扫描未选择威胁分析"
        : scan.threat_analysis_run?.error_message || "等待生成攻击树",
    status: threatAnalysisStatus,
    active: activeTab === "threat",
    tone: "green",
  };
  const fpReviewNode: FlowNodeView = {
    id: "fp_review",
    label: fpReviewMethodLabel(
      fpReview?.method ?? scan.fp_review_method,
      scan.fp_review_method_selection,
    ),
    detail: fpReviewTotal > 0
      ? `${fpReviewProcessed}/${fpReviewTotal} 已复核`
      : fpReviewTargetCount > 0
        ? "等待正报复核"
        : "当前没有复核目标",
    status: isFpReviewing
      ? "running"
      : fpReviewDone
        ? "done"
        : fpReview?.status === "error"
          ? "error"
          : fpReview?.status === "cancelled"
            ? "cancelled"
            : isDone && fpReviewTargetCount === 0
              ? "skipped"
              : "pending",
    active: activeTab === "fp_review",
    tone: "amber",
  };
  const validationNode: FlowNodeView = {
    id: "validation",
    label: "漏洞验证",
    detail: validationDetail,
    status: validationRunningCount > 0
      ? "running"
      : validationDone
        ? "done"
        : isDone && confirmedCount === 0
          ? "skipped"
          : "pending",
    active: activeTab === "validation",
    tone: "purple",
  };

  const engineNode = (engine: MiningEngineSelection): FlowNodeView => {
    const run = miningEngineRun(scan, engine.engine_id);
    const legacyStaticStatus: FlowNodeStatus = scan.status === "auditing"
      ? "running"
      : scan.total_candidates > 0 && scan.processed_candidates >= scan.total_candidates
        ? "done"
        : staticNodeStatus === "error" || staticNodeStatus === "cancelled"
          ? staticNodeStatus
          : "pending";
    const threatRunStatus = engine.engine_id === THREAT_ENGINE_ID
      ? threatAuditFlowStatus(scan, run)
      : null;
    const label = engine.engine_id === STATIC_ENGINE_ID
      ? "候选点审计"
      : engine.engine_id === THREAT_ENGINE_ID
        ? "威胁审计"
        : engine.engine_label;
    const detail = engine.engine_id === THREAT_ENGINE_ID
      ? threatTasks.length > 0
        ? `${activeThreatTasks} 运行 · ${completedThreatTasks}/${threatTasks.length} 完成${failedThreatTasks ? ` · ${failedThreatTasks} 未成功` : ""}`
        : scan.threat_analysis
          ? "等待创建审计任务"
          : "等待威胁分析完成"
      : run?.error_message
        || (engine.engine_id === STATIC_ENGINE_ID && candidateCount > 0
          ? `${scan.processed_candidates}/${scan.total_candidates || candidateCount} 候选点已审计`
          : run?.started_at
            ? `引擎 ID：${engine.engine_id}`
            : "等待启动");
    return {
      id: `engine:${engine.engine_id}`,
      label,
      detail,
      status: threatRunStatus ?? (run ? engineFlowStatus(run) : engine.engine_id === STATIC_ENGINE_ID ? legacyStaticStatus : "unknown"),
      active: activeTab === "mining" && activeEngineId === engine.engine_id,
      tone: engine.engine_id === THREAT_ENGINE_ID ? "green" : engine.engine_id === STATIC_ENGINE_ID ? "cyan" : "blue",
    };
  };
  return (
    <nav className="border-t border-slate-700/60 pt-3" aria-label="扫描执行流程">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">执行流程</div>
        <div className="flex flex-wrap items-center gap-2">
          <FlowUtilityButton active={activeTab === "overview"} onClick={onHome}>
            首页
          </FlowUtilityButton>
          <FlowUtilityButton active={activeTab === "issues"} onClick={onIssues}>
            发现的问题
            <span className="ml-1.5 text-xs text-red-300">发现 {issueCount} · 已验证 {verifiedIssueCount}</span>
          </FlowUtilityButton>
        </div>
      </div>

      <div className="relative -mx-1">
        <div
          className="pointer-events-none absolute inset-y-1 left-0 z-10 w-8 bg-gradient-to-r from-slate-900/90 to-transparent xl:hidden"
          aria-hidden="true"
        />
        <div
          className="pointer-events-none absolute inset-y-1 right-0 z-10 w-8 bg-gradient-to-l from-slate-900/90 to-transparent xl:hidden"
          aria-hidden="true"
        />
        <div
          className="overflow-x-auto overscroll-x-contain rounded-xl border border-slate-700/50 bg-slate-900/35 px-2 py-3 shadow-inner scroll-smooth snap-x snap-proximity focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400/60 motion-reduce:scroll-auto sm:px-3"
          tabIndex={0}
          aria-label="执行流程图，可横向滚动"
        >
          <div className="mx-auto w-max min-w-[68rem] px-4">
            <div className="flex items-center justify-center">
              <div
                className="flex flex-col gap-2 rounded-xl border border-slate-700/60 bg-slate-950/40 p-2"
                role="group"
                aria-label="分析阶段"
              >
                <div className="px-1 text-center text-xs font-semibold text-slate-400">分析阶段</div>
                <FlowNodeButton node={staticNode} onClick={onNodeClick} />
                <FlowNodeButton node={threatAnalysisNode} onClick={onNodeClick} />
              </div>
              <FlowArrow label="分析结果" />
              <div
                role="group"
                aria-label="漏洞挖掘"
                className="relative flex-none rounded-xl border border-cyan-500/25 bg-gradient-to-br from-slate-950/80 via-slate-900/60 to-cyan-950/20 px-3 pb-3 pt-9 shadow-sm"
              >
                <div className="absolute inset-x-3 top-2 text-center text-sm font-semibold text-slate-100">
                  漏洞挖掘 · {engines.length} 个引擎
                </div>
                <div className="flex w-[22rem] flex-col gap-2">
                  {engines.length > 0 ? engines.map((engine) => (
                    <div key={engine.engine_id} className="rounded-lg border border-cyan-500/15 bg-cyan-500/5 p-2">
                      <FlowNodeButton node={engineNode(engine)} onClick={onNodeClick} wide />
                    </div>
                  )) : (
                    <div className="flex h-[5.75rem] items-center justify-center rounded-lg border border-dashed border-slate-700 px-4 text-center text-sm text-slate-500">
                      本次扫描未选择漏洞挖掘引擎
                    </div>
                  )}
                </div>
              </div>
              <FlowArrow label="确认问题" />
              <div
                className="flex flex-col gap-2 rounded-xl border border-slate-700/60 bg-slate-950/40 p-2"
                role="group"
                aria-label="结果处理阶段"
              >
                <div className="px-1 text-center text-xs font-semibold text-slate-400">结果处理</div>
                <FlowNodeButton node={validationNode} onClick={onNodeClick} />
                <FlowNodeButton node={fpReviewNode} onClick={onNodeClick} />
              </div>
            </div>
            <div className="relative mt-4 pt-4">
              <div className="absolute left-1/2 top-0 h-4 w-px bg-slate-600" aria-hidden="true" />
              <div
                className="rounded-xl border border-blue-500/25 bg-gradient-to-r from-blue-950/25 via-slate-950/65 to-blue-950/25 p-2"
                role="group"
                aria-label="扫描底层能力"
              >
                <div className="mb-2 text-center text-xs font-semibold uppercase tracking-wider text-blue-300/80">
                  底层能力 · 支撑全部业务阶段
                </div>
                <FlowNodeButton node={indexNode} onClick={onNodeClick} wide />
              </div>
            </div>
          </div>
        </div>
      </div>
    </nav>
  );
}

function FlowUtilityButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-current={active ? "page" : undefined}
      className={`rounded-lg border px-3 py-1.5 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400/70 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-900 motion-reduce:transition-none ${
        active
          ? "border-blue-500/50 bg-blue-500/15 text-blue-100"
          : "border-slate-700 bg-slate-800/60 text-slate-300 hover:bg-slate-700"
      }`}
    >
      {children}
    </button>
  );
}

function FlowNodeButton({
  node,
  onClick,
  compact = false,
  wide = false,
}: {
  node: FlowNodeView;
  onClick: (node: FlowNodeId) => void;
  compact?: boolean;
  wide?: boolean;
}) {
  const statusTone = flowStatusTone(node.status, node.tone);
  const condensed = compact || wide;
  const sizeClass = compact
    ? "h-[4.75rem] w-36"
    : wide
      ? "h-[4.75rem] w-full"
      : "min-h-[5.5rem] w-44";
  return (
    <button
      type="button"
      onClick={() => onClick(node.id)}
      aria-current={node.active ? "step" : undefined}
      aria-label={`${node.label}，${flowStatusLabel(node.status)}，${node.detail}`}
      className={`${sizeClass} snap-center rounded-lg border px-3 ${condensed ? "py-1.5" : "py-2"} text-left transition-[background-color,border-color,box-shadow,transform] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400/80 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-900 motion-safe:hover:-translate-y-0.5 motion-reduce:transition-none ${
        node.active
          ? `${toneBorder(node.tone)} ${toneBg(node.tone)} ring-1 ring-current/20`
          : "border-slate-700 bg-slate-900/70 hover:border-slate-600 hover:bg-slate-800/80"
      }`}
      title={`${node.label} · ${flowStatusLabel(node.status)} · ${node.detail}`}
    >
      <div className="flex items-start justify-between gap-2">
        <span className={`break-words text-sm font-semibold ${node.active ? toneText(node.tone) : "text-slate-100"}`}>
          {node.label}
        </span>
        {node.status === "running" && (
          <span className="mt-0.5 h-3 w-3 shrink-0 rounded-full border border-blue-500/30 border-t-blue-300 animate-spin motion-reduce:animate-none" aria-hidden="true" />
        )}
      </div>
      <div className={`${condensed ? "mt-1" : "mt-2"} flex flex-wrap items-center gap-1.5`}>
        <StatusPill label={flowStatusLabel(node.status)} tone={statusTone} />
      </div>
      <div className={`${condensed ? "mt-0.5 truncate leading-4" : "mt-2 line-clamp-2 leading-5"} text-xs text-slate-400`}>
        {node.detail}
      </div>
    </button>
  );
}

function FlowArrow({ label, compact = false }: { label?: string; compact?: boolean }) {
  return (
    <div
      className={`relative flex shrink-0 items-center ${compact ? "w-6" : "w-8"}`}
      aria-hidden="true"
    >
      {label && !compact && (
        <span className="absolute -top-5 left-1/2 -translate-x-1/2 whitespace-nowrap text-[10px] font-medium tracking-wide text-slate-500">
          {label}
        </span>
      )}
      <div className="h-px flex-1 bg-slate-600" />
      <svg className="h-4 w-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
      </svg>
    </div>
  );
}

function flowStatusLabel(status: FlowNodeStatus): string {
  if (status === "running") return "正在执行";
  if (status === "done") return "执行完毕";
  if (status === "warning") return "完成但有失败";
  if (status === "error") return "执行失败";
  if (status === "cancelled") return "已取消";
  if (status === "skipped") return "已跳过";
  if (status === "unknown") return "状态未知";
  return "待执行";
}

function flowStatusTone(status: FlowNodeStatus, doneTone: TaskTone): TaskTone {
  if (status === "running") return "blue";
  if (status === "done") return doneTone;
  if (status === "warning") return "amber";
  if (status === "error" || status === "cancelled") return "red";
  return "slate";
}

function GenericEnginePanel({
  engine,
  run,
  children,
}: {
  engine: MiningEngineSelection;
  run: MiningEngineRunStatus | null;
  children: React.ReactNode;
}) {
  const status = engineFlowStatus(run);
  const duration = engineRunDuration(run);
  return (
    <TaskPanel
      title={engine.engine_label}
      status={flowStatusLabel(status)}
      tone={flowStatusTone(status, "green")}
      summary={`漏洞挖掘引擎 ${engine.engine_id} 的运行状态和输出结果。`}
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <EngineInfoCard label="引擎 ID" value={engine.engine_id} detail="扫描配置快照" tone="cyan" />
        <EngineInfoCard
          label="开始时间"
          value={run?.started_at ? formatDateTime(run.started_at) : "-"}
          detail={run?.started_at ? "引擎已启动" : "尚未启动"}
          tone="blue"
        />
        <EngineInfoCard
          label="运行耗时"
          value={duration || "-"}
          detail={run?.finished_at ? "已结束" : run?.started_at ? "执行中" : "等待运行"}
          tone="purple"
        />
      </div>
      {run?.error_message && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3">
          <div className="text-xs font-semibold text-red-200">引擎错误</div>
          <div className="mt-1 whitespace-pre-wrap break-words text-sm text-red-300">{run.error_message}</div>
        </div>
      )}
      <section>
        <h3 className="mb-3 text-sm font-semibold text-slate-200">该引擎输出的问题</h3>
        {children}
      </section>
    </TaskPanel>
  );
}

function EngineInfoCard({
  label,
  value,
  detail,
  tone,
}: {
  label: string;
  value: string;
  detail: string;
  tone: TaskTone;
}) {
  return (
    <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
      <div className="text-xs text-slate-500">{label}</div>
      <div className={`mt-1 break-all text-sm font-semibold ${toneText(tone)}`}>{value}</div>
      <div className="mt-1 text-xs text-slate-600">{detail}</div>
    </div>
  );
}

function engineRunDuration(run: MiningEngineRunStatus | null): string {
  if (!run?.started_at) return "";
  const started = Date.parse(run.started_at);
  const finished = Date.parse(run.finished_at || new Date().toISOString());
  if (Number.isNaN(started) || Number.isNaN(finished)) return "";
  const seconds = Math.max(0, Math.round((finished - started) / 1000));
  if (seconds < 60) return `${seconds} 秒`;
  const minutes = Math.floor(seconds / 60);
  const remaining = seconds % 60;
  return `${minutes} 分 ${remaining} 秒`;
}

function ThreatAuditPanel({
  scan,
  events,
}: {
  scan: ScanStatusType;
  events: ScanEvent[];
}) {
  const [statusFilter, setStatusFilter] = useState("__all__");
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const tasks = scan.threat_audit_tasks ?? [];
  const queueTasks = useMemo(
    () => collectScanQueueTasks(scan.opencode_pool ?? null).filter(
      (item) => isThreatAuditPoolTask(item.task),
    ),
    [scan.opencode_pool],
  );
  const runtimeByTaskId = useMemo(() => {
    const result = new Map<string, ScanQueueTask>();
    for (const item of queueTasks) {
      const taskName = String(item.task.task_name || "");
      if (taskName && !result.has(taskName)) result.set(taskName, item);
    }
    return result;
  }, [queueTasks]);
  const visibleTasks = useMemo(
    () => tasks.filter((task) => (
      statusFilter === "__all__"
      || effectiveThreatAuditTaskStatus(task, runtimeByTaskId.get(task.task_id)) === statusFilter
    )),
    [tasks, runtimeByTaskId, statusFilter],
  );
  const totalPages = Math.max(1, Math.ceil(visibleTasks.length / THREAT_AUDIT_PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const pagedTasks = visibleTasks.slice(
    (safePage - 1) * THREAT_AUDIT_PAGE_SIZE,
    safePage * THREAT_AUDIT_PAGE_SIZE,
  );
  const selected = tasks.find((task) => task.task_id === selectedTaskId) ?? null;
  const selectedRuntime = selected ? runtimeByTaskId.get(selected.task_id) ?? null : null;
  const statusCounts = useMemo(() => {
    const counts = new Map<string, number>();
    tasks.forEach((task) => {
      const status = effectiveThreatAuditTaskStatus(task, runtimeByTaskId.get(task.task_id));
      counts.set(status, (counts.get(status) ?? 0) + 1);
    });
    return counts;
  }, [tasks, runtimeByTaskId]);
  const run = miningEngineRun(scan, THREAT_ENGINE_ID);
  const processStatus = threatAuditFlowStatus(scan, run);

  useEffect(() => {
    setPage(1);
  }, [statusFilter]);

  useEffect(() => {
    if (visibleTasks.length === 0) {
      setSelectedTaskId(null);
      return;
    }
    if (!selectedTaskId || !visibleTasks.some((task) => task.task_id === selectedTaskId)) {
      setSelectedTaskId(visibleTasks[0].task_id);
    }
  }, [selectedTaskId, visibleTasks]);

  return (
    <TaskPanel
      title="威胁审计"
      status={flowStatusLabel(processStatus)}
      tone={flowStatusTone(processStatus, "green")}
      summary="按威胁分析产生的节点与攻击模式拆分任务，并逐项执行模型审计。"
    >
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
        <MiniMetric label="任务总数" value={tasks.length} />
        <MiniMetric label="待执行" value={(statusCounts.get("pending") ?? 0) + (statusCounts.get("queued") ?? 0)} tone="amber" />
        <MiniMetric label="运行中" value={statusCounts.get("running") ?? 0} tone="cyan" />
        <MiniMetric label="已完成" value={statusCounts.get("completed") ?? 0} tone="green" />
        <MiniMetric
          label="未成功"
          value={["failed", "failure", "error", "timeout", "no_result"].reduce(
            (sum, status) => sum + (statusCounts.get(status) ?? 0),
            0,
          )}
          tone="red"
        />
        <MiniMetric label="已取消" value={statusCounts.get("cancelled") ?? 0} />
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <StaticFilterSelect
          label="状态"
          value={statusFilter}
          options={threatAuditStatusOptions(tasks, runtimeByTaskId)}
          onChange={setStatusFilter}
        />
      </div>

      {tasks.length === 0 ? (
        <div className="rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-10 text-center text-sm text-slate-500">
          {run?.status === "running"
            ? "威胁分析完成后会在这里实时创建审计任务。"
            : run?.status === "success"
              ? "本次威胁分析没有生成需要审计的任务。"
              : "尚未创建威胁审计任务。"}
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(20rem,26rem)_1fr]">
          <div className="flex min-h-[28rem] flex-col overflow-hidden rounded-xl border border-slate-700 bg-slate-900/40">
            <div className="max-h-[72vh] flex-1 overflow-y-auto">
              {pagedTasks.length === 0 ? (
                <div className="px-4 py-10 text-center text-sm text-slate-500">当前筛选条件下无任务</div>
              ) : (
                <ul className="divide-y divide-slate-800">
                  {pagedTasks.map((task) => {
                    const status = effectiveThreatAuditTaskStatus(task, runtimeByTaskId.get(task.task_id));
                    return (
                      <li key={task.task_id}>
                        <button
                          type="button"
                          onClick={() => setSelectedTaskId(task.task_id)}
                          className={`w-full px-3 py-3 text-left transition-colors ${
                            selectedTaskId === task.task_id
                              ? "bg-cyan-500/15"
                              : status === "running"
                                ? "bg-blue-500/10 hover:bg-blue-500/15"
                                : "hover:bg-slate-800/60"
                          }`}
                        >
                          <div className="flex items-start gap-2">
                            <StatusPill label={threatAuditStatusLabel(status)} tone={threatAuditStatusTone(status)} />
                            <div className="min-w-0">
                              <div className="truncate text-sm font-medium text-slate-200">
                                {task.method_name || "未命名攻击模式"}
                              </div>
                              <div className="mt-1 truncate text-xs text-slate-500">
                                {task.surface_name || "未命名威胁节点"}
                              </div>
                            </div>
                            {status === "running" && (
                              <span className="ml-auto mt-1 h-3 w-3 shrink-0 rounded-full border border-blue-500/30 border-t-blue-300 animate-spin" />
                            )}
                          </div>
                          {(task.code_path || task.code_paths?.length) && (
                            <div className="mt-2 truncate font-mono text-[11px] text-cyan-300">
                              {task.code_path || task.code_paths?.[0]?.path}
                            </div>
                          )}
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
            {visibleTasks.length > THREAT_AUDIT_PAGE_SIZE && (
              <div className="flex items-center justify-between gap-2 border-t border-slate-800 px-3 py-2">
                <button
                  type="button"
                  disabled={safePage === 1}
                  onClick={() => setPage((value) => Math.max(1, value - 1))}
                  className="rounded-lg border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-30"
                >
                  上一页
                </button>
                <span className="text-xs text-slate-500">第 {safePage}/{totalPages} 页 · 共 {visibleTasks.length} 条</span>
                <button
                  type="button"
                  disabled={safePage === totalPages}
                  onClick={() => setPage((value) => Math.min(totalPages, value + 1))}
                  className="rounded-lg border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-30"
                >
                  下一页
                </button>
              </div>
            )}
          </div>

          <div className="min-h-[28rem] rounded-xl border border-slate-700 bg-slate-900/40">
            {selected ? (
              <ThreatAuditTaskDetail task={selected} runtime={selectedRuntime} />
            ) : (
              <div className="flex h-full items-center justify-center px-4 py-16 text-sm text-slate-500">
                从左侧选择一个威胁审计任务查看详情
              </div>
            )}
          </div>
        </div>
      )}
      <EventList events={events} empty="暂无威胁审计日志" />
    </TaskPanel>
  );
}

function threatAuditStatusOptions(
  tasks: ThreatAuditTask[],
  runtimeByTaskId: Map<string, ScanQueueTask>,
): StaticFilterOption[] {
  const values = tasks.map((task) => {
    return effectiveThreatAuditTaskStatus(task, runtimeByTaskId.get(task.task_id));
  });
  return valueOptions(values, threatAuditStatusLabel);
}

function effectiveThreatAuditTaskStatus(
  task: ThreatAuditTask,
  runtime: ScanQueueTask | undefined,
): string {
  if (runtime?.status === "running") return "running";
  if (runtime?.status === "queued" || runtime?.status === "planned") return "queued";
  return String(task.status || "pending").toLowerCase();
}

function threatAuditStatusLabel(status: string): string {
  const labels: Record<string, string> = {
    pending: "待执行",
    planned: "计划中",
    queued: "排队中",
    running: "运行中",
    completed: "已完成",
    success: "已完成",
    failed: "失败",
    failure: "失败",
    error: "异常",
    timeout: "超时",
    no_result: "无结果",
    cancelled: "已取消",
  };
  return labels[status] ?? status;
}

function threatAuditStatusTone(status: string): TaskTone {
  if (status === "running") return "cyan";
  if (status === "queued" || status === "planned") return "amber";
  if (status === "completed" || status === "success") return "green";
  if (["failed", "failure", "error", "timeout", "no_result", "cancelled"].includes(status)) return "red";
  return "slate";
}

function ThreatAuditTaskDetail({
  task,
  runtime,
}: {
  task: ThreatAuditTask;
  runtime: ScanQueueTask | null;
}) {
  const prompt = runtime ? scanQueueTaskPrompt(runtime.task) : "";
  const sessionId = runtime ? scanQueueTaskSessionId(runtime.task) : "";
  const tokenUsage = runtime ? taskTokenUsage(runtime.task) : null;
  const source = formatOutputSource(task.output_source);
  const codePaths = task.code_paths ?? [];
  const status = effectiveThreatAuditTaskStatus(task, runtime ?? undefined);
  return (
    <div className="max-h-[72vh] space-y-4 overflow-y-auto p-4">
      <div className="border-b border-slate-800 pb-3">
        <div className="flex flex-wrap items-center gap-2">
          <StatusPill label={threatAuditStatusLabel(status)} tone={threatAuditStatusTone(status)} />
          <span className="text-sm font-semibold text-slate-100">{task.method_name || "未命名攻击模式"}</span>
        </div>
        <div className="mt-2 break-all font-mono text-[11px] text-slate-600">{task.task_id}</div>
      </div>
      <ThreatAuditDetailSection title="审计目标">
        <DetailGrid items={[
          ["威胁节点", task.surface_name || task.surface_node_id || "—"],
          ["攻击模式", task.method_name || task.method_node_id || "—"],
          ["攻击目标", task.attack_goal || "—"],
          ["价值资产", task.asset_name || task.asset_id || "—"],
          ["风险", task.risk_name || task.risk_id || "—"],
          ["攻击路径", task.attack_path_id || "—"],
        ]} />
      </ThreatAuditDetailSection>
      {(task.description || task.code_path_description) && (
        <ThreatAuditDetailSection title="任务说明">
          <MarkdownContent content={task.description || task.code_path_description || ""} />
        </ThreatAuditDetailSection>
      )}
      {(task.code_path || codePaths.length > 0) && (
        <ThreatAuditDetailSection title="代码路径">
          <div className="space-y-2">
            {(codePaths.length > 0 ? codePaths : [{ path: task.code_path, description: task.code_path_description }]).map((item, index) => (
              <div key={`${item.path}-${index}`} className="rounded border border-slate-800 bg-slate-950/60 px-3 py-2">
                <div className="break-all font-mono text-xs text-cyan-300">{item.path}</div>
                {item.description && <div className="mt-1 text-xs text-slate-400">{item.description}</div>}
              </div>
            ))}
          </div>
        </ThreatAuditDetailSection>
      )}
      {task.failure_reason && (
        <ThreatAuditDetailSection title="失败原因">
          <div className="whitespace-pre-wrap break-words rounded border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300">
            {task.failure_reason}
          </div>
        </ThreatAuditDetailSection>
      )}
      <ThreatAuditDetailSection title="执行信息">
        <DetailGrid items={[
          ["模型", runtime?.modelId || task.output_source?.model || task.output_source?.model_id || "—"],
          ["OpenCode Session ID", sessionId || "尚无记录"],
          ["开始时间", task.started_at ? formatDateTime(task.started_at) : "—"],
          ["结束时间", task.finished_at ? formatDateTime(task.finished_at) : "—"],
          ["输出来源", source || "—"],
          ["结果索引", task.result_vuln_indexes?.length ? task.result_vuln_indexes.map((value) => `#${value}`).join("、") : "无漏洞结果"],
        ]} />
      </ThreatAuditDetailSection>
      {tokenUsage && (
        <ThreatAuditDetailSection title="Token 用量">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            {[
              ["输入", tokenUsage.input_tokens],
              ["输出", tokenUsage.output_tokens],
              ["推理", tokenUsage.reasoning_tokens],
              ["缓存读", tokenUsage.cache_read_tokens],
              ["缓存写", tokenUsage.cache_write_tokens],
              ["总计", tokenUsage.total_tokens],
            ].map(([label, value]) => (
              <MiniMetric key={String(label)} label={String(label)} value={Number(value)} />
            ))}
          </div>
        </ThreatAuditDetailSection>
      )}
      <ThreatAuditDetailSection title="Prompt">
        {prompt ? (
          <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words rounded border border-slate-800 bg-slate-950 p-3 font-mono text-xs leading-relaxed text-slate-300">
            {prompt}
          </pre>
        ) : (
          <div className="rounded border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-500">
            {runtime ? "该任务记录未保存完整 Prompt。" : "尚未匹配到该任务的 OpenCode 队列或历史记录。"}
          </div>
        )}
      </ThreatAuditDetailSection>
    </div>
  );
}

function ThreatAuditDetailSection({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section>
      <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">{title}</h4>
      {children}
    </section>
  );
}

function DetailGrid({ items }: { items: Array<[string, string]> }) {
  return (
    <dl className="grid grid-cols-1 gap-2 sm:grid-cols-2">
      {items.map(([label, value]) => (
        <div key={label} className="rounded border border-slate-800 bg-slate-950/60 px-3 py-2">
          <dt className="text-[10px] uppercase tracking-wide text-slate-600">{label}</dt>
          <dd className="mt-1 break-all text-xs text-slate-300">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function ScanOverview({
  scan,
  issueCount,
  continuableCount,
  variantIssueCount,
  gitHistoryCount,
  showGitHistoryStages,
  currentStage,
  indexProgress,
  pct,
  isRunning,
  isDone,
  fpReview,
  isFpReviewing,
  currentFpReviewTargets,
  hasReportModeSkill,
  verifiedIssueCount,
  onNavigate,
}: {
  scan: ScanStatusType;
  issueCount: number;
  continuableCount: number;
  variantIssueCount: number;
  gitHistoryCount: number;
  showGitHistoryStages: boolean;
  currentStage: string;
  indexProgress: ReturnType<typeof formatIndexProgress>;
  pct: number;
  isRunning: boolean;
  isDone: boolean;
  fpReview: FpReviewJob | null;
  isFpReviewing: boolean;
  currentFpReviewTargets: Vulnerability[];
  hasReportModeSkill: boolean;
  verifiedIssueCount: number;
  onNavigate: (tab: MainTab) => void;
}) {
  const engines = effectiveMiningEngines(scan);
  const staticEngineSelected = engines.some((engine) => engine.engine_id === STATIC_ENGINE_ID);
  const staticEngineRun = miningEngineRun(scan, STATIC_ENGINE_ID);
  const staticAnalysisDone = scan.static_analysis_done || (
    scan.status === "complete" && staticEngineRun?.status !== "error"
  );
  const auditRunning = scan.status === "auditing";
  const fpReviewTargetCount = scan.vulnerabilities.filter(isAiConfirmed).length;
  const threatAnalysisStatus = threatAnalysisFlowStatus(scan);
  const validations = scan.validations ?? [];
  const validationRunning = validations.filter((item) => item.running || ["pending", "queued", "running"].includes(item.status)).length;
  const validationFinished = validations.filter((item) => !item.running && isValidationTerminalStatus(item.status)).length;
  const target = scan.current_candidate;
  return (
    <div className="space-y-4">
      <section className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">当前扫描</div>
            <h2 className="mt-1 text-xl font-semibold text-white">{currentStage}</h2>
            <p className="mt-1 text-sm text-slate-400">
              {scan.product || scan.project_id || scan.scan_id}
              {scan.validation_environment && (
                <span className="ml-3 border-l border-slate-700 pl-3">
                  验证环境：<span className="text-slate-300">{scan.validation_environment}</span>
                </span>
              )}
              {scan.agent_name && (
                <span className="ml-3 border-l border-slate-700 pl-3">
                  Agent: <span className={scan.agent_online ? "text-green-300" : "text-slate-500"}>{scan.agent_name}</span>
                </span>
              )}
            </p>
          </div>
          <StatusPill
            label={scan.status === "complete" ? "已完成" : scan.status === "error" ? "异常" : scan.status === "cancelled" ? "已取消" : isRunning ? "运行中" : "等待"}
            tone={scan.status === "error" ? "red" : scan.status === "cancelled" ? "amber" : isDone ? "green" : "blue"}
          />
        </div>
      </section>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
        {staticEngineSelected && (
          <OverviewMetric icon="target" label="候选点" value={scan.total_candidates || scan.vulnerabilities.length} detail={`${scan.processed_candidates} 已审计`} tone="blue" />
        )}
        <OverviewMetric icon="alert" label="发现的问题" value={issueCount} detail={`${verifiedIssueCount} 已验证`} tone="red" onClick={() => onNavigate("issues")} />
        {showGitHistoryStages && (
          <OverviewMetric icon="history" label="历史模式" value={gitHistoryCount} detail={`${variantIssueCount} 个变体候选`} tone="purple" onClick={() => onNavigate("threat")} />
        )}
        <OverviewMetric
          icon="queue"
          label="任务总数"
          value={scan.opencode_pool?.total_tasks ?? scan.total_task_count}
          detail={`${scan.opencode_pool?.completed_task_count ?? scan.completed_task_count} 已执行`}
          tone="blue"
        />
        {scan.opencode_pool?.token_usage && (
          <OverviewMetric
            icon="queue"
            label="Token 总量"
            value={scan.opencode_pool.token_usage.total_tokens}
            detail={scan.opencode_pool.token_usage.complete ? "统计完整" : "统计可能有偏差"}
            tone="purple"
          />
        )}
        <OverviewMetric icon="queue" label="可续扫任务" value={continuableCount} detail={continuableCount > 0 ? "可续扫" : "无待处理项"} tone="amber" />
      </div>

      <ScanTokenUsagePanel usage={scan.opencode_pool?.token_usage ?? null} />
      <ScanTaskQueuePanel pool={scan.opencode_pool ?? null} />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1fr_22rem]">
        <section className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-200">任务进展</h3>
            <span className="text-xs text-slate-500">扫描 ID: {scan.scan_id}</span>
          </div>
          <div className="space-y-3">
            <TaskSummaryRow
              label="代码图谱构建（底层能力）"
              status={taskStateLabel(indexProgress.done, indexProgress.running, indexProgress.failed)}
              tone={indexProgress.failed ? "red" : indexProgress.done ? "green" : indexProgress.running ? "amber" : "slate"}
              progress={indexProgress.total ? percent(indexProgress.current, indexProgress.total) : undefined}
              detail={indexProgress.total ? `${indexProgress.current}/${indexProgress.total} 文件` : "等待代码图谱状态"}
            />
            <TaskSummaryRow
              label="静态分析"
              status={staticEngineSelected
                ? taskStateLabel(
                    staticAnalysisDone,
                    scan.status === "analyzing" && !staticAnalysisDone,
                    scan.status === "error" || staticEngineRun?.status === "error",
                  )
                : "已跳过"}
              tone={staticEngineSelected
                ? staticAnalysisDone ? "green" : scan.status === "analyzing" ? "cyan" : scan.status === "error" || staticEngineRun?.status === "error" ? "red" : "slate"
                : "slate"}
              progress={staticEngineSelected && scan.static_total_files ? percent(scan.static_scanned_files, scan.static_total_files) : undefined}
              detail={staticEngineSelected
                ? scan.total_candidates > 0 ? `${scan.total_candidates} 个候选点` : "等待静态规则扫描"
                : "本次扫描未选择静态候选引擎"}
            />
            <TaskSummaryRow
              label="威胁分析"
              status={flowStatusLabel(threatAnalysisStatus)}
              tone={flowStatusTone(threatAnalysisStatus, "green")}
              detail={scan.threat_analysis
                ? threatAnalysisSummary(scan.threat_analysis)
                : isThreatAnalysisSelected(scan)
                  ? scan.threat_analysis_run?.error_message || "等待生成攻击树"
                  : "本次扫描未选择威胁分析"}
            />
            {engines.map((engine) => {
              const run = miningEngineRun(scan, engine.engine_id);
              if (engine.engine_id === THREAT_ENGINE_ID) {
                const auditStatus = threatAuditFlowStatus(scan, run);
                const threatTasks = scan.threat_audit_tasks ?? [];
                const threatCompleted = threatTasks.filter((task) => task.status === "completed").length;
                return (
                  <Fragment key={engine.engine_id}>
                    <TaskSummaryRow
                      label="威胁审计"
                      status={flowStatusLabel(auditStatus)}
                      tone={flowStatusTone(auditStatus, "green")}
                      detail={threatTasks.length ? `${threatCompleted}/${threatTasks.length} 任务完成` : "等待威胁审计任务"}
                    />
                    {showGitHistoryStages && (
                      <TaskSummaryRow
                        label="Git 历史问题分析"
                        status={taskStateLabel(gitHistoryCount > 0 || hasEvent(scan.events, ["git_history"]), hasEvent(scan.events, ["git_history"]) && !auditRunning && !isDone)}
                        tone={gitHistoryCount > 0 ? "purple" : hasEvent(scan.events, ["git_history"]) ? "amber" : "slate"}
                        detail={gitHistoryCount > 0 ? `${gitHistoryCount} 条历史问题模式` : "暂无历史模式"}
                      />
                    )}
                  </Fragment>
                );
              }
              const status = run
                ? engineFlowStatus(run)
                : engine.engine_id === STATIC_ENGINE_ID && scan.static_analysis_done
                  ? "done"
                  : "pending";
              return (
                <TaskSummaryRow
                  key={engine.engine_id}
                  label={engine.engine_id === STATIC_ENGINE_ID ? "候选点审计" : engine.engine_label}
                  status={flowStatusLabel(status)}
                  tone={flowStatusTone(status, "green")}
                  progress={engine.engine_id === STATIC_ENGINE_ID && scan.total_candidates ? pct : undefined}
                  detail={run?.error_message || (
                    engine.engine_id === STATIC_ENGINE_ID
                      ? scan.total_candidates
                        ? `${scan.processed_candidates}/${scan.total_candidates} 候选点已审计`
                        : "等待静态分析候选点"
                      : `引擎 ID：${engine.engine_id}`
                  )}
                />
              );
            })}
            <TaskSummaryRow
              label="漏洞验证"
              status={validationRunning > 0
                ? "进行中"
                : validationFinished > 0
                  ? "完成"
                  : fpReviewTargetCount > 0
                    ? "等待"
                    : "无目标"}
              tone={validationRunning > 0 ? "purple" : validationFinished > 0 ? "green" : "slate"}
              progress={fpReviewTargetCount > 0 ? percent(validationFinished, fpReviewTargetCount) : undefined}
              detail={fpReviewTargetCount > 0
                ? `${validationFinished}/${fpReviewTargetCount} 已完成`
                : "当前没有待验证问题"}
            />
            <TaskSummaryRow
              label={fpReviewMethodLabel(
                fpReview?.method ?? scan.fp_review_method,
                scan.fp_review_method_selection,
              )}
              status={fpReview
                ? taskStateLabel(fpReview.status === "complete", isFpReviewing, fpReview.status === "error")
                : fpReviewTargetCount > 0 ? "等待" : "无目标"}
              tone={isFpReviewing ? "amber" : fpReview?.status === "complete" ? "green" : fpReview?.status === "error" ? "red" : "slate"}
              progress={fpReview?.total ? percent(fpReview.processed, fpReview.total) : undefined}
              detail={fpReview
                ? `${fpReview.processed}/${fpReview.total} 已复核`
                : fpReviewTargetCount > 0
                  ? `${fpReviewTargetCount} 个可复核问题`
                  : "当前没有可复核问题"}
            />
            <TaskSummaryRow
              label="报告导出"
              status={hasReportModeSkill ? (isRunning ? "同步中" : "可查看") : "预留"}
              tone={hasReportModeSkill ? "purple" : "slate"}
              detail={hasReportModeSkill ? `${scan.skill_reports?.length ?? 0} 个 SKILL 报告` : "可使用顶部导出按钮"}
            />
          </div>
        </section>

        <aside className="space-y-4">
          <section className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
            <h3 className="text-sm font-semibold text-slate-200">当前目标</h3>
            {target ? (
              <div className="mt-3 rounded-lg border border-blue-500/30 bg-blue-500/10 p-3">
                <div className="font-mono text-xs text-blue-100">{target.file}:{target.line}</div>
                <div className="mt-1 truncate font-mono text-xs text-slate-400">{target.function}</div>
                <div className="mt-2 text-xs text-slate-300">{target.vuln_type.toUpperCase()}</div>
              </div>
            ) : currentFpReviewTargets.length > 0 ? (
              <div className="mt-3 space-y-2">
                {currentFpReviewTargets.map((item, index) => (
                  <div key={`${index}:${item.file}:${item.line}:${item.function}`} className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3">
                    <div className="font-mono text-xs text-amber-100">{vulnerabilityLocation(item)}</div>
                    <div className="mt-1 truncate font-mono text-xs text-slate-400">{vulnerabilityFunctionLabel(item)}</div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="mt-2 text-sm text-slate-500">当前没有正在处理的候选。</p>
            )}
          </section>
          <section className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
            <h3 className="text-sm font-semibold text-slate-200">模型池</h3>
            <div className="mt-3 grid grid-cols-2 gap-2">
              <MiniMetric label="运行中" value={scan.opencode_pool?.global_running ?? 0} tone="cyan" />
              <MiniMetric label="排队中" value={scan.opencode_pool?.global_queued ?? 0} tone="amber" />
            </div>
          </section>
        </aside>
      </div>
    </div>
  );
}

function ScanTokenUsagePanel({ usage }: { usage: OpenCodeTokenUsage | null }) {
  if (!usage) {
    return <section className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
      <h3 className="text-sm font-semibold text-slate-200">Token 统计</h3>
      <p className="mt-2 text-xs text-slate-500">暂无统计。升级前创建的扫描不会回填 Token 用量。</p>
    </section>;
  }
  const items = [
    ["输入", usage.input_tokens],
    ["输出", usage.output_tokens],
    ["推理", usage.reasoning_tokens],
    ["缓存读取", usage.cache_read_tokens],
    ["缓存写入", usage.cache_write_tokens],
    ["总计", usage.total_tokens],
  ] as const;
  return <section className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <div>
        <h3 className="text-sm font-semibold text-slate-200">Token 统计</h3>
        <p className="mt-1 text-xs text-slate-500">包含主会话、子会话、重试与 JSON 修正调用。</p>
      </div>
      {!usage.complete && <StatusPill label="统计可能不完整" tone="amber" />}
    </div>
    <div className="mt-4 grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-6">
      {items.map(([label, value]) => <div key={label} className="rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2">
        <div className="text-[11px] text-slate-500">{label}</div>
        <div className="mt-1 font-mono text-sm text-slate-200">{formatTokenCount(value)}</div>
      </div>)}
    </div>
    {usage.by_model.length > 1 && <div className="mt-3 flex flex-wrap gap-2">
      {[...usage.by_model].sort((left, right) => right.total_tokens - left.total_tokens).map((item) => (
        <span key={item.model} className="rounded border border-slate-700 bg-slate-950/60 px-2 py-1 font-mono text-[11px] text-slate-400">
          {item.model}: {formatTokenCount(item.total_tokens)}
        </span>
      ))}
    </div>}
  </section>;
}

function ScanTaskQueuePanel({ pool }: { pool: OpenCodePoolStatus | null }) {
  const [page, setPage] = useState(1);
  const [expandedTaskId, setExpandedTaskId] = useState<string | null>(null);
  const tasks = useMemo(() => collectScanQueueTasks(pool), [pool]);
  const runningCount = tasks.filter((task) => task.status === "running").length;
  const queuedCount = tasks.filter((task) => task.status === "queued").length;
  const plannedCount = tasks.filter((task) => task.status === "planned").length;
  const completedCount = tasks.filter((task) => !["planned", "queued", "running"].includes(task.status)).length;
  const unsuccessfulCount = tasks.filter((task) => ["failure", "timeout", "cancelled", "unknown"].includes(task.status)).length;
  const totalPages = Math.max(1, Math.ceil(tasks.length / SCAN_QUEUE_PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const pagedTasks = tasks.slice((safePage - 1) * SCAN_QUEUE_PAGE_SIZE, safePage * SCAN_QUEUE_PAGE_SIZE);
  const toggleTask = (taskId: string) => {
    setExpandedTaskId((current) => (current === taskId ? null : taskId));
  };

  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  useEffect(() => {
    if (expandedTaskId && !tasks.some((task) => scanQueueTaskKey(task) === expandedTaskId)) {
      setExpandedTaskId(null);
    }
  }, [expandedTaskId, tasks]);

  return (
    <section className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-slate-200">任务队列</h3>
          <p className="mt-1 text-xs text-slate-500">
            当前扫描的 OpenCode Session 计划、排队、运行和历史任务
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <StatusPill label={`计划中 ${plannedCount}`} tone="slate" />
          <StatusPill label={`排队中 ${queuedCount}`} tone="amber" />
          <StatusPill label={`运行中 ${runningCount}`} tone="cyan" />
          <StatusPill label={`已执行 ${completedCount}`} tone="green" />
          {unsuccessfulCount > 0 && <StatusPill label={`未成功 ${unsuccessfulCount}`} tone="red" />}
        </div>
      </div>

      {tasks.length === 0 ? (
        <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-6 text-center text-sm text-slate-500">
          当前扫描还没有 OpenCode 任务记录
        </div>
      ) : (
        <div className="mt-4 overflow-hidden rounded-lg border border-slate-800">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[52rem] text-sm">
              <thead className="bg-slate-950/70">
                <tr>
                  <th className={thCls}>状态</th>
                  <th className={thCls}>任务</th>
                  <th className={thCls}>目标</th>
                  <th className={thCls}>模型</th>
                  <th className={thCls}>时间</th>
                </tr>
              </thead>
              <tbody>
                {pagedTasks.map((task) => {
                  const taskKey = scanQueueTaskKey(task);
                  const isExpanded = expandedTaskId === taskKey;
                  const prompt = scanQueueTaskPrompt(task.task);
                  const promptLength = scanQueueTaskPromptLength(task.task, prompt);
                  const failureReason = typeof task.task.failure_reason === "string"
                    ? task.task.failure_reason.trim()
                    : "";
                  const blockedReason = typeof task.task.blocked_reason === "string"
                    ? task.task.blocked_reason.trim()
                    : "";
                  const sessionId = scanQueueTaskSessionId(task.task);
                  const tokenUsage = taskTokenUsage(task.task);
                  const isTerminal = !["planned", "queued", "running"].includes(task.status);
                  return (
                    <Fragment key={taskKey}>
                      <tr
                        className="cursor-pointer border-t border-slate-800/70 transition-colors hover:bg-slate-800/40 focus-within:bg-slate-800/40"
                        onClick={() => toggleTask(taskKey)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            toggleTask(taskKey);
                          }
                        }}
                        tabIndex={0}
                        aria-expanded={isExpanded}
                      >
                        <td className="px-3 py-3 align-top">
                          <StatusPill label={scanQueueStatusLabel(task.status)} tone={scanQueueStatusTone(task.status)} />
                        </td>
                        <td className="px-3 py-3 align-top">
                          <div className="flex items-start gap-2">
                            <span
                              className={`mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded border border-slate-700 text-slate-400 transition-transform ${isExpanded ? "rotate-90" : ""}`}
                              aria-hidden="true"
                            >
                              <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="m9 5 7 7-7 7" />
                              </svg>
                            </span>
                            <div className="min-w-0">
                              <div className="font-medium text-slate-200">{scanQueueTaskTitle(task.task)}</div>
                              {task.scopeId && (
                                <div className="mt-1 font-mono text-[11px] text-slate-600">{task.scopeId}</div>
                              )}
                            </div>
                          </div>
                        </td>
                        <td className="max-w-[28rem] px-3 py-3 align-top">
                          <div className="truncate font-mono text-xs text-slate-400" title={scanQueueTaskTarget(task.task)}>
                            {scanQueueTaskTarget(task.task) || "-"}
                          </div>
                        </td>
                        <td className="px-3 py-3 align-top text-xs text-slate-400">
                          {task.modelId || "-"}
                        </td>
                        <td className="px-3 py-3 align-top text-xs text-slate-500">
                          {formatDateTime(task.timestamp)}
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr className="border-t border-slate-800/70 bg-slate-950/60">
                          <td colSpan={5} className="px-3 pb-4 pt-0">
                            <div className="space-y-3 rounded-lg border border-slate-800 bg-slate-950 p-3">
                              {failureReason && (
                                <div className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2">
                                  <div className="text-xs font-semibold text-red-200">失败原因</div>
                                  <div className="mt-1 whitespace-pre-wrap break-words text-xs leading-relaxed text-red-300">
                                    {failureReason}
                                  </div>
                                </div>
                              )}
                              {blockedReason && (
                                <div className="rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2">
                                  <div className="text-xs font-semibold text-amber-200">阻塞原因</div>
                                  <div className="mt-1 whitespace-pre-wrap break-words text-xs leading-relaxed text-amber-300">
                                    {blockedReason}
                                  </div>
                                </div>
                              )}
                              {tokenUsage && (
                                <div>
                                  <div className="mb-2 flex items-center gap-2 text-xs font-semibold text-slate-300">
                                    Token 用量
                                    {!tokenUsage.complete && <StatusPill label="可能不完整" tone="amber" />}
                                  </div>
                                  <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
                                    {[
                                      ["输入", tokenUsage.input_tokens],
                                      ["输出", tokenUsage.output_tokens],
                                      ["推理", tokenUsage.reasoning_tokens],
                                      ["缓存读", tokenUsage.cache_read_tokens],
                                      ["缓存写", tokenUsage.cache_write_tokens],
                                      ["总计", tokenUsage.total_tokens],
                                    ].map(([label, value]) => (
                                      <div key={String(label)} className="rounded-md border border-slate-800 bg-slate-900/80 px-2.5 py-2">
                                        <div className="text-[10px] text-slate-500">{label}</div>
                                        <div className="mt-1 font-mono text-xs text-slate-200">{formatTokenCount(Number(value))}</div>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                              <div>
                                <div className="mb-2 text-xs font-semibold text-slate-300">
                                  OpenCode Session ID
                                </div>
                                {sessionId ? (
                                  <div
                                    className="select-text break-all rounded-md border border-slate-800 bg-slate-900/80 px-3 py-2 font-mono text-xs text-cyan-300"
                                    title={sessionId}
                                  >
                                    {sessionId}
                                  </div>
                                ) : (
                                  <div className="rounded-md border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs text-slate-500">
                                    {isTerminal
                                      ? "该任务在 OpenCode Session 创建前结束，或历史记录未保存 Session ID。"
                                      : "OpenCode Session 尚未创建，创建后会在此显示。"}
                                  </div>
                                )}
                              </div>
                              <div>
                                <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                                  <span className="text-xs font-semibold text-slate-300">Prompt</span>
                                  {prompt && (
                                    <span className="font-mono text-[11px] text-slate-600">
                                      {promptLength} chars
                                    </span>
                                  )}
                                </div>
                                {prompt ? (
                                  <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-md border border-slate-800 bg-slate-900/80 p-3 font-mono text-xs leading-relaxed text-slate-300">
                                    {prompt}
                                  </pre>
                                ) : !["planned", "queued", "running"].includes(task.status) ? (
                                  <div className="rounded-md border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs text-slate-500">
                                    该历史任务未保存完整 Prompt{promptLength > 0 ? `，仅记录长度 ${promptLength} chars` : ""}。
                                  </div>
                                ) : (
                                  <div className="rounded-md border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs text-slate-500">
                                    完整 prompt 尚未生成，进入排队或运行后显示。
                                  </div>
                                )}
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
          {tasks.length > SCAN_QUEUE_PAGE_SIZE && (
            <div className="flex items-center justify-between gap-2 border-t border-slate-800 px-3 py-2">
              <button
                type="button"
                disabled={safePage === 1}
                onClick={() => setPage((current) => Math.max(1, current - 1))}
                className="rounded-lg border border-slate-700 px-2.5 py-1 text-xs text-slate-300 transition-colors hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-30"
              >
                上一页
              </button>
              <span className="text-xs text-slate-500">
                第 {safePage}/{totalPages} 页 · 共 {tasks.length} 条
              </span>
              <button
                type="button"
                disabled={safePage === totalPages}
                onClick={() => setPage((current) => Math.min(totalPages, current + 1))}
                className="rounded-lg border border-slate-700 px-2.5 py-1 text-xs text-slate-300 transition-colors hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-30"
              >
                下一页
              </button>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

function collectScanQueueTasks(pool: OpenCodePoolStatus | null): ScanQueueTask[] {
  if (!pool) return [];
  const out: ScanQueueTask[] = [];
  for (const [index, task] of (pool.planned_tasks ?? []).entries()) {
    out.push({
      id: String(task.planned_task_id || `planned-${index}`),
      status: "planned",
      modelId: "",
      scopeId: String(task.scope_id || pool.scope_id || ""),
      task,
      timestamp: String(task.planned_at || ""),
    });
  }
  for (const [index, task] of (pool.queued_tasks ?? []).entries()) {
    out.push({
      id: String(task.request_id || `queued-${index}`),
      status: "queued",
      modelId: "",
      scopeId: String(task.scope_id || pool.scope_id || ""),
      task,
      timestamp: String(task.queued_at || ""),
    });
  }
  for (const model of pool.models ?? []) {
    for (const [index, task] of (model.active_tasks ?? []).entries()) {
      out.push({
        id: String(task.task_id || `${model.id}-running-${index}`),
        status: "running",
        modelId: model.id,
        scopeId: String(task.scope_id || pool.scope_id || ""),
        task,
        timestamp: String(task.started_at || ""),
      });
    }
  }
  for (const [index, task] of (pool.completed_tasks ?? []).entries()) {
    const outcome = normalizeCompletedTaskOutcome(task.outcome);
    out.push({
      id: String(task.task_id || `completed-${index}`),
      status: outcome,
      modelId: String(task.model_id || task.model || ""),
      scopeId: String(task.scope_id || pool.scope_id || ""),
      task,
      timestamp: String(task.finished_at || task.started_at || ""),
    });
  }
  return out.sort((a, b) => {
    const rank = scanQueueStatusRank(a.status) - scanQueueStatusRank(b.status);
    if (rank !== 0) return rank;
    if (scanQueueStatusRank(a.status) >= 3) return compareScanQueueTime(b.timestamp, a.timestamp);
    return compareScanQueueTime(a.timestamp, b.timestamp);
  });
}

function normalizeCompletedTaskOutcome(value: unknown): ScanQueueTaskStatus {
  const outcome = String(value || "unknown");
  if (["success", "failure", "timeout", "cancelled"].includes(outcome)) {
    return outcome as ScanQueueTaskStatus;
  }
  return "unknown";
}

function scanQueueTaskKey(task: ScanQueueTask): string {
  return `${task.status}-${task.id}`;
}

function scanQueueStatusRank(status: ScanQueueTaskStatus): number {
  if (status === "running") return 0;
  if (status === "queued") return 1;
  if (status === "planned") return 2;
  return 3;
}

function compareScanQueueTime(a: string, b: string): number {
  const at = Date.parse(a);
  const bt = Date.parse(b);
  if (Number.isNaN(at) && Number.isNaN(bt)) return 0;
  if (Number.isNaN(at)) return 1;
  if (Number.isNaN(bt)) return -1;
  return at - bt;
}

function scanQueueTaskTypeLabel(task: Record<string, unknown>): string {
  const type = poolTaskType(task);
  const taskName = poolTaskName(task);
  if (type === "vulnerability_mining") {
    if (taskName.startsWith("candidate-audit-")) return "候选点审计";
    if (taskName.startsWith("project-audit-")) return "项目级审计";
    if (taskName.startsWith("threat-audit-")) return "威胁审计";
    return "漏洞挖掘";
  }
  if (type === "audit") return "候选点审计";
  if (type === "project_audit") return "项目级审计";
  if (type === "sensitive_clear") return "敏感信息清理审计";
  if (type === "report_audit") return "报告审计";
  if (type === "fp_review") return "去误报复核";
  if (type === "threat_analysis") return "威胁分析";
  if (type === "threat_audit") return "威胁审计";
  if (type === "validation" || type === "vulnerability_validation") return "漏洞验证";
  return type || "漏洞挖掘";
}

function scanQueueTaskTitle(task: Record<string, unknown>): string {
  const type = scanQueueTaskTypeLabel(task);
  const stage = task.stage ? `/${String(task.stage)}` : "";
  const checker = task.checker ? String(task.checker) : "";
  const vulnType = task.vuln_type ? String(task.vuln_type) : "";
  const revision = Number(task.revision || 1) > 1 ? `r${String(task.revision)}` : "";
  return [revision, type + stage, checker || vulnType].filter(Boolean).join(" · ");
}

function scanQueueTaskTarget(task: Record<string, unknown>): string {
  const file = task.file ? String(task.file) : "";
  const line = task.line ? `:${String(task.line)}` : "";
  const fn = task.function ? String(task.function) : "";
  const auditIndex = task.audit_index != null ? `#${String(task.audit_index)}` : "";
  const vulnIndex = task.vuln_index != null ? `漏洞 #${String(task.vuln_index)}` : "";
  return [auditIndex || vulnIndex, file ? `${file}${line}` : "", fn].filter(Boolean).join(" ");
}

function scanQueueTaskPrompt(task: Record<string, unknown>): string {
  return typeof task.prompt === "string" ? task.prompt : "";
}

function scanQueueTaskSessionId(task: Record<string, unknown>): string {
  if (typeof task.serve_session_id === "string") return task.serve_session_id.trim();
  if (task.serve_session_id == null) return "";
  return String(task.serve_session_id).trim();
}

function scanQueueTaskPromptLength(task: Record<string, unknown>, prompt: string): number {
  if (typeof task.prompt_length === "number" && Number.isFinite(task.prompt_length)) {
    return task.prompt_length;
  }
  const parsed = Number(task.prompt_length);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : prompt.length;
}

function scanQueueStatusLabel(status: ScanQueueTaskStatus): string {
  if (status === "running") return "运行中";
  if (status === "queued") return "排队中";
  if (status === "planned") return "计划中";
  if (status === "success") return "成功";
  if (status === "failure") return "失败";
  if (status === "timeout") return "超时";
  if (status === "cancelled") return "已停止";
  return "未知";
}

function scanQueueStatusTone(status: ScanQueueTaskStatus): TaskTone {
  if (status === "running") return "cyan";
  if (status === "queued") return "amber";
  if (status === "planned") return "slate";
  if (status === "success") return "green";
  if (status === "cancelled" || status === "timeout") return "amber";
  return "red";
}

function OverviewMetric({
  icon,
  label,
  value,
  detail,
  tone,
  onClick,
}: {
  icon: "target" | "alert" | "history" | "queue";
  label: string;
  value: number;
  detail: string;
  tone: TaskTone;
  onClick?: () => void;
}) {
  const content = (
    <>
      <div className={`flex h-9 w-9 items-center justify-center rounded-lg border ${toneBorder(tone)} ${toneBg(tone)} ${toneText(tone)}`}>
        <PanelIcon name={icon} />
      </div>
      <div className="min-w-0">
        <div className="text-xs text-slate-500">{label}</div>
        <div className="mt-1 flex items-baseline gap-2">
          <span className={`text-2xl font-semibold ${toneText(tone)}`}>{formatTokenCount(value)}</span>
          <span className="truncate text-xs text-slate-500">{detail}</span>
        </div>
      </div>
    </>
  );
  const cls = "flex items-center gap-3 rounded-lg border border-slate-700 bg-slate-900/50 p-4 text-left";
  if (onClick) {
    return <button type="button" onClick={onClick} className={`${cls} transition-colors hover:border-slate-600 hover:bg-slate-800/70`}>{content}</button>;
  }
  return <div className={cls}>{content}</div>;
}

function StaticTaskPanel({
  scan,
  indexProgress,
  candidates,
  vulnerabilities,
  validations,
  currentCandidate,
  processedCandidates,
  events,
}: {
  scan: ScanStatusType;
  indexProgress: ReturnType<typeof formatIndexProgress>;
  candidates: ScanCandidate[];
  vulnerabilities: Vulnerability[];
  validations: VulnerabilityValidation[];
  currentCandidate: Candidate | null;
  processedCandidates: number;
  events: ScanEvent[];
}) {
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  const [typeFilter, setTypeFilter] = useState(ALL_STATIC_FILTER);
  const [auditFilter, setAuditFilter] = useState(ALL_STATIC_FILTER);
  const [validationFilter, setValidationFilter] = useState(ALL_STATIC_FILTER);
  const [currentPage, setCurrentPage] = useState(1);
  const running = scan.status === "analyzing" && !scan.static_analysis_done;
  const seen = scan.static_analysis_done || running || scan.status === "auditing" || events.length > 0;
  const scannedFiles = seen ? (scan.static_scanned_files || indexProgress.current) : 0;
  const totalFiles = seen ? (scan.static_total_files || indexProgress.total) : 0;
  const displayedCandidates = useMemo<ScanCandidate[]>(() => {
    if (candidates.length > 0) return candidates.filter(isStaticCandidate);
    return vulnerabilities
      .filter(isStaticCandidateVulnerability)
      .map((vuln, index) => ({
        idx: index,
        file: vuln.file,
        line: vuln.line,
        function: vuln.function,
        description: vuln.description,
        vuln_type: vuln.vuln_type,
        related_functions: [],
        metadata: {},
      }));
  }, [candidates, vulnerabilities]);
  const vulnerabilityByKey = useMemo(() => {
    const out = new Map<string, { vuln: Vulnerability; index: number }>();
    vulnerabilities.forEach((vuln, index) => {
      out.set(candidateKey(vuln), { vuln, index });
    });
    return out;
  }, [vulnerabilities]);
  const validationByIndex = useMemo(
    () => new Map(validations.map((validation) => [validation.vuln_index, validation])),
    [validations],
  );
  const currentKey = currentCandidate ? candidateKey(currentCandidate) : "";
  const annotated = useMemo(
    () =>
      displayedCandidates.map((candidate) => {
        const vulnEntry = vulnerabilityByKey.get(candidateKey(candidate));
        const validation = vulnEntry ? validationByIndex.get(vulnEntry.index) : undefined;
        const auditStatus = currentKey && candidateKey(candidate) === currentKey
          ? "running"
          : vulnEntry
            ? "done"
            : "pending";
        const validationStatus = !vulnEntry || !isAiConfirmed(vulnEntry.vuln)
          ? "not_applicable"
          : validation?.running || validation?.status === "running" || validation?.status === "queued"
            ? "running"
            : validation && isValidationTerminalStatus(validation.status)
              ? isValidationFailed(validation.status) || validation.status === "failed"
                ? "failed"
                : "verified"
              : "unverified";
        return {
          candidate,
          vulnerability: vulnEntry?.vuln,
          vulnerabilityIndex: vulnEntry?.index,
          validation,
          auditStatus,
          validationStatus,
        };
      }),
    [currentKey, displayedCandidates, validationByIndex, vulnerabilityByKey],
  );
  const typeOptions = useMemo(
    () => valueOptions(displayedCandidates.map((candidate) => candidate.vuln_type), (value) => value.toUpperCase()),
    [displayedCandidates],
  );
  const auditOptions = useMemo(() => countStaticOptions(annotated.map((item) => item.auditStatus), AUDIT_FILTER_LABELS), [annotated]);
  const validationOptions = useMemo(
    () => countStaticOptions(annotated.map((item) => item.validationStatus), VALIDATION_FILTER_LABELS),
    [annotated],
  );
  const visible = useMemo(() => {
    let list = annotated;
    if (typeFilter !== ALL_STATIC_FILTER) list = list.filter((item) => item.candidate.vuln_type === typeFilter);
    if (auditFilter !== ALL_STATIC_FILTER) list = list.filter((item) => item.auditStatus === auditFilter);
    if (validationFilter !== ALL_STATIC_FILTER) list = list.filter((item) => item.validationStatus === validationFilter);
    return list;
  }, [annotated, auditFilter, typeFilter, validationFilter]);
  const totalPages = Math.max(1, Math.ceil(visible.length / STATIC_CANDIDATE_PAGE_SIZE));
  const safePage = Math.min(currentPage, totalPages);
  const paged = visible.slice((safePage - 1) * STATIC_CANDIDATE_PAGE_SIZE, safePage * STATIC_CANDIDATE_PAGE_SIZE);
  const selected = selectedIndex === null
    ? null
    : annotated.find((item) => item.candidate.idx === selectedIndex) ?? null;
  const verifiedCount = annotated.filter((item) => item.validationStatus === "verified" || item.validationStatus === "failed").length;
  const runningValidationCount = annotated.filter((item) => item.validationStatus === "running").length;

  useEffect(() => {
    setCurrentPage(1);
  }, [auditFilter, typeFilter, validationFilter]);

  useEffect(() => {
    if (visible.length === 0) {
      if (selectedIndex !== null) setSelectedIndex(null);
      return;
    }
    if (selectedIndex === null || !visible.some((item) => item.candidate.idx === selectedIndex)) {
      setSelectedIndex(visible[0].candidate.idx);
    }
  }, [selectedIndex, visible]);

  return (
    <TaskPanel
      title="静态分析"
      status={taskStateLabel(scan.static_analysis_done, running, scan.status === "error")}
      tone={scan.static_analysis_done ? "green" : running ? "cyan" : scan.status === "error" ? "red" : "slate"}
      summary="基于底层代码图谱运行静态规则，产出供漏洞挖掘阶段审计的候选点。"
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <MiniMetric label="扫描文件" value={scannedFiles} tone="cyan" />
        <MiniMetric label="总文件" value={totalFiles} />
        <MiniMetric label="候选点" value={displayedCandidates.length || scan.total_candidates} tone="blue" />
      </div>
      <ProgressBlock label="候选点生成" current={scannedFiles} total={totalFiles} fallback="等待静态分析进度" />
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <MiniMetric label="已审计" value={processedCandidates} tone="blue" />
        <MiniMetric label="验证中" value={runningValidationCount} tone="cyan" />
        <MiniMetric label="已验证" value={verifiedCount} tone="green" />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <StaticFilterSelect label="类型" value={typeFilter} options={typeOptions} onChange={setTypeFilter} />
        <StaticFilterSelect label="审计" value={auditFilter} options={auditOptions} onChange={setAuditFilter} />
        <StaticFilterSelect label="验证" value={validationFilter} options={validationOptions} onChange={setValidationFilter} />
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(18rem,24rem)_1fr]">
        <div className="flex flex-col rounded-xl border border-slate-700 bg-slate-900/40">
          <div className="max-h-[70vh] flex-1 overflow-y-auto">
            {visible.length === 0 ? (
              <div className="px-4 py-10 text-center text-sm text-slate-500">
                {displayedCandidates.length === 0 ? "暂无静态分析候选点" : "当前筛选条件下无候选点"}
              </div>
            ) : (
              <ul className="divide-y divide-slate-800">
                {paged.map((item) => (
                  <StaticCandidateListItem
                    key={item.candidate.idx}
                    item={item}
                    active={selectedIndex === item.candidate.idx}
                    onClick={() => setSelectedIndex(item.candidate.idx)}
                  />
                ))}
              </ul>
            )}
          </div>
          {visible.length > STATIC_CANDIDATE_PAGE_SIZE && (
            <div className="flex items-center justify-between gap-2 border-t border-slate-800 px-3 py-2">
              <button
                type="button"
                disabled={safePage === 1}
                onClick={() => setCurrentPage((page) => Math.max(1, page - 1))}
                className="rounded-lg border border-slate-700 px-2.5 py-1 text-xs text-slate-300 transition-colors hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-30"
              >
                上一页
              </button>
              <span className="text-xs text-slate-500">
                第 {safePage}/{totalPages} 页 · 共 {visible.length} 条
              </span>
              <button
                type="button"
                disabled={safePage === totalPages}
                onClick={() => setCurrentPage((page) => Math.min(totalPages, page + 1))}
                className="rounded-lg border border-slate-700 px-2.5 py-1 text-xs text-slate-300 transition-colors hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-30"
              >
                下一页
              </button>
            </div>
          )}
        </div>
        <div className="min-h-[20rem] rounded-xl border border-slate-700 bg-slate-900/40">
          {selected ? (
            <StaticCandidateDetail item={selected} />
          ) : (
            <div className="flex h-full items-center justify-center px-4 py-16 text-sm text-slate-500">
              从左侧选择一个候选点查看详情
            </div>
          )}
        </div>
      </div>
      <EventList events={events} empty="暂无静态分析日志" />
    </TaskPanel>
  );
}

function CallGraphBuildPanel({
  indexStatus,
  indexProgress,
  events,
}: {
  indexStatus: IndexStatus | null;
  indexProgress: ReturnType<typeof formatIndexProgress>;
  events: ScanEvent[];
}) {
  const stats = indexProgress.stats;
  const files = stats?.files ?? indexProgress.total;
  const functions = stats?.functions ?? 0;
  const structs = stats?.structs ?? 0;
  const globals = stats?.global_variables ?? 0;
  const calls = stats?.function_calls ?? 0;
  const globalRefs = stats?.global_variable_references ?? 0;
  const statusText = indexProgress.failed
    ? (indexStatus?.error || "索引构建失败")
    : indexProgress.done
      ? "索引已完成"
      : indexProgress.running
        ? "索引构建中"
        : "等待索引状态";

  return (
    <>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <MiniMetric label="文件数" value={files} tone="cyan" />
        <MiniMetric label="函数数量" value={functions} tone="blue" />
        <MiniMetric label="调用关系" value={calls} tone="purple" />
        <MiniMetric label="结构体/类/联合体" value={structs} />
        <MiniMetric label="全局变量" value={globals} />
        <MiniMetric label="全局变量引用" value={globalRefs} />
      </div>
      <ProgressBlock label="文件解析" current={indexProgress.current} total={indexProgress.total} fallback="等待索引文件进度" />
      {indexProgress.stage && (
        <ProgressBlock
          label={`索引阶段：${indexProgress.stage}`}
          current={indexProgress.stageCurrent}
          total={indexProgress.stageTotal}
          fallback="等待阶段进度"
        />
      )}
      <div className="rounded-lg border border-slate-700 bg-slate-900/40 px-4 py-3 text-sm text-slate-300">
        {statusText}
      </div>
      <EventList events={events} empty="暂无调用图构建日志" />
    </>
  );
}

const ALL_STATIC_FILTER = "__all__";

const AUDIT_FILTER_LABELS: Record<string, string> = {
  pending: "待审计",
  running: "审计中",
  done: "已审计",
};

const VALIDATION_FILTER_LABELS: Record<string, string> = {
  unverified: "未验证",
  running: "验证中",
  verified: "已验证",
  failed: "验证异常",
  not_applicable: "无验证目标",
};

interface StaticFilterOption {
  value: string;
  label: string;
  count: number;
}

interface StaticCandidateItem {
  candidate: ScanCandidate;
  vulnerability?: Vulnerability;
  vulnerabilityIndex?: number;
  validation?: VulnerabilityValidation;
  auditStatus: string;
  validationStatus: string;
}

function valueOptions(
  values: string[],
  formatLabel: (value: string) => string = (value) => value,
): StaticFilterOption[] {
  const counts = new Map<string, number>();
  values.forEach((value) => counts.set(value, (counts.get(value) ?? 0) + 1));
  return Array.from(counts.entries())
    .sort(([a], [b]) => formatLabel(a).localeCompare(formatLabel(b)))
    .map(([value, count]) => ({ value, label: formatLabel(value), count }));
}

function countStaticOptions(values: string[], labels: Record<string, string>): StaticFilterOption[] {
  const counts = new Map<string, number>();
  values.forEach((value) => counts.set(value, (counts.get(value) ?? 0) + 1));
  return Object.entries(labels).map(([value, label]) => ({
    value,
    label,
    count: counts.get(value) ?? 0,
  }));
}

function StaticFilterSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: StaticFilterOption[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="inline-flex items-center gap-1.5 text-xs text-slate-400">
      <span>{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-1.5 text-xs text-slate-200 focus:border-blue-500 focus:outline-none"
      >
        <option value={ALL_STATIC_FILTER}>全部</option>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label} ({option.count})
          </option>
        ))}
      </select>
    </label>
  );
}

function StaticCandidateListItem({
  item,
  active,
  onClick,
}: {
  item: StaticCandidateItem;
  active: boolean;
  onClick: () => void;
}) {
  const fileName = item.candidate.file.split("/").pop() || item.candidate.file;
  const auditTone: TaskTone = item.auditStatus === "running" ? "blue" : item.auditStatus === "done" ? "green" : "slate";
  const validationToneValue: TaskTone =
    item.validationStatus === "running"
      ? "blue"
      : item.validationStatus === "verified"
        ? "green"
        : item.validationStatus === "failed"
          ? "red"
          : "slate";
  return (
    <li>
      <button
        type="button"
        onClick={onClick}
        className={`w-full px-3 py-2.5 text-left transition-colors ${
          active ? "bg-blue-500/15" : item.auditStatus === "running" ? "bg-blue-500/10 hover:bg-blue-500/15" : "hover:bg-slate-800/60"
        }`}
      >
        <div className="flex items-center gap-1.5">
          <span className="font-mono text-[11px] text-slate-500">#{item.candidate.idx}</span>
          <span className="truncate font-mono text-xs text-slate-200" title={`${item.candidate.file}:${item.candidate.line}`}>
            {fileName}:{item.candidate.line}
          </span>
          {item.auditStatus === "running" && (
            <span className="ml-auto h-3 w-3 shrink-0 rounded-full border border-blue-500/30 border-t-blue-300 animate-spin" />
          )}
        </div>
        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
          <span className="rounded bg-slate-700/50 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-slate-400">
            {item.candidate.vuln_type}
          </span>
          <StatusPill label={AUDIT_FILTER_LABELS[item.auditStatus] ?? item.auditStatus} tone={auditTone} />
          <StatusPill label={VALIDATION_FILTER_LABELS[item.validationStatus] ?? item.validationStatus} tone={validationToneValue} />
        </div>
        {item.candidate.function && (
          <div className="mt-1 truncate font-mono text-[11px] text-slate-500" title={item.candidate.function}>
            {item.candidate.function}
          </div>
        )}
      </button>
    </li>
  );
}

function StaticCandidateDetail({ item }: { item: StaticCandidateItem }) {
  const metadata = item.candidate.metadata && Object.keys(item.candidate.metadata).length > 0
    ? JSON.stringify(item.candidate.metadata, null, 2)
    : "";
  const related = item.candidate.related_functions ?? [];
  return (
    <div className="max-h-[70vh] overflow-y-auto p-4">
      <div className="border-b border-slate-800 pb-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-slate-500">#{item.candidate.idx}</span>
              <span className="text-sm font-semibold text-slate-100">{item.candidate.vuln_type}</span>
              {item.vulnerabilityIndex !== undefined && (
                <span className="rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 text-xs text-red-300">
                  结果 #{item.vulnerabilityIndex}
                </span>
              )}
            </div>
            <div className="mt-1 break-all font-mono text-xs text-slate-300">{item.candidate.file}:{item.candidate.line}</div>
            <div className="mt-1 truncate font-mono text-xs text-slate-500">{item.candidate.function}</div>
          </div>
          <div className="flex flex-wrap gap-2">
            <StatusPill label={AUDIT_FILTER_LABELS[item.auditStatus] ?? item.auditStatus} tone={item.auditStatus === "done" ? "green" : item.auditStatus === "running" ? "blue" : "slate"} />
            <StatusPill label={VALIDATION_FILTER_LABELS[item.validationStatus] ?? item.validationStatus} tone={item.validationStatus === "verified" ? "green" : item.validationStatus === "running" ? "blue" : item.validationStatus === "failed" ? "red" : "slate"} />
          </div>
        </div>
      </div>
      <div className="mt-4 space-y-4">
        <section>
          <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">候选描述</h4>
          <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-2">
            <MarkdownContent content={item.candidate.description || "（无描述）"} />
          </div>
        </section>
        {item.vulnerability && (
          <section>
            <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">AI 审计结论</h4>
            <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-2">
              <MarkdownContent content={item.vulnerability.ai_analysis || "（无分析）"} />
            </div>
          </section>
        )}
        {item.validation && (
          <section>
            <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">漏洞验证状态</h4>
            <div className="flex flex-wrap gap-2">
              <StatusPill label={validationStatusLabel(item.validation.status)} tone={validationTone(item.validation)} />
              <StatusPill label={`验证成功：${formatNullableBool(item.validation.validation_success)}`} tone={nullableBoolTone(item.validation.validation_success)} />
              <StatusPill label={`是否问题：${formatNullableBool(item.validation.is_problem)}`} tone={nullableBoolTone(item.validation.is_problem)} />
              <StatusPill label={`人工介入：${formatNullableBool(item.validation.requires_human_intervention)}`} tone={humanInterventionTone(item.validation.requires_human_intervention)} />
            </div>
          </section>
        )}
        {related.length > 0 && (
          <section>
            <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">相关函数</h4>
            <div className="rounded border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-300">
              {related.join(", ")}
            </div>
          </section>
        )}
        {metadata && (
          <section>
            <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">候选元数据</h4>
            <pre className="max-h-72 overflow-auto rounded border border-slate-800 bg-slate-950 px-3 py-2 font-mono text-xs leading-5 text-slate-300">
              {metadata}
            </pre>
          </section>
        )}
      </div>
    </div>
  );
}

function AuditTaskPanel({
  scan,
  pct,
  currentCandidate,
  events,
  pool,
}: {
  scan: ScanStatusType;
  pct: number;
  currentCandidate: Candidate | null;
  events: ScanEvent[];
  pool: OpenCodePoolStatus | null;
}) {
  const runningAudits = (pool?.models ?? []).reduce(
    (count, model) => count + model.active_tasks.filter(
      (task) => isCandidateAuditPoolTask(task),
    ).length,
    0,
  );
  const queuedAudits = (pool?.queued_tasks ?? []).filter(
    (task) => isCandidateAuditPoolTask(task),
  ).length;
  return (
    <TaskPanel
      title="候选点 AI 审计"
      status={scan.status === "auditing" ? "进行中" : scan.status === "complete" ? "完成" : scan.status === "error" ? "异常" : "等待"}
      tone={scan.status === "auditing" ? "blue" : scan.status === "complete" ? "green" : scan.status === "error" ? "red" : "slate"}
      summary="对静态分析和历史同类问题挖掘产生的候选点逐条审计，确认是否为真实问题。"
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
        <MiniMetric label="已审计" value={scan.processed_candidates} tone="blue" />
        <MiniMetric label="总候选" value={scan.total_candidates} />
        <MiniMetric label="运行中" value={runningAudits} tone="cyan" />
        <MiniMetric label="排队中" value={queuedAudits} tone="amber" />
      </div>
      <ProgressBlock label="AI 审计" current={scan.processed_candidates} total={scan.total_candidates} percentOverride={scan.static_analysis_done ? pct : undefined} fallback="等待审计候选点" />
      {currentCandidate && (
        <div className="rounded-lg border border-blue-500/30 bg-blue-500/10 p-3">
          <div className="text-xs font-semibold uppercase text-blue-200">正在审计</div>
          <div className="mt-1 font-mono text-xs text-slate-200">{currentCandidate.file}:{currentCandidate.line}</div>
          <div className="mt-1 truncate font-mono text-xs text-slate-500">{currentCandidate.function}</div>
        </div>
      )}
      <EventList events={events} empty="暂无 AI 审计日志" />
    </TaskPanel>
  );
}

function FpReviewPanel({
  vulnerabilities,
  fpReview,
  methodLabel,
  methodDescription,
  stages,
  isFpReviewing,
  loading,
  stopping,
  events,
  onTrigger,
  onStop,
}: {
  vulnerabilities: Vulnerability[];
  fpReview: FpReviewJob | null;
  methodLabel: string;
  methodDescription: string;
  stages: FpReviewStageConfig[];
  isFpReviewing: boolean;
  loading: boolean;
  stopping: boolean;
  events: ScanEvent[];
  onTrigger: () => void | Promise<void>;
  onStop: () => void | Promise<void>;
}) {
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  const confirmed = useMemo(
    () => vulnerabilities
      .map((vuln, index) => ({ vuln, index }))
      .filter(({ vuln }) => isAiConfirmed(vuln)),
    [vulnerabilities],
  );
  const resultByIndex = useMemo(
    () => new Map((fpReview?.results ?? []).map((result) => [result.vuln_index, result])),
    [fpReview],
  );
  const currentIndices = useMemo(() => {
    if (!isFpReviewing) return new Set<number>();
    const values = fpReview?.current_vuln_indices?.length
      ? fpReview.current_vuln_indices
      : fpReview?.current_vuln_index != null
        ? [fpReview.current_vuln_index]
        : [];
    return new Set(values.filter((index) => index >= 0));
  }, [fpReview, isFpReviewing]);
  const items = useMemo(
    () =>
      confirmed
        .map(({ vuln, index }) => ({
          vuln,
          index,
          result: resultByIndex.get(index),
          running: currentIndices.has(index),
        }))
        .sort((a, b) => fpReviewSortRank(a.result, a.running) - fpReviewSortRank(b.result, b.running) || a.index - b.index),
    [confirmed, currentIndices, resultByIndex],
  );
  const waitingCount = items.filter(
    (item) => !isEffectiveFpReviewResult(item.result) && !item.running,
  ).length;
  const tpCount = items.filter((item) => item.result?.verdict === "tp").length;
  const fpCount = items.filter((item) => item.result?.verdict === "fp").length;
  const status = isFpReviewing
    ? "复核中"
    : fpReview?.status === "complete"
      ? "已完成"
      : fpReview?.status === "error"
        ? "异常"
        : fpReview?.status === "cancelled"
          ? "已停止"
          : confirmed.length > 0
            ? "等待"
            : "无目标";
  const tone: TaskTone = isFpReviewing
    ? "amber"
    : fpReview?.status === "complete"
      ? "green"
      : fpReview?.status === "error"
        ? "red"
        : fpReview?.status === "cancelled"
          ? "amber"
          : "slate";
  const selected = selectedIndex === null ? null : items.find((item) => item.index === selectedIndex) ?? null;
  const canTrigger = confirmed.length > 0
    && !isFpReviewing
    && !loading;

  useEffect(() => {
    if (items.length === 0) {
      if (selectedIndex !== null) setSelectedIndex(null);
      return;
    }
    if (selectedIndex === null || !items.some((item) => item.index === selectedIndex)) {
      setSelectedIndex(items[0].index);
    }
  }, [items, selectedIndex]);

  return (
    <TaskPanel
      title={methodLabel}
      status={status}
      tone={tone}
      summary={methodDescription}
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-5">
        <MiniMetric label="确认问题" value={confirmed.length} tone="red" />
        <MiniMetric label="等待复核" value={waitingCount} />
        <MiniMetric label="复核中" value={currentIndices.size} tone="amber" />
        <MiniMetric label="保留正报" value={tpCount} tone="red" />
        <MiniMetric label="判定误报" value={fpCount} tone="green" />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {confirmed.length > 0 && (
          <button
            type="button"
            onClick={onTrigger}
            disabled={!canTrigger}
            className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-sm font-medium text-amber-200 transition-colors hover:bg-amber-500/20 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? "启动中..." : `启动${methodLabel}`}
          </button>
        )}
        {isFpReviewing && (
          <button
            type="button"
            onClick={onStop}
            disabled={stopping}
            className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-1.5 text-sm font-medium text-red-300 transition-colors hover:bg-red-500/20 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {stopping ? "停止中..." : "停止复核"}
          </button>
        )}
        {fpReview?.error_message && (
          <span className="text-xs text-red-300">{fpReview.error_message}</span>
        )}
      </div>
      {confirmed.length === 0 ? (
        <EmptyState text="当前没有允许进入去误报的确认问题。" />
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(18rem,22rem)_1fr]">
          <div className="flex flex-col rounded-xl border border-slate-700 bg-slate-900/40">
            <div className="max-h-[70vh] flex-1 overflow-y-auto">
              <ul className="divide-y divide-slate-800">
                {items.map(({ vuln, index, result, running }) => {
                  const active = selectedIndex === index;
                  return (
                    <li key={`${index}-${vuln.file}-${vuln.line}`}>
                      <button
                        type="button"
                        onClick={() => setSelectedIndex(index)}
                        className={`w-full px-3 py-2.5 text-left transition-colors ${
                          active ? "bg-amber-500/15" : running ? "bg-amber-500/10 hover:bg-amber-500/15" : "hover:bg-slate-800/60"
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-[11px] text-slate-500">#{index}</span>
                          <span className="truncate font-mono text-xs text-slate-200" title={vulnerabilityLocation(vuln)}>
                            {vulnerabilityLocation(vuln, true)}
                          </span>
                          {running && <span className="ml-auto h-3 w-3 shrink-0 rounded-full border border-amber-500/30 border-t-amber-300 animate-spin" />}
                        </div>
                        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                          <span className="rounded bg-slate-700/50 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-slate-400">
                            {vulnerabilityTypeLabel(vuln)}
                          </span>
                          <StatusPill label={fpReviewItemLabel(result, running)} tone={fpReviewItemTone(result, running)} />
                        </div>
                        <div className="mt-1 truncate font-mono text-[11px] text-slate-500" title={vulnerabilityFunctionLabel(vuln)}>
                          {vulnerabilityFunctionLabel(vuln)}
                        </div>
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          </div>
          <div className="min-h-[20rem] rounded-xl border border-slate-700 bg-slate-900/40">
            {selected ? (
              <FpReviewDetail
                index={selected.index}
                vulnerability={selected.vuln}
                result={selected.result}
                running={selected.running}
                stages={stages}
              />
            ) : (
              <div className="flex h-full items-center justify-center px-4 py-16 text-sm text-slate-500">
                从左侧选择一个问题查看复核详情
              </div>
            )}
          </div>
        </div>
      )}
      <EventList events={events} empty="暂无去误报任务日志" />
    </TaskPanel>
  );
}

function FpReviewDetail({
  index,
  vulnerability,
  result,
  running,
  stages,
}: {
  index: number;
  vulnerability: Vulnerability;
  result?: FpReviewJob["results"][number];
  running: boolean;
  stages: FpReviewStageConfig[];
}) {
  const stageLabels = Object.fromEntries(stages.map((stage) => [stage.key, stage.label]));
  const stageOrder = new Map(stages.map((stage, index) => [stage.key, index]));
  const stageEntries = Object.entries(result?.stage_outputs ?? {})
    .filter(([, content]) => Boolean(content))
    .sort(([a], [b]) => (
      (stageOrder.get(a) ?? stages.length) - (stageOrder.get(b) ?? stages.length)
    ));
  return (
    <div className="max-h-[70vh] overflow-y-auto p-4">
      <div className="border-b border-slate-800 pb-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-slate-500">#{index}</span>
              <span className="text-sm font-semibold text-slate-100">{vulnerabilityTypeLabel(vulnerability)}</span>
              <span className="text-xs text-slate-500">{vulnerabilitySeverityLabel(vulnerability.severity)}</span>
            </div>
            <div className="mt-1 break-all font-mono text-xs text-slate-300">{vulnerabilityLocation(vulnerability)}</div>
            <div className="mt-1 truncate font-mono text-xs text-slate-500">{vulnerabilityFunctionLabel(vulnerability)}</div>
          </div>
          <div className="flex items-center gap-2">
            {running && <span className="h-3 w-3 rounded-full border border-amber-500/30 border-t-amber-300 animate-spin" />}
            <StatusPill label={fpReviewItemLabel(result, running)} tone={fpReviewItemTone(result, running)} />
          </div>
        </div>
      </div>
      <div className="mt-4 space-y-4">
        <section>
          <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">漏洞摘要</h4>
          <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-2">
            <MarkdownContent content={vulnerability.description || "（无描述）"} />
          </div>
        </section>
        {result ? (
          <>
            <section>
              <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">复核结论</h4>
              <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-2">
                <div className="mb-2 flex flex-wrap gap-2">
                  <StatusPill
                    label={result.verdict === "fp" ? "误报" : result.verdict === "tp" ? "正报" : "未完成"}
                    tone={result.verdict === "fp" ? "green" : result.verdict === "tp" ? "red" : "slate"}
                  />
                  <StatusPill label={`严重性：${result.severity || "-"}`} tone="slate" />
                  {result.match_type && <StatusPill label={`依据：${result.match_type}`} tone="purple" />}
                </div>
                <MarkdownContent content={result.reason || "（无结论说明）"} />
                {result.match_reference && (
                  <div className="mt-2 rounded border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-400">
                    {result.match_reference}
                  </div>
                )}
              </div>
            </section>
            {result.vulnerability_report && (
              <section>
                <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">漏洞报告</h4>
                <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-2">
                  <MarkdownContent content={result.vulnerability_report} />
                </div>
              </section>
            )}
            {stageEntries.length > 0 && (
              <section className="space-y-3">
                <h4 className="text-xs font-semibold uppercase text-slate-500">阶段输出</h4>
                {stageEntries.map(([stage, content]) => (
                  <div key={stage} className="rounded-lg border border-slate-800 bg-slate-950/40">
                    <div className="border-b border-slate-800 px-3 py-2 text-xs font-semibold text-slate-400">
                      {stageLabels[stage] ?? stage}
                    </div>
                    <div className="px-4 py-2">
                      <MarkdownContent content={content} />
                    </div>
                  </div>
                ))}
              </section>
            )}
          </>
        ) : (
          <div className="rounded border border-slate-800 bg-slate-900/50 px-3 py-2 text-xs text-slate-500">
            {running ? "当前问题正在复核中" : "等待去误报任务处理"}
          </div>
        )}
      </div>
    </div>
  );
}

function fpReviewSortRank(result: FpReviewJob["results"][number] | undefined, running: boolean): number {
  if (running) return 0;
  if (!result) return 1;
  return 2;
}

function fpReviewItemLabel(result: FpReviewJob["results"][number] | undefined, running: boolean): string {
  if (running) return "复核中";
  if (!result) return "等待复核";
  return result.verdict === "fp" ? "误报" : result.verdict === "tp" ? "正报" : "未完成";
}

function fpReviewItemTone(result: FpReviewJob["results"][number] | undefined, running: boolean): TaskTone {
  if (running) return "amber";
  if (!result) return "slate";
  return result.verdict === "fp" ? "green" : result.verdict === "tp" ? "red" : "slate";
}

function ValidationPanel({
  vulnerabilities,
  validations,
  stoppingValidationIndices,
  events,
  onStopValidation,
}: {
  vulnerabilities: Vulnerability[];
  validations: VulnerabilityValidation[];
  stoppingValidationIndices?: Set<number>;
  events: ScanEvent[];
  onStopValidation?: (index: number) => void | Promise<void>;
}) {
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  const confirmed = vulnerabilities
    .map((vuln, index) => ({ vuln, index }))
    .filter(({ vuln }) => isAiConfirmed(vuln));
  const validationByIndex = new Map(validations.map((item) => [item.vuln_index, item]));
  const items = confirmed
    .map(({ vuln, index }) => ({ vuln, index, validation: validationByIndex.get(index) }))
    .sort((a, b) => {
      const aRank = validationSortRank(a.validation);
      const bRank = validationSortRank(b.validation);
      if (aRank !== bRank) return aRank - bRank;
      return a.index - b.index;
    });
  const itemValidations = items.map((item) => item.validation).filter((item): item is VulnerabilityValidation => Boolean(item));
  const waitingCount = items.filter((item) => !item.validation || item.validation.status === "queued" || item.validation.status === "pending").length;
  const runningCount = itemValidations.filter((item) => item.running || item.status === "running").length;
  const completedCount = itemValidations.filter((item) => isValidationComplete(item.status)).length;
  const failedCount = itemValidations.filter((item) => isValidationFailed(item.status)).length;
  const status = runningCount > 0 ? "验证中" : completedCount > 0 ? "已验证" : confirmed.length > 0 ? "等待" : "无目标";
  const tone: TaskTone = runningCount > 0 ? "blue" : failedCount > 0 ? "red" : completedCount > 0 ? "green" : "slate";
  const selected = selectedIndex === null ? null : items.find((item) => item.index === selectedIndex) ?? null;

  useEffect(() => {
    if (items.length === 0) {
      if (selectedIndex !== null) setSelectedIndex(null);
      return;
    }
    if (selectedIndex === null || !items.some((item) => item.index === selectedIndex)) {
      setSelectedIndex(items[0].index);
    }
  }, [items, selectedIndex]);

  return (
    <TaskPanel
      title="漏洞验证"
      status={status}
      tone={tone}
      summary="对漏洞挖掘阶段确认的问题调用 Agent 本地验证脚本，展示验证过程和脚本返回结果。"
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-5">
        <MiniMetric label="确认问题" value={confirmed.length} tone="red" />
        <MiniMetric label="等待验证" value={waitingCount} />
        <MiniMetric label="验证中" value={runningCount} tone="blue" />
        <MiniMetric label="已完成" value={completedCount} tone="green" />
        <MiniMetric label="异常/超时" value={failedCount} tone="amber" />
      </div>
      {confirmed.length === 0 ? (
        <EmptyState text="当前还没有漏洞挖掘阶段确认的问题。" />
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(18rem,22rem)_1fr]">
          <div className="flex flex-col rounded-xl border border-slate-700 bg-slate-900/40">
            <div className="max-h-[70vh] flex-1 overflow-y-auto">
              <ul className="divide-y divide-slate-800">
                {items.map(({ vuln, index, validation }) => {
                  const active = selectedIndex === index;
                  const statusText = validation?.status || "pending";
                  const itemTone = validationTone(validation);
                  return (
                    <li key={`${index}-${vuln.file}-${vuln.line}`}>
                      <button
                        type="button"
                        onClick={() => setSelectedIndex(index)}
                        className={`w-full px-3 py-2.5 text-left transition-colors ${
                          active ? "bg-blue-500/15" : "hover:bg-slate-800/60"
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          <span className="truncate font-mono text-xs text-slate-200" title={vulnerabilityLocation(vuln)}>
                            {vulnerabilityLocation(vuln, true)}
                          </span>
                          {validation?.running && <span className="ml-auto h-3 w-3 shrink-0 rounded-full border border-blue-500/30 border-t-blue-300 animate-spin" />}
                        </div>
                        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                          <span className="text-[10px] font-semibold uppercase text-slate-400 bg-slate-700/50 px-1.5 py-0.5 rounded">
                            {vulnerabilityTypeLabel(vuln)}
                          </span>
                          <StatusPill label={validationStatusLabel(statusText)} tone={itemTone} />
                        </div>
                        <div className="mt-1 truncate font-mono text-[11px] text-slate-500" title={vulnerabilityFunctionLabel(vuln)}>
                          {vulnerabilityFunctionLabel(vuln)}
                        </div>
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          </div>

          <div className="min-h-[20rem] rounded-xl border border-slate-700 bg-slate-900/40">
            {selected ? (
              <ValidationDetail
                index={selected.index}
                vulnerability={selected.vuln}
                validation={selected.validation}
                stopping={stoppingValidationIndices?.has(selected.index) ?? false}
                onStopValidation={onStopValidation}
              />
            ) : (
              <div className="flex h-full items-center justify-center px-4 py-16 text-sm text-slate-500">
                从左侧选择一个问题查看验证详情
              </div>
            )}
          </div>
        </div>
      )}
      <EventList events={events} empty="暂无验证任务日志" />
    </TaskPanel>
  );
}

function ValidationDetail({
  index,
  vulnerability,
  validation,
  stopping = false,
  onStopValidation,
}: {
  index: number;
  vulnerability: Vulnerability;
  validation?: VulnerabilityValidation;
  stopping?: boolean;
  onStopValidation?: (index: number) => void | Promise<void>;
}) {
  const status = validation?.status || "pending";
  const tone = validationTone(validation);
  const canStop = Boolean(onStopValidation && (stopping || validation?.running || status === "queued" || status === "running"));
  return (
    <div className="max-h-[70vh] overflow-y-auto p-4">
      <div className="border-b border-slate-800 pb-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-slate-500">#{index}</span>
              <span className="text-sm font-semibold text-slate-100">{vulnerabilityTypeLabel(vulnerability)}</span>
              <span className="text-xs text-slate-500">{vulnerabilitySeverityLabel(vulnerability.severity)}</span>
            </div>
            <div className="mt-1 break-all font-mono text-xs text-slate-300">{vulnerabilityLocation(vulnerability)}</div>
            <div className="mt-1 truncate font-mono text-xs text-slate-500">{vulnerabilityFunctionLabel(vulnerability)}</div>
          </div>
          <div className="flex items-center gap-2">
            {canStop && (
              <button
                type="button"
                onClick={() => onStopValidation?.(index)}
                disabled={stopping}
                className="rounded border border-red-500/30 bg-red-500/10 px-2 py-1 text-xs font-medium text-red-300 transition-colors hover:bg-red-500/20 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {stopping ? "停止中..." : "停止验证"}
              </button>
            )}
            {validation?.running && <span className="h-3 w-3 rounded-full border border-blue-500/30 border-t-blue-300 animate-spin" />}
            <StatusPill label={validationStatusLabel(status)} tone={tone} />
          </div>
        </div>
      </div>
      <div className="mt-4 space-y-4">
        <div className="min-w-0">
          <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">漏洞摘要</h4>
          <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-2">
            <MarkdownContent content={vulnerability.description || "（无描述）"} />
          </div>
        </div>
        {validation ? (
          <div className="space-y-3">
            <div className="flex flex-wrap gap-2">
              <StatusPill
                label={`验证成功：${formatNullableBool(validation.validation_success)}`}
                tone={nullableBoolTone(validation.validation_success)}
              />
              <StatusPill
                label={`是否问题：${formatNullableBool(validation.is_problem)}`}
                tone={nullableBoolTone(validation.is_problem)}
              />
              <StatusPill
                label={`人工介入：${formatNullableBool(validation.requires_human_intervention)}`}
                tone={humanInterventionTone(validation.requires_human_intervention)}
              />
              {validation.product && <StatusPill label={`产品：${validation.product}`} tone="slate" />}
              {validation.validation_environment && <StatusPill label={`环境：${validation.validation_environment}`} tone="slate" />}
            </div>
            <div className="space-y-3">
              <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
                <div className="space-y-3">
                  <ValidationOutputSections validation={validation} />
                </div>
                <div className="space-y-3">
                  <ValidationArtifacts validation={validation} />
                </div>
              </div>
              <ValidationBlock title="最终结论" content={validation.final_output || validation.validation_output} />
            </div>
          </div>
        ) : (
          <div className="rounded border border-slate-800 bg-slate-900/50 px-3 py-2 text-xs text-slate-500">等待验证脚本启动</div>
        )}
      </div>
    </div>
  );
}

function ValidationOutputSections({ validation }: { validation: VulnerabilityValidation }) {
  const sections = validationOutputSections(validation);
  if (sections.length === 0) return null;
  return (
    <>
      {sections.map((section, idx) => (
        <ValidationBlock
          key={`${section.title}-${idx}`}
          title={section.title || "中间产出"}
          content={section.content || ""}
        />
      ))}
    </>
  );
}

function ValidationArtifacts({ validation }: { validation: VulnerabilityValidation }) {
  const artifacts = validation.artifacts && validation.artifacts.length > 0
    ? validation.artifacts
    : validation.validation_code
      ? [{ title: "产物", name: "validation.py", kind: "code", content: validation.validation_code }]
      : [];
  const groups = groupedValidationArtifacts(artifacts);
  if (groups.length === 0) return null;
  return (
    <>
      {groups.map(([title, items]) => (
        <div key={title} className="min-w-0 rounded border border-slate-800 bg-slate-950">
          <div className="border-b border-slate-800 px-3 py-2 text-xs font-semibold text-slate-500">{title}</div>
        <div className="max-h-72 overflow-auto">
          {items.map((artifact, idx) => (
            <div key={`${artifact.name}-${idx}`} className="border-b border-slate-900 last:border-b-0">
              <div className="flex flex-wrap items-center gap-2 px-3 py-2 text-xs">
                <span className="font-mono text-slate-200">{artifact.name}</span>
                {artifact.kind && <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] uppercase text-slate-400">{artifact.kind}</span>}
                {artifact.path && <span className="break-all font-mono text-[11px] text-slate-500">{artifact.path}</span>}
              </div>
              {artifact.content && (
                <pre className="whitespace-pre-wrap break-words px-3 pb-2 font-mono text-xs leading-5 text-slate-300">
                  {artifact.content}
                </pre>
              )}
            </div>
          ))}
        </div>
        </div>
      ))}
    </>
  );
}

function validationOutputSections(validation: VulnerabilityValidation) {
  const sections = (validation.output_sections ?? [])
    .filter((section) => section && (section.title || section.content))
    .map((section) => ({
      title: section.title || "中间产出",
      content: section.content || "",
      updated_at: section.updated_at || "",
    }));
  if (sections.length > 0) return sections;
  if (validation.intermediate_output) {
    return [{ title: "中间产出", content: validation.intermediate_output, updated_at: validation.updated_at }];
  }
  return [];
}

function groupedValidationArtifacts(artifacts: NonNullable<VulnerabilityValidation["artifacts"]>) {
  const groups = new Map<string, typeof artifacts>();
  for (const artifact of artifacts) {
    const title = artifact.title?.trim() || "产物";
    const items = groups.get(title) ?? [];
    items.push(artifact);
    groups.set(title, items);
  }
  return Array.from(groups.entries());
}

function ValidationBlock({ title, content }: { title: string; content: string }) {
  return (
    <div className="min-w-0 rounded border border-slate-800 bg-slate-950">
      <div className="border-b border-slate-800 px-3 py-2 text-xs font-semibold text-slate-500">{title}</div>
      <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words px-3 py-2 font-mono text-xs leading-5 text-slate-300">
        {content || "（暂无）"}
      </pre>
    </div>
  );
}

function validationStatusLabel(status: string): string {
  const labels: Record<string, string> = {
    pending: "等待",
    queued: "等待",
    running: "验证中",
    verified: "已验证",
    success: "已验证",
    failed: "未通过",
    error: "异常",
    timeout: "超时",
    cancelled: "已取消",
    skipped: "跳过",
  };
  return labels[status] ?? status;
}

function formatNullableBool(value?: boolean | null): string {
  if (value === true) return "是";
  if (value === false) return "否";
  return "未知";
}

function nullableBoolTone(value?: boolean | null): TaskTone {
  if (value === true) return "green";
  if (value === false) return "amber";
  return "slate";
}

function humanInterventionTone(value?: boolean | null): TaskTone {
  if (value === true) return "amber";
  if (value === false) return "green";
  return "slate";
}

function validationTone(validation?: VulnerabilityValidation): TaskTone {
  const status = validation?.status || "pending";
  if (validation?.running || status === "queued" || status === "running") return "blue";
  if (isValidationFailed(status)) return "red";
  if (isValidationComplete(status)) return "green";
  return "slate";
}

function validationSortRank(validation?: VulnerabilityValidation): number {
  if (!validation) return 1;
  if (validation.running || validation.status === "running") return 0;
  if (validation.status === "queued" || validation.status === "pending") return 1;
  if (isValidationFailed(validation.status)) return 2;
  if (isValidationComplete(validation.status)) return 3;
  return 4;
}

function isValidationComplete(status: string): boolean {
  return ["verified", "success", "failed"].includes(status);
}

function isValidationFailed(status: string): boolean {
  return ["error", "timeout", "cancelled"].includes(status);
}

function TaskPanel({
  title,
  status,
  tone,
  summary,
  children,
}: {
  title: string;
  status: string;
  tone: TaskTone;
  summary: string;
  children: React.ReactNode;
}) {
  return (
    <section className="space-y-4 rounded-lg border border-slate-700 bg-slate-900/50 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-white">{title}</h2>
          <p className="mt-1 text-sm text-slate-400">{summary}</p>
        </div>
        <StatusPill label={status} tone={tone} />
      </div>
      {children}
    </section>
  );
}

function TaskSummaryRow({
  label,
  status,
  tone,
  detail,
  progress,
}: {
  label: string;
  status: string;
  tone: TaskTone;
  detail: string;
  progress?: number;
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-sm font-medium text-slate-200">{label}</div>
          <div className="mt-0.5 text-xs text-slate-500">{detail}</div>
        </div>
        <StatusPill label={status} tone={tone} />
      </div>
      {progress !== undefined && <ProgressBar value={progress} tone={tone} className="mt-3" />}
    </div>
  );
}

function ProgressBlock({
  label,
  current,
  total,
  fallback,
  percentOverride,
}: {
  label: string;
  current: number;
  total: number;
  fallback: string;
  percentOverride?: number;
}) {
  const value = percentOverride ?? percent(current, total);
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-xs text-slate-400">
        <span>{total > 0 ? `${label}: ${current}/${total}` : fallback}</span>
        {total > 0 || percentOverride !== undefined ? <span>{value}%</span> : null}
      </div>
      <ProgressBar value={total > 0 || percentOverride !== undefined ? value : 0} tone="blue" />
    </div>
  );
}

function ProgressBar({ value, tone, className = "" }: { value: number; tone: TaskTone; className?: string }) {
  return (
    <div className={`h-1.5 overflow-hidden rounded-full bg-slate-800 ${className}`}>
      <div className={`h-full rounded-full transition-all duration-500 ${toneFill(tone)}`} style={{ width: `${value}%` }} />
    </div>
  );
}

function EventList({ events, empty }: { events: ScanEvent[]; empty: string }) {
  const visible = events.slice(-80);
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/50">
      <div className="border-b border-slate-800 px-3 py-2 text-xs font-semibold uppercase tracking-wider text-slate-500">任务日志</div>
      <div className="max-h-80 overflow-y-auto p-3 font-mono text-xs">
        {visible.length === 0 ? (
          <p className="text-slate-600">{empty}</p>
        ) : (
          <div className="space-y-1">
            {visible.map((event, index) => <EventLine key={`${event.timestamp}-${index}`} event={event} />)}
          </div>
        )}
      </div>
    </div>
  );
}

function EmptyState({ text }: { text: string }) {
  return <div className="rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-6 text-center text-sm text-slate-500">{text}</div>;
}

function MiniMetric({ label, value, tone = "slate" }: { label: string; value: number; tone?: TaskTone }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/50 px-3 py-3">
      <div className="text-xs text-slate-500">{label}</div>
      <div className={`mt-1 text-xl font-semibold ${toneText(tone)}`}>{value}</div>
    </div>
  );
}

function StatusPill({ label, tone }: { label: string; tone: TaskTone }) {
  return (
    <span className={`inline-flex rounded border px-2 py-0.5 text-xs font-semibold ${toneBorder(tone)} ${toneBg(tone)} ${toneText(tone)}`}>
      {label}
    </span>
  );
}

function PanelIcon({ name }: { name: "target" | "alert" | "history" | "queue" }) {
  if (name === "alert") {
    return (
      <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v4m0 4h.01M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      </svg>
    );
  }
  if (name === "history") {
    return (
      <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12a9 9 0 1 0 3-6.7M3 4v6h6m3-2v5l4 2" />
      </svg>
    );
  }
  if (name === "queue") {
    return (
      <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7h16M4 12h16M4 17h10" />
      </svg>
    );
  }
  return (
    <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6l4 2m5-2a9 9 0 1 1-18 0 9 9 0 0 1 18 0z" />
    </svg>
  );
}

function toneText(tone: TaskTone): string {
  return {
    slate: "text-slate-300",
    cyan: "text-cyan-300",
    amber: "text-amber-300",
    green: "text-green-300",
    red: "text-red-300",
    purple: "text-purple-300",
    blue: "text-blue-300",
  }[tone];
}

function toneBorder(tone: TaskTone): string {
  return {
    slate: "border-slate-700",
    cyan: "border-cyan-500/30",
    amber: "border-amber-500/30",
    green: "border-green-500/30",
    red: "border-red-500/30",
    purple: "border-purple-500/30",
    blue: "border-blue-500/30",
  }[tone];
}

function toneBg(tone: TaskTone): string {
  return {
    slate: "bg-slate-800",
    cyan: "bg-cyan-500/10",
    amber: "bg-amber-500/10",
    green: "bg-green-500/10",
    red: "bg-red-500/10",
    purple: "bg-purple-500/10",
    blue: "bg-blue-500/10",
  }[tone];
}

function toneFill(tone: TaskTone): string {
  return {
    slate: "bg-slate-500",
    cyan: "bg-cyan-400",
    amber: "bg-amber-400",
    green: "bg-green-500",
    red: "bg-red-500",
    purple: "bg-purple-500",
    blue: "bg-blue-500",
  }[tone];
}

function EventLine({ event }: { event: ScanEvent }) {
  const time = new Date(event.timestamp).toLocaleTimeString();

  const phaseColor: Record<string, string> = {
    init: "text-yellow-400",
    mcp_ready: "text-green-400",
    threat_analysis: "text-emerald-300",
    threat_audit: "text-cyan-300",
    static_analysis: "text-cyan-400",
    git_history: "text-purple-300",
    variant_hunt: "text-purple-400",
    auditing: "text-blue-400",
    opencode_output: "text-slate-500",
    fp_review: "text-amber-300",
    complete: "text-green-400",
    error: "text-red-400",
  };

  return (
    <div className="flex gap-2 leading-5">
      <span className="text-slate-600 shrink-0">{time}</span>
      <span className={`shrink-0 ${phaseColor[event.phase] ?? "text-slate-400"}`}>
        [{event.phase}]
      </span>
      <span className="text-slate-400 break-all">{event.message}</span>
    </div>
  );
}

function ModelPoolDashboard({ pool }: { pool: OpenCodePoolStatus | null }) {
  const models = pool?.models ?? [];
  const plannedTasks = pool?.planned_tasks ?? [];
  const queuedTasks = pool?.queued_tasks ?? [];
  const completedTasks = pool?.completed_tasks ?? [];
  const failedTasks = completedTasks.filter((task) => {
    const outcome = String(task.outcome || "unknown");
    return outcome !== "success";
  });
  const recentFailedTasks = failedTasks.slice(-10).reverse();
  const unassignedCompletedTasks = completedTasks.filter(
    (task) => !String(task.model_id || task.model || "").trim(),
  );
  const hasEnabledModel = models.some((model) => model.enabled);
  const total = models.reduce((sum, item) => sum + item.total, 0) + unassignedCompletedTasks.length;
  const success = models.reduce((sum, item) => sum + item.success, 0)
    + unassignedCompletedTasks.filter((task) => task.outcome === "success").length;
  const failure = models.reduce((sum, item) => sum + item.failure, 0)
    + unassignedCompletedTasks.filter((task) => task.outcome === "failure").length;
  const timeout = models.reduce((sum, item) => sum + item.timeout, 0)
    + unassignedCompletedTasks.filter((task) => task.outcome === "timeout").length;
  const cancelled = models.reduce((sum, item) => sum + item.cancelled, 0)
    + unassignedCompletedTasks.filter((task) => task.outcome === "cancelled").length;

  if (!pool) {
    return (
      <div className="flex-1 overflow-y-auto p-5">
        <div className="rounded-lg border border-slate-800 bg-slate-950 px-4 py-5 text-sm text-slate-500">
          当前扫描尚未收到 OpenCode 模型池状态。
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-y-auto p-5 space-y-4">
      {!hasEnabledModel && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm leading-6 text-amber-200">
          当前没有启用的模型，新的 OpenCode 任务会保持阻塞排队，直到启用满足能力要求的模型或用户取消。
        </div>
      )}
      <div className="grid grid-cols-2 md:grid-cols-7 gap-3">
        <MetricBox label="计划中" value={plannedTasks.length} tone="amber" />
        <MetricBox label="运行中" value={pool.global_running} tone="cyan" />
        <MetricBox label="排队中" value={pool.global_queued} tone="amber" />
        <MetricBox label="累计任务" value={total} />
        <MetricBox label="成功" value={success} tone="green" />
        <MetricBox label="失败" value={failure} tone="red" />
        <MetricBox label="超时/取消" value={timeout + cancelled} tone="amber" />
      </div>

      {plannedTasks.length > 0 && (
        <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
          <div className="mb-2 text-xs font-semibold text-slate-400">计划中任务</div>
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
            {plannedTasks.map((task, index) => (
              <div
                key={String(task.planned_task_id || index)}
                className="truncate rounded border border-slate-500/20 bg-slate-800/70 px-2 py-1.5 text-xs text-slate-200"
                title={modelTaskLabel(task)}
              >
                {modelTaskLabel(task)}
              </div>
            ))}
          </div>
        </div>
      )}

      {queuedTasks.length > 0 && (
        <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
          <div className="mb-2 text-xs font-semibold text-slate-400">全局排队任务</div>
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
            {queuedTasks.map((task, index) => (
              <div
                key={String(task.request_id || index)}
                className="truncate rounded border border-amber-500/20 bg-amber-500/10 px-2 py-1.5 text-xs text-amber-100"
                title={modelTaskLabel(task)}
              >
                {modelTaskLabel(task)}
              </div>
            ))}
          </div>
        </div>
      )}

      {failedTasks.length > 0 && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3">
          <div className="mb-2 text-xs font-semibold text-red-200">
            任务失败 {failedTasks.length} 个{failedTasks.length > recentFailedTasks.length ? `（显示最近 ${recentFailedTasks.length} 个）` : ""}
          </div>
          <div className="space-y-2">
            {recentFailedTasks.map((task, index) => {
              const reason = typeof task.failure_reason === "string" && task.failure_reason.trim()
                ? task.failure_reason.trim()
                : "未记录失败原因";
              return (
                <div key={String(task.task_id || index)} className="rounded border border-red-500/20 bg-slate-950/50 px-3 py-2">
                  <div className="text-xs font-medium text-red-100">{modelTaskLabel(task)}</div>
                  <div className="mt-1 whitespace-pre-wrap break-words text-xs leading-relaxed text-red-300">{reason}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {models.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full min-w-[64rem] text-sm">
          <thead className="bg-slate-950">
            <tr>
              <th className={thCls}>模型</th>
              <th className={thCls}>能力</th>
              <th className={thCls}>可用</th>
              <th className={thCls}>配置/有效权重</th>
              <th className={thCls}>运行/上限</th>
              <th className={thCls}>累计</th>
              <th className={thCls}>成功</th>
              <th className={thCls}>失败</th>
              <th className={thCls}>超时</th>
              <th className={thCls}>取消</th>
              <th className={thCls}>平均耗时</th>
              <th className={thCls}>当前任务</th>
              <th className={thCls}>最近状态</th>
            </tr>
          </thead>
          <tbody>
            {models.map((model) => (
              <tr key={model.id} className="border-t border-slate-800/70">
                <td className={tdCls}>
                  <div className="font-semibold text-slate-100">{model.id}</div>
                  <div className="mt-1 max-w-48 truncate font-mono text-[11px] text-slate-500">
                    {model.use_default_model ? "(CLI 默认模型)" : (model.model || "(模型名为空)")}
                  </div>
                </td>
                <td className={tdCls}>{capabilityLabel(model.capability)}</td>
                <td className={tdCls}>
                  <span className={model.enabled && model.available ? "text-green-300" : "text-slate-500"}>
                    {model.enabled ? (model.available ? "可用" : "时间窗外") : "禁用"}
                  </span>
                </td>
                <td className={tdCls}>
                  <div className="font-mono">
                    {model.weight} / {model.effective_weight ?? model.weight}
                  </div>
                  <div className={`mt-1 text-[11px] ${!model.enabled ? "text-slate-500" : (model.health_penalty_level ?? 0) > 0 ? "text-amber-300" : "text-green-400"}`}>
                    {!model.enabled
                      ? "无当前健康状态"
                      : (model.health_penalty_level ?? 0) > 0
                        ? `健康降级 ${model.health_penalty_level} 级`
                        : "健康正常"}
                  </div>
                  {model.enabled && model.last_health_failure_at && (
                    <div
                      className="mt-1 text-[11px] text-slate-600"
                      title={formatDateTime(model.last_health_failure_at)}
                    >
                      最近失败：{model.last_health_failure_kind === "timeout" ? "超时" : "请求失败"}
                    </div>
                  )}
                </td>
                <td className={tdCls}>{model.running}/{model.max_concurrency}</td>
                <td className={tdCls}>{model.total}</td>
                <td className={`${tdCls} text-green-300`}>{model.success}</td>
                <td className={`${tdCls} text-red-300`}>{model.failure}</td>
                <td className={`${tdCls} text-amber-300`}>{model.timeout}</td>
                <td className={`${tdCls} text-slate-300`}>{model.cancelled}</td>
                <td className={tdCls}>{formatDuration(model.avg_duration_seconds)}</td>
                <td className={`${tdCls} max-w-72 text-slate-400`}>
                  <ModelTaskList tasks={model.active_tasks} />
                </td>
                <td className={tdCls}>
                  <div className={statusClass(model.last_status)}>
                    {statusLabel(model.last_status)}
                  </div>
                  <div className="mt-1 text-[11px] text-slate-600">
                    {formatDateTime(model.last_finished_at || model.last_started_at)}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

const thCls = "px-3 py-2 text-left text-xs font-semibold text-slate-400";
const tdCls = "px-3 py-3 text-slate-300 align-top";

function MetricBox({
  label,
  value,
  tone = "slate",
}: {
  label: string;
  value: number;
  tone?: "slate" | "cyan" | "amber" | "green" | "red";
}) {
  const color = {
    slate: "text-slate-100",
    cyan: "text-cyan-300",
    amber: "text-amber-300",
    green: "text-green-300",
    red: "text-red-300",
  }[tone];
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-3">
      <div className="text-xs text-slate-500">{label}</div>
      <div className={`mt-1 text-xl font-semibold ${color}`}>{value}</div>
    </div>
  );
}

function capabilityLabel(value: string): string {
  if (value === "high") return "高";
  if (value === "medium") return "中";
  if (value === "low") return "低";
  return value || "-";
}

function vulnerabilitySeverityLabel(value: string): string {
  if (value === "critical") return "致命";
  if (value === "high") return "严重";
  if (value === "medium") return "一般";
  if (value === "low") return "提示";
  return value || "未知严重性";
}

function statusLabel(value: string): string {
  if (value === "queued") return "排队";
  if (value === "running") return "运行中";
  if (value === "success") return "成功";
  if (value === "failure") return "失败";
  if (value === "timeout") return "超时";
  if (value === "cancelled") return "取消";
  return value || "-";
}

function statusClass(value: string): string {
  const base = "inline-flex rounded border px-2 py-0.5 text-xs";
  if (value === "running") return `${base} border-cyan-500/30 bg-cyan-500/10 text-cyan-300`;
  if (value === "success") return `${base} border-green-500/30 bg-green-500/10 text-green-300`;
  if (value === "failure") return `${base} border-red-500/30 bg-red-500/10 text-red-300`;
  if (value === "timeout" || value === "queued") return `${base} border-amber-500/30 bg-amber-500/10 text-amber-300`;
  return `${base} border-slate-700 bg-slate-800 text-slate-400`;
}

function modelTaskLabel(task: Record<string, unknown> | undefined): string {
  if (!task) return "-";
  const taskType = scanQueueTaskTypeLabel(task);
  const stage = task.stage ? `/${String(task.stage)}` : "";
  const checker = task.checker ? String(task.checker) : "";
  const file = task.file ? String(task.file) : "";
  const line = task.line ? `:${String(task.line)}` : "";
  const target = file ? `${file}${line}` : checker;
  const session = task.serve_session_id ? String(task.serve_session_id) : "";
  const revision = Number(task.revision || 1) > 1 ? `r${String(task.revision)}` : "";
  const blocked = task.blocked_reason ? "阻塞" : "";
  return [revision, taskType + stage, target, session, blocked].filter(Boolean).join(" ");
}

function ModelTaskList({ tasks }: { tasks?: Record<string, unknown>[] }) {
  const activeTasks = tasks || [];
  if (activeTasks.length === 0) return <>-</>;
  return (
    <div className="space-y-1">
      {activeTasks.map((task, index) => (
        <div key={String(task.task_id || index)} className="truncate">
          {modelTaskLabel(task)}
        </div>
      ))}
    </div>
  );
}

function formatDuration(seconds: number): string {
  if (!seconds || seconds <= 0) return "-";
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds % 60);
  return `${minutes}m ${rest}s`;
}

function formatDateTime(value: string): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function MarkdownContent({ content }: { content: string }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={{
        h1: ({ children }) => <h1 className="mb-4 text-xl font-semibold text-white">{children}</h1>,
        h2: ({ children }) => <h2 className="mt-6 mb-2 text-base font-semibold text-purple-100">{children}</h2>,
        h3: ({ children }) => <h3 className="mt-4 mb-2 text-sm font-semibold text-slate-100">{children}</h3>,
        p: ({ children }) => <p className="my-2 text-sm leading-7 text-slate-300">{children}</p>,
        ul: ({ children }) => <ul className="my-2 list-disc space-y-1 pl-5 text-sm leading-relaxed text-slate-300 marker:text-purple-400">{children}</ul>,
        ol: ({ children }) => <ol className="my-2 list-decimal space-y-1 pl-5 text-sm leading-relaxed text-slate-300 marker:text-purple-400">{children}</ol>,
        li: ({ children }) => <li>{children}</li>,
        table: ({ children }) => (
          <div className="my-3 overflow-x-auto rounded-lg border border-slate-800">
            <table className="w-full min-w-max text-sm">{children}</table>
          </div>
        ),
        thead: ({ children }) => <thead className="bg-slate-950">{children}</thead>,
        th: ({ children }) => <th className="border-b border-slate-800 px-3 py-2 text-left text-xs font-semibold text-slate-400">{children}</th>,
        tr: ({ children }) => <tr className="border-t border-slate-800/70 first:border-t-0">{children}</tr>,
        td: ({ children }) => <td className="px-3 py-2 text-slate-300">{children}</td>,
        pre: ({ children }) => (
          <pre className="my-3 overflow-x-auto rounded-lg border border-slate-700 bg-slate-950 p-4 text-xs leading-relaxed text-slate-300 [&_code]:border-0 [&_code]:bg-transparent [&_code]:p-0 [&_code]:text-slate-300">
            {children}
          </pre>
        ),
        code: ({ className, children }) => (
          <code className={`${className ?? ""} rounded border border-slate-700 bg-slate-950 px-1.5 py-0.5 text-[0.85em] text-purple-200`}>
            {children}
          </code>
        ),
        strong: ({ children }) => <strong className="font-semibold text-slate-100">{children}</strong>,
      }}
    >
      {content}
    </ReactMarkdown>
  );
}
