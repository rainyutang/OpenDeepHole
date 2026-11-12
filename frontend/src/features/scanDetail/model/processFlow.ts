import {
  STATIC_CANDIDATE_ENGINE_ID as STATIC_ENGINE_ID,
  THREAT_AUDIT_ENGINE_ID as THREAT_ENGINE_ID,
  canonicalMiningEngineLabel,
  isPatternAuditEngine,
  miningEngineRequiresCodeIndex,
  threatPatternAuditFlowDetail,
} from "../../../miningEngines";
import { staticAnalysisFailures, staticCandidateAuditFlowStatus } from "../../../staticAudit";
import type { FpReviewJob } from "../../../types/fpReview";
import type { MiningEngineCatalogItem, MiningEngineSelection } from "../../../types/mining";
import type { ScanStatus as ScanStatusType } from "../../../types/scans";
import { getThreatAnalysisResultCounts, isThreatAnalysisResultReady } from "../../threatAnalysis/analysisModel";
import {
  currentThreatAuditTasks,
  effectiveMiningEngines,
  engineFlowStatus,
  formatIndexProgress,
  fpReviewMethodLabel,
  hasEvent,
  isActiveThreatAuditStatus,
  isAiConfirmed,
  isThreatAnalysisSelected,
  isValidationTerminalStatus,
  miningEngineRun,
  threatAnalysisFlowStatus,
  threatAnalysisMethodLabel,
  threatAnalysisSummary,
  threatAuditFlowStatus,
} from "./scan";
import type { FlowNodeId, FlowNodeStatus, MainTab, TaskTone } from "./types";

export interface FlowNodeView {
  id: FlowNodeId;
  label: string;
  detail: string;
  status: FlowNodeStatus;
  active: boolean;
  tone: TaskTone;
}

interface MiningFlowEntry {
  engine: MiningEngineSelection;
  node: FlowNodeView;
}

interface CatalogMiningFlowEntry extends MiningFlowEntry {
  selected: boolean;
}

export interface ProcessFlowModel {
  threatAnalysisNode: FlowNodeView;
  threatResultsReady: boolean;
  threatResultCounts: ReturnType<typeof getThreatAnalysisResultCounts>;
  miningEntries: MiningFlowEntry[];
  allMiningEntries: CatalogMiningFlowEntry[];
  staticAnalysisNode: FlowNodeView;
  validationNode: FlowNodeView;
  fpReviewNode: FlowNodeView;
  indexNode: FlowNodeView;
  codeGraphMcpEnabled: boolean;
  knowledgeBaseEnabled: boolean;
}

function processFlowEngineLabel(engineId: string, label: string): string {
  if (engineId === STATIC_ENGINE_ID) {
    return "DeepHole基于代码风险点的问题识别引擎";
  }
  return canonicalMiningEngineLabel(engineId, label);
}

export function buildProcessFlowModel({
  scan,
  indexProgress,
  fpReview,
  activeTab,
  activeEngineId,
  engineCatalog,
  threatAnalysisLoading,
  isDone,
  isFpReviewing,
}: {
  scan: ScanStatusType;
  indexProgress: ReturnType<typeof formatIndexProgress>;
  fpReview: FpReviewJob | null;
  activeTab: MainTab;
  activeEngineId: string;
  engineCatalog: MiningEngineCatalogItem[];
  threatAnalysisLoading: boolean;
  isDone: boolean;
  isFpReviewing: boolean;
}): ProcessFlowModel {
  const engines = effectiveMiningEngines(scan);
  const candidates = scan.candidates ?? [];
  const candidateCount = scan.detail_counts?.candidates ?? (
    scan.total_candidates
    || candidates.length
    || scan.vulnerabilities.length
  );
  const staticSelected = engines.some((engine) => engine.engine_id === STATIC_ENGINE_ID);
  const indexRequired = engines.some((engine) => miningEngineRequiresCodeIndex(engine.engine_id));
  const staticRun = miningEngineRun(scan, STATIC_ENGINE_ID);
  const staticFailureCount = staticAnalysisFailures(scan).length;
  const staticStageFailed = staticRun?.status === "error" && !scan.static_analysis_done;
  const staticRunning = staticSelected && !staticStageFailed && scan.status === "analyzing" && !scan.static_analysis_done;
  const staticDone = staticSelected && !staticStageFailed && (
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

  const validationDetail = !scan.vulnerability_validation_enabled
    ? "本次扫描未启用验证利用"
    : confirmedCount > 0
      ? `${validationRunningCount} 运行 · ${validationDoneCount}/${confirmedCount} 完成`
      : "等待确认问题";
  const indexNode: FlowNodeView = {
    id: "index",
    label: "代码图谱构建",
    detail: !indexRequired || indexProgress.skipped
      ? "本次扫描未选择静态分析引擎"
      : indexProgress.total > 0
        ? `${indexProgress.current}/${indexProgress.total} 文件`
        : "为静态分析提供调用关系与代码上下文",
    status: !indexRequired || indexProgress.skipped
      ? "disabled"
      : indexProgress.failed
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
    ? "disabled"
    : staticDone
      ? staticFailureCount > 0 ? "warning" : "done"
      : staticRunning
        ? "running"
        : staticRun?.status === "error"
          ? "error"
          : staticRun?.status === "cancelled" || scan.status === "cancelled"
            ? "cancelled"
            : "pending";
  const staticAnalysisNode: FlowNodeView = {
    id: "static",
    label: "静态分析",
    detail: !staticSelected
      ? "本次扫描未选择代码风险点引擎"
      : staticFailureCount > 0
        ? `${staticFailureCount} 条规则失败 · ${candidateCount} 个候选点`
        : staticRunning
          ? `${scan.static_scanned_files}/${scan.static_total_files || "?"} 文件`
          : candidateCount > 0
            ? `${candidateCount} 个候选点`
            : "查看候选点生成详情",
    status: staticNodeStatus,
    active: activeTab === "static",
    tone: "cyan",
  };
  const allThreatTasks = scan.threat_audit_tasks ?? [];
  const threatTasks = currentThreatAuditTasks(allThreatTasks);
  const supersededThreatTasks = scan.detail_counts?.threat_audit_superseded
    ?? allThreatTasks.length - threatTasks.length;
  const currentThreatTaskCount = scan.detail_counts?.threat_audit_current
    ?? threatTasks.length;
  const completedThreatTasks = scan.detail_counts?.threat_audit_completed
    ?? threatTasks.filter((task) => task.status === "completed").length;
  const failedThreatTasks = scan.detail_counts?.threat_audit_failed ?? threatTasks.filter((task) =>
    ["failed", "failure", "error", "timeout", "no_result"].includes(String(task.status || "").toLowerCase()),
  ).length;
  const activeThreatTasks = scan.detail_counts?.threat_audit_running
    ?? threatTasks.filter((task) => isActiveThreatAuditStatus(task.status)).length;
  const threatResultsReady = isThreatAnalysisResultReady(scan.threat_analysis);
  const threatResultCounts = getThreatAnalysisResultCounts(scan.threat_analysis);
  let threatAnalysisStatus = threatAnalysisFlowStatus(scan);
  if (
    threatAnalysisStatus === "pending"
    && (threatAnalysisLoading || (!isDone && hasEvent(scan.events, ["threat_analysis"])))
  ) {
    threatAnalysisStatus = "running";
  }
  const threatAnalysisNode: FlowNodeView = {
    id: "threat",
    label: threatAnalysisMethodLabel(scan),
    detail: threatResultsReady
      ? threatAnalysisSummary(scan.threat_analysis!)
      : scan.threat_analysis_run?.status === "error"
        ? scan.threat_analysis_run.error_message || "威胁分析执行失败"
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
    detail: !scan.auto_fp_review && !fpReview
      ? "本次扫描未启用自动去误报"
      : fpReviewTotal > 0
        ? `${fpReviewProcessed}/${fpReviewTotal} 已复核`
        : fpReviewTargetCount > 0
          ? "等待正报复核"
          : "当前没有复核目标",
    status: !scan.auto_fp_review && !fpReview
      ? "disabled"
      : isFpReviewing
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
    label: "验证利用",
    detail: validationDetail,
    status: !scan.vulnerability_validation_enabled
      ? "disabled"
      : validationRunningCount > 0
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
    const threatRunStatus = engine.engine_id === THREAT_ENGINE_ID
      ? threatAuditFlowStatus(scan, run)
      : null;
    const label = processFlowEngineLabel(engine.engine_id, engine.engine_label);
    const detail = engine.engine_id === THREAT_ENGINE_ID
      ? currentThreatTaskCount > 0
        ? `${activeThreatTasks} 运行 · ${completedThreatTasks}/${currentThreatTaskCount} 完成${failedThreatTasks ? ` · ${failedThreatTasks} 未成功` : ""}`
        : supersededThreatTasks > 0
          ? `${supersededThreatTasks} 个历史任务已取代 · 当前没有叶子节点审计任务`
          : scan.threat_analysis
            ? "等待创建审计任务"
            : "等待威胁分析完成"
      : isPatternAuditEngine(engine.engine_id)
        ? threatPatternAuditFlowDetail(run, Boolean(scan.threat_analysis))
        : run?.error_message
        || (engine.engine_id === STATIC_ENGINE_ID && staticRunning
          ? `静态分析 ${scan.static_scanned_files}/${scan.static_total_files || "?"} 文件`
          : engine.engine_id === STATIC_ENGINE_ID && candidateCount > 0
            ? `静态分析完成 · ${scan.processed_candidates}/${scan.total_candidates || candidateCount} 候选点已审计`
            : run?.started_at
              ? `引擎 ID：${engine.engine_id}`
              : "等待启动");
    return {
      id: `engine:${engine.engine_id}`,
      label,
      detail,
      status: engine.engine_id === STATIC_ENGINE_ID
        ? staticCandidateAuditFlowStatus(scan, run)
        : threatRunStatus ?? engineFlowStatus(run),
      active: activeTab === "mining" && activeEngineId === engine.engine_id,
      tone: engine.engine_id === THREAT_ENGINE_ID ? "green" : engine.engine_id === STATIC_ENGINE_ID ? "cyan" : "blue",
    };
  };
  const selectedById = new Map(engines.map((engine) => [engine.engine_id, engine]));
  const catalogIds = new Set<string>();
  const allMiningEntries: CatalogMiningFlowEntry[] = engineCatalog.map((item) => {
    catalogIds.add(item.engine_id);
    const selectedEngine = selectedById.get(item.engine_id);
    const engine = selectedEngine ?? {
      engine_id: item.engine_id,
      engine_label: canonicalMiningEngineLabel(item.engine_id, item.label),
      enabled: false,
    };
    return {
      engine,
      selected: Boolean(selectedEngine),
      node: selectedEngine
        ? engineNode(selectedEngine)
        : {
          id: `engine:${item.engine_id}`,
          label: processFlowEngineLabel(item.engine_id, item.label),
          detail: "本次扫描未选择",
          status: "skipped",
          active: false,
          tone: item.engine_id === THREAT_ENGINE_ID ? "green" : item.engine_id === STATIC_ENGINE_ID ? "cyan" : "blue",
        },
    };
  });
  for (const engine of engines) {
    if (catalogIds.has(engine.engine_id)) continue;
    allMiningEntries.push({
      engine,
      node: engineNode(engine),
      selected: true,
    });
  }
  return {
    threatAnalysisNode,
    threatResultsReady,
    threatResultCounts,
    miningEntries: engines.map((engine) => ({ engine, node: engineNode(engine) })),
    allMiningEntries,
    staticAnalysisNode,
    validationNode,
    fpReviewNode,
    indexNode,
    codeGraphMcpEnabled: scan.code_graph_mcp_enabled,
    knowledgeBaseEnabled: scan.knowledge_base_enabled,
  };
}

export function sidebarStatusDotClass(status: FlowNodeStatus): string {
  if (status === "running") return "bg-blue-400 animate-pulse motion-reduce:animate-none";
  if (status === "queued") return "bg-amber-400";
  if (status === "done") return "bg-emerald-400";
  if (status === "warning") return "bg-amber-400";
  if (status === "incomplete") return "bg-amber-400";
  if (status === "error") return "bg-red-400";
  if (status === "cancelled") return "bg-orange-400";
  if (status === "disabled") return "bg-slate-600";
  if (status === "skipped") return "bg-slate-600";
  if (status === "unknown") return "bg-slate-500";
  return "bg-slate-400";
}

export function flowStatusLabel(status: FlowNodeStatus): string {
  if (status === "running") return "正在执行";
  if (status === "queued") return "排队中";
  if (status === "done") return "执行完毕";
  if (status === "warning") return "完成但有失败";
  if (status === "incomplete") return "未完成，可续扫";
  if (status === "error") return "执行失败";
  if (status === "cancelled") return "已取消";
  if (status === "disabled") return "未启用";
  if (status === "skipped") return "已跳过";
  if (status === "unknown") return "状态未知";
  return "待执行";
}

export function flowStatusTone(status: FlowNodeStatus, doneTone: TaskTone): TaskTone {
  if (status === "running") return "blue";
  if (status === "queued") return "amber";
  if (status === "done") return doneTone;
  if (status === "warning") return "amber";
  if (status === "incomplete") return "amber";
  if (status === "error" || status === "cancelled") return "red";
  return "slate";
}
