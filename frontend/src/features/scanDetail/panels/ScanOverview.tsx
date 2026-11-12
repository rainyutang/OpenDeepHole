import type { ReactNode } from "react";
import { Fragment } from "react";
import { ScanProgressPanel } from "../../../components/ScanProgressPanel";
import { ScanTokenUsagePanel } from "../../../components/ScanTokenUsagePanel";
import {
  STATIC_CANDIDATE_ENGINE_ID as STATIC_ENGINE_ID,
  THREAT_AUDIT_ENGINE_LABEL,
  THREAT_AUDIT_ENGINE_ID as THREAT_ENGINE_ID,
  canonicalMiningEngineLabel,
} from "../../../miningEngines";
import { hasActiveScanProgress } from "../../../scanProgress";
import { staticAnalysisFailures, staticCandidateAuditFlowStatus } from "../../../staticAudit";
import type { FpReviewJob } from "../../../types/fpReview";
import type { ScanStatus as ScanStatusType } from "../../../types/scans";
import type { Vulnerability } from "../../../types/issues";
import { isThreatAnalysisResultReady } from "../../threatAnalysis/analysisModel";
import { OverviewMetric } from "../components/OverviewMetric";
import { MiniMetric, StatusPill, TaskSummaryRow } from "../components/taskUi";
import { flowStatusLabel, flowStatusTone } from "../model/processFlow";
import {
  currentThreatAuditTasks,
  effectiveMiningEngines,
  engineFlowStatus,
  fpReviewMethodLabel,
  hasEvent,
  isAiConfirmed,
  isThreatAnalysisSelected,
  isValidationTerminalStatus,
  miningEngineRun,
  percent,
  taskStateLabel,
  threatAnalysisFlowStatus,
  threatAnalysisMethodLabel,
  threatAnalysisSummary,
  threatAuditFlowStatus,
  vulnerabilityFunctionLabel,
  vulnerabilityLocation,
} from "../model/scan";
import type { MainTab } from "../model/types";
import { ScanTaskQueuePanel } from "./ScanTaskQueuePanel";

export function ScanOverview({
  scan,
  issueCount,
  continuableCount,
  variantIssueCount,
  gitHistoryCount,
  showGitHistoryStages,
  currentStage,
  pct,
  isRunning,
  isDone,
  fpReview,
  isFpReviewing,
  currentFpReviewTargets,
  confirmedIssueCount,
  onNavigate,
  coverage,
}: {
  scan: ScanStatusType;
  issueCount: number;
  continuableCount: number;
  variantIssueCount: number;
  gitHistoryCount: number;
  showGitHistoryStages: boolean;
  currentStage: string;
  pct: number;
  isRunning: boolean;
  isDone: boolean;
  fpReview: FpReviewJob | null;
  isFpReviewing: boolean;
  currentFpReviewTargets: Vulnerability[];
  confirmedIssueCount: number;
  onNavigate: (tab: MainTab) => void;
  coverage: ReactNode;
}) {
  const engines = effectiveMiningEngines(scan);
  const staticEngineSelected = engines.some((engine) => engine.engine_id === STATIC_ENGINE_ID);
  const staticEngineRun = miningEngineRun(scan, STATIC_ENGINE_ID);
  const staticAnalysisDone = scan.static_analysis_done || (
    scan.status === "complete" && staticEngineRun?.status !== "error"
  );
  const partialStatic = staticAnalysisDone && staticAnalysisFailures(scan).length > 0;
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
              {scan.product || scan.scan_name || scan.project_id || scan.scan_id}
              {scan.validation_method_label && (
                <span className="ml-3 border-l border-slate-700 pl-3">
                  验证方法：<span className="text-slate-300">{scan.validation_method_label}</span>
                </span>
              )}
              {!scan.validation_method_label && scan.validation_environment && (
                <span className="ml-3 border-l border-slate-700 pl-3">
                  旧验证环境：<span className="text-slate-300">{scan.validation_environment}</span>
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

      <ScanProgressPanel scan={scan} active={isRunning || hasActiveScanProgress(scan, fpReview)} />

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
        {staticEngineSelected && (
          <OverviewMetric icon="target" label="候选点" value={scan.total_candidates || scan.vulnerabilities.length} detail={`${scan.processed_candidates} 已审计`} tone="blue" />
        )}
        <OverviewMetric icon="alert" label="疑似问题" value={issueCount} detail={`${confirmedIssueCount} 确认问题`} tone="red" onClick={() => onNavigate("issues")} />
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
      <ScanTaskQueuePanel key={scan.scan_id} scanId={scan.scan_id} pool={scan.opencode_pool ?? null} />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1fr_22rem]">
        <section className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-200">任务进展</h3>
            <span className="text-xs text-slate-500">扫描 ID: {scan.scan_id}</span>
          </div>
          <div className="space-y-3">
            <TaskSummaryRow
              label="代码图谱构建（底层能力）"
              status={scan.code_graph_mcp_enabled ? "已启用" : "未启用"}
              tone={scan.code_graph_mcp_enabled ? "green" : "slate"}
              detail={scan.code_graph_mcp_enabled ? "本次扫描已启用 CodeGraph" : "本次扫描未启用 CodeGraph"}
            />
            <TaskSummaryRow
              label="静态分析"
              status={staticEngineSelected
                ? partialStatic ? "完成（部分规则失败）" : taskStateLabel(
                  staticAnalysisDone,
                  scan.status === "analyzing" && !staticAnalysisDone,
                  scan.status === "error" || staticEngineRun?.status === "error",
                )
                : "已跳过"}
              tone={staticEngineSelected
                ? partialStatic ? "amber" : staticAnalysisDone ? "green" : scan.status === "analyzing" ? "cyan" : scan.status === "error" || staticEngineRun?.status === "error" ? "red" : "slate"
                : "slate"}
              progress={staticEngineSelected && scan.static_total_files ? percent(scan.static_scanned_files, scan.static_total_files) : undefined}
              detail={staticEngineSelected
                ? scan.total_candidates > 0 ? `${scan.total_candidates} 个候选点` : "等待静态规则扫描"
                : "本次扫描未选择静态候选引擎"}
            />
            <TaskSummaryRow
              label={threatAnalysisMethodLabel(scan)}
              status={flowStatusLabel(threatAnalysisStatus)}
              tone={flowStatusTone(threatAnalysisStatus, "green")}
              detail={isThreatAnalysisResultReady(scan.threat_analysis)
                ? threatAnalysisSummary(scan.threat_analysis)
                : scan.threat_analysis_run?.status === "error"
                  ? scan.threat_analysis_run.error_message || "威胁分析执行失败"
                  : isThreatAnalysisSelected(scan)
                    ? scan.threat_analysis_run?.error_message || "等待生成攻击树"
                    : "本次扫描未选择威胁分析"}
            />
            {engines.map((engine) => {
              const run = miningEngineRun(scan, engine.engine_id);
              if (engine.engine_id === THREAT_ENGINE_ID) {
                const auditStatus = threatAuditFlowStatus(scan, run);
                const allThreatTasks = scan.threat_audit_tasks ?? [];
                const threatTasks = currentThreatAuditTasks(allThreatTasks);
                const supersededCount = scan.detail_counts?.threat_audit_superseded
                  ?? allThreatTasks.length - threatTasks.length;
                const threatTaskCount = scan.detail_counts?.threat_audit_current
                  ?? threatTasks.length;
                const threatCompleted = scan.detail_counts?.threat_audit_completed
                  ?? threatTasks.filter((task) => task.status === "completed").length;
                return (
                  <Fragment key={engine.engine_id}>
                    <TaskSummaryRow
                      label={THREAT_AUDIT_ENGINE_LABEL}
                      status={flowStatusLabel(auditStatus)}
                      tone={flowStatusTone(auditStatus, "green")}
                      detail={threatTaskCount
                        ? `${threatCompleted}/${threatTaskCount} 任务完成`
                        : supersededCount > 0
                          ? `${supersededCount} 个历史任务已取代`
                          : "等待威胁审计任务"}
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
              const status = engine.engine_id === STATIC_ENGINE_ID
                ? staticCandidateAuditFlowStatus(scan, run)
                : engineFlowStatus(run);
              return (
                <TaskSummaryRow
                  key={engine.engine_id}
                  label={canonicalMiningEngineLabel(engine.engine_id, engine.engine_label)}
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
              progress={percent(fpReview?.processed ?? 0, fpReview?.total ?? 0)}
              detail={fpReview
                ? `${fpReview.processed}/${fpReview.total} 已复核`
                : fpReviewTargetCount > 0
                  ? `${fpReviewTargetCount} 个可复核问题`
                  : "当前没有可复核问题"}
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
                <div className="mt-2 text-xs text-slate-300">{String(target.vuln_type || "未知类型").toUpperCase()}</div>
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
      {coverage}
    </div>
  );
}
