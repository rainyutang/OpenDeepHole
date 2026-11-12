import { STATIC_CANDIDATE_ENGINE_LABEL, STATIC_CANDIDATE_ENGINE_ID as STATIC_ENGINE_ID } from "../../../miningEngines";
import {
  staticAuditExecutionEnded,
  staticCandidateAuditCounts,
  staticCandidateAuditFlowStatus,
} from "../../../staticAudit";
import type { Candidate } from "../../../types/audit";
import type { OpenCodePoolStatus } from "../../../types/modelPool";
import type { ScanEvent, ScanStatus as ScanStatusType } from "../../../types/scans";
import { EventList, MiniMetric, ProgressBlock, TaskPanel } from "../components/taskUi";
import { flowStatusLabel, flowStatusTone } from "../model/processFlow";
import { isCandidateAuditPoolTask, miningEngineRun } from "../model/scan";

export function AuditTaskPanel({
  scan,
  pct,
  currentCandidate,
  events,
  pool,
  onOpenStaticAnalysis,
}: {
  scan: ScanStatusType;
  pct: number;
  currentCandidate: Candidate | null;
  events: ScanEvent[];
  pool: OpenCodePoolStatus | null;
  onOpenStaticAnalysis: () => void;
}) {
  const status = staticCandidateAuditFlowStatus(scan, miningEngineRun(scan, STATIC_ENGINE_ID));
  const ended = staticAuditExecutionEnded(scan);
  const counts = staticCandidateAuditCounts(scan);
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
      title={STATIC_CANDIDATE_ENGINE_LABEL}
      status={flowStatusLabel(status)}
      tone={flowStatusTone(status, "green")}
      summary="先通过静态分析生成代码风险候选点，再逐项执行模型审计并确认真实问题。"
    >
      <div className="flex flex-col gap-3 rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="text-xs font-semibold text-cyan-200">内部阶段</div>
          <div className="mt-1 text-sm text-slate-300">静态分析 → 候选点 AI 审计</div>
        </div>
        <button
          type="button"
          onClick={onOpenStaticAnalysis}
          className="rounded-lg border border-cyan-500/30 px-3 py-1.5 text-sm font-medium text-cyan-200 transition-colors hover:bg-cyan-500/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/70"
        >
          查看静态分析详情
        </button>
      </div>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
        <MiniMetric label="已审计" value={scan.processed_candidates} tone="blue" />
        <MiniMetric label="总候选" value={scan.total_candidates} />
        <MiniMetric label={ended ? "审计失败" : "运行中"} value={ended ? counts.failed : runningAudits} tone={ended ? "red" : "cyan"} />
        <MiniMetric label={ended ? "待续扫" : "排队中"} value={ended ? Math.max(
          counts.pending + counts.queued + counts.running, scan.total_candidates - scan.processed_candidates,
        ) : queuedAudits} tone="amber" />
      </div>
      <ProgressBlock label="AI 审计" current={scan.processed_candidates} total={scan.total_candidates} percentOverride={scan.static_analysis_done ? pct : undefined} fallback="等待审计候选点" />
      {!ended && currentCandidate && (
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
