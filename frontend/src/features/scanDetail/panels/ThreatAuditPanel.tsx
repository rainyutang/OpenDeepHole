import {
  THREAT_PATTERN_AUDIT_ENGINE_ID as THREAT_PATTERN_ENGINE_ID,
  THREAT_AUDIT_ENGINE_ID as THREAT_ENGINE_ID,
  THREAT_PATTERN_ITERATIVE_ENGINE_ID,
  canonicalMiningEngineLabel,
} from "../../../miningEngines";
import type { ScanStatus as ScanStatusType, ScanEvent } from "../../../types/scans";
import type { FpReviewJob } from "../../../types/fpReview";
import type { ListFocusRequest } from "../../../auditNavigation";
import { useState, useRef, useMemo, useEffect } from "react";
import { createIterativeAuditDetailCache, IterativeAuditTaskDetail } from "../../threatAudit/IterativeAuditTaskDetail";
import { useIterativeAuditTasks } from "../../threatAudit/useIterativeAuditTasks";
import type { ThreatAuditTask } from "../../../types/audit";
import {
  currentThreatAuditTasks,
  isThreatPatternAuditPoolTask,
  isThreatAuditPoolTask,
  THREAT_AUDIT_PAGE_SIZE,
  miningEngineRun,
  engineFlowStatus,
  threatAuditFlowStatus,
} from "../model/scan";
import { collectScanQueueTasks } from "../model/taskQueue";
import type { ScanQueueTask } from "../model/types";
import {
  useThreatAuditResults,
  ThreatAuditFindingBadge,
  ThreatAuditResults,
} from "../../threatAudit/ThreatAuditResults";
import { useListFocus } from "../../../auditNavigation";
import { TaskPanel, MiniMetric, StatusPill, EventList } from "../components/taskUi";
import { flowStatusLabel, flowStatusTone } from "../model/processFlow";
import { StaticFilterSelect } from "./StaticCandidateDetail";
import { ThreatAuditTaskDetail } from "./ThreatAuditTaskDetail";
import {
  effectiveThreatAuditTaskStatus,
  threatAuditStatusOptions,
  threatAuditStatusLabel,
  threatAuditStatusTone,
} from "../model/threatAudit";

export function ThreatAuditPanel({
  scan,
  patternMode = false,
  engineId = patternMode ? THREAT_PATTERN_ENGINE_ID : THREAT_ENGINE_ID,
  taskRevision = 0,
  events,
  fpReview,
  resultRevision,
  focusRequest,
  onOpenIssue,
}: {
  scan: ScanStatusType;
  patternMode?: boolean;
  engineId?: string;
  taskRevision?: number;
  events: ScanEvent[];
  fpReview: FpReviewJob | null;
  resultRevision: number;
  focusRequest?: ListFocusRequest<string>;
  onOpenIssue: (index: number) => void;
}) {
  const [statusFilter, setStatusFilter] = useState("__all__");
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(focusRequest?.key ?? null);
  const [page, setPage] = useState(1);
  const adjacentFocus = useRef<string | null>(null);
  const iterative = engineId === THREAT_PATTERN_ITERATIVE_ENGINE_ID;
  const [detailCache] = useState(createIterativeAuditDetailCache);
  const iterativePages = useIterativeAuditTasks(scan.scan_id, engineId,
    iterative && Boolean(scan.detail_counts), scan.threat_pattern_audit_tasks ?? [], taskRevision);
  const tasks = useMemo(() => patternMode
    ? iterativePages.tasks.map((task): ThreatAuditTask => ({
      ...task, surface_name: task.module_name, method_node_id: task.pattern_id,
      method_name: task.pattern_name, code_path: task.code_paths?.[0]?.path ?? "",
    }))
    : scan.threat_audit_tasks ?? [], [patternMode, iterativePages.tasks, scan.threat_audit_tasks]);
  const prefix = patternMode ? "threat_pattern_audit" : "threat_audit";
  const engineCounts = patternMode ? scan.detail_counts?.threat_pattern_audit_by_engine?.[engineId] : undefined;
  const aggregate = iterative || (patternMode && scan.detail_counts?.threat_pattern_audit_by_engine)
    ? undefined : scan.detail_counts;
  const currentTasks = useMemo(() => currentThreatAuditTasks(tasks), [tasks]);
  const supersededTaskCount = engineCounts?.superseded ?? aggregate?.[`${prefix}_superseded`]
    ?? tasks.length - currentTasks.length;
  const queueTasks = useMemo(
    () => collectScanQueueTasks(scan.opencode_pool ?? null).filter(
      (item) => patternMode ? isThreatPatternAuditPoolTask(item.task, engineId) : isThreatAuditPoolTask(item.task),
    ),
    [scan.opencode_pool, patternMode, engineId],
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
  const resultsScan = useMemo(() => iterative
    ? { ...scan, threat_pattern_audit_tasks: iterativePages.tasks } : scan, [iterative, scan, iterativePages.tasks]);
  const auditResults = useThreatAuditResults(
    resultsScan,
    [...pagedTasks.map((task) => task.task_id), ...(selected ? [selected.task_id] : [])],
    fpReview,
    resultRevision,
    patternMode,
  );
  const statusCounts = useMemo(() => {
    const counts = new Map<string, number>();
    currentTasks.forEach((task) => {
      const status = effectiveThreatAuditTaskStatus(task, runtimeByTaskId.get(task.task_id));
      counts.set(status, (counts.get(status) ?? 0) + 1);
    });
    return counts;
  }, [currentTasks, runtimeByTaskId]);
  const run = miningEngineRun(scan, engineId);
  const processStatus = patternMode ? engineFlowStatus(run) : threatAuditFlowStatus(scan, run);
  const totalTaskCount = engineCounts?.current ?? aggregate?.[`${prefix}_current`] ?? currentTasks.length;
  const pendingTaskCount = engineCounts?.pending ?? aggregate?.[`${prefix}_pending`]
    ?? statusCounts.get("pending") ?? 0;
  const queuedTaskCount = engineCounts?.queued ?? aggregate?.[`${prefix}_queued`]
    ?? statusCounts.get("queued") ?? 0;
  const runningTaskCount = engineCounts?.running ?? aggregate?.[`${prefix}_running`]
    ?? ["running", "analyzing", "auditing"].reduce(
      (sum, status) => sum + (statusCounts.get(status) ?? 0),
      0,
    );
  const completedTaskCount = engineCounts?.completed ?? aggregate?.[`${prefix}_completed`]
    ?? statusCounts.get("completed") ?? 0;
  const failedTaskCount = engineCounts?.failed ?? aggregate?.[`${prefix}_failed`]
    ?? ["failed", "failure", "error", "timeout", "no_result"].reduce(
      (sum, status) => sum + (statusCounts.get(status) ?? 0),
      0,
    );
  const cancelledTaskCount = engineCounts?.cancelled ?? aggregate?.[`${prefix}_cancelled`]
    ?? statusCounts.get("cancelled") ?? 0;

  useEffect(() => {
    setPage(1);
  }, [statusFilter]);

  useEffect(() => {
    if (!adjacentFocus.current) return;
    const index = visibleTasks.findIndex((task) => task.task_id === adjacentFocus.current);
    if (index < 0) return;
    setPage(Math.floor(index / THREAT_AUDIT_PAGE_SIZE) + 1);
    adjacentFocus.current = null;
  }, [visibleTasks, selectedTaskId]);

  const listFocus = useListFocus(focusRequest, visibleTasks.map((task) => task.task_id), THREAT_AUDIT_PAGE_SIZE,
    setSelectedTaskId, setPage, () => setStatusFilter("__all__"));

  useEffect(() => {
    if (listFocus.pinned !== null || listFocus.pending) return;
    if (visibleTasks.length === 0) {
      setSelectedTaskId(null);
      return;
    }
    if (!selectedTaskId || !visibleTasks.some((task) => task.task_id === selectedTaskId)) {
      setSelectedTaskId(visibleTasks[0].task_id);
    }
  }, [selectedTaskId, visibleTasks, listFocus.pinned, listFocus.pending]);

  return (
    <TaskPanel
      title={canonicalMiningEngineLabel(engineId)}
      status={flowStatusLabel(processStatus)}
      tone={flowStatusTone(processStatus, "green")}
      summary={iterative ? "按模块与攻击模式审计，有后续线索时继续，每个威胁最多 3 轮。" : patternMode ? "按高风险模块与攻击模式拆分任务，并逐项执行模型审计。" : "按威胁分析产生的叶子节点与攻击模式拆分任务，并逐项执行模型审计。"}
    >
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
        <MiniMetric label="任务总数" value={totalTaskCount} />
        <MiniMetric label="待执行" value={pendingTaskCount} tone="amber" />
        <MiniMetric label="排队中" value={queuedTaskCount} tone="amber" />
        <MiniMetric label="运行中" value={runningTaskCount} tone="cyan" />
        <MiniMetric label="已完成" value={completedTaskCount} tone="green" />
        <MiniMetric
          label="未成功"
          value={failedTaskCount}
          tone="red"
        />
        <MiniMetric label="已取消" value={cancelledTaskCount} />
        <MiniMetric label="已取代" value={supersededTaskCount} />
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <StaticFilterSelect
          label="状态"
          value={statusFilter}
          options={threatAuditStatusOptions(tasks, runtimeByTaskId)}
          onChange={(value) => { listFocus.release(); setStatusFilter(value); }}
        />
        {iterative && (iterativePages.cursor || iterativePages.error) && <button type="button"
          disabled={iterativePages.loading} onClick={() => void iterativePages.loadMore()}
          className="rounded border border-slate-700 px-3 py-2 text-xs text-slate-300 disabled:opacity-40">
          {iterativePages.error ? "重试加载审计任务" : "加载更多审计任务"}
        </button>}
        {iterative && iterativePages.loading && <span className="text-xs text-slate-400">正在加载审计任务…</span>}
      </div>

      {tasks.length === 0 ? (
        <div className="rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-10 text-center text-sm text-slate-500">
          {patternMode && (["success", "error", "cancelled"].includes(run?.status ?? "")
            || ["complete", "error", "cancelled"].includes(scan.status)) && run?.total_candidates !== 0
            ? "此扫描未保存审计任务记录，已有问题可在问题页面查看。"
            : run?.status === "running"
              ? "威胁分析完成后会在这里实时创建审计任务。"
              : run?.status === "success" && (!patternMode || run.total_candidates === 0)
                ? "本次威胁分析没有生成需要审计的任务。"
                : "尚未创建审计任务。"}
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
                          ref={listFocus.pinned === task.task_id ? listFocus.targetRef : undefined}
                          aria-current={selectedTaskId === task.task_id ? "true" : undefined}
                          onClick={() => { listFocus.release(); setSelectedTaskId(task.task_id); }}
                          className={`w-full px-3 py-3 text-left transition-colors ${selectedTaskId === task.task_id
                              ? "bg-cyan-500/15"
                              : status === "running"
                                ? "bg-blue-500/10 hover:bg-blue-500/15"
                                : "hover:bg-slate-800/60"
                            }`}
                        >
                          <div className="flex items-start gap-2">
                            <div className="flex shrink-0 flex-col items-start gap-1">
                              {iterative && <span className="shrink-0 whitespace-nowrap rounded bg-cyan-500/15 px-2 py-0.5 text-xs font-medium text-cyan-300">第 {task.iteration || 1} 轮</span>}
                              <StatusPill label={threatAuditStatusLabel(status)} tone={threatAuditStatusTone(status)} />
                              <ThreatAuditFindingBadge result={auditResults.results.get(task.task_id)} />
                            </div>
                            <div className="min-w-0">
                              <div className="truncate text-sm font-medium text-slate-200">
                                {task.method_name || "未命名攻击模式"}
                              </div>
                              <div className="mt-1 truncate text-xs text-slate-500">
                                {task.surface_name || (patternMode ? "未命名模块" : "未命名叶子节点")}
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
                  onClick={() => { listFocus.release(); setPage((value) => Math.max(1, value - 1)); }}
                  className="rounded-lg border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-30"
                >
                  上一页
                </button>
                <span className="text-xs text-slate-500">第 {safePage}/{totalPages} 页 · 共 {visibleTasks.length} 条</span>
                <button
                  type="button"
                  disabled={safePage === totalPages}
                  onClick={() => { listFocus.release(); setPage((value) => Math.min(totalPages, value + 1)); }}
                  className="rounded-lg border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-30"
                >
                  下一页
                </button>
              </div>
            )}
          </div>

          <div className="min-h-[28rem] rounded-xl border border-slate-700 bg-slate-900/40">
            {selected && iterative ? (
              <IterativeAuditTaskDetail
                key={selected.task_id}
                scanId={scan.scan_id}
                historyAvailable={Boolean(scan.detail_counts)}
                task={selected}
                runtime={selectedRuntime}
                statusLabel={threatAuditStatusLabel(effectiveThreatAuditTaskStatus(selected, selectedRuntime ?? undefined))}
                statusBadge={<StatusPill label={threatAuditStatusLabel(effectiveThreatAuditTaskStatus(selected, selectedRuntime ?? undefined))}
                  tone={threatAuditStatusTone(effectiveThreatAuditTaskStatus(selected, selectedRuntime ?? undefined))} />}
                results={<ThreatAuditResults result={auditResults.results.get(selected.task_id)}
                  status={effectiveThreatAuditTaskStatus(selected, selectedRuntime ?? undefined)}
                  loading={auditResults.loading} error={auditResults.error} onRetry={auditResults.retry} onOpenIssue={onOpenIssue} />}
                nextTask={tasks.find((task) => task.parent_task_id === selected.task_id)}
                cache={detailCache}
                onSelectTask={(id, loaded) => {
                  listFocus.release();
                  adjacentFocus.current = id;
                  setStatusFilter("__all__");
                  if (loaded) iterativePages.addTask(loaded);
                  setSelectedTaskId(id);
                }}
              />
            ) : selected ? (
              <ThreatAuditTaskDetail
                key={selected.task_id}
                scan={scan}
                task={selected}
                patternMode={patternMode}
                runtime={selectedRuntime}
                result={auditResults.results.get(selected.task_id)}
                resultLoading={auditResults.loading}
                resultError={auditResults.error}
                onRetryResult={auditResults.retry}
                onOpenIssue={onOpenIssue}
              />
            ) : (
              <div className="flex h-full items-center justify-center px-4 py-16 text-sm text-slate-500">
                从左侧选择一个审计任务查看详情
              </div>
            )}
          </div>
        </div>
      )}
      <EventList events={events} empty={patternMode ? "暂无攻击模式审计日志" : "暂无威胁审计日志"} />
    </TaskPanel>
  );
}
