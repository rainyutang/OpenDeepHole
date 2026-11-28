import { useEffect, useMemo, useState } from "react";
import { getScanRedlineAuditResults } from "../../api/redlines";
import type { ListFocusRequest } from "../../auditNavigation";
import { REDLINE_AUDIT_ENGINE_ID, REDLINE_AUDIT_ENGINE_LABEL } from "../../miningEngines";
import type { ThreatAuditTaskResult } from "../../types/audit";
import type { ScanEvent, ScanStatus } from "../../types/scans";
import { formatDateTime } from "../modelPool/presentation";
import { EventList, MiniMetric, StatusPill, TaskPanel } from "../scanDetail/components/taskUi";
import { flowStatusLabel, flowStatusTone } from "../scanDetail/model/processFlow";
import { engineFlowStatus, formatOutputSource, hasOutputSource, miningEngineRun } from "../scanDetail/model/scan";
import type { TaskTone } from "../scanDetail/model/types";
import {
  buildRedlineItemProgressList,
  redlineItemStatusLabel,
  redlineRoundStatusLabel,
  redlineStopReasonLabel,
  summarizeRedlineProgress,
} from "./redlinesModel";
import type { RedlineItemAuditState, RedlineItemProgress } from "./redlinesModel";
import { useRedlineAuditTasks } from "./useRedlineAuditTasks";

interface Props {
  scan: ScanStatus;
  events: ScanEvent[];
  taskRevision: number;
  resultRevision: number;
  focusRequest?: ListFocusRequest<string>;
  onOpenIssue: (index: number) => void;
}

function itemStateTone(state: RedlineItemAuditState): TaskTone {
  if (state === "completed") return "green";
  if (state === "running") return "blue";
  if (state === "queued") return "amber";
  if (state === "failed" || state === "cancelled") return "red";
  return "slate";
}

function roundStatusTone(status: string): TaskTone {
  const normalized = String(status || "pending").trim().toLowerCase();
  if (normalized === "completed") return "green";
  if (normalized === "running" || normalized === "analyzing" || normalized === "auditing") return "blue";
  if (normalized === "queued") return "amber";
  if (["failed", "failure", "error", "timeout", "no_result", "cancelled"].includes(normalized)) return "red";
  return "slate";
}

export function RedlineAuditPanel({
  scan,
  events,
  taskRevision,
  resultRevision,
  focusRequest,
  onOpenIssue,
}: Props) {
  const [keyword, setKeyword] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  const [selectedItemId, setSelectedItemId] = useState<string | null>(null);
  const [taskResults, setTaskResults] = useState<Map<string, ThreatAuditTaskResult>>(new Map());
  const [resultsLoading, setResultsLoading] = useState(false);

  const { tasks, loading, error, reload } = useRedlineAuditTasks(
    scan.scan_id,
    Boolean(scan.detail_counts) || (scan.redline_audit_tasks?.length ?? 0) === 0,
    scan.redline_audit_tasks ?? [],
    taskRevision,
  );

  const items = useMemo(
    () => buildRedlineItemProgressList(scan.redline_items ?? [], tasks),
    [scan.redline_items, tasks],
  );
  const summary = useMemo(() => summarizeRedlineProgress(items), [items]);
  const categories = useMemo(() => {
    const set = new Set<string>();
    for (const item of items) {
      if (item.category.trim()) set.add(item.category.trim());
    }
    return [...set].sort((a, b) => a.localeCompare(b, "zh-CN"));
  }, [items]);

  const visibleItems = useMemo(() => {
    const needle = keyword.trim().toLowerCase();
    return items.filter((item) => {
      if (categoryFilter && item.category.trim() !== categoryFilter) return false;
      if (statusFilter === "with_findings" && item.findingCount === 0) return false;
      if (statusFilter !== "all" && statusFilter !== "with_findings" && item.state !== statusFilter) return false;
      if (!needle) return true;
      return [
        item.code,
        item.securityAttribute,
        item.attributeDescription,
        item.requirement,
        item.category,
      ].some((field) => field.toLowerCase().includes(needle));
    });
  }, [items, keyword, statusFilter, categoryFilter]);

  useEffect(() => {
    if (!focusRequest) return;
    const focusedTask = tasks.find((task) => task.task_id === focusRequest.key);
    const targetItemId = focusedTask?.redline_item_id
      || items.find((item) => item.itemId === focusRequest.key || item.rounds.some((round) => round.task_id === focusRequest.key))?.itemId;
    if (targetItemId) {
      setKeyword("");
      setStatusFilter("all");
      setCategoryFilter("");
      setSelectedItemId(targetItemId);
    }
  }, [focusRequest?.key, focusRequest?.revision, tasks, items]);

  const selectedItem: RedlineItemProgress | null = useMemo(() => {
    if (visibleItems.length === 0) return null;
    if (selectedItemId) {
      const exact = visibleItems.find((item) => item.itemId === selectedItemId);
      if (exact) return exact;
    }
    return visibleItems[0];
  }, [visibleItems, selectedItemId]);

  const selectedRoundTaskIds = useMemo(
    () => (selectedItem?.rounds ?? []).filter((round) => (round.result_vuln_indexes?.length ?? 0) > 0 || round.found === true).map((round) => round.task_id),
    [selectedItem],
  );
  const selectedRoundTaskKey = selectedRoundTaskIds.join("\0");

  useEffect(() => {
    if (!selectedRoundTaskIds.length) {
      setTaskResults(new Map());
      setResultsLoading(false);
      return;
    }
    const controller = new AbortController();
    let disposed = false;
    setResultsLoading(true);
    getScanRedlineAuditResults(scan.scan_id, selectedRoundTaskIds, controller.signal)
      .then((rows) => {
        if (disposed || controller.signal.aborted) return;
        setTaskResults(new Map(rows.map((row) => [row.task_id, row])));
      })
      .catch(() => {
        if (!disposed && !controller.signal.aborted) {
          setTaskResults(new Map());
        }
      })
      .finally(() => {
        if (!disposed && !controller.signal.aborted) {
          setResultsLoading(false);
        }
      });
    return () => {
      disposed = true;
      controller.abort();
    };
  }, [scan.scan_id, selectedRoundTaskKey, resultRevision]);

  const run = miningEngineRun(scan, REDLINE_AUDIT_ENGINE_ID);
  const runStatus = engineFlowStatus(run);
  const counts = scan.detail_counts;
  const totalMetric = counts?.redline_audit_items_total ?? summary.total;
  const completedMetric = counts?.redline_audit_items_completed ?? summary.completed;
  const runningMetric = (counts?.redline_audit_items_running ?? summary.running)
    + (counts?.redline_audit_items_queued ?? summary.queued);
  const failedMetric = counts?.redline_audit_items_failed ?? summary.failed;
  const findingsMetric = counts?.redline_audit_findings ?? summary.findings;

  return (
    <div className="space-y-4">
      <TaskPanel
        title={REDLINE_AUDIT_ENGINE_LABEL}
        status={flowStatusLabel(runStatus)}
        tone={flowStatusTone(runStatus, "blue")}
        summary="按管理员已启用的网络安全红线条目逐条执行最多 5 轮迭代排查；发现的违规问题跳过误报复核，直接进入「疑似问题」列表并标注 [红线]。"
      >
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
          <MiniMetric label="红线条目总数" value={totalMetric} />
          <MiniMetric label="已完成条目" value={completedMetric} tone="green" />
          <MiniMetric label="排查中 / 排队" value={runningMetric} tone="blue" />
          <MiniMetric label="发现违规问题" value={findingsMetric} tone={findingsMetric > 0 ? "red" : "slate"} />
          <MiniMetric label="失败条目" value={failedMetric} tone={failedMetric > 0 ? "amber" : "slate"} />
        </div>

        {run?.error_message && (
          <div role="alert" className="mt-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-200">
            引擎异常：{run.error_message}
          </div>
        )}
        {error && (
          <div role="alert" className="mt-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
            {error}
          </div>
        )}

        <div className="mt-4 flex flex-wrap items-center gap-2">
          <input
            type="search"
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            placeholder="搜索编号、安全属性、红线要求..."
            className="min-w-[200px] flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 outline-none focus:border-blue-500"
          />
          {categories.length > 0 && (
            <select
              aria-label="按红线分类筛选"
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-200"
            >
              <option value="">全部分类</option>
              {categories.map((cat) => (
                <option key={cat} value={cat}>{cat}</option>
              ))}
            </select>
          )}
          <select
            aria-label="按排查状态筛选"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-200"
          >
            <option value="all">全部状态（{items.length}）</option>
            <option value="with_findings">仅看有问题（{items.filter((i) => i.findingCount > 0).length}）</option>
            <option value="running">排查中（{summary.running}）</option>
            <option value="queued">排队中（{summary.queued}）</option>
            <option value="pending">待排查（{summary.pending}）</option>
            <option value="completed">已完成（{summary.completed}）</option>
            <option value="failed">失败（{summary.failed}）</option>
            <option value="cancelled">已取消（{summary.cancelled}）</option>
          </select>
          <button
            type="button"
            onClick={reload}
            disabled={loading}
            className="rounded-lg border border-slate-600 bg-slate-800 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-700 disabled:opacity-50"
          >
            {loading ? "刷新中..." : "刷新进度"}
          </button>
        </div>

        <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-[minmax(19rem,24rem)_1fr]">
          {/* Left: redline items list */}
          <div className="min-w-0 overflow-hidden rounded-xl border border-slate-700/80 bg-slate-900/50">
            <div className="max-h-[65vh] overflow-y-auto divide-y divide-slate-800">
              {visibleItems.length === 0 ? (
                <div className="px-4 py-10 text-center text-xs text-slate-500">
                  {items.length === 0 ? "当前扫描未包含网络安全红线条目快照。" : "当前筛选条件下没有匹配的红线条目。"}
                </div>
              ) : (
                visibleItems.map((item) => {
                  const active = selectedItem?.itemId === item.itemId;
                  const latestIteration = item.latestRound?.iteration ?? 0;
                  const progressPct = item.state === "completed"
                    ? 100
                    : Math.min(100, Math.round((item.completedRounds / item.maxIterations) * 100));
                  return (
                    <button
                      key={item.itemId}
                      type="button"
                      onClick={() => setSelectedItemId(item.itemId)}
                      aria-current={active ? "true" : undefined}
                      className={`w-full px-3.5 py-3 text-left transition-colors ${
                        active ? "bg-blue-500/15" : "hover:bg-slate-800/70"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex min-w-0 items-center gap-1.5">
                          <span className="shrink-0 rounded border border-rose-500/40 bg-rose-500/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-rose-300">
                            {item.code}
                          </span>
                          {item.category && (
                            <span className="shrink-0 rounded border border-slate-600 bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300">
                              {item.category}
                            </span>
                          )}
                        </div>
                        <StatusPill label={redlineItemStatusLabel(item.state)} tone={itemStateTone(item.state)} />
                      </div>
                      <p className="mt-1.5 line-clamp-2 text-xs leading-relaxed text-slate-200">
                        {item.requirement}
                      </p>
                      <div className="mt-2 flex items-center justify-between gap-2 text-[11px] text-slate-400">
                        <span>
                          {latestIteration > 0
                            ? `轮次 ${latestIteration}/${item.maxIterations}`
                            : `未开始（最多 ${item.maxIterations} 轮）`}
                        </span>
                        {item.findingCount > 0 && (
                          <span className="rounded border border-red-500/40 bg-red-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-red-300">
                            发现 {item.findingCount} 个问题
                          </span>
                        )}
                      </div>
                      <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                        <div
                          className={`h-full transition-all ${
                            item.state === "failed"
                              ? "bg-red-500"
                              : item.state === "completed"
                                ? "bg-emerald-500"
                                : "bg-blue-500"
                          }`}
                          style={{ width: `${progressPct}%` }}
                        />
                      </div>
                    </button>
                  );
                })
              )}
            </div>
          </div>

          {/* Right: selected redline detail & round timeline */}
          <div className="min-w-0 rounded-xl border border-slate-700/80 bg-slate-900/50 p-4">
            {!selectedItem ? (
              <div className="py-12 text-center text-xs text-slate-500">请从左侧选择一条红线查看审计进度与各轮次结果。</div>
            ) : (
              <div className="space-y-4">
                <div className="rounded-lg border border-slate-700/80 bg-slate-950/60 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 font-mono text-xs font-semibold text-rose-300">
                        编号 {selectedItem.code}
                      </span>
                      {selectedItem.category && (
                        <span className="rounded border border-slate-600 bg-slate-800 px-2 py-0.5 text-xs text-slate-200">
                          分类：{selectedItem.category}
                        </span>
                      )}
                      <StatusPill label={redlineItemStatusLabel(selectedItem.state)} tone={itemStateTone(selectedItem.state)} />
                    </div>
                    {selectedItem.findingCount > 0 && (
                      <span className="text-xs font-semibold text-red-300">
                        累计发现 {selectedItem.findingCount} 个红线违规问题
                      </span>
                    )}
                  </div>
                  <dl className="mt-3 space-y-2 text-xs">
                    <div>
                      <dt className="inline font-semibold text-slate-300">红线要求：</dt>
                      <dd className="inline text-slate-100">{selectedItem.requirement}</dd>
                    </div>
                    {selectedItem.securityAttribute && (
                      <div>
                        <dt className="inline font-semibold text-slate-300">安全属性：</dt>
                        <dd className="inline text-slate-300">{selectedItem.securityAttribute}</dd>
                      </div>
                    )}
                    {selectedItem.attributeDescription && (
                      <div>
                        <dt className="inline font-semibold text-slate-300">属性描述：</dt>
                        <dd className="inline text-slate-300">{selectedItem.attributeDescription}</dd>
                      </div>
                    )}
                    {selectedItem.guidance && (
                      <div>
                        <dt className="inline font-semibold text-slate-300">解读及指导：</dt>
                        <dd className="inline whitespace-pre-wrap text-slate-400">{selectedItem.guidance}</dd>
                      </div>
                    )}
                    {selectedItem.remark && (
                      <div>
                        <dt className="inline font-semibold text-slate-300">备注：</dt>
                        <dd className="inline whitespace-pre-wrap text-slate-400">{selectedItem.remark}</dd>
                      </div>
                    )}
                  </dl>
                </div>

                <div>
                  <h3 className="mb-2.5 text-xs font-semibold uppercase tracking-wider text-slate-400">
                    迭代审计轮次（最多 {selectedItem.maxIterations} 轮）
                  </h3>
                  {selectedItem.rounds.length === 0 ? (
                    <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-4 text-xs text-slate-500">
                      该条红线尚未创建执行轮次，等待调度启动。
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {selectedItem.rounds.map((round) => {
                        const result = taskResults.get(round.task_id);
                        const findings = result?.findings ?? [];
                        const fallbackIndexes = round.result_vuln_indexes ?? [];
                        const focused = focusRequest?.key === round.task_id;
                        return (
                          <div
                            key={round.task_id}
                            className={`rounded-lg border p-3.5 ${
                              focused
                                ? "border-blue-500/60 bg-blue-500/10"
                                : "border-slate-700/80 bg-slate-950/50"
                            }`}
                          >
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="font-mono text-xs font-semibold text-slate-200">
                                  第 {round.iteration}/{round.max_iterations} 轮
                                </span>
                                <StatusPill
                                  label={redlineRoundStatusLabel(round.status)}
                                  tone={roundStatusTone(round.status)}
                                />
                                {round.found === true && (
                                  <span className="rounded border border-red-500/40 bg-red-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-red-300">
                                    发现问题
                                  </span>
                                )}
                                {round.found === false && (
                                  <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-0.5 text-[10px] text-emerald-300">
                                    未发现违规
                                  </span>
                                )}
                                {(round.validation_retries ?? 0) > 0 && (
                                  <span className="rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 text-[10px] text-amber-200">
                                    原 Session 校验纠正 {round.validation_retries} 次
                                  </span>
                                )}
                              </div>
                              <span className="font-mono text-[11px] text-slate-500">
                                {round.finished_at
                                  ? `完成于 ${formatDateTime(round.finished_at)}`
                                  : round.started_at
                                    ? `开始于 ${formatDateTime(round.started_at)}`
                                    : round.created_at
                                      ? `创建于 ${formatDateTime(round.created_at)}`
                                      : ""}
                              </span>
                            </div>

                            {round.stop_reason && (
                              <div className="mt-2 text-xs text-emerald-300/90">
                                收敛说明：{redlineStopReasonLabel(round.stop_reason)}
                              </div>
                            )}

                            {round.failure_reason && (
                              <div role="alert" className="mt-2 rounded border border-red-500/30 bg-red-500/10 px-2.5 py-1.5 text-xs text-red-200">
                                失败原因：{round.failure_reason}
                              </div>
                            )}

                            {hasOutputSource(round.output_source) && (
                              <div className="mt-2 text-[11px] text-slate-400">
                                执行来源：{formatOutputSource(round.output_source)}
                                {round.output_source?.serve_session_id && (
                                  <span className="ml-2 font-mono text-slate-500">
                                    Session: {round.output_source.serve_session_id}
                                  </span>
                                )}
                              </div>
                            )}

                            {findings.length > 0 ? (
                              <div className="mt-2.5 space-y-2">
                                {findings.map((finding) => (
                                  <div
                                    key={finding.vuln_index}
                                    className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs"
                                  >
                                    <div className="min-w-0 flex-1">
                                      <div className="flex items-center gap-1.5">
                                        <span className="rounded border border-rose-500/40 bg-rose-500/20 px-1.5 py-0.5 text-[10px] font-semibold text-rose-200">
                                          [红线]
                                        </span>
                                        <span className="truncate font-mono text-slate-100">
                                          {finding.file}:{finding.line}
                                        </span>
                                        {finding.function && (
                                          <span className="truncate font-mono text-slate-400">
                                            ({finding.function})
                                          </span>
                                        )}
                                      </div>
                                      {finding.description && (
                                        <p className="mt-1 line-clamp-2 text-slate-300">{finding.description}</p>
                                      )}
                                    </div>
                                    <button
                                      type="button"
                                      onClick={() => onOpenIssue(finding.vuln_index)}
                                      className="shrink-0 rounded-lg border border-blue-500/40 bg-blue-500/15 px-2.5 py-1 text-xs font-medium text-blue-200 hover:bg-blue-500/25"
                                    >
                                      查看问题报告 →
                                    </button>
                                  </div>
                                ))}
                              </div>
                            ) : fallbackIndexes.length > 0 ? (
                              <div className="mt-2.5 flex flex-wrap items-center gap-2">
                                {resultsLoading && (
                                  <span className="text-[11px] text-slate-400">正在加载问题摘要...</span>
                                )}
                                {fallbackIndexes.map((vulnIndex) => (
                                  <button
                                    key={vulnIndex}
                                    type="button"
                                    onClick={() => onOpenIssue(vulnIndex)}
                                    className="rounded-lg border border-blue-500/40 bg-blue-500/15 px-2.5 py-1 text-xs text-blue-200 hover:bg-blue-500/25"
                                  >
                                    查看问题 #{vulnIndex + 1} →
                                  </button>
                                ))}
                              </div>
                            ) : null}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </TaskPanel>

      {events.length > 0 && (
        <TaskPanel
          title="红线排查运行日志"
          status={`${events.length} 条`}
          tone="slate"
          summary="展示网络安全红线排查过程中的关键运行事件与进度日志。"
        >
          <EventList events={events} empty="暂无红线排查运行日志" />
        </TaskPanel>
      )}
    </div>
  );
}
