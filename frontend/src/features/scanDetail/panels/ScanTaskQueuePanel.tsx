import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { getScanTaskDetail, getScanTasksPage } from "../../../api/scanDetails";
import { isInvalidTaskCursorError } from "../../../api/errors";
import { compareTaskHistory, shouldMergeTaskHistory } from "../../../taskOrder";
import type { OpenCodePoolStatus } from "../../../types/modelPool";
import { thCls } from "../../modelPool/ModelPoolDashboard";
import { formatDateTime, formatDuration, formatTokenCount, SCAN_QUEUE_TASK_KINDS, scanQueueTaskKind } from "../../modelPool/presentation";
import type { ScanQueueTaskKind } from "../../modelPool/presentation";
import { StatusPill } from "../components/taskUi";
import { SCAN_QUEUE_PAGE_SIZE, taskTokenUsage } from "../model/scan";
import {
  collectScanQueueTasks,
  scanQueueFailureKindLabel,
  scanQueueSessionEventLabel,
  scanQueueSessionOutcomeLabel,
  scanQueueSessionOutcomeTone,
  scanQueueStatusLabel,
  scanQueueStatusTone,
  scanQueueTaskFailureReason,
  scanQueueTaskKey,
  scanQueueTaskPrompt,
  scanQueueTaskPromptLength,
  scanQueueTaskSessionEvents,
  scanQueueTaskSessionId,
  scanQueueTaskTitle,
} from "../model/taskQueue";
import type { ScanQueueTask } from "../model/types";

export function ScanTaskQueuePanel({ scanId, pool }: { scanId: string; pool: OpenCodePoolStatus | null; }) {
  return <ScanTaskQueueFilter key={scanId} scanId={scanId} pool={pool} />;
}

function ScanTaskQueueFilter({ scanId, pool }: { scanId: string; pool: OpenCodePoolStatus | null; }) {
  const [taskKind, setTaskKind] = useState<ScanQueueTaskKind | "">("");
  const filterInteracted = useRef(false);
  // A new scan starts with all types. A new type gets its own history, cursors
  // and expanded detail state; an old request cannot populate the new list.
  return <ScanTaskQueueContent key={taskKind} scanId={scanId} pool={pool} taskKind={taskKind}
    focusFilter={filterInteracted.current} onTaskKindChange={(kind) => {
      filterInteracted.current = true;
      setTaskKind(kind);
    }} />;
}

function ScanTaskQueueContent({ scanId, pool, taskKind, focusFilter, onTaskKindChange }: {
  scanId: string;
  pool: OpenCodePoolStatus | null;
  taskKind: ScanQueueTaskKind | "";
  focusFilter: boolean;
  onTaskKindChange: (kind: ScanQueueTaskKind | "") => void;
}) {
  const [page, setPage] = useState(1);
  const [expandedTaskId, setExpandedTaskId] = useState<string | null>(null);
  const [history, setHistory] = useState<Record<string, unknown>[]>([]);
  const historyRef = useRef<Record<string, unknown>[]>([]);
  const [historyGaps, setHistoryGaps] = useState<{ cursor: string; boundary: Record<string, unknown>; }[]>([]);
  const [details, setDetails] = useState<Record<string, Record<string, unknown>>>({});
  const detailsRef = useRef(details);
  detailsRef.current = details;
  const [detailRetry, setDetailRetry] = useState(0);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const nextCursorRef = useRef<string | null>(null);
  const lastCompletedCount = useRef(pool?.completed_task_count ?? 0);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState(false);
  const [detailLoading, setDetailLoading] = useState<string | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const loadedMore = useRef(false);
  const cursorResetUsed = useRef(false);
  const historyPageFailed = useRef(false);
  const historyGeneration = useRef(0);
  const historyController = useRef<AbortController | null>(null);
  useEffect(() => () => {
    historyGeneration.current += 1;
    historyController.current?.abort();
  }, []);
  const cacheKey = (item: ScanQueueTask) => JSON.stringify([
    scanId, item.status, item.id, item.task.revision || 1,
    item.task.record_id || [
      item.task.execution_kind, item.task.execution_id,
      item.task.execution_revision ?? pool?.execution_revision,
      item.task.agent_session_id ?? pool?.agent_session_id,
      item.task.serve_session_id,
    ],
  ]);
  const mergeHistory = (incoming: Record<string, unknown>[]) => {
    const merged = new Map(historyRef.current.map((task) => [String(task.task_id), task]));
    incoming.forEach((task) => {
      const previousTask = merged.get(String(task.task_id));
      if (shouldMergeTaskHistory(previousTask, task)) merged.set(String(task.task_id), task);
    });
    historyRef.current = [...merged.values()];
    setHistory(historyRef.current);
  };
  useEffect(() => {
    let cancelled = false;
    const generation = historyGeneration.current;
    if (document.hidden) return;
    const controller = new AbortController();
    getScanTasksPage(scanId, undefined, undefined, controller.signal, taskKind).then((result) => {
      if (cancelled || generation !== historyGeneration.current) return;
      const newestKnown = historyRef.current.reduce<Record<string, unknown> | null>(
        (newest, task) => !newest || compareTaskHistory(task, newest) < 0 ? task : newest, null);
      const last = result.items[result.items.length - 1];
      if (loadedMore.current && newestKnown && last && result.next_cursor && compareTaskHistory(last, newestKnown) < 0) {
        // A refresh can contain more than 50 new completions. Fill this new
        // interval before continuing from the older history page boundary.
        const gap = { cursor: result.next_cursor, boundary: newestKnown };
        setHistoryGaps((previous) => [gap, ...previous]);
      }
      mergeHistory(result.items);
      // A newly reported task may have an old finish time, beyond the first
      // page. Reopen exhausted history once when the scan count actually grows;
      // never compare that global count with the number loaded for this type.
      const completedCount = pool?.completed_task_count ?? 0;
      if (!historyPageFailed.current && (!loadedMore.current
        || (nextCursorRef.current == null && completedCount > lastCompletedCount.current))) {
        nextCursorRef.current = result.next_cursor;
        setNextCursor(result.next_cursor);
        lastCompletedCount.current = completedCount;
      }
      // A successful first-page refresh does not repair a failed older page.
      setHistoryError(historyPageFailed.current);
    }).catch(() => { if (!cancelled && generation === historyGeneration.current) setHistoryError(true); });
    return () => { cancelled = true; controller.abort(); };
  }, [scanId, pool, taskKind]);
  const loadHistory = async () => {
    if (historyLoading) return;
    setHistoryLoading(true);
    setHistoryError(false);
    const gap = historyGaps[0];
    const requestedCursor = gap?.cursor ?? nextCursor;
    let generation = historyGeneration.current;
    const controller = new AbortController();
    historyController.current = controller;
    const isCurrent = () => !controller.signal.aborted && generation === historyGeneration.current;
    try {
      let result;
      let reset = false;
      try {
        result = await getScanTasksPage(scanId, requestedCursor, undefined, controller.signal, taskKind);
      } catch (error) {
        if (!isCurrent()) return;
        if (!requestedCursor || !isInvalidTaskCursorError(error) || cursorResetUsed.current) throw error;
        // An open page may still hold the old task-ID-only cursor at deploy.
        // Restart once, and invalidate any older first-page request in flight.
        reset = true;
        cursorResetUsed.current = true;
        generation = ++historyGeneration.current;
        loadedMore.current = false;
        nextCursorRef.current = null;
        setNextCursor(null);
        setHistory([]);
        historyRef.current = [];
        setHistoryGaps([]);
        setPage(1);
        setExpandedTaskId(null);
        result = await getScanTasksPage(scanId, undefined, undefined, controller.signal, taskKind);
      }
      if (!isCurrent()) return;
      mergeHistory(result.items);
      historyPageFailed.current = false;
      setHistoryError(false);
      loadedMore.current = !reset;
      if (gap && !reset) {
        const last = result.items[result.items.length - 1];
        const cursor = last && compareTaskHistory(last, gap.boundary) < 0 ? result.next_cursor : null;
        setHistoryGaps((previous) => previous.flatMap((item) => {
          if (item !== gap) return [item];
          return cursor ? [{ ...gap, cursor }] : [];
        }));
      } else {
        nextCursorRef.current = result.next_cursor;
        setNextCursor(result.next_cursor);
      }
    } catch {
      if (isCurrent()) {
        historyPageFailed.current = true;
        setHistoryError(true);
      }
    } finally { if (isCurrent()) setHistoryLoading(false); }
  };
  const allTasks = useMemo(() => {
    const merged = new Map((pool?.completed_tasks ?? []).map((task) => [String(task.task_id), task]));
    history.forEach((task) => {
      const previous = merged.get(String(task.task_id));
      if (shouldMergeTaskHistory(previous, task)) merged.set(String(task.task_id), task);
    });
    const combined = {
      scope_id: scanId, global_running: 0, global_queued: 0, total_tasks: 0,
      completed_task_count: 0, models: [], queued_tasks: [], planned_tasks: [], updated_at: "", ...pool,
      completed_tasks: [...merged.values()]
    };
    // Keep planned work in the shared pool for scheduling and audit panels,
    // but do not collect or sort potentially thousands of planned queue rows.
    return collectScanQueueTasks({ ...combined, planned_tasks: [] });
  }, [scanId, pool, history]);
  const tasks = useMemo(() => taskKind
    ? allTasks.filter((task) => scanQueueTaskKind(task.task) === taskKind)
    : allTasks, [allTasks, taskKind]);
  const expandedTask = tasks.find((task) => scanQueueTaskKey(task) === expandedTaskId);
  const expandedDetailKey = expandedTask ? cacheKey(expandedTask) : null;
  const hasInlinePrompt = Boolean(expandedTask && scanQueueTaskPrompt(expandedTask.task));
  const expandedTaskRef = useRef(expandedTask);
  expandedTaskRef.current = expandedTask;
  useEffect(() => {
    setDetailLoading(null);
    setDetailError(null);
    const selected = expandedTaskRef.current;
    const key = expandedDetailKey;
    if (!selected || !key || detailsRef.current[key]) return;
    if (["queued", "running"].includes(selected.status) && hasInlinePrompt) return;
    const controller = new AbortController();
    setDetailLoading(key);
    // The SSE snapshot is only a summary. Read the selected task's body once,
    // and retain it across subsequent summary-only heartbeats.
    void getScanTaskDetail(scanId, { ...selected.task, task_id: selected.id }, controller.signal)
      .then((result) => {
        if (!controller.signal.aborted) setDetails((previous) => ({ ...previous, [key]: result }));
      })
      .catch(() => { if (!controller.signal.aborted) setDetailError(key); })
      .finally(() => { if (!controller.signal.aborted) setDetailLoading(null); });
    return () => controller.abort();
  }, [scanId, expandedDetailKey, hasInlinePrompt, detailRetry]);
  const retryTask = (key: string) => {
    setDetails((previous) => {
      const next = { ...previous };
      delete next[key];
      return next;
    });
    setDetailRetry((current) => current + 1);
  };
  const runningCount = allTasks.filter((task) => task.status === "running").length;
  const queuedCount = allTasks.filter((task) => task.status === "queued").length;
  const completedCount = Math.max(pool?.completed_task_count ?? 0, allTasks.filter((task) => !["queued", "running"].includes(task.status)).length);
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
            当前扫描的 OpenCode Session 任务；进行中任务置顶，历史任务按执行结束时间从新到旧加载
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-slate-500">扫描整体</span>
          <StatusPill label={`排队中 ${queuedCount}`} tone="amber" />
          <StatusPill label={`运行中 ${runningCount}`} tone="cyan" />
          <StatusPill label={`已执行 ${completedCount}`} tone="green" />
        </div>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 text-xs text-slate-400">
          任务类型
          <select aria-label="任务类型" value={taskKind} autoFocus={focusFilter}
            onChange={(event) => onTaskKindChange(event.target.value as ScanQueueTaskKind | "")}
            className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-slate-200 focus:border-cyan-500 focus:outline-none">
            <option value="">全部类型</option>
            {Object.entries(SCAN_QUEUE_TASK_KINDS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select>
        </label>
        {unsuccessfulCount > 0 && <StatusPill label={`当前筛选已加载未成功 ${unsuccessfulCount}`} tone="red" />}
      </div>

      {historyError && <p className="my-2 text-xs text-amber-300">历史任务加载失败，请重试。</p>}
      {(nextCursor || historyGaps.length > 0 || historyError) && <button type="button" onClick={() => void loadHistory()} disabled={historyLoading}
        className="my-3 rounded border border-slate-700 px-3 py-2 text-xs text-slate-300 disabled:opacity-40">
        {historyLoading ? "加载中…" : historyError ? "重试加载历史任务" : `加载更多历史任务（已加载 ${history.length} 条）`}
      </button>}
      {tasks.length === 0 ? (
        <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-6 text-center text-sm text-slate-500">
          {taskKind ? "当前类型暂无任务记录" : "当前扫描还没有 OpenCode 任务记录"}
        </div>
      ) : (
        <div className="mt-4 overflow-hidden rounded-lg border border-slate-800">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[52rem] text-sm">
              <thead className="bg-slate-950/70">
                <tr>
                  <th className={thCls}>状态</th>
                  <th className={thCls}>任务</th>
                  <th className={thCls}>模型</th>
                  <th className={thCls}>时间</th>
                </tr>
              </thead>
              <tbody>
                {pagedTasks.map((task) => {
                  const taskKey = scanQueueTaskKey(task);
                  const isExpanded = expandedTaskId === taskKey;
                  const detailKey = cacheKey(task);
                  const detail = { ...details[detailKey], ...task.task };
                  const prompt = scanQueueTaskPrompt(task.task) || scanQueueTaskPrompt(details[detailKey] ?? {});
                  const promptLength = scanQueueTaskPromptLength(detail, prompt);
                  const failureReason = typeof detail.failure_reason === "string"
                    ? detail.failure_reason.trim()
                    : "";
                  const failureKind = typeof detail.failure_kind === "string"
                    ? detail.failure_kind.trim()
                    : "";
                  const blockedReason = typeof detail.blocked_reason === "string"
                    ? detail.blocked_reason.trim()
                    : "";
                  const sessionId = scanQueueTaskSessionId(detail);
                  const tokenUsage = taskTokenUsage(detail);
                  const isTerminal = !["queued", "running"].includes(task.status);
                  const terminalFailureReason = scanQueueTaskFailureReason(
                    task.status,
                    failureKind,
                    failureReason,
                  );
                  const sessionEvents = scanQueueTaskSessionEvents(
                    detail,
                    task.status,
                    task.modelId,
                    task.timestamp,
                  );
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
                        <td className="px-3 py-3 align-top text-xs text-slate-400">
                          {task.modelId || "-"}
                        </td>
                        <td className="px-3 py-3 align-top text-xs text-slate-500">
                          {formatDateTime(task.timestamp)}
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr className="border-t border-slate-800/70 bg-slate-950/60">
                          <td colSpan={4} className="px-3 pb-4 pt-0">
                            {detailLoading === detailKey && <p className="mb-3 text-xs text-slate-400">正在加载完整 Prompt 和 Session 轨迹…</p>}
                            {detailError === detailKey && <button type="button" onClick={() => retryTask(detailKey)} className="mb-3 text-xs text-amber-300">完整任务加载失败，点击重试</button>}

                            <div className="space-y-3 rounded-lg border border-slate-800 bg-slate-950 p-3">
                              {terminalFailureReason && (
                                <div className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2">
                                  <div className="text-xs font-semibold text-red-200">失败原因</div>
                                  <div className="mt-1 whitespace-pre-wrap break-words text-xs leading-relaxed text-red-300">
                                    {failureKind && (
                                      <span className="mr-2 rounded border border-red-400/30 bg-red-950/50 px-1.5 py-0.5 font-medium text-red-200">
                                        {scanQueueFailureKindLabel(failureKind)}
                                      </span>
                                    )}
                                    {terminalFailureReason}
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
                                <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                                  <span className="text-xs font-semibold text-slate-300">OpenCode Session 执行轨迹</span>
                                  {sessionEvents.length > 0 && (
                                    <span className="text-[11px] text-slate-600">{sessionEvents.length} 个执行事件</span>
                                  )}
                                </div>
                                {sessionEvents.length > 0 ? (
                                  <div className="space-y-2">
                                    {sessionEvents.map((event) => {
                                      const eventTime = event.finishedAt || event.startedAt;
                                      const eventModel = event.model || event.modelId;
                                      return (
                                        <div
                                          key={`${event.sequence}-${event.phase}-${event.sessionId}-${event.retryOrdinal}`}
                                          className="rounded-md border border-slate-800 bg-slate-900/80 px-3 py-2.5"
                                        >
                                          <div className="flex flex-wrap items-start justify-between gap-2">
                                            <div className="text-xs font-medium text-slate-200">
                                              {scanQueueSessionEventLabel(event)}
                                            </div>
                                            <StatusPill
                                              label={scanQueueSessionOutcomeLabel(event.outcome)}
                                              tone={scanQueueSessionOutcomeTone(event.outcome)}
                                            />
                                          </div>
                                          <div className="mt-2 select-text break-all font-mono text-xs text-cyan-300" title={event.sessionId || undefined}>
                                            {event.sessionId || "未记录 Session ID"}
                                          </div>
                                          {(eventModel || eventTime || event.durationSeconds != null) && (
                                            <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-slate-500">
                                              {eventModel && <span>模型：{eventModel}</span>}
                                              {eventTime && <span>结束：{formatDateTime(eventTime)}</span>}
                                              {event.durationSeconds != null && (
                                                <span>耗时：{formatDuration(event.durationSeconds)}</span>
                                              )}
                                            </div>
                                          )}
                                          {(event.failureKind || event.failureReason) && (
                                            <div className="mt-2 rounded border border-amber-500/20 bg-amber-500/5 px-2.5 py-2 text-xs leading-relaxed text-amber-200">
                                              {event.failureKind && (
                                                <span className="mr-2 font-semibold">
                                                  {scanQueueFailureKindLabel(event.failureKind)}
                                                </span>
                                              )}
                                              {event.failureReason}
                                            </div>
                                          )}
                                        </div>
                                      );
                                    })}
                                  </div>
                                ) : (
                                  <div className="rounded-md border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs text-slate-500">
                                    {sessionId
                                      ? `历史任务仅保存最终 Session：${sessionId}`
                                      : isTerminal
                                        ? "该任务未记录 Session ID，无法确认是否已创建 Session。"
                                        : "等待 Session ID 上报。"}
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
                                ) : detailLoading === detailKey ? (
                                  <p className="text-xs text-slate-400">正在读取完整 Prompt…</p>
                                ) : detailError === detailKey ? (
                                  <p className="text-xs text-amber-300">完整 Prompt 加载失败，请重试。</p>
                                ) : isTerminal ? (
                                  <div className="rounded-md border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs text-slate-500">
                                    该历史任务未保存完整 Prompt{promptLength > 0 ? `，仅记录长度 ${promptLength} chars` : ""}。
                                  </div>
                                ) : (
                                  <div className="rounded-md border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs text-slate-500">
                                    完整 Prompt 暂未同步{promptLength > 0 ? `，已记录长度 ${promptLength} chars` : ""}。
                                    <button type="button" onClick={() => retryTask(detailKey)} className="ml-2 text-cyan-300">
                                      重新读取完整 Prompt
                                    </button>
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
                第 {safePage}/{totalPages} 页 · 已加载 {tasks.length} 条
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
