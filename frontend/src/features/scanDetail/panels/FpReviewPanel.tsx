import { useEffect, useMemo, useState } from "react";
import { getFpReviewResultsPage } from "../../../api/fpReview";
import type { ListFocusRequest } from "../../../auditNavigation";
import { useListFocus } from "../../../auditNavigation";
import { hasFpReviewRecord, isEffectiveFpReviewResult } from "../../../fpReview";
import { mergeIndexedVulnerabilities } from "../../../scanRuntime/issues";
import type { FpReviewJob, FpReviewStageConfig } from "../../../types/fpReview";
import type { IndexedVulnerability } from "../../../types/issues";
import type { ScanEvent } from "../../../types/scans";
import { EmptyState, EventList, MiniMetric, StatusPill, TaskPanel } from "../components/taskUi";
import { fpReviewItemLabel, fpReviewItemTone, fpReviewSortRank } from "../model/fpReview";
import {
  FP_REVIEW_PAGE_SIZE,
  hasFinalUserVerdict,
  isAiConfirmed,
  vulnerabilityFunctionLabel,
  vulnerabilityLocation,
  vulnerabilityTypeLabel,
} from "../model/scan";
import type { TaskTone } from "../model/types";
import { FpReviewDetail } from "./FpReviewDetail";

export function FpReviewPanel({
  canControl = true,
  vulnerabilities,
  scanId,
  reviewDataLoaded,
  focusRequest,
  onOpenIssue,
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
  canControl?: boolean;
  vulnerabilities: IndexedVulnerability[];
  scanId: string;
  reviewDataLoaded: boolean;
  focusRequest?: ListFocusRequest<number>;
  onOpenIssue?: (index: number) => void;
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
  const [selectedIndex, setSelectedIndex] = useState<number | null>(focusRequest?.key ?? null);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageLoading, setPageLoading] = useState(false);
  const [pageError, setPageError] = useState("");
  const [pageRetry, setPageRetry] = useState(0);
  const [unstartedPage, setUnstartedPage] = useState<Awaited<ReturnType<typeof getFpReviewResultsPage>> | null>(null);
  useEffect(() => {
    setUnstartedPage(null);
    setPageError("");
  }, [scanId, Boolean(fpReview)]);
  // Before a job exists, the same endpoint pages through its waiting candidates.
  useEffect(() => {
    const cursor = unstartedPage ? unstartedPage.next_cursor : -1;
    if (fpReview || !reviewDataLoaded || cursor == null) {
      setPageLoading(false);
      return;
    }
    const controller = new AbortController();
    setPageLoading(true);
    setPageError("");
    getFpReviewResultsPage(scanId, cursor, 50, controller.signal)
      .then((page) => {
        if (controller.signal.aborted) return;
        if (page.next_cursor != null && page.next_cursor <= cursor) throw new Error("复核结果游标未前进");
        setUnstartedPage((previous) => controller.signal.aborted ? previous : {
          ...page,
          items: [...new Map([...(previous?.items ?? []), ...page.items].map((item) => [item.vuln_index, item])).values()],
          vulnerabilities: mergeIndexedVulnerabilities(previous?.vulnerabilities ?? [],
            page.vulnerabilities.map((vulnerability) => ({ index: vulnerability.vuln_index, vulnerability }))),
        });
      })
      .catch(() => { if (!controller.signal.aborted) setPageError("待复核问题读取失败，请重试"); })
      .finally(() => { if (!controller.signal.aborted) setPageLoading(false); });
    return () => controller.abort();
  }, [scanId, Boolean(fpReview), reviewDataLoaded, unstartedPage?.next_cursor, pageRetry]);
  const dataComplete = reviewDataLoaded && ((fpReview !== null && fpReview.next_cursor == null)
    || (unstartedPage !== null && unstartedPage.next_cursor == null && !pageError && !pageLoading));
  const records = useMemo(
    // Current scan data contains newer human feedback than a review page snapshot.
    () => mergeIndexedVulnerabilities(fpReview?.result_vulnerabilities ?? unstartedPage?.vulnerabilities ?? [],
      vulnerabilities.map((vulnerability) => ({ index: vulnerability.vuln_index, vulnerability })))
      .map((vuln) => ({
        vuln, index: vuln.vuln_index,
        eligible: !vuln.provisional && isAiConfirmed(vuln) && !hasFinalUserVerdict(vuln)
      })),
    [vulnerabilities, fpReview?.result_vulnerabilities, unstartedPage],
  );
  const resultByIndex = useMemo(
    () => new Map((fpReview?.results ?? unstartedPage?.items ?? []).map((result) => [result.vuln_index, result])),
    [fpReview?.results, unstartedPage],
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
      records
        .filter(({ index, eligible }) => eligible || hasFpReviewRecord(resultByIndex.get(index)))
        .map(({ vuln, index, eligible }) => ({
          vuln,
          index,
          eligible,
          result: resultByIndex.get(index),
          running: currentIndices.has(index),
        }))
        .sort((a, b) => fpReviewSortRank(a.result, a.running) - fpReviewSortRank(b.result, b.running) || a.index - b.index),
    [records, currentIndices, resultByIndex],
  );
  const eligibleItems = items.filter((item) => item.eligible);
  const waitingCount = (!dataComplete ? fpReview?.result_counts?.unresolved : undefined) ?? eligibleItems.filter(
    (item) => !isEffectiveFpReviewResult(item.result) && !item.running,
  ).length;
  const allReviewed = dataComplete && items.some((item) => isEffectiveFpReviewResult(item.result))
    && eligibleItems.every((item) => isEffectiveFpReviewResult(item.result));
  const tpCount = (!dataComplete ? fpReview?.result_counts?.tp : undefined) ?? items.filter(
    (item) => isEffectiveFpReviewResult(item.result) && item.result.verdict === "tp",
  ).length;
  const fpCount = (!dataComplete ? fpReview?.result_counts?.fp : undefined) ?? items.filter(
    (item) => isEffectiveFpReviewResult(item.result) && item.result.verdict === "fp",
  ).length;
  const status = isFpReviewing
    ? "复核中"
    : !dataComplete
      ? "加载中"
      : fpReview?.status === "error"
        ? "异常"
        : fpReview?.status === "cancelled"
          ? "已停止"
          : allReviewed
            ? "已完成"
            : eligibleItems.length > 0
              ? "等待"
              : "无目标";
  const tone: TaskTone = isFpReviewing
    ? "amber"
    : fpReview?.status === "error"
      ? "red"
      : fpReview?.status === "cancelled"
        ? "amber"
        : allReviewed
          ? "green"
          : "slate";
  const selected = selectedIndex === null ? null : items.find((item) => item.index === selectedIndex) ?? null;
  const canTrigger = eligibleItems.length > 0
    && dataComplete
    && !isFpReviewing
    && !loading;

  const totalPages = Math.max(1, Math.ceil(items.length / FP_REVIEW_PAGE_SIZE));
  const safePage = Math.min(currentPage, totalPages);
  const paged = items.slice((safePage - 1) * FP_REVIEW_PAGE_SIZE, safePage * FP_REVIEW_PAGE_SIZE);
  const listFocus = useListFocus(focusRequest, items.map((item) => item.index), FP_REVIEW_PAGE_SIZE,
    setSelectedIndex, setCurrentPage, () => { });

  useEffect(() => {
    if (listFocus.pinned !== null || listFocus.pending) return;
    if (items.length === 0) {
      if (selectedIndex !== null) setSelectedIndex(null);
      return;
    }
    if (selectedIndex === null || !items.some((item) => item.index === selectedIndex)) {
      setSelectedIndex(items[0].index);
    }
  }, [items, selectedIndex, listFocus.pinned, listFocus.pending]);

  return (
    <TaskPanel
      title={methodLabel}
      status={status}
      tone={tone}
      summary={methodDescription}
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-5">
        <MiniMetric label="确认问题" value={!dataComplete && fpReview?.result_counts ? tpCount + fpCount + waitingCount : items.length} tone="red" />
        <MiniMetric label="等待复核" value={waitingCount} />
        <MiniMetric label="复核中" value={currentIndices.size} tone="amber" />
        <MiniMetric label="保留正报" value={tpCount} tone="red" />
        <MiniMetric label="判定误报" value={fpCount} tone="green" />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {canControl && eligibleItems.length > 0 && (
          <button
            type="button"
            onClick={onTrigger}
            disabled={!canTrigger}
            title={!dataComplete
              ? "正在加载复核状态"
              : allReviewed
                ? "全部问题均已形成有效结论，点击后重新复核全部问题"
                : `仅复核 ${waitingCount} 个尚未形成有效结论的问题`}
            className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-sm font-medium text-amber-200 transition-colors hover:bg-amber-500/20 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading
              ? "启动中..."
              : isFpReviewing
                ? "复核中..."
                : !dataComplete
                  ? "加载中..."
                  : allReviewed
                    ? "重新复核"
                    : "启动复核"}
          </button>
        )}
        {canControl && isFpReviewing && (
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
      {!dataComplete && !pageError && <div role="status" className="text-xs text-slate-400">复核记录尚未加载完整，已加载 {items.length} 条。</div>}
      {pageError && <div role="alert" className="text-sm text-red-300">{pageError}
        <button type="button" onClick={() => setPageRetry((value) => value + 1)} className="ml-3 underline">重试</button>
      </div>}
      {items.length === 0 ? (
        <EmptyState text={dataComplete ? "当前没有复核记录或待复核问题。" : "正在加载复核记录…"} />
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(18rem,22rem)_1fr]">
          <div className="flex flex-col rounded-xl border border-slate-700 bg-slate-900/40">
            <div className="max-h-[24rem] flex-1 overflow-y-auto lg:max-h-[70vh]">
              <ul className="divide-y divide-slate-800">
                {paged.map(({ vuln, index, result, running }) => {
                  const active = selectedIndex === index;
                  return (
                    <li key={`${index}-${vuln.file}-${vuln.line}`}>
                      <button
                        type="button"
                        ref={listFocus.pinned === index ? listFocus.targetRef : undefined}
                        aria-current={active ? "true" : undefined}
                        onClick={() => { listFocus.release(); setSelectedIndex(index); }}
                        className={`w-full px-3 py-2.5 text-left transition-colors ${active ? "bg-amber-500/15" : running ? "bg-amber-500/10 hover:bg-amber-500/15" : "hover:bg-slate-800/60"
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
            {items.length > FP_REVIEW_PAGE_SIZE && (
              <div className="flex items-center justify-between gap-2 border-t border-slate-800 px-3 py-2">
                <button type="button" disabled={safePage === 1}
                  onClick={() => { listFocus.release(); setCurrentPage(Math.max(1, safePage - 1)); }}
                  className="rounded-lg border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-30">上一页</button>
                <span className="text-xs text-slate-500">第 {safePage}/{totalPages} 页 · {dataComplete ? "共" : "已加载"} {items.length} 条</span>
                <button type="button" disabled={safePage === totalPages}
                  onClick={() => { listFocus.release(); setCurrentPage(Math.min(totalPages, safePage + 1)); }}
                  className="rounded-lg border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-30">下一页</button>
              </div>
            )}
          </div>
          <div className="min-h-[20rem] rounded-xl border border-slate-700 bg-slate-900/40">
            {selected ? (
              <FpReviewDetail
                key={selected.index}
                index={selected.index}
                vulnerability={selected.vuln}
                result={selected.result}
                running={selected.running}
                stages={stages}
                onOpenIssue={onOpenIssue}
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
