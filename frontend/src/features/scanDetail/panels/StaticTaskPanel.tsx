import { useEffect, useMemo, useState } from "react";
import type { ListFocusRequest } from "../../../auditNavigation";
import { useListFocus } from "../../../auditNavigation";
import { STATIC_CANDIDATE_ENGINE_ID as STATIC_ENGINE_ID } from "../../../miningEngines";
import type { StaticAuditStatus } from "../../../staticAudit";
import {
  staticAnalysisFailures,
  staticAuditDisplayStatus,
  staticAuditExecutionEnded,
  staticAuditStatus,
  staticCandidateTaskName,
} from "../../../staticAudit";
import type { FpReviewJob } from "../../../types/fpReview";
import type { IndexedVulnerability } from "../../../types/issues";
import type { ScanCandidate } from "../../../types/audit";
import type { ScanEvent, ScanStatus as ScanStatusType } from "../../../types/scans";
import { useCandidateAuditResults } from "../../auditResults/useAuditResults";
import { EventList, MiniMetric, ProgressBlock, TaskPanel } from "../components/taskUi";
import {
  formatIndexProgress,
  isStaticCandidate,
  isStaticCandidateVulnerability,
  miningEngineRun,
  STATIC_CANDIDATE_PAGE_SIZE,
  taskStateLabel,
} from "../model/scan";
import { ALL_STATIC_FILTER, countStaticAuditOptions, valueOptions } from "../model/staticCandidates";
import { collectScanQueueTasks } from "../model/taskQueue";
import type { ScanQueueTask } from "../model/types";
import { StaticCandidateDetail, StaticCandidateListItem, StaticFilterSelect } from "./StaticCandidateDetail";

export function StaticTaskPanel({
  scan,
  indexProgress,
  candidates,
  vulnerabilities,
  events,
  fpReview,
  resultRevision,
  focusRequest,
  onOpenIssue,
}: {
  scan: ScanStatusType;
  indexProgress: ReturnType<typeof formatIndexProgress>;
  candidates: ScanCandidate[];
  vulnerabilities: IndexedVulnerability[];
  events: ScanEvent[];
  fpReview: FpReviewJob | null;
  resultRevision: number;
  focusRequest?: ListFocusRequest<number>;
  onOpenIssue: (index: number) => void;
}) {
  const [selectedIndex, setSelectedIndex] = useState<number | null>(focusRequest?.key ?? null);
  const [typeFilter, setTypeFilter] = useState(ALL_STATIC_FILTER);
  const [auditFilter, setAuditFilter] = useState(ALL_STATIC_FILTER);
  const [findingFilter, setFindingFilter] = useState(ALL_STATIC_FILTER);
  const [currentPage, setCurrentPage] = useState(1);
  const failed = !scan.static_analysis_done && (
    scan.status === "error" || miningEngineRun(scan, STATIC_ENGINE_ID)?.status === "error"
  );
  const running = !failed && scan.status === "analyzing" && !scan.static_analysis_done;
  const partialStatic = scan.static_analysis_done && staticAnalysisFailures(scan).length > 0;
  const auditExecutionEnded = staticAuditExecutionEnded(scan);
  const seen = scan.static_analysis_done || running || scan.status === "auditing" || events.length > 0;
  const scannedFiles = seen ? (scan.static_scanned_files || indexProgress.current) : 0;
  const totalFiles = seen ? (scan.static_total_files || indexProgress.total) : 0;
  const displayedCandidates = useMemo<ScanCandidate[]>(() => {
    if (candidates.length > 0) return candidates.filter(isStaticCandidate);
    return vulnerabilities
      .filter((vuln) => (
        isStaticCandidateVulnerability(vuln)
        && vuln.audit_index !== null
        && vuln.audit_index !== undefined
      ))
      .map((vuln) => ({
        idx: Number(vuln.audit_index),
        file: vuln.file,
        line: vuln.line,
        function: vuln.function,
        description: vuln.description,
        vuln_type: vuln.vuln_type,
        related_functions: [],
        metadata: {},
        audit_state: staticAuditStatus(vuln),
        audit_result: vuln,
        vulnerability_idx: vuln.vuln_index,
      }));
  }, [candidates, vulnerabilities]);
  const annotated = useMemo(
    () =>
      displayedCandidates.map((candidate) => {
        return {
          candidate,
          vulnerability: candidate.audit_result ?? undefined,
          vulnerabilityIndex: candidate.vulnerability_idx ?? undefined,
          auditStatus: staticAuditDisplayStatus(
            candidate.audit_state ?? staticAuditStatus(candidate.audit_result ?? undefined), auditExecutionEnded,
          ),
        };
      }),
    [displayedCandidates, auditExecutionEnded],
  );
  const typeOptions = useMemo(
    () => valueOptions(displayedCandidates.map((candidate) => candidate.vuln_type), (value) => value.toUpperCase()),
    [displayedCandidates],
  );
  const auditOptions = useMemo(
    () => countStaticAuditOptions(annotated.map((item) => item.auditStatus), auditExecutionEnded),
    [annotated, auditExecutionEnded],
  );
  const matchingCandidates = useMemo(() => {
    let list = annotated;
    if (typeFilter !== ALL_STATIC_FILTER) list = list.filter((item) => item.candidate.vuln_type === typeFilter);
    if (auditFilter !== ALL_STATIC_FILTER) list = list.filter((item) => item.auditStatus === auditFilter);
    return list;
  }, [annotated, auditFilter, typeFilter]);
  const selected = selectedIndex === null
    ? null
    : annotated.find((item) => item.candidate.idx === selectedIndex) ?? null;
  const findingFilterActive = findingFilter === "found";
  const summaryPage = Math.min(currentPage, Math.max(1, Math.ceil(matchingCandidates.length / STATIC_CANDIDATE_PAGE_SIZE)));
  const summaryCandidates = findingFilterActive ? matchingCandidates : matchingCandidates.slice(
    (summaryPage - 1) * STATIC_CANDIDATE_PAGE_SIZE, summaryPage * STATIC_CANDIDATE_PAGE_SIZE,
  );
  const auditResults = useCandidateAuditResults(scan,
    [...summaryCandidates.map((item) => item.candidate.idx), ...(selected ? [selected.candidate.idx] : [])],
    fpReview, resultRevision);
  const visible = useMemo(() => findingFilterActive
    ? matchingCandidates.filter((item) => (auditResults.results.get(item.candidate.idx)?.confirmed_issue_count ?? 0) > 0)
    : matchingCandidates,
    [matchingCandidates, findingFilterActive, auditResults.results]);
  const candidatesLoading = scan.detail_pages?.candidates_next_cursor != null
    || (candidates.length === 0 && scan.detail_pages?.vulnerabilities_next_cursor != null);
  const filterLoading = findingFilterActive && (candidatesLoading || auditResults.loading);
  const filterError = findingFilterActive ? auditResults.error : "";
  const totalPages = Math.max(1, Math.ceil(visible.length / STATIC_CANDIDATE_PAGE_SIZE));
  const safePage = Math.min(currentPage, totalPages);
  const paged = visible.slice((safePage - 1) * STATIC_CANDIDATE_PAGE_SIZE, safePage * STATIC_CANDIDATE_PAGE_SIZE);
  const runtimeByTaskName = useMemo(() => {
    const result = new Map<string, ScanQueueTask>();
    // Queue collection puts active work first and historical attempts newest first.
    for (const task of collectScanQueueTasks(scan.opencode_pool ?? null)) {
      if (task.scopeId && task.scopeId !== scan.scan_id) continue;
      const name = String(task.task.task_name || "");
      if (name && !result.has(name)) result.set(name, task);
    }
    return result;
  }, [scan.scan_id, scan.opencode_pool]);
  const selectedRuntime = selected
    ? runtimeByTaskName.get(staticCandidateTaskName(scan.scan_id, selected.candidate)) ?? null
    : null;
  const auditCounts = useMemo(() => {
    const counts: Record<StaticAuditStatus, number> = {
      success: 0,
      failed: 0,
      pending: 0,
      queued: 0,
      running: 0,
    };
    annotated.forEach((item) => {
      counts[item.candidate.audit_state ?? staticAuditStatus(item.candidate.audit_result ?? undefined)] += 1;
    });
    return counts;
  }, [annotated]);
  const completeAuditCounts = scan.detail_counts ? {
    success: scan.detail_counts.candidate_audit_success ?? auditCounts.success,
    failed: scan.detail_counts.candidate_audit_failed ?? auditCounts.failed,
    pending: scan.detail_counts.candidate_audit_pending ?? auditCounts.pending,
    queued: scan.detail_counts.candidate_audit_queued ?? auditCounts.queued,
    running: scan.detail_counts.candidate_audit_running ?? auditCounts.running,
  } : { ...auditCounts };
  if (auditExecutionEnded) {
    completeAuditCounts.pending += completeAuditCounts.queued + completeAuditCounts.running;
    completeAuditCounts.queued = 0;
    completeAuditCounts.running = 0;
  }
  const completeCandidateCount = scan.detail_counts?.candidates
    ?? scan.total_candidates
    ?? displayedCandidates.length;

  useEffect(() => {
    setCurrentPage(1);
  }, [auditFilter, typeFilter, findingFilter]);

  useEffect(() => {
    if (auditExecutionEnded && ["queued", "running"].includes(auditFilter)) setAuditFilter("pending");
  }, [auditExecutionEnded, auditFilter]);

  const listFocus = useListFocus(focusRequest, visible.map((item) => item.candidate.idx), STATIC_CANDIDATE_PAGE_SIZE,
    setSelectedIndex, setCurrentPage, () => {
      setTypeFilter(ALL_STATIC_FILTER);
      setAuditFilter(ALL_STATIC_FILTER);
      setFindingFilter(ALL_STATIC_FILTER);
    });

  useEffect(() => {
    if (listFocus.pinned !== null || listFocus.pending || filterLoading || filterError) return;
    if (visible.length === 0) {
      if (selectedIndex !== null) setSelectedIndex(null);
      return;
    }
    if (selectedIndex === null || !visible.some((item) => item.candidate.idx === selectedIndex)) {
      setSelectedIndex(visible[0].candidate.idx);
    }
  }, [selectedIndex, visible, listFocus.pinned, listFocus.pending, filterLoading, filterError]);

  return (
    <TaskPanel
      title="静态分析"
      status={partialStatic ? "完成（部分规则失败）" : taskStateLabel(scan.static_analysis_done, running, failed)}
      tone={partialStatic ? "amber" : scan.static_analysis_done ? "green" : running ? "cyan" : failed ? "red" : "slate"}
      summary="基于底层代码图谱运行静态规则，产出供漏洞挖掘阶段审计的候选点。"
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <MiniMetric label="扫描文件" value={scannedFiles} tone="cyan" />
        <MiniMetric label="总文件" value={totalFiles} />
        <MiniMetric label="候选点" value={completeCandidateCount} tone="blue" />
      </div>
      <ProgressBlock label="候选点生成" current={scannedFiles} total={totalFiles} fallback="等待静态分析进度" />
      <div className="grid grid-cols-1 gap-3 md:grid-cols-5">
        <MiniMetric label="审计成功" value={completeAuditCounts.success} tone="green" />
        <MiniMetric label="审计失败" value={completeAuditCounts.failed} tone="red" />
        <MiniMetric label={auditExecutionEnded ? "待续扫" : "待审计"} value={completeAuditCounts.pending} />
        <MiniMetric label="排队中" value={completeAuditCounts.queued} tone="amber" />
        <MiniMetric label="审计中" value={completeAuditCounts.running} tone="blue" />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <StaticFilterSelect label="类型" value={typeFilter} options={typeOptions} onChange={(value) => { listFocus.release(); setTypeFilter(value); }} />
        <StaticFilterSelect label="审计" value={auditFilter} options={auditOptions} onChange={(value) => { listFocus.release(); setAuditFilter(value); }} />
        <StaticFilterSelect label="问题" value={findingFilter} options={[{ value: "found", label: "发现问题" }]}
          onChange={(value) => { listFocus.release(); setFindingFilter(value); }} />
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(18rem,24rem)_minmax(0,1fr)]">
        <div className="flex min-w-0 flex-col rounded-xl border border-slate-700 bg-slate-900/40">
          <div className="max-h-[72vh] flex-1 overflow-y-auto" aria-busy={filterLoading}>
            {filterError ? (
              <div role="alert" className="px-4 py-4 text-sm text-amber-300">
                问题筛选结果读取失败。<button type="button" onClick={auditResults.retry} className="ml-2 underline">重试</button>
              </div>
            ) : filterLoading && (
              <div role="status" className="px-4 py-4 text-xs text-slate-400">
                {candidatesLoading ? "正在加载候选点，筛选结果尚未完整…" : "正在读取问题筛选结果…"}
              </div>
            )}
            {visible.length === 0 ? !filterLoading && !filterError && (
              <div className="px-4 py-10 text-center text-sm text-slate-500">
                {displayedCandidates.length === 0 ? "暂无静态分析候选点" : "当前筛选条件下无候选点"}
              </div>
            ) : (
              <ul className="divide-y divide-slate-800">
                {paged.map((item) => (
                  <StaticCandidateListItem
                    key={item.candidate.idx}
                    item={item}
                    auditExecutionEnded={auditExecutionEnded}
                    result={auditResults.results.get(item.candidate.idx)}
                    focusRef={listFocus.pinned === item.candidate.idx ? listFocus.targetRef : undefined}
                    active={selectedIndex === item.candidate.idx}
                    onClick={() => { listFocus.release(); setSelectedIndex(item.candidate.idx); }}
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
                onClick={() => { listFocus.release(); setCurrentPage((page) => Math.max(1, page - 1)); }}
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
                onClick={() => { listFocus.release(); setCurrentPage((page) => Math.min(totalPages, page + 1)); }}
                className="rounded-lg border border-slate-700 px-2.5 py-1 text-xs text-slate-300 transition-colors hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-30"
              >
                下一页
              </button>
            </div>
          )}
        </div>
        <div className="min-h-[20rem] min-w-0 rounded-xl border border-slate-700 bg-slate-900/40">
          {selected ? (
            <StaticCandidateDetail
              key={selected.candidate.idx}
              scan={scan}
              item={selected}
              runtime={selectedRuntime}
              result={auditResults.results.get(selected.candidate.idx)}
              resultLoading={auditResults.loading}
              resultError={auditResults.error}
              onRetryResult={auditResults.retry}
              onOpenIssue={onOpenIssue}
            />
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
