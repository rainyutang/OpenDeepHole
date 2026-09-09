import { useCallback, useEffect, useRef, useState } from "react";
import type { Dispatch, MutableRefObject, SetStateAction } from "react";
import { getScanFpReviewResult, getScanVulnerabilitiesPage, getScanVulnerabilityAuditSource } from "./api/client";
import { hasFpReviewRecord } from "./fpReview";
import { mergeIndexedVulnerabilities } from "./scanRuntime";
import type { FpReviewJob, FpReviewResult, IndexedVulnerability, ScanCandidate, ScanStatus, ThreatAuditTask, Vulnerability } from "./types";

export interface ListFocusRequest<K> { key: K; revision: number }
export type AuditFocus = (
  | { kind: "issue" | "static_candidate" | "fp_review"; key: number }
  | { kind: "threat_audit"; key: string }
) & { revision: number };
export type AuditTarget =
  | { kind: "issue"; vulnerability: IndexedVulnerability }
  | { kind: "fp_review"; vulnerability: IndexedVulnerability; result: FpReviewResult }
  | { kind: "threat_audit"; task: ThreatAuditTask }
  | { kind: "static_candidate"; candidate: ScanCandidate };
export interface AuditNavigationRequest { kind: "issue" | "source" | "fp_review"; index: number }

export function auditSourceKind(vuln: Vulnerability): "threat_audit" | "static_candidate" | null {
  if ([vuln.analysis_source, vuln.engine_id, vuln.vuln_type].includes("threat_audit")) return "threat_audit";
  return (vuln.analysis_source || "static_candidate") === "static_candidate" ? "static_candidate" : null;
}

export function focusPage<K>(keys: K[], key: K, pageSize: number): number | null {
  const position = keys.indexOf(key);
  return position < 0 ? null : Math.floor(position / pageSize) + 1;
}

export async function resolveAuditNavigation(
  scan: ScanStatus,
  request: AuditNavigationRequest,
  signal: AbortSignal,
  fpReview: FpReviewJob | null = null,
): Promise<AuditTarget> {
  const { index } = request;
  if (!Number.isInteger(index) || index < 0) throw new Error("问题索引无效");
  const review = fpReview?.scan_id === scan.scan_id ? fpReview : null;
  const known = scan.vulnerabilities.find((vuln) => vuln.vuln_index === index)
    ?? review?.result_vulnerabilities?.find((vuln) => vuln.vuln_index === index);
  if (request.kind === "fp_review") {
    const cached = review?.results.find((result) => result.vuln_index === index);
    const [issue, result] = await Promise.all([
      resolveAuditNavigation(scan, { kind: "issue", index }, signal, review),
      hasFpReviewRecord(cached) ? cached : getScanFpReviewResult(scan.scan_id, index, signal),
    ]);
    if (issue.kind !== "issue" || !hasFpReviewRecord(result)) throw new Error("该问题尚无去误报详情");
    return { kind: "fp_review", vulnerability: issue.vulnerability, result };
  }
  if (request.kind === "issue") {
    if (known) return { kind: "issue", vulnerability: known };
    const page = await getScanVulnerabilitiesPage(scan.scan_id, index - 1, signal, 1);
    const row = page.items.find((item) => item.index === index);
    if (!row) throw new Error("该问题记录已不存在，无法打开报告");
    return { kind: "issue", vulnerability: { ...row.vulnerability, vuln_index: row.index } };
  }
  if (known && auditSourceKind(known) === "threat_audit" && known.source_task_id) {
    const task = scan.threat_audit_tasks?.find((item) => item.task_id === known.source_task_id);
    if (task) return { kind: "threat_audit", task };
  }
  if (known && auditSourceKind(known) === "static_candidate" && known.audit_index != null) {
    const candidate = scan.candidates.find((item) => item.idx === known.audit_index);
    if (candidate) return { kind: "static_candidate", candidate };
  }
  const source = await getScanVulnerabilityAuditSource(scan.scan_id, index, signal);
  if (source.status === "resolved") {
    if (source.kind === "threat_audit" && source.threat_task) return { kind: "threat_audit", task: source.threat_task };
    if (source.kind === "static_candidate" && source.candidate) return { kind: "static_candidate", candidate: source.candidate };
  }
  throw new Error(source.status === "ambiguous"
    ? "历史记录对应多个审计任务，无法唯一定位"
    : source.status === "unsupported" ? "该问题来源没有对应的审计任务页面"
      : "未找到关联的审计任务，历史记录可能缺少来源信息或任务已不存在");
}

/** Targeted reads must never advance the cursor used to load intervening rows. */
export function mergeAuditTarget(scan: ScanStatus, target: AuditTarget): ScanStatus {
  // A live update can arrive while the targeted read is in flight. Keep it.
  if ((target.kind === "issue" || target.kind === "fp_review") && scan.vulnerabilities.some((item) => item.vuln_index === target.vulnerability.vuln_index)) return scan;
  if (target.kind === "static_candidate" && scan.candidates.some((item) => item.idx === target.candidate.idx)) return scan;
  if (target.kind === "threat_audit" && scan.threat_audit_tasks?.some((item) => item.task_id === target.task.task_id)) return scan;
  if (target.kind === "issue" || target.kind === "fp_review") return {
    ...scan,
    vulnerabilities: mergeIndexedVulnerabilities(scan.vulnerabilities, [{
      index: target.vulnerability.vuln_index, vulnerability: target.vulnerability,
    }]),
  };
  if (target.kind === "static_candidate") return {
    ...scan,
    candidates: [...scan.candidates.filter((item) => item.idx !== target.candidate.idx), target.candidate]
      .sort((a, b) => a.idx - b.idx),
  };
  return {
    ...scan,
    threat_audit_tasks: [...(scan.threat_audit_tasks ?? []).filter((item) => item.task_id !== target.task.task_id), target.task]
      .sort((a, b) => (a.created_at || "").localeCompare(b.created_at || "") || a.task_id.localeCompare(b.task_id)),
  };
}

export function useAuditNavigation(
  scanId: string,
  scanRef: MutableRefObject<ScanStatus | null>,
  setScan: Dispatch<SetStateAction<ScanStatus | null>>,
  onNavigate: (kind: AuditTarget["kind"]) => void,
  fpReview: FpReviewJob | null = null,
  setFpReview?: Dispatch<SetStateAction<FpReviewJob | null>>,
) {
  const fpReviewRef = useRef(fpReview);
  fpReviewRef.current = fpReview;
  const [focus, setFocus] = useState<AuditFocus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const controller = useRef<AbortController | null>(null);
  const revision = useRef(0);
  const lastRequest = useRef<AuditNavigationRequest | null>(null);

  const cancel = useCallback(() => {
    controller.current?.abort();
    setLoading(false);
    setError("");
    setFocus(null);
  }, []);
  useEffect(() => {
    cancel();
    lastRequest.current = null;
    return () => { controller.current?.abort(); };
  }, [scanId, cancel]);

  const open = useCallback(async (request: AuditNavigationRequest) => {
    controller.current?.abort();
    const pending = new AbortController();
    controller.current = pending;
    lastRequest.current = request;
    const scan = scanRef.current;
    if (!scan || scan.scan_id !== scanId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError("");
    try {
      const review = fpReviewRef.current;
      if (request.kind === "fp_review" && (review?.scan_id !== scanId || !setFpReview)) {
        throw new Error("去误报状态尚未加载，请稍后重试");
      }
      const target = await resolveAuditNavigation(scan, request, pending.signal, review);
      if (pending.signal.aborted || scanRef.current?.scan_id !== scanId) return;
      if (target.kind === "fp_review") {
        const sameReview = (job: FpReviewJob | null) => job?.scan_id === scanId
          && job.review_id === review?.review_id && job.execution_revision === review?.execution_revision;
        if (!sameReview(fpReviewRef.current)) return;
        setFpReview?.((previous) => {
          if (pending.signal.aborted || !previous || !sameReview(previous)
            || previous.results.some((result) => result.vuln_index === request.index && hasFpReviewRecord(result))) return previous;
          return { ...previous, results: [...previous.results.filter((result) => result.vuln_index !== request.index), target.result] };
        });
      }
      setScan((previous) => !pending.signal.aborted && previous?.scan_id === scanId ? mergeAuditTarget(previous, target) : previous);
      const nextRevision = ++revision.current;
      setFocus(target.kind === "issue" || target.kind === "fp_review"
        ? { kind: target.kind, key: target.vulnerability.vuln_index, revision: nextRevision }
        : target.kind === "static_candidate"
          ? { kind: "static_candidate", key: target.candidate.idx, revision: nextRevision }
          : { kind: "threat_audit", key: target.task.task_id, revision: nextRevision });
      onNavigate(target.kind);
    } catch (failure) {
      if (!pending.signal.aborted) setError(failure instanceof Error ? failure.message : "定位失败，请重试");
    } finally {
      if (!pending.signal.aborted) setLoading(false);
    }
  }, [scanId, scanRef, setScan, onNavigate, setFpReview]);

  return {
    focus, loading, error, cancel,
    openIssue: (index: number) => { void open({ kind: "issue", index }); },
    openSource: (index: number) => { void open({ kind: "source", index }); },
    openFpReview: (index: number) => { void open({ kind: "fp_review", index }); },
    retry: () => { if (lastRequest.current) void open(lastRequest.current); },
  };
}

/** Keep a requested row visible as preceding pages arrive; user actions release it. */
export function useListFocus<K>(
  request: ListFocusRequest<K> | undefined,
  keys: K[],
  pageSize: number,
  setSelected: Dispatch<SetStateAction<K | null>>,
  setPage: Dispatch<SetStateAction<number>>,
  resetFilters: () => void,
) {
  const [pinned, setPinned] = useState<K | null>(request?.key ?? null);
  const applied = useRef<number | null>(null);
  const scrolled = useRef<number | null>(null);
  const pending = !!request && request.revision !== applied.current;
  const resetRef = useRef(resetFilters);
  resetRef.current = resetFilters;
  useEffect(() => {
    if (!request) return;
    applied.current = request.revision;
    setPinned(request.key);
    setSelected(request.key);
    resetRef.current();
  }, [request?.revision, request?.key, setSelected]);
  useEffect(() => {
    if (pinned === null) return;
    const page = focusPage(keys, pinned, pageSize);
    if (page !== null) {
      setSelected(pinned);
      setPage(page);
    }
  }, [pinned, keys, pageSize, setPage, setSelected]);
  const targetRef = useCallback((node: HTMLButtonElement | null) => {
    if (node && request && pinned === request.key && scrolled.current !== request.revision) {
      node.scrollIntoView?.({ block: "nearest", inline: "nearest" });
      scrolled.current = request.revision;
    }
  }, [pinned, request?.key, request?.revision]);
  return { pinned, pending, targetRef, release: () => setPinned(null) };
}
