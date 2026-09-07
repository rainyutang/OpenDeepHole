import { useCallback, useEffect, useRef, useState } from "react";
import { getScanThreatAuditResults } from "../../api/client";
import type { FpReviewJob, ScanStatus, ThreatAuditFindingSummary, ThreatAuditTaskResult } from "../../types";

interface ResultState {
  scanId: string;
  key: string;
  results: Map<string, ThreatAuditTaskResult>;
  loading: boolean;
  error: string;
}

export function useThreatAuditResults(scan: ScanStatus, taskIds: string[], fpReview: FpReviewJob | null, refreshRevision: number) {
  const scanId = scan.scan_id;
  const key = JSON.stringify([...new Set(taskIds)].sort());
  const [state, setState] = useState<ResultState>({
    scanId: "", key: "", results: new Map(), loading: true, error: "",
  });
  const refreshRef = useRef<() => void>(() => {});
  const inputsRef = useRef<readonly unknown[]>([]);
  const retry = useCallback(() => refreshRef.current(), []);

  useEffect(() => {
    const ids: string[] = JSON.parse(key);
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | null = null;
    let inFlight = false;
    let dirty = false;
    inputsRef.current = [scan.threat_audit_tasks, scan.vulnerabilities, fpReview?.results, refreshRevision];

    const schedule = () => {
      if (controller.signal.aborted) return;
      dirty = true;
      // Coalesce bursts without postponing a refresh on every incoming event.
      if (!inFlight && timer === null) timer = setTimeout(() => { void load(); }, 300);
    };
    const load = async () => {
      timer = null;
      dirty = false;
      inFlight = true;
      setState((previous) => ({
        scanId, key,
        results: previous.scanId === scanId && previous.key === key ? previous.results : new Map(),
        loading: true, error: "",
      }));
      try {
        const results = await getScanThreatAuditResults(scanId, ids, controller.signal);
        if (!controller.signal.aborted) setState({
          scanId, key, results: new Map(results.map((result) => [result.task_id, result])),
          loading: false, error: "",
        });
      } catch {
        if (!controller.signal.aborted) setState({
          scanId, key, results: new Map(), loading: false, error: "审计结果读取失败",
        });
      } finally {
        inFlight = false;
        if (dirty) schedule();
      }
    };
    refreshRef.current = schedule;
    void load();
    return () => {
      controller.abort();
      if (timer !== null) clearTimeout(timer);
      refreshRef.current = () => {};
    };
  }, [scanId, key]);

  useEffect(() => {
    const inputs = [scan.threat_audit_tasks, scan.vulnerabilities, fpReview?.results, refreshRevision];
    if (inputs.some((input, index) => input !== inputsRef.current[index])) {
      inputsRef.current = inputs;
      refreshRef.current();
    }
  }, [scan.threat_audit_tasks, scan.vulnerabilities, fpReview?.results, refreshRevision]);

  const current = state.scanId === scanId && state.key === key;
  return {
    results: current ? state.results : new Map<string, ThreatAuditTaskResult>(),
    loading: !current || state.loading,
    error: current ? state.error : "",
    retry,
  };
}

export function ThreatAuditFindingBadge({ result }: { result?: ThreatAuditTaskResult }) {
  if (!result || result.confirmed_issue_count <= 0) return null;
  return (
    <span className="inline-flex shrink-0 items-center rounded border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-[11px] font-medium text-red-300">
      发现问题
    </span>
  );
}

const verdictLabels: Record<ThreatAuditFindingSummary["verdict"], string> = {
  confirmed: "确认问题",
  false_positive: "非问题",
  unreviewed: "尚无最终确认结论",
  not_confirmed: "审计未确认问题",
};
const sourceLabels = { human: "人工判定", fp_review: "去误报复核", audit: "审计" };
const severityLabels: Record<string, string> = {
  critical: "严重", high: "高", medium: "中", low: "低", info: "提示", unknown: "未知",
};

function emptyResultMessage(status: string): string {
  if (["pending", "queued", "planned", "running", "analyzing", "auditing"].includes(status)) {
    return "审计尚未完成";
  }
  if (["failed", "failure", "error", "timeout", "no_result"].includes(status)) {
    return "审计未成功，未关联到问题结果";
  }
  if (status === "cancelled") return "审计已取消，未关联到问题结果";
  return "未关联到问题结果";
}

export function ThreatAuditResults({
  result, status, loading, error, onRetry,
}: {
  result?: ThreatAuditTaskResult;
  status: string;
  loading: boolean;
  error: string;
  onRetry: () => void;
}) {
  if (error) return (
    <div role="alert" className="text-sm text-amber-300">
      {error}。<button type="button" onClick={onRetry} className="ml-2 underline">重试</button>
    </div>
  );
  if (!result) return <div className="text-xs text-slate-500">{loading ? "正在读取审计结果…" : "未读取到审计结果"}</div>;
  return (
    <div className="space-y-3" aria-busy={loading}>
      {!result.association_complete && (
        <div className="rounded border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-300">
          历史记录不足或关联失效，无法还原完整审计结果。{result.findings.length > 0 ? "以下为已关联的结果。" : ""}
        </div>
      )}
      {result.findings.length === 0 && result.association_complete && (
        <div className="text-xs text-slate-500">{emptyResultMessage(status)}</div>
      )}
      {result.findings.map((finding) => (
        <article key={finding.vuln_index} className="rounded-lg border border-slate-700 bg-slate-950/50 px-3 py-3">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="font-mono text-slate-500">#{finding.vuln_index}</span>
            <span className="font-semibold text-slate-200">{finding.vuln_type || "未记录问题类型"}</span>
            <span className="text-slate-400">严重程度：{severityLabels[finding.severity] || finding.severity || "未知"}</span>
            <span className={finding.verdict === "confirmed" ? "text-red-300" : "text-slate-400"}>
              {sourceLabels[finding.verdict_source]} · {verdictLabels[finding.verdict]}
            </span>
          </div>
          <p className="mt-2 whitespace-pre-wrap break-words text-sm leading-relaxed text-slate-300">
            {finding.description || "该记录未保存问题简介。"}
          </p>
          <div className="mt-2 break-all font-mono text-xs text-cyan-300">
            {finding.file || "未记录代码位置"}{finding.line > 0 ? `:${finding.line}` : ""}
            {finding.function ? ` · ${finding.function}` : ""}
          </div>
        </article>
      ))}
    </div>
  );
}
