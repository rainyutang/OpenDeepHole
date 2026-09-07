import type { ThreatAuditFindingSummary, ThreatAuditTaskResult } from "../../types";

export type AuditResultSummary = Omit<ThreatAuditTaskResult, "task_id">;

export function AuditFindingBadge({ result }: { result?: AuditResultSummary }) {
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

export function AuditResults({
  result, status, loading, error, onRetry, onOpenIssue,
}: {
  result?: AuditResultSummary;
  status: string;
  loading: boolean;
  error: string;
  onRetry: () => void;
  onOpenIssue?: (index: number) => void;
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
          {finding.verdict === "confirmed" && onOpenIssue && (
            <button
              type="button"
              onClick={() => onOpenIssue(finding.vuln_index)}
              className="mt-3 rounded border border-blue-500/30 bg-blue-500/10 px-2.5 py-1 text-xs text-blue-300 hover:bg-blue-500/20"
            >
              查看问题报告
            </button>
          )}
        </article>
      ))}
    </div>
  );
}
