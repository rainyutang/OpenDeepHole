import type { RefCallback } from "react";
import {
  staticAuditConclusion,
  staticAuditExecutionEnded,
  staticAuditStatusLabel,
  staticCandidateRelatedVariable,
  staticCandidateTaskName,
} from "../../../staticAudit";
import type { CandidateAuditTaskResult } from "../../../types/audit";
import type { ScanStatus as ScanStatusType } from "../../../types/scans";
import { AuditFindingBadge, AuditResults } from "../../auditResults/AuditResults";
import { AuditDetailSection, AuditPromptSection, DetailGrid } from "../components/AuditDetail";
import { MarkdownContent } from "../components/MarkdownContent";
import { StatusPill } from "../components/taskUi";
import type { StaticCandidateItem, StaticFilterOption } from "../model/staticCandidates";
import { ALL_STATIC_FILTER, staticAuditTone } from "../model/staticCandidates";
import type { ScanQueueTask } from "../model/types";

export function StaticFilterSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: StaticFilterOption[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="inline-flex items-center gap-1.5 text-xs text-slate-400">
      <span>{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-1.5 text-xs text-slate-200 focus:border-blue-500 focus:outline-none"
      >
        <option value={ALL_STATIC_FILTER}>全部</option>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}{option.count === undefined ? "" : ` (${option.count})`}
          </option>
        ))}
      </select>
    </label>
  );
}

export function StaticCandidateListItem({
  item,
  auditExecutionEnded,
  result,
  active,
  onClick,
  focusRef,
}: {
  item: StaticCandidateItem;
  auditExecutionEnded: boolean;
  result?: CandidateAuditTaskResult;
  active: boolean;
  onClick: () => void;
  focusRef?: RefCallback<HTMLButtonElement>;
}) {
  const fileName = item.candidate.file.split("/").pop() || item.candidate.file;
  return (
    <li>
      <button
        type="button"
        ref={focusRef}
        aria-current={active ? "true" : undefined}
        onClick={onClick}
        className={`w-full px-3 py-2.5 text-left transition-colors ${active ? "bg-blue-500/15" : item.auditStatus === "running" ? "bg-blue-500/10 hover:bg-blue-500/15" : "hover:bg-slate-800/60"
          }`}
      >
        <div className="flex items-center gap-1.5">
          <span className="font-mono text-[11px] text-slate-500">#{item.candidate.idx}</span>
          <span className="truncate font-mono text-xs text-slate-200" title={`${item.candidate.file}:${item.candidate.line}`}>
            {fileName}:{item.candidate.line}
          </span>
          {item.auditStatus === "running" && (
            <span className="ml-auto h-3 w-3 shrink-0 rounded-full border border-blue-500/30 border-t-blue-300 animate-spin" />
          )}
        </div>
        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
          <span className="rounded bg-slate-700/50 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-slate-400">
            {item.candidate.vuln_type}
          </span>
          <StatusPill label={staticAuditStatusLabel(item.auditStatus, auditExecutionEnded)} tone={staticAuditTone(item.auditStatus)} />
          <AuditFindingBadge result={result} />
        </div>
        {item.candidate.function && (
          <div className="mt-1 truncate font-mono text-[11px] text-slate-500" title={item.candidate.function}>
            {item.candidate.function}
          </div>
        )}
      </button>
    </li>
  );
}

export function StaticCandidateDetail({ scan, item, runtime, result, resultLoading, resultError, onRetryResult, onOpenIssue }: {
  scan: ScanStatusType;
  item: StaticCandidateItem;
  runtime: ScanQueueTask | null;
  result?: CandidateAuditTaskResult;
  resultLoading: boolean;
  resultError: string;
  onRetryResult: () => void;
  onOpenIssue: (index: number) => void;
}) {
  const metadata = item.candidate.metadata && Object.keys(item.candidate.metadata).length > 0
    ? JSON.stringify(item.candidate.metadata, null, 2)
    : "";
  const related = item.candidate.related_functions ?? [];
  return (
    <div className="max-h-[72vh] min-w-0 space-y-4 overflow-y-auto p-4">
      <div className="border-b border-slate-800 pb-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-slate-500">#{item.candidate.idx}</span>
              <span className="text-sm font-semibold text-slate-100">{item.candidate.vuln_type}</span>
              {item.vulnerabilityIndex !== undefined && (
                <span className="rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 text-xs text-red-300">
                  结果 #{item.vulnerabilityIndex}
                </span>
              )}
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <StatusPill label={staticAuditStatusLabel(item.auditStatus, staticAuditExecutionEnded(scan))} tone={staticAuditTone(item.auditStatus)} />
            <AuditFindingBadge result={result} />
          </div>
        </div>
      </div>
      <AuditDetailSection title="审计结果">
        <AuditResults result={result} status={item.auditStatus} loading={resultLoading}
          error={resultError} onRetry={onRetryResult} onOpenIssue={onOpenIssue} />
      </AuditDetailSection>
      <AuditDetailSection title="审计目标">
        <DetailGrid items={[
          ["文件路径", item.candidate.file || "未指定"],
          ["行号", String(Math.max(1, item.candidate.line || 1))],
          ["函数", item.candidate.function || "未指定"],
          ["相关变量", staticCandidateRelatedVariable(item.candidate)],
          ["问题类型", item.candidate.vuln_type || "未指定"],
          ...(related.length ? [["相关函数", related.join("、")] as [string, string]] : []),
        ]} />
      </AuditDetailSection>
      {item.vulnerability && (
        <AuditDetailSection title="AI 审计结论">
          <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-2 [overflow-wrap:anywhere]">
            <MarkdownContent content={staticAuditConclusion(item.vulnerability)} />
          </div>
        </AuditDetailSection>
      )}
      <AuditPromptSection scan={scan} taskName={staticCandidateTaskName(scan.scan_id, item.candidate)}
        runtime={runtime} pending={item.auditStatus === "pending"} taskRevision={`${item.auditStatus}:${item.candidate.audit_updated_at || ""}`} />
      {metadata && (
        <details className="rounded border border-slate-800 bg-slate-950/40">
          <summary className="cursor-pointer px-3 py-2 text-xs text-slate-500 hover:text-slate-300">候选元数据</summary>
          <pre className="max-h-72 overflow-auto border-t border-slate-800 px-3 py-2 font-mono text-xs leading-5 text-slate-300">
            {metadata}
          </pre>
        </details>
      )}
    </div>
  );
}
