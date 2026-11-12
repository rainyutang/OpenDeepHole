import { useState } from "react";
import type { IssueDetailProps } from "./types";
import { auditSourceKind } from "../../auditNavigation";
import { hasFpReviewRecord } from "../../fpReview";
import { IssueFeedback } from "./IssueFeedback";
import { IssueReportSections } from "./IssueReportSections";
import { IssueValidationActions } from "./IssueValidationActions";
import {
  SEVERITY_STYLES,
  engineId,
  engineLabel,
  getVerdict,
  severityLabel,
  vulnerabilityFunctionLabel,
  vulnerabilityLocation,
  vulnerabilityTypeLabel,
} from "./model";
import { FpStatusBadge, OutputSourceLine, hasOutputSource } from "./presentation";
import { finalFpReviewPresentation } from "./reportModel";
import { useIssueFeedback } from "./useIssueFeedback";
import { useIssueReportDownload } from "./useIssueReportDownload";

export function VulnDetail({
  scanId,
  index,
  vuln,
  fpReviewResult,
  fpReviewStages,
  hasFpReview,
  fpReviewRunning,
  finalTpOnly,
  validation,
  validating,
  stoppingValidation = false,
  agentOnline,
  onTriggerValidation,
  onStopValidation,
  events,
  onVulnMarked,
  onOpenAuditSource,
  onOpenFpReview,
  onFeedbackCreated,
  onFeedbackRemoved,
}: IssueDetailProps) {
  const [detailsOpen, setDetailsOpen] = useState(false);
  const feedback = useIssueFeedback({ scanId, index, vuln, onVulnMarked, onFeedbackCreated, onFeedbackRemoved });
  const { exporting, handleExportMarkdown } = useIssueReportDownload(scanId, index);
  const finalFpPresentation = finalTpOnly && fpReviewResult
    ? finalFpReviewPresentation(fpReviewResult, fpReviewStages)
    : null;

  const aiVerdict = getVerdict(vuln);
  const isProblem = aiVerdict === "confirmed";
  return (
    <div className="p-3 sm:p-4 lg:max-h-[70vh] lg:overflow-y-auto">
      {/* Header */}
      <div className="mb-3 border-b border-slate-800 pb-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="min-w-0 break-all font-mono text-sm text-slate-200" title={vulnerabilityLocation(vuln)}>
            {vulnerabilityLocation(vuln)}
          </span>
          {!finalTpOnly && (
            <>
              <span className="text-xs font-semibold uppercase text-slate-400 bg-slate-700/50 px-2 py-0.5 rounded">
                {vulnerabilityTypeLabel(vuln)}
              </span>
              <span
                className={`text-xs font-semibold px-2 py-0.5 rounded border ${
                  SEVERITY_STYLES[vuln.severity] ?? "bg-slate-700/50 text-slate-400 border-slate-600"
                }`}
              >
                {severityLabel(vuln.severity)}
              </span>
              <span
                className="rounded border border-cyan-500/30 bg-cyan-500/10 px-2 py-0.5 text-xs font-semibold text-cyan-200"
                title={`引擎 ID：${engineId(vuln)}`}
              >
                {engineLabel(vuln)}
              </span>
              {vuln.provisional && (
                <span className="rounded border border-blue-500/30 bg-blue-500/10 px-2 py-0.5 text-xs font-semibold text-blue-300">
                  临时上报，等待最终对账
                </span>
              )}
              {(() => {
                if (aiVerdict === "confirmed") return <span className="text-xs font-semibold text-red-400">AI: 是问题</span>;
                if (aiVerdict === "timeout") return <span className="text-xs font-semibold text-amber-400 italic">AI: 超时</span>;
                if (aiVerdict === "no_result") return <span className="text-xs text-slate-500 italic">AI: 无结果</span>;
                if (aiVerdict === "failed") return <span className="text-xs text-amber-400 italic">AI: 失败</span>;
                return <span className="text-xs text-slate-500">AI: 非问题</span>;
              })()}
              {hasFpReview && (
                <FpStatusBadge fpResult={fpReviewResult} fpReviewRunning={fpReviewRunning} />
              )}
            </>
          )}
          <div className="flex w-full flex-wrap items-center gap-2 sm:ml-auto sm:w-auto">
            {finalTpOnly && (
              <button type="button" aria-expanded={detailsOpen}
                aria-controls={`issue-details-${index}`}
                onClick={() => setDetailsOpen((open) => !open)}
                className="rounded text-xs text-slate-400 hover:text-slate-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400">
                详情 {detailsOpen ? "▾" : "▸"}
              </button>
            )}
            {!finalTpOnly && (<>
            {onOpenFpReview && hasFpReviewRecord(fpReviewResult) && (
              <button
                type="button"
                onClick={() => onOpenFpReview(index)}
                className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-xs text-amber-300 hover:bg-amber-500/20"
              >
                查看去误报详情
              </button>
            )}
            {onOpenAuditSource && auditSourceKind(vuln) && (
              <button
                type="button"
                onClick={() => onOpenAuditSource(index)}
                className="rounded border border-cyan-500/30 bg-cyan-500/10 px-2 py-0.5 text-xs text-cyan-300 hover:bg-cyan-500/20"
              >
                {auditSourceKind(vuln) === "threat_pattern_audit" ? "查看攻击模式审计任务"
                  : auditSourceKind(vuln) === "threat_audit" ? "查看威胁审计任务" : "查看静态候选点"}
              </button>
            )}
            </>)}
            <IssueValidationActions index={index} vuln={vuln} validation={validation}
              validating={validating} stoppingValidation={stoppingValidation} agentOnline={agentOnline}
              onTriggerValidation={onTriggerValidation} onStopValidation={onStopValidation} finalTpOnly={finalTpOnly} />
            {isProblem && (
              <button
                onClick={handleExportMarkdown}
                disabled={exporting}
                className="text-xs px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/30 hover:bg-blue-500/20 disabled:opacity-50 transition-colors"
                title="导出该漏洞的 Markdown 报告（含 AI 分析与去误报复核）"
              >
                {exporting ? "导出中" : "导出 MD"}
              </button>
            )}
          </div>
        </div>
        <div className="mt-1.5 break-all font-mono text-xs text-slate-500">
          {vulnerabilityFunctionLabel(vuln)}
        </div>
        {!finalTpOnly && (
          <div className="mt-1.5 text-xs text-slate-500">
            输出引擎：{engineLabel(vuln)} · {engineId(vuln)}
          </div>
        )}
      </div>

      {finalTpOnly && detailsOpen && (
        <div id={`issue-details-${index}`} className="mb-3 space-y-2 rounded-lg border border-slate-800 bg-slate-950/40 p-3">
          <div className="flex flex-wrap items-center gap-2">
            {onOpenFpReview && hasFpReviewRecord(fpReviewResult) && (
              <button
                type="button"
                onClick={() => onOpenFpReview(index)}
                className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-xs text-amber-300 hover:bg-amber-500/20"
              >
                查看去误报详情
              </button>
            )}
            {onOpenAuditSource && auditSourceKind(vuln) && (
              <button
                type="button"
                onClick={() => onOpenAuditSource(index)}
                className="rounded border border-cyan-500/30 bg-cyan-500/10 px-2 py-0.5 text-xs text-cyan-300 hover:bg-cyan-500/20"
              >
                {auditSourceKind(vuln) === "threat_pattern_audit" ? "查看攻击模式审计任务"
                  : auditSourceKind(vuln) === "threat_audit" ? "查看威胁审计任务" : "查看静态候选点"}
              </button>
            )}
          </div>
          {hasOutputSource(vuln.output_source) && <div className="break-all">
            <span className="text-xs text-slate-500">漏洞报告</span>
            <OutputSourceLine source={vuln.output_source} />
          </div>}
          {hasOutputSource(finalFpPresentation?.source) && <div className="break-all">
            <span className="text-xs text-slate-500">AI 去误报复核</span>
            <OutputSourceLine source={finalFpPresentation?.source} />
          </div>}
        </div>
      )}

      <IssueFeedback vuln={vuln} feedback={feedback} />

      {/* Content sections */}
      <IssueReportSections vuln={vuln} fpReviewResult={fpReviewResult} fpReviewStages={fpReviewStages}
        fpReviewRunning={fpReviewRunning} finalTpOnly={finalTpOnly} events={events} index={index}
        finalFpPresentation={finalFpPresentation} />
    </div>
  );
}
