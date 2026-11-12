import { getFpReviewStageDisplays, isEffectiveFpReviewResult } from "../../../fpReview";
import type { FpReviewJob, FpReviewStageConfig } from "../../../types/fpReview";
import type { Vulnerability } from "../../../types/issues";
import { vulnerabilitySeverityLabel } from "../../modelPool/ModelPoolDashboard";
import { MarkdownContent } from "../components/MarkdownContent";
import { StatusPill } from "../components/taskUi";
import { fpReviewItemLabel, fpReviewItemTone } from "../model/fpReview";
import { vulnerabilityFunctionLabel, vulnerabilityLocation, vulnerabilityTypeLabel } from "../model/scan";

export function FpReviewDetail({
  index,
  vulnerability,
  result,
  running,
  stages,
  onOpenIssue,
}: {
  index: number;
  vulnerability: Vulnerability;
  result?: FpReviewJob["results"][number];
  running: boolean;
  stages: FpReviewStageConfig[];
  onOpenIssue?: (index: number) => void;
}) {
  const stageEntries = getFpReviewStageDisplays(result, stages);
  return (
    <div className="max-h-[70vh] overflow-y-auto p-4">
      <div className="border-b border-slate-800 pb-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-slate-500">#{index}</span>
              <span className="text-sm font-semibold text-slate-100">{vulnerabilityTypeLabel(vulnerability)}</span>
              <span className="text-xs text-slate-500">{vulnerabilitySeverityLabel(vulnerability.severity)}</span>
            </div>
            <div className="mt-1 break-all font-mono text-xs text-slate-300">{vulnerabilityLocation(vulnerability)}</div>
            <div className="mt-1 truncate font-mono text-xs text-slate-500">{vulnerabilityFunctionLabel(vulnerability)}</div>
          </div>
          <div className="flex items-center gap-2">
            {onOpenIssue && isEffectiveFpReviewResult(result) && result.verdict === "tp" && (
              <button type="button" onClick={() => onOpenIssue(index)}
                className="rounded border border-cyan-500/30 bg-cyan-500/10 px-2 py-0.5 text-xs text-cyan-300 hover:bg-cyan-500/20">
                查看疑似问题
              </button>
            )}
            {running && <span className="h-3 w-3 rounded-full border border-amber-500/30 border-t-amber-300 animate-spin" />}
            <StatusPill label={fpReviewItemLabel(result, running)} tone={fpReviewItemTone(result, running)} />
          </div>
        </div>
      </div>
      <div className="mt-4 space-y-4">
        <section>
          <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">问题摘要</h4>
          <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-2">
            <MarkdownContent content={vulnerability.description || "（无描述）"} />
          </div>
        </section>
        <section>
          <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">复核结论</h4>
          <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-2">
            {result ? (
              <>
                <div className="mb-2 flex flex-wrap gap-2">
                  <StatusPill
                    label={result.verdict === "fp" ? "误报" : result.verdict === "tp" ? "正报" : "未完成"}
                    tone={result.verdict === "fp" ? "green" : result.verdict === "tp" ? "red" : "slate"}
                  />
                  <StatusPill label={`严重性：${result.severity || "-"}`} tone="slate" />
                  {result.match_type && <StatusPill label={`依据：${result.match_type}`} tone="purple" />}
                </div>
                <MarkdownContent content={result.reason || (isEffectiveFpReviewResult(result)
                  ? "（无结论说明）" : running ? "复核中，等待结论" : "暂无复核结论")} />
                {result.match_reference && (
                  <div className="mt-2 rounded border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-400">
                    {result.match_reference}
                  </div>
                )}
              </>
            ) : (
              <p className="py-2 text-xs text-slate-500">{running ? "复核中，等待结论" : "等待复核"}</p>
            )}
          </div>
        </section>
        <section className="space-y-3">
          <h4 className="text-xs font-semibold uppercase text-slate-500">阶段输出</h4>
          {stageEntries.length > 0 ? stageEntries.map((stage) => (
            <div key={stage.key} className="rounded-lg border border-slate-800 bg-slate-950/40">
              <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 px-3 py-2 text-xs font-semibold text-slate-400">
                <span>{stage.label}</span>
                {stage.verdict && <StatusPill label={stage.verdict.label} tone={stage.verdict.tone} />}
              </div>
              {stage.sections.length > 0 && (
                <div className="divide-y divide-slate-800/60">
                  {stage.sections.map((section, sectionIndex) => (
                    <div key={sectionIndex} className="px-4 py-3">
                      {section.label && (
                        <h5 className="mb-1 text-xs font-semibold text-slate-400">{section.label}</h5>
                      )}
                      <MarkdownContent content={section.markdown} />
                    </div>
                  ))}
                </div>
              )}
            </div>
          )) : (
            <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-4 text-xs text-slate-500">
              {running ? "复核中，等待阶段输出" : "暂无阶段输出"}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
