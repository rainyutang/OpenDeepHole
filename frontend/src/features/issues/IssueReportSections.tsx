import { useState } from "react";
import VulnerabilityMarkdownReport from "../../components/VulnerabilityMarkdownReport";
import type { IssueDetailProps } from "./types";
import { MATCH_TYPE_LABELS, SEVERITY_STYLES } from "./model";
import { MarkdownReport, OutputSourceLine } from "./presentation";
import type { finalFpReviewPresentation } from "./reportModel";
import { vulnerabilityReportContent } from "./reportModel";

type ReportSectionProps = Pick<IssueDetailProps,
  "vuln" | "fpReviewResult" | "fpReviewStages" | "fpReviewRunning" | "finalTpOnly" | "events" | "index"
> & { finalFpPresentation: ReturnType<typeof finalFpReviewPresentation> | null };

export function IssueReportSections({
  vuln, fpReviewResult, fpReviewStages, fpReviewRunning, finalTpOnly, events, index, finalFpPresentation,
}: ReportSectionProps) {
  const [showDialogue, setShowDialogue] = useState(false);
  const [showFpReason, setShowFpReason] = useState(false);
  const [activeFpStage, setActiveFpStage] = useState(
    fpReviewStages[fpReviewStages.length - 1]?.key ?? "",
  );
  const fpStageOutputs = fpReviewResult?.stage_outputs ?? {};
  const fpStageOutputSources = fpReviewResult?.stage_output_sources ?? {};
  const fpStageTabs = fpReviewStages.length > 0
    ? fpReviewStages
    : Object.keys(fpStageOutputs).map((key) => ({ key, label: key }));
  const hasFpFinalResult = Boolean(fpReviewResult?.reason || fpReviewResult?.vulnerability_report);
  // 方法可以按证据提前结束，默认选中的阶段不一定有产出；回退到第一个有内容的阶段。
  const readyStageKeys = fpStageTabs.map((s) => s.key).filter((k) => fpStageOutputs[k]?.trim());
  const effectiveFpStage = fpStageOutputs[activeFpStage]?.trim()
    ? activeFpStage
    : readyStageKeys[0] ?? activeFpStage;
  const activeStageOutput = fpStageOutputs[effectiveFpStage] ?? "";
  const activeStageOutputSource = fpStageOutputSources[effectiveFpStage];
  const vulnerabilityReport = vulnerabilityReportContent(vuln, finalTpOnly);

  const dialogueEvents = events.filter(
    (e) => e.phase === "opencode_output" && e.candidate_index === index,
  );

  return (
    <div className="space-y-4">
      <section>
        <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">漏洞报告</h4>
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-2">
          {!finalTpOnly && <OutputSourceLine source={vuln.output_source} />}
          <VulnerabilityMarkdownReport content={vulnerabilityReport} />
        </div>
      </section>

      {!finalTpOnly && vuln.variant_of && (
        <section>
          <h4 className="mb-1 text-xs font-semibold uppercase text-purple-300/80">同类变体来源</h4>
          <p className="text-sm text-slate-300">{vuln.variant_of}</p>
        </section>
      )}

      {fpReviewResult && (
        finalTpOnly && finalFpPresentation ? (
          <section>
            <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">AI 去误报复核</h4>
            <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-2">
              <MarkdownReport content={finalFpPresentation.content} />
            </div>
          </section>
        ) : (
          <section>
            <div className="mb-2 flex flex-wrap items-center gap-2">
            <h4
              className={`text-xs font-semibold uppercase ${
                !hasFpFinalResult
                  ? "text-blue-300/80"
                  : fpReviewResult.verdict === "fp"
                    ? "text-amber-400/80"
                    : "text-red-400/80"
              }`}
            >
              AI 去误报复核 — {!hasFpFinalResult ? (fpReviewRunning ? "复核中" : "复核失败") : fpReviewResult.verdict === "fp" ? "可能误报" : "确认漏洞"}
            </h4>
            {hasFpFinalResult && (
              <span
                className={`text-xs font-semibold px-2 py-0.5 rounded border ${
                  SEVERITY_STYLES[fpReviewResult.severity] ?? "bg-slate-700/50 text-slate-400 border-slate-600"
                }`}
              >
                {fpReviewResult.severity}
              </span>
            )}
            {fpReviewResult.match_type && (
              <span className="text-xs font-semibold px-2 py-0.5 rounded border border-purple-500/40 bg-purple-500/15 text-purple-200">
                {MATCH_TYPE_LABELS[fpReviewResult.match_type] ?? fpReviewResult.match_type}
              </span>
            )}
            {fpReviewResult.reason && !Object.keys(fpStageOutputs).length && (
              <button
                onClick={() => setShowFpReason(!showFpReason)}
                className="text-xs px-2 py-0.5 rounded border border-slate-600 bg-slate-700/40 text-slate-300 hover:bg-slate-700 transition-colors"
              >
                {showFpReason ? "隐藏论证过程" : "查看论证过程"}
              </button>
            )}
          </div>
          {fpReviewResult.match_reference && (
            <div className="mb-2 rounded-lg border border-purple-500/30 bg-purple-500/5 px-3 py-2">
              <span className="mr-2 text-xs font-semibold uppercase text-purple-300/80">对应修复/校验</span>
              <span className="text-sm text-slate-300">{fpReviewResult.match_reference}</span>
            </div>
          )}
          <OutputSourceLine source={fpReviewResult.output_source} />
          {Object.keys(fpStageOutputs).length > 0 && (
            <div>
              <div className="mb-2 flex flex-wrap gap-1.5">
                {fpStageTabs.map((stage) => {
                  const ready = Boolean(fpStageOutputs[stage.key]?.trim());
                  const active = effectiveFpStage === stage.key;
                  return (
                    <button
                      key={stage.key}
                      type="button"
                      disabled={!ready}
                      onClick={() => setActiveFpStage(stage.key)}
                      className={`text-xs px-2.5 py-1 rounded border transition-colors ${
                        active && ready
                          ? "border-blue-500/40 bg-blue-500/15 text-blue-200"
                          : ready
                            ? "border-slate-600 bg-slate-800 text-slate-300 hover:bg-slate-700"
                            : "border-slate-800 bg-slate-900/60 text-slate-600 cursor-not-allowed"
                      }`}
                    >
                      {stage.label}
                    </button>
                  );
                })}
              </div>
              {activeStageOutput ? (
                <div className="rounded-lg border border-slate-700 bg-slate-950/70 p-4">
                  <OutputSourceLine source={activeStageOutputSource} />
                  <MarkdownReport content={activeStageOutput} />
                </div>
              ) : (
                <div className="rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-2 text-xs text-slate-500">
                  该阶段尚未生成 Markdown 输出。
                </div>
              )}
            </div>
          )}
          {fpReviewResult.reason && showFpReason && (
            <pre className="mt-3 max-h-64 overflow-y-auto whitespace-pre-wrap rounded-lg border border-slate-700 bg-slate-900 p-4 text-xs leading-relaxed text-slate-400">
              {fpReviewResult.reason}
            </pre>
          )}
          </section>
        )
      )}

      {dialogueEvents.length > 0 && (
        <section>
          <button
            onClick={() => setShowDialogue(!showDialogue)}
            className={`text-xs px-2.5 py-1 rounded transition-colors ${
              showDialogue
                ? "bg-blue-500/20 text-blue-400 border border-blue-500/30"
                : "text-slate-400 hover:text-slate-200 border border-slate-700 hover:border-slate-600"
            }`}
          >
            {showDialogue ? "隐藏对话日志" : `查看对话日志 (${dialogueEvents.length} 行)`}
          </button>
          {showDialogue && (
            <pre className="mt-2 max-h-96 overflow-y-auto whitespace-pre-wrap rounded-lg border border-slate-700 bg-slate-900 p-4 text-xs leading-relaxed text-slate-400">
              {dialogueEvents.map((e) => e.message).join("\n")}
            </pre>
          )}
        </section>
      )}
    </div>
  );
}
