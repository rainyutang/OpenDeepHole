import type { SkillReport } from "../../../types/checkers";
import { formatOutputSource, hasOutputSource } from "../model/scan";
import { MarkdownContent } from "./MarkdownContent";

interface Props {
  reportsOpen: boolean;
  setReportsOpen: React.Dispatch<React.SetStateAction<boolean>>;
  isRunning: boolean | null;
  displayedReports: SkillReport[];
  reportsLoading: boolean;
  setActiveReportIndex: React.Dispatch<React.SetStateAction<number>>;
  activeReportIndex: number;
  activeReport: SkillReport;
}

export function ScanReportsPanel({
  reportsOpen,
  setReportsOpen,
  isRunning,
  displayedReports,
  reportsLoading,
  setActiveReportIndex,
  activeReportIndex,
  activeReport,
}: Props) {
  return (
    <>{reportsOpen && (
      <>
        <div
          className="fixed inset-0 bg-black/30 z-40"
          onClick={() => setReportsOpen(false)}
        />
        <div className="fixed right-0 top-0 bottom-0 w-[52rem] max-w-full bg-slate-900 border-l border-slate-700 z-50 flex flex-col shadow-2xl">
          <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
            <div>
              <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
                SKILL 报告
              </h3>
              <p className="text-xs text-slate-500 mt-1">
                {isRunning ? "报告型 SKILL 正在运行或等待同步" : `已同步 ${displayedReports.length} 个 Markdown 报告`}
              </p>
            </div>
            <button
              onClick={() => setReportsOpen(false)}
              className="text-slate-500 hover:text-slate-300 transition-colors"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <div className="flex min-h-0 flex-1">
            <div className="w-64 shrink-0 border-r border-slate-800 p-3 overflow-y-auto">
              {reportsLoading ? (
                <div className="flex items-center gap-2 text-xs text-slate-500">
                  <div className="w-3 h-3 border border-slate-600 border-t-purple-400 rounded-full animate-spin" />
                  加载中...
                </div>
              ) : displayedReports.length === 0 ? (
                <div className="rounded border border-slate-800 bg-slate-950 px-3 py-4 text-xs text-slate-500">
                  暂无报告
                </div>
              ) : (
                <div className="space-y-2">
                  {displayedReports.map((report, index) => (
                    <button
                      key={`${report.checker_name}-${report.filename}-${index}`}
                      onClick={() => setActiveReportIndex(index)}
                      className={`w-full rounded-lg border px-3 py-2 text-left transition-colors ${index === activeReportIndex
                          ? "border-purple-500/50 bg-purple-500/10"
                          : "border-slate-800 bg-slate-950 hover:border-slate-700"
                        }`}
                    >
                      <div className="text-xs font-semibold text-slate-200 truncate">{report.title || report.filename}</div>
                      <div className="mt-1 text-[11px] text-slate-500 font-mono truncate">{report.checker_name}/{report.filename}</div>
                      {hasOutputSource(report.output_source) && (
                        <div className="mt-1 text-[11px] text-cyan-300 truncate">{formatOutputSource(report.output_source)}</div>
                      )}
                    </button>
                  ))}
                </div>
              )}
            </div>
            <div className="min-w-0 flex-1 overflow-y-auto p-5">
              {activeReport ? (
                <>
                  {hasOutputSource(activeReport.output_source) && (
                    <div
                      className="mb-3 rounded border border-cyan-500/20 bg-cyan-500/5 px-3 py-2 text-xs text-cyan-200"
                      title={[
                        activeReport.output_source?.agent_id ? `Agent ID: ${activeReport.output_source.agent_id}` : "",
                        activeReport.output_source?.agent_session_id ? `Session: ${activeReport.output_source.agent_session_id}` : "",
                        activeReport.output_source?.task_id ? `Task: ${activeReport.output_source.task_id}` : "",
                      ].filter(Boolean).join("\n")}
                    >
                      输出来源：{formatOutputSource(activeReport.output_source)}
                    </div>
                  )}
                  <MarkdownContent content={activeReport.content} />
                </>
              ) : (
                <div className="text-sm text-slate-500">选择左侧报告查看内容</div>
              )}
            </div>
          </div>
        </div>
      </>
    )}</>
  );
}
