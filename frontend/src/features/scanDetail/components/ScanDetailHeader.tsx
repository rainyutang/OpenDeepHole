import { isPublicScan } from "../../../api/accessPolicy";
import ScanShareButton from "../../../components/ScanShareButton";
import { ThemeToggle } from "../../../components/ThemeToggle";
import type { ScanStatus as ScanStatusType } from "../../../types/scans";
import type { ThreatAnalysisResultTab } from "../../threatAnalysis/analysisModel";
import { buildProcessFlowModel } from "../model/processFlow";
import type { FlowNodeId, MainTab, ReportExportFormat } from "../model/types";
import { ProcessFlowNav } from "./ProcessFlowNav";
import { ScanBrandButton } from "./ScanDetailSidebar";

interface Props {
  onHome: () => void;
  setSidebarOpen: React.Dispatch<React.SetStateAction<boolean>>;
  sidebarOpen: boolean;
  scan: ScanStatusType;
  agentDisconnectError: boolean;
  isRunning: boolean | null;
  isDone: boolean | null;
  sharedView: boolean;
  scanId: string;
  handleContinue: () => Promise<void>;
  continuing: boolean;
  continuableCount: number;
  exportMenuRef: React.RefObject<HTMLDivElement>;
  setExportMenuOpen: React.Dispatch<React.SetStateAction<boolean>>;
  exportingReport: ReportExportFormat | null;
  exportMenuOpen: boolean;
  handleExportReport: (format: ReportExportFormat) => Promise<void>;
  handleStop: () => Promise<void>;
  stopping: boolean;
  activeTab: MainTab;
  flowModel: ReturnType<typeof buildProcessFlowModel>;
  handleFlowNodeClick: (node: FlowNodeId) => void;
  threatAnalysisResultTab: ThreatAnalysisResultTab;
  visibleErrorMessage: string | null;
}

export function ScanDetailHeader({
  onHome,
  setSidebarOpen,
  sidebarOpen,
  scan,
  agentDisconnectError,
  isRunning,
  isDone,
  sharedView,
  scanId,
  handleContinue,
  continuing,
  continuableCount,
  exportMenuRef,
  setExportMenuOpen,
  exportingReport,
  exportMenuOpen,
  handleExportReport,
  handleStop,
  stopping,
  activeTab,
  flowModel,
  handleFlowNodeClick,
  threatAnalysisResultTab,
  visibleErrorMessage,
}: Props) {
  return (
    <div className="bg-slate-800/80 backdrop-blur border-b border-slate-700 px-4 py-4 sm:px-6">
      <div className="mb-4 flex items-center justify-between gap-3 lg:hidden">
        <ScanBrandButton onClick={onHome} />
        <button
          type="button"
          onClick={() => setSidebarOpen(true)}
          aria-label="打开扫描导航"
          aria-expanded={sidebarOpen}
          className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-slate-600 text-slate-300 transition-colors hover:bg-slate-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400/70"
        >
          <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>
      </div>
      <div className="mb-3 flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between">
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-4 gap-y-2">
          <div className="min-w-0 w-full sm:w-auto sm:max-w-sm">
            <h1 className="text-lg font-bold text-white">扫描导航</h1>
            <div className="mt-1 truncate text-sm text-slate-400" aria-label="当前扫描名称"
              title={scan.scan_name?.trim() || scan.project_id || scan.scan_id}>
              {scan.scan_name?.trim() || scan.project_id || scan.scan_id}
            </div>
          </div>
          <span className="text-sm text-slate-400">
            {scan.status === "cancelled"
              ? (agentDisconnectError ? (scan.agent_online ? "扫描已中断" : "Agent 断开，已中断") : "已取消")
              : scan.status === "error" ? "扫描异常"
                : isRunning ? "扫描中..." : isDone ? "扫描完成" : "扫描中..."}
          </span>
          {scan.agent_name && (
            <span className="flex items-center gap-1.5 text-sm text-slate-400 border-l border-slate-600 pl-4">
              <span
                className={`w-2 h-2 rounded-full flex-shrink-0 ${scan.agent_online ? "bg-green-400" : "bg-slate-500"
                  }`}
              />
              Agent: {scan.agent_name}
              {!scan.agent_online && (
                <span className="text-xs text-slate-500">(离线)</span>
              )}
            </span>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2 xl:max-w-[72%] xl:justify-end">
          <ThemeToggle />
          {sharedView && <span className="text-xs text-cyan-300">分享访问</span>}
          {!sharedView && !isPublicScan(scanId) && <ScanShareButton scanId={scanId} />}
          {!sharedView && isDone && (
            <>
              {scan.can_continue && (
                <button
                  onClick={handleContinue}
                  disabled={continuing || !scan.agent_online}
                  title={!scan.agent_online ? "Agent 离线，无法续扫" : `续扫 ${continuableCount} 个任务`}
                  className="px-3 py-1.5 text-sm font-medium text-amber-300 border border-amber-500/50 rounded-lg hover:bg-amber-500/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {continuing ? "启动中..." : "续扫"}
                </button>
              )}
            </>
          )}
          <div ref={exportMenuRef} className="relative">
            <button
              type="button"
              onClick={() => setExportMenuOpen((open) => !open)}
              disabled={exportingReport !== null}
              aria-haspopup="menu"
              aria-expanded={exportMenuOpen}
              className="flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-blue-700 disabled:cursor-not-allowed disabled:bg-blue-800"
            >
              {exportingReport === "zip"
                ? "压缩包导出中..."
                : exportingReport === "csv"
                  ? "CSV 导出中..."
                  : "导出报告"}
              {!exportingReport && (
                <svg
                  className={`h-3.5 w-3.5 transition-transform ${exportMenuOpen ? "rotate-180" : ""}`}
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              )}
            </button>
            {exportMenuOpen && (
              <div
                role="menu"
                aria-label="导出报告格式"
                className="absolute right-0 top-full z-40 mt-2 w-28 overflow-hidden rounded-lg border border-slate-600 bg-slate-900 py-1 shadow-xl"
              >
                <button
                  type="button"
                  role="menuitem"
                  onClick={() => { void handleExportReport("zip"); }}
                  className="block w-full px-3 py-2 text-left text-sm font-medium text-slate-100 transition-colors hover:bg-slate-800 focus:bg-slate-800 focus:outline-none"
                >
                  ZIP
                </button>
                <button
                  type="button"
                  role="menuitem"
                  onClick={() => { void handleExportReport("csv"); }}
                  className="block w-full border-t border-slate-700 px-3 py-2 text-left text-sm font-medium text-slate-100 transition-colors hover:bg-slate-800 focus:bg-slate-800 focus:outline-none"
                >
                  CSV
                </button>
              </div>
            )}
          </div>
          {!sharedView && isRunning && (
            <button
              onClick={handleStop}
              disabled={stopping}
              className="px-3 py-1.5 text-sm font-medium text-red-400 border border-red-500/50 rounded-lg hover:bg-red-500/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {stopping ? "停止中..." : "停止扫描"}
            </button>
          )}
        </div>
      </div>

      {activeTab === "overview" && <ProcessFlowNav
        flow={flowModel}
        onNodeClick={handleFlowNodeClick}
        activeThreatResultTab={threatAnalysisResultTab}
        issuesActive={false}
      />}

      {/* Error */}
      {visibleErrorMessage && (
        <div className={`mt-3 rounded-lg border p-2.5 text-sm ${scan.status === "complete"
            ? "border-amber-500/30 bg-amber-500/10 text-amber-300"
            : "border-red-500/30 bg-red-500/10 text-red-400"
          }`}>
          {visibleErrorMessage}
        </div>
      )}
    </div>
  );
}
