import { isPublicScan } from "../../api/accessPolicy";
import ScanShareButton from "../../components/ScanShareButton";
import { ThemeToggle } from "../../components/ThemeToggle";
import { DEFAULT_SCAN_ROUTE } from "../../routing";
import type { ScanNavigation } from "../../routing";
import type { ScanStatus } from "../../types/scans";
import JavelinFileCoverageView from "./JavelinFileCoverageView";
import JavelinWorkbenchHost from "./JavelinWorkbenchHost";

interface Props {
  scan: ScanStatus;
  scanId: string;
  sharedView?: boolean;
  navigation?: ScanNavigation;
  onHome: () => void;
  onCopyScan?: (scanId: string) => void;
}

export default function JavelinScanDetailPage({
  scan,
  scanId,
  sharedView = false,
  navigation,
  onHome,
  onCopyScan,
}: Props) {
  const isCoverageView = navigation?.state.tab === "coverage";
  const publicMode = sharedView || isPublicScan(scanId);

  const openCoverage = () => {
    navigation?.onNavigate({ ...(navigation.state || DEFAULT_SCAN_ROUTE), tab: "coverage" });
  };

  const openWorkbench = () => {
    navigation?.onNavigate({ ...(navigation.state || DEFAULT_SCAN_ROUTE), tab: "overview" });
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      <header className="sticky top-0 z-30 flex h-14 items-center justify-between gap-3 border-b border-slate-800 bg-slate-900/95 px-4 backdrop-blur">
        <div className="flex min-w-0 items-center gap-3">
          <button
            type="button"
            onClick={onHome}
            className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
          >
            ← 返回扫描列表
          </button>
          <span className="truncate text-sm font-semibold text-white" title={scan.scan_name || scan.project_id}>
            {scan.scan_name || scan.project_id}
          </span>
          <span className="shrink-0 rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-300">
            Java · Javelin
          </span>
          {scan.product && (
            <span className="hidden truncate text-xs text-slate-400 sm:inline">产品：{scan.product}</span>
          )}
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={isCoverageView ? openWorkbench : openCoverage}
            className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
          >
            {isCoverageView ? "审计工作台" : "文件覆盖详情"}
          </button>
          {!publicMode && scan.can_copy_scan && onCopyScan && (
            <button
              type="button"
              onClick={() => onCopyScan(scanId)}
              className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
            >
              复制配置
            </button>
          )}
          {!publicMode && <ScanShareButton scanId={scanId} compact />}
          <ThemeToggle />
        </div>
      </header>

      <main className="flex-1">
        {isCoverageView ? (
          <JavelinFileCoverageView scanId={scanId} onBackToWorkbench={openWorkbench} />
        ) : (
          <JavelinWorkbenchHost
            scanId={scanId}
            onOpenCoverage={openCoverage}
            onBackHome={onHome}
          />
        )}
      </main>
    </div>
  );
}
