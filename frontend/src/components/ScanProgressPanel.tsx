import { formatRemainingTime, selectScanProgressEstimate } from "../scanProgress";
import type { ScanStatus } from "../types";

export function ScanProgressPanel({ scan, active }: { scan: ScanStatus; active: boolean }) {
  const estimate = selectScanProgressEstimate(undefined, scan.progress_estimate, scan.execution_revision);
  const complete = estimate?.state === "complete" && !active
    || !estimate && scan.status === "complete" && !active;
  const progress = complete ? 100 : estimate ? Math.min(99, Math.round(estimate.progress * 100)) : null;
  const remaining = complete ? "0 分钟"
    : estimate?.state === "unavailable" || scan.agent_online === false
      || ["error", "cancelled"].includes(scan.status) ? "暂无法估算"
    : estimate?.state === "ready" && estimate.remaining_seconds !== null
      ? formatRemainingTime(estimate.remaining_seconds) : "估算中";
  return <section aria-label="整体进度" className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div className="flex items-baseline gap-3">
        <h3 className="text-sm font-semibold text-slate-200">整体进度</h3>
        <span className="font-mono text-lg font-semibold text-slate-100">{progress === null ? "估算中" : `${progress}%`}</span>
      </div>
      <div className="text-sm text-slate-400">预计剩余时间 <span className="ml-2 text-slate-200">{remaining}</span></div>
    </div>
    <div role="progressbar" aria-label="整体进度" aria-valuemin={0} aria-valuemax={100}
      aria-valuenow={progress ?? undefined} aria-valuetext={progress === null ? "估算中" : `${progress}%`}
      className="mt-3 h-2 overflow-hidden rounded-full bg-slate-800">
      <div className={`h-full rounded-full transition-all duration-500 ${complete ? "bg-green-500" : "bg-cyan-500"}`}
        style={{ width: `${progress ?? 0}%` }} />
    </div>
  </section>;
}
