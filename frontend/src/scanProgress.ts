import type { FpReviewJob, ScanProgressEstimate, ScanStatus } from "./types";

export function normalizeScanProgressEstimate(value: unknown): ScanProgressEstimate | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const item = value as Record<string, unknown>;
  if (typeof item.progress !== "number" || !Number.isFinite(item.progress)
    || typeof item.state !== "string" || !["ready", "estimating", "unavailable", "complete"].includes(item.state)
    || typeof item.calculated_at !== "string" || !Number.isFinite(Date.parse(item.calculated_at))
    || typeof item.execution_revision !== "number" || !Number.isFinite(item.execution_revision)
    || typeof item.active !== "boolean"
    || (item.remaining_seconds !== null && (typeof item.remaining_seconds !== "number"
      || !Number.isFinite(item.remaining_seconds) || item.remaining_seconds < 0))) return undefined;
  return {
    progress: Math.min(1, Math.max(0, item.progress)),
    remaining_seconds: item.remaining_seconds as number | null,
    state: item.state as ScanProgressEstimate["state"],
    calculated_at: item.calculated_at,
    execution_revision: item.execution_revision,
    active: item.active,
  };
}

/** A missing field preserves this execution's estimate, never a previous run's. */
export function selectScanProgressEstimate(
  previous: ScanProgressEstimate | undefined,
  incoming: ScanProgressEstimate | undefined,
  executionRevision?: number,
): ScanProgressEstimate | undefined {
  if (executionRevision !== undefined) {
    if (previous?.execution_revision !== executionRevision) previous = undefined;
    if (incoming?.execution_revision !== executionRevision) incoming = undefined;
  }
  if (!previous) return incoming;
  if (!incoming) return previous;
  if (incoming.execution_revision !== previous.execution_revision) {
    return incoming.execution_revision > previous.execution_revision ? incoming : previous;
  }
  return Date.parse(incoming.calculated_at) >= Date.parse(previous.calculated_at) ? incoming : previous;
}

export function hasActiveScanProgress(
  scan: Partial<ScanStatus> | null,
  review?: Pick<FpReviewJob, "status"> | null,
): boolean {
  if (!scan) return false;
  const active = (status?: string) => ["pending", "queued", "running", "analyzing", "auditing"].includes(status ?? "");
  const pool = scan.opencode_pool;
  return active(scan.status) || scan.progress_estimate?.active === true
    || active(review?.status) || scan.fp_review_running === true
    || Boolean(pool && (pool.global_running > 0 || pool.global_queued > 0
      || pool.planned_tasks?.length || pool.queued_tasks?.length
      || pool.models.some((model) => model.active_tasks?.length > 0)))
    || (scan.validations ?? []).some((item) => item.running || active(item.status))
    || active(scan.threat_analysis_run?.status)
    || (scan.mining_engine_runs ?? []).some((item) => active(item.status));
}

export function formatRemainingTime(seconds: number): string {
  if (seconds < 60) return "约 1 分钟内";
  const minutes = Math.ceil(seconds / 60);
  if (minutes < 60) return `约 ${minutes} 分钟`;
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  return `约 ${hours} 小时${rest ? ` ${rest} 分钟` : ""}`;
}
