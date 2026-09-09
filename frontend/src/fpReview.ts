import type { FpReviewResult } from "./types";

const FP_REVIEW_NO_RESULT_REASON = "Review incomplete";

/** Waiting placeholders returned by pagination are not stored review history. */
export function hasFpReviewRecord(result?: FpReviewResult | null): result is FpReviewResult {
  return !!result && Boolean(result.review_id || result.created_at || result.reason || result.vulnerability_report
    || Object.values(result.stage_outputs ?? {}).some(Boolean)
    || Object.values(result.pending_stage_outputs ?? {}).some(Boolean));
}

export function isEffectiveFpReviewResult(
  result?: FpReviewResult | null,
): result is FpReviewResult {
  if (!result || !["tp", "fp"].includes(result.verdict)) return false;
  if (!result.reason && !result.vulnerability_report) return false;
  return !String(result.reason || "").startsWith(FP_REVIEW_NO_RESULT_REASON);
}

export function isFpReviewNonProblem(
  result?: FpReviewResult | null,
): boolean {
  return isEffectiveFpReviewResult(result) && result.verdict === "fp";
}
