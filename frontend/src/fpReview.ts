import type { FpReviewResult } from "./types";

const FP_REVIEW_NO_RESULT_REASON = "Review incomplete";

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
