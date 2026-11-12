import { isEffectiveFpReviewResult } from "../../../fpReview";
import type { FpReviewJob } from "../../../types/fpReview";
import type { TaskTone } from "./types";

export function fpReviewSortRank(result: FpReviewJob["results"][number] | undefined, running: boolean): number {
  if (running) return 0;
  if (!isEffectiveFpReviewResult(result)) return 1;
  return 2;
}

export function fpReviewItemLabel(result: FpReviewJob["results"][number] | undefined, running: boolean): string {
  if (running) return "复核中";
  if (!result) return "等待复核";
  if (!isEffectiveFpReviewResult(result)) return "未完成";
  return result.verdict === "fp" ? "误报" : result.verdict === "tp" ? "正报" : "未完成";
}

export function fpReviewItemTone(result: FpReviewJob["results"][number] | undefined, running: boolean): TaskTone {
  if (running) return "amber";
  if (!isEffectiveFpReviewResult(result)) return "slate";
  return result.verdict === "fp" ? "green" : result.verdict === "tp" ? "red" : "slate";
}
