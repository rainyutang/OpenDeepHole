import type { ReportFpReviewState } from "../../api/reports";
import type { FpReviewResult } from "../../types/fpReview";
import type { UserFeedbackVerdict, Vulnerability, VulnerabilityValidation } from "../../types/issues";
import { isEffectiveFpReviewResult, isFpReviewNonProblem } from "../../fpReview";
import { canonicalMiningEngineLabel } from "../../miningEngines";

export type AiVerdict = "confirmed" | "not_confirmed" | "timeout" | "no_result" | "failed" | "filtered_same_pattern";

export type VulnerabilityListMode = "all_results" | "final_tp";

/** Derive effective verdict, with fallback for old data missing ai_verdict. */
export function getVerdict(v: Vulnerability): AiVerdict {
  if (v.ai_verdict) return v.ai_verdict as AiVerdict;
  if (v.confirmed) return "confirmed";
  if (v.severity === "unknown") return "no_result";
  return "not_confirmed";
}

/**
 * 判定一个候选是否仍算「问题」：
 *  - AI 审计阶段未确认（confirmed=false）→ 非问题；
 *  - 去误报复核最终判为 fp → 非问题；
 *  - 其余（确认且未被判 fp，含尚在复核中的）→ 问题。
 */
export function isProblemVuln(vuln: Vulnerability, fpResult?: FpReviewResult | null): boolean {
  if (getVerdict(vuln) !== "confirmed") return false;
  if (isFpReviewNonProblem(fpResult)) return false;
  return true;
}

export const ALL_FILTER = "__all__";

export const PAGE_SIZE = 20;

export const VALIDATION_FILTER_LABELS: Record<string, string> = {
  unverified: "未验证",
  running: "验证中",
  verified: "已完成验证",
};

export const FP_REVIEW_FILTER_LABELS: Record<ReportFpReviewState, string> = {
  no_conclusion: "未形成有效结论",
  tp: "确认问题",
  fp: "非问题",
};

export interface FilterOption {
  value: string;
  label: string;
  count: number;
}

export const USER_FEEDBACK_DISPLAY: Record<UserFeedbackVerdict, { label: string; color: string }> = {
  confirmed: { label: "确认正报", color: "text-red-400" },
  false_positive: { label: "实为误报", color: "text-green-400" },
  pending_analysis: { label: "待分析", color: "text-sky-300" },
};

export type UserFeedbackFilterState = UserFeedbackVerdict | "unmarked";

export const USER_FEEDBACK_FILTER_LABELS: Record<UserFeedbackFilterState, string> = {
  unmarked: "未标记",
  pending_analysis: "待分析",
  confirmed: "确认正报",
  false_positive: "实为误报",
};

export const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-fuchsia-500/20 text-fuchsia-300 border-fuchsia-500/40",
  high: "bg-red-500/20 text-red-400 border-red-500/30",
  medium: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  low: "bg-green-500/20 text-green-400 border-green-500/30",
};

export function severityLabel(severity: string): string {
  if (!severity) return "未知严重性";
  return {
    critical: "致命",
    high: "严重",
    medium: "一般",
    low: "提示",
  }[severity] ?? severity;
}

export function vulnerabilityTypeLabel(vuln: Vulnerability): string {
  return vuln.vuln_type?.trim() || "未知类型";
}

export function vulnerabilityLocation(vuln: Vulnerability, short = false): string {
  const file = vuln.file?.trim();
  const fileLabel = file
    ? (short ? file.split("/").pop() || file : file)
    : "未知文件";
  const lineLabel = vuln.line > 0 ? String(vuln.line) : "未知行号";
  return `${fileLabel}:${lineLabel}`;
}

export function vulnerabilityFunctionLabel(vuln: Vulnerability): string {
  return vuln.function?.trim() || "未知函数";
}

export function auditOrder(vuln: Vulnerability, index: number): number {
  return typeof vuln.audit_index === "number" ? vuln.audit_index : index;
}

export function engineId(vuln: Vulnerability): string {
  return vuln.engine_id
    || (vuln.analysis_source === "threat_audit"
      ? "threat_audit"
      : "static_candidate");
}

export function issueSourceOrder(vuln: Vulnerability): number {
  return engineId(vuln) === "threat_audit" ? 1 : 0;
}

export function engineLabel(vuln: Vulnerability): string {
  return canonicalMiningEngineLabel(engineId(vuln), vuln.engine_label || "");
}

export function versionLabels(vuln: Vulnerability): string[] {
  return [...new Set((vuln.version_labels || []).map((item) => item.trim()).filter(Boolean))];
}

export function displayedVulnerabilityTypeLabel(
  vuln: Vulnerability,
  staticRuleTypeLabels?: ReadonlyMap<string, string>,
): string {
  const rawLabel = vulnerabilityTypeLabel(vuln);
  if (engineId(vuln) !== "static_candidate") return rawLabel;
  return staticRuleTypeLabels?.get(rawLabel.toLowerCase()) || rawLabel;
}

export function isFinalFpProblem(result?: FpReviewResult | null): boolean {
  return isEffectiveFpReviewResult(result) && result.verdict === "tp";
}

export function validationStatusLabel(status: string): string {
  const labels: Record<string, string> = {
    pending: "等待验证",
    queued: "等待验证",
    running: "验证中",
    verified: "已验证",
    success: "已验证",
    failed: "未通过",
    error: "异常",
    timeout: "超时",
    cancelled: "已取消",
    skipped: "跳过",
  };
  return labels[status] ?? status;
}

export function validationBadgeClass(status: string, running: boolean): string {
  if (running || status === "queued" || status === "running") {
    return "border-blue-500/30 bg-blue-500/15 text-blue-300";
  }
  if (["verified", "success"].includes(status)) {
    return "border-emerald-500/30 bg-emerald-500/15 text-emerald-300";
  }
  if (["failed", "error", "timeout", "cancelled"].includes(status)) {
    return "border-red-500/30 bg-red-500/15 text-red-300";
  }
  return "border-slate-600 bg-slate-700/40 text-slate-400";
}

export function validationFilterState(validation?: VulnerabilityValidation): string {
  if (!validation) return "unverified";
  if (validation.running || validation.status === "queued" || validation.status === "running") {
    return "running";
  }
  if (["verified", "success", "failed", "error", "timeout", "cancelled", "skipped"].includes(validation.status)) {
    return "verified";
  }
  return "unverified";
}

export function fpReviewFilterState(result?: FpReviewResult | null): ReportFpReviewState {
  if (!isEffectiveFpReviewResult(result)) return "no_conclusion";
  return result.verdict === "fp" ? "fp" : "tp";
}

export function userFeedbackFilterState(vuln: Vulnerability): UserFeedbackFilterState {
  return vuln.user_verdict ?? "unmarked";
}

export function countedOptions(values: string[], labels: Record<string, string>): FilterOption[] {
  const counts = new Map<string, number>();
  values.forEach((value) => counts.set(value, (counts.get(value) ?? 0) + 1));
  return Object.entries(labels).map(([value, label]) => ({
    value,
    label,
    count: counts.get(value) ?? 0,
  }));
}

export const MATCH_TYPE_LABELS: Record<string, string> = {
  history: "对应历史问题模式",
  validation: "对应其它函数校验",
};

export function valueOptions(values: string[], formatLabel: (value: string) => string = (value) => value): FilterOption[] {
  const counts = new Map<string, number>();
  values.forEach((value) => counts.set(value, (counts.get(value) ?? 0) + 1));
  return Array.from(counts.entries())
    .sort(([a], [b]) => formatLabel(a).localeCompare(formatLabel(b)))
    .map(([value, count]) => ({ value, label: formatLabel(value), count }));
}
