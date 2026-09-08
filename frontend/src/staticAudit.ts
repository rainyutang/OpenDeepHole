import type { Candidate, ScanCandidate, Vulnerability } from "./types";

export function staticCandidateRelatedVariable(candidate: Candidate): string {
  const metadata = candidate.metadata;
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return "未指定";
  // Keep the same precedence as candidate_audit.runner._related_variable().
  const subject = String(metadata.subject || "").trim();
  if (subject) return subject;
  const variables = [metadata.focus_variable, metadata.target_variable]
    .map((value) => String(value || "").trim()).filter(Boolean);
  return [...new Set(variables)].join("、") || "未指定";
}

export function staticCandidateTaskName(scanId: string, candidate: ScanCandidate): string {
  const prefix = candidate.function === "__project__" ? "project-audit" : "candidate-audit";
  return `${prefix}-${scanId}-${candidate.idx}`;
}

export const STATIC_AUDIT_STATUS_ORDER = [
  "success",
  "failed",
  "pending",
  "queued",
  "running",
] as const;

export type StaticAuditStatus = (typeof STATIC_AUDIT_STATUS_ORDER)[number];

export const STATIC_AUDIT_STATUS_LABELS: Record<StaticAuditStatus, string> = {
  success: "审计成功",
  failed: "审计失败",
  pending: "待审计",
  queued: "排队中",
  running: "审计中",
};

const FAILED_AI_VERDICTS = new Set(["failed", "timeout", "no_result"]);
export const SAME_PATTERN_AUDIT_CONCLUSION =
  "候选点去重：同模式代表点已被 AI 审计为非问题，本候选未再次调用模型。";

type StaticAuditVulnerability = Pick<
  Vulnerability,
  | "ai_verdict"
  | "confirmed"
  | "severity"
  | "description"
  | "failure_reason"
  | "ai_analysis"
>;

function nonemptyText(...values: Array<string | null | undefined>): string {
  for (const value of values) {
    const normalized = String(value || "").trim();
    if (normalized) return normalized;
  }
  return "";
}

export function staticAuditStatus(
  vulnerability?: StaticAuditVulnerability,
  running = false,
): StaticAuditStatus {
  if (running) return "running";
  if (!vulnerability) return "pending";

  const verdict = String(vulnerability.ai_verdict || "").trim().toLowerCase();
  if (FAILED_AI_VERDICTS.has(verdict)) return "failed";

  // Compatibility for historical failure records written before ai_verdict
  // was persisted. Successful non-problem conclusions used low severity.
  if (
    !verdict
    && !vulnerability.confirmed
    && String(vulnerability.severity || "").trim().toLowerCase() === "unknown"
  ) {
    return "failed";
  }
  return "success";
}

export function staticAuditConclusion(vulnerability: StaticAuditVulnerability): string {
  const status = staticAuditStatus(vulnerability);
  if (status === "failed") {
    return nonemptyText(vulnerability.failure_reason, vulnerability.ai_analysis)
      || "审计失败，但未记录错误信息";
  }

  if (vulnerability.ai_verdict === "filtered_same_pattern") {
    return SAME_PATTERN_AUDIT_CONCLUSION;
  }

  return nonemptyText(vulnerability.description, vulnerability.ai_analysis)
    || "审计成功，但未记录审计结论";
}
