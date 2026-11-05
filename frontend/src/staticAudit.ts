import type { Candidate, MiningEngineRunStatus, ScanCandidate, ScanStatus, StaticAnalysisError, Vulnerability } from "./types";

export function staticAnalysisFailures(scan: Pick<ScanStatus, "mining_engine_runs">): Array<StaticAnalysisError & { engine_id: string }> {
  return (scan.mining_engine_runs ?? []).flatMap((run) => (
    Array.isArray(run.static_analysis_errors)
      ? run.static_analysis_errors.map((failure) => ({ ...failure, engine_id: run.engine_id }))
      : []
  ));
}

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

export function staticAuditExecutionEnded(
  scan: Pick<ScanStatus, "status" | "mining_engine_runs">,
  run = scan.mining_engine_runs?.find((item) => item.engine_id === "static_candidate"),
): boolean {
  return ["complete", "error", "cancelled"].includes(scan.status)
    || ["success", "error", "cancelled", "skipped"].includes(run?.status ?? "");
}

export function staticAuditDisplayStatus(status: StaticAuditStatus, ended: boolean): StaticAuditStatus {
  return ended && ["pending", "queued", "running"].includes(status) ? "pending" : status;
}

export function staticAuditStatusLabel(status: StaticAuditStatus, ended = false): string {
  return ended && status === "pending" ? "待续扫" : STATIC_AUDIT_STATUS_LABELS[status];
}

export function staticCandidateAuditCounts(scan: ScanStatus): Record<StaticAuditStatus, number> {
  const counts = { success: 0, failed: 0, pending: 0, queued: 0, running: 0 };
  for (const candidate of scan.candidates ?? []) {
    if (String(candidate.vuln_type || "").toLowerCase() === "threat_audit"
      || String(candidate.metadata?.source || "").toLowerCase() === "threat_analysis") continue;
    counts[candidate.audit_state ?? staticAuditStatus(candidate.audit_result ?? undefined)] += 1;
  }
  // Detail pages may contain only a small subset of the scan's candidates.
  for (const status of STATIC_AUDIT_STATUS_ORDER) {
    const aggregate = scan.detail_counts?.[`candidate_audit_${status}`];
    if (aggregate !== undefined) counts[status] = aggregate;
  }
  return counts;
}

export function staticCandidateAuditFlowStatus(
  scan: ScanStatus,
  run: MiningEngineRunStatus | null,
): "pending" | "queued" | "running" | "done" | "warning" | "incomplete" | "error" | "cancelled" | "skipped" | "unknown" {
  const counts = staticCandidateAuditCounts(scan);
  const total = Math.max(scan.detail_counts?.candidates ?? 0, scan.total_candidates);
  const unfinished = Math.max(
    counts.pending + counts.queued + counts.running,
    total - scan.processed_candidates,
  );
  if (staticAuditExecutionEnded(scan, run ?? undefined) && unfinished > 0) return "incomplete";
  if (run?.status === "error") return "error";
  if (run?.status === "cancelled") return "cancelled";
  if (run?.status === "skipped") return "skipped";
  if (counts.running > 0) return "running";
  if (counts.queued > 0) return "queued";
  if (unfinished > 0) {
    return !scan.static_analysis_done && run?.status === "running" ? "running" : "pending";
  }
  if (total > 0 && scan.static_analysis_done) {
    return counts.failed > 0 || run?.static_analysis_errors?.length ? "warning" : "done";
  }
  if (run?.status === "success") return run.static_analysis_errors?.length ? "warning" : "done";
  if (scan.status === "cancelled") return "cancelled";
  if (run?.status === "running" || scan.status === "auditing") return "running";
  if (scan.status === "complete" && scan.static_analysis_done) return "done";
  return "pending";
}

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
