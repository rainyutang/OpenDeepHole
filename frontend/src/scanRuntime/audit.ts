import type { FpReviewJob, FpReviewResult } from "../types/fpReview";
import type { ThreatAuditTask, ThreatPatternAuditTask } from "../types/audit";
import { isRecord, text, finiteNumber, recordArray, stringRecord } from './record';

export function normalizePatternTask(value: unknown): ThreatPatternAuditTask {
  const raw = isRecord(value) ? value : {};
  return {
    ...raw, task_id: text(raw.task_id), status: text(raw.status),
    engine_id: text(raw.engine_id) || "threat_pattern_audit",
    iteration: typeof raw.iteration === "number" && Number.isInteger(raw.iteration) ? Math.max(1, Math.min(3, raw.iteration)) : 1,
    parent_task_id: text(raw.parent_task_id),
    has_more_findings: typeof raw.has_more_findings === "boolean" ? raw.has_more_findings : null,
    module_name: text(raw.module_name), pattern_id: text(raw.pattern_id), pattern_name: text(raw.pattern_name)
  };
}

export function mergePatternTasks(previous: ThreatPatternAuditTask[], incoming: ThreatPatternAuditTask[]): ThreatPatternAuditTask[] {
  const tasks = new Map(previous.map((task) => [task.task_id, task]));
  for (const task of incoming) {
    const current = tasks.get(task.task_id);
    if (!current?.updated_at || !task.updated_at || Date.parse(task.updated_at) >= Date.parse(current.updated_at)) {
      tasks.set(task.task_id, task);
    }
  }
  return [...tasks.values()].sort((a, b) => (a.created_at || "").localeCompare(b.created_at || "") || a.task_id.localeCompare(b.task_id));
}

export function normalizeThreatTask(value: unknown): ThreatAuditTask {
  const raw = isRecord(value) ? value : {};
  return {
    ...raw,
    task_id: text(raw.task_id),
    status: text(raw.status),
    code_path: text(raw.code_path),
  } as ThreatAuditTask;
}

export function normalizeFpReviewJob(value: unknown): FpReviewJob | null {
  if (!isRecord(value) || typeof value.review_id !== "string" || typeof value.scan_id !== "string") {
    return null;
  }
  const results = recordArray(value.results).map((item): FpReviewResult => ({
    ...item,
    vuln_index: finiteNumber(item.vuln_index),
    verdict: text(item.verdict, "uncertain") as FpReviewResult["verdict"],
    severity: text(item.severity, "low") as FpReviewResult["severity"],
    reason: text(item.reason),
    vulnerability_report: text(item.vulnerability_report),
    stage_outputs: stringRecord(item.stage_outputs),
    stage_output_sources: isRecord(item.stage_output_sources)
      ? item.stage_output_sources as FpReviewResult["stage_output_sources"]
      : undefined,
    created_at: text(item.created_at),
  }));
  return {
    ...value,
    review_id: value.review_id,
    scan_id: value.scan_id,
    method: text(value.method, "adversarial") as FpReviewJob["method"],
    status: text(value.status, "pending") as FpReviewJob["status"],
    created_at: text(value.created_at),
    total: finiteNumber(value.total),
    processed: finiteNumber(value.processed),
    current_vuln_index: value.current_vuln_index == null
      ? null
      : finiteNumber(value.current_vuln_index),
    current_vuln_indices: Array.isArray(value.current_vuln_indices)
      ? value.current_vuln_indices.filter((item): item is number => typeof item === "number" && Number.isFinite(item))
      : [],
    results,
    error_message: value.error_message == null ? null : text(value.error_message),
  } as FpReviewJob;
}
