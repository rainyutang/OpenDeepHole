import { compareTaskHistory, taskHistorySortTime } from "../../../taskOrder";
import type { OpenCodePoolStatus } from "../../../types/modelPool";
import { scanQueueTaskTypeLabel } from "../../modelPool/presentation";
import type { ScanQueueSessionEvent, ScanQueueTask, ScanQueueTaskStatus, TaskTone } from "./types";

export function collectScanQueueTasks(pool: OpenCodePoolStatus | null): ScanQueueTask[] {
  if (!pool) return [];
  const out: ScanQueueTask[] = [];
  for (const [index, task] of (pool.planned_tasks ?? []).entries()) {
    out.push({
      id: String(task.planned_task_id || `planned-${index}`),
      status: "planned",
      modelId: "",
      scopeId: String(task.scope_id || pool.scope_id || ""),
      task,
      timestamp: String(task.planned_at || ""),
    });
  }
  for (const [index, task] of (pool.queued_tasks ?? []).entries()) {
    out.push({
      id: String(task.task_id || task.request_id || `queued-${index}`),
      status: "queued",
      modelId: "",
      scopeId: String(task.scope_id || pool.scope_id || ""),
      task,
      timestamp: String(task.queued_at || ""),
    });
  }
  for (const model of pool.models ?? []) {
    for (const [index, task] of (model.active_tasks ?? []).entries()) {
      out.push({
        id: String(task.task_id || `${model.id}-running-${index}`),
        status: "running",
        modelId: model.id,
        scopeId: String(task.scope_id || pool.scope_id || ""),
        task,
        timestamp: String(task.started_at || ""),
      });
    }
  }
  for (const [index, task] of (pool.completed_tasks ?? []).entries()) {
    const outcome = normalizeCompletedTaskOutcome(task.outcome);
    out.push({
      id: String(task.task_id || `completed-${index}`),
      status: outcome,
      modelId: String(task.model_id || task.model || ""),
      scopeId: String(task.scope_id || pool.scope_id || ""),
      task,
      timestamp: taskHistorySortTime(task),
    });
  }
  return out.sort((a, b) => {
    const rank = scanQueueStatusRank(a.status) - scanQueueStatusRank(b.status);
    if (rank !== 0) return rank;
    if (scanQueueStatusRank(a.status) >= 3) return compareTaskHistory(a.task, b.task);
    return compareScanQueueTime(a.timestamp, b.timestamp);
  });
}

function normalizeCompletedTaskOutcome(value: unknown): ScanQueueTaskStatus {
  const outcome = String(value || "unknown");
  if (["success", "failure", "timeout", "cancelled"].includes(outcome)) {
    return outcome as ScanQueueTaskStatus;
  }
  return "unknown";
}

export function scanQueueTaskKey(task: ScanQueueTask): string {
  return `${task.status}-${task.id}`;
}

function scanQueueStatusRank(status: ScanQueueTaskStatus): number {
  if (status === "running") return 0;
  if (status === "queued") return 1;
  if (status === "planned") return 2;
  return 3;
}

function compareScanQueueTime(a: string, b: string): number {
  const at = Date.parse(a);
  const bt = Date.parse(b);
  if (Number.isNaN(at) && Number.isNaN(bt)) return 0;
  if (Number.isNaN(at)) return 1;
  if (Number.isNaN(bt)) return -1;
  return at - bt;
}

export function scanQueueTaskTitle(task: Record<string, unknown>): string {
  const type = scanQueueTaskTypeLabel(task);
  const stage = task.stage ? `/${String(task.stage)}` : "";
  const checker = task.checker ? String(task.checker) : "";
  const vulnType = task.vuln_type ? String(task.vuln_type) : "";
  const revision = Number(task.revision || 1) > 1 ? `r${String(task.revision)}` : "";
  return [revision, type + stage, checker || vulnType].filter(Boolean).join(" · ");
}

export function scanQueueTaskPrompt(task: Record<string, unknown>): string {
  return typeof task.prompt === "string" ? task.prompt : "";
}

export function scanQueueTaskSessionId(task: Record<string, unknown>): string {
  if (typeof task.serve_session_id === "string") return task.serve_session_id.trim();
  if (task.serve_session_id == null) return "";
  return String(task.serve_session_id).trim();
}

export function scanQueueTaskSessionEvents(
  task: Record<string, unknown>,
  taskStatus: ScanQueueTaskStatus,
  fallbackModelId: string,
  fallbackTimestamp: string,
): ScanQueueSessionEvent[] {
  const rawEvents = Array.isArray(task.session_events) ? task.session_events : [];
  const events = rawEvents.flatMap((value, index): ScanQueueSessionEvent[] => {
    if (typeof value !== "object" || value == null || Array.isArray(value)) return [];
    const event = value as Record<string, unknown>;
    const phaseValue = String(event.phase || "business");
    const phase = ["business", "json_format", "json_retry", "validation_retry"].includes(phaseValue)
      ? phaseValue as ScanQueueSessionEvent["phase"]
      : "business";
    const outcomeValue = String(event.outcome || "unknown");
    const outcome = ["success", "failure", "timeout", "cancelled", "invalid_output", "running"].includes(outcomeValue)
      ? outcomeValue as ScanQueueSessionEvent["outcome"]
      : "unknown";
    const duration = Number(event.duration_seconds);
    return [{
      sequence: Number.isFinite(Number(event.sequence)) ? Number(event.sequence) : index + 1,
      phase,
      sessionId: String(event.session_id || "").trim(),
      sessionAttempt: Math.max(1, Number(event.session_attempt) || 1),
      retryOrdinal: Math.max(0, Number(event.retry_ordinal) || 0),
      retryTotal: Math.max(0, Number(event.retry_total) || 0),
      outcome,
      modelId: String(event.model_id || "").trim(),
      model: String(event.model || "").trim(),
      failureKind: String(event.failure_kind || "").trim(),
      failureReason: String(event.failure_reason || "").trim(),
      startedAt: String(event.started_at || "").trim(),
      finishedAt: String(event.finished_at || "").trim(),
      durationSeconds: Number.isFinite(duration) && duration >= 0 ? duration : null,
    }];
  }).sort((a, b) => a.sequence - b.sequence);

  const sessionId = scanQueueTaskSessionId(task);
  if (
    taskStatus === "running"
    && sessionId
    && !events.some((event) => event.sessionId === sessionId && event.outcome === "running")
  ) {
    events.push({
      sequence: events.length + 1,
      phase: "business",
      sessionId,
      sessionAttempt: Math.max(1, Number(task.session_attempt) || 1),
      retryOrdinal: 0,
      retryTotal: 0,
      outcome: "running",
      modelId: fallbackModelId,
      model: String(task.model || "").trim(),
      failureKind: "",
      failureReason: "",
      startedAt: String(task.started_at || fallbackTimestamp || ""),
      finishedAt: "",
      durationSeconds: null,
    });
  }
  if (events.length === 0 && sessionId) {
    const duration = Number(task.duration_seconds);
    events.push({
      sequence: 1,
      phase: "business",
      sessionId,
      sessionAttempt: Math.max(1, Number(task.session_attempt) || 1),
      retryOrdinal: 0,
      retryTotal: 0,
      outcome: taskStatus,
      modelId: fallbackModelId,
      model: String(task.model || "").trim(),
      failureKind: String(task.failure_kind || "").trim(),
      failureReason: String(task.failure_reason || "").trim(),
      startedAt: String(task.started_at || fallbackTimestamp || ""),
      finishedAt: String(task.finished_at || ""),
      durationSeconds: Number.isFinite(duration) && duration >= 0 ? duration : null,
    });
  }
  return events;
}

export function scanQueueSessionEventLabel(event: ScanQueueSessionEvent): string {
  if (event.phase === "json_format") return "JSON 格式修复 Session";
  if (event.phase === "validation_retry") {
    const total = event.retryTotal > 0 ? `/${event.retryTotal}` : "";
    return `同 Session 校验重试 ${event.retryOrdinal || 1}${total}`;
  }
  if (event.phase === "json_retry") {
    const total = event.retryTotal > 0 ? `/${event.retryTotal}` : "";
    return `同 Session JSON 重试 ${event.retryOrdinal || 1}${total}`;
  }
  return event.sessionAttempt > 1
    ? `Fresh Session 重试 #${event.sessionAttempt}`
    : "业务 Session #1";
}

export function scanQueueSessionOutcomeLabel(outcome: ScanQueueSessionEvent["outcome"]): string {
  if (outcome === "invalid_output") return "输出不合规";
  return scanQueueStatusLabel(outcome);
}

export function scanQueueSessionOutcomeTone(outcome: ScanQueueSessionEvent["outcome"]): TaskTone {
  if (outcome === "invalid_output") return "amber";
  return scanQueueStatusTone(outcome);
}

export function scanQueueFailureKindLabel(kind: string): string {
  if (kind === "empty_output") return "空输出";
  if (kind === "no_json") return "未找到 JSON";
  if (kind === "invalid_json") return "JSON 语法错误";
  if (kind === "schema_mismatch") return "Schema 不匹配";
  if (kind === "source_unrelated") return "无法无损格式化";
  if (kind === "timeout") return "执行超时";
  if (kind === "quota") return "Provider 配额限制";
  if (kind === "no_available_model") return "没有可用模型";
  if (kind === "quality_error") return "任务质量校验失败";
  if (kind === "post_session_validation_failed") return "产物校验失败";
  if (kind === "provider_error") return "Provider 请求失败";
  if (kind === "model_not_found") return "配置的模型不存在";
  if (kind === "cancelled") return "任务已停止";
  return "执行失败";
}

export function scanQueueTaskFailureReason(
  status: ScanQueueTaskStatus,
  failureKind: string,
  failureReason: string,
): string {
  if (!["failure", "timeout", "unknown"].includes(status)) return "";
  if (failureReason) return failureReason;
  if (failureKind) return scanQueueFailureKindLabel(failureKind);
  if (status === "timeout") return "任务在重试预算耗尽后仍然超时。";
  return "任务执行失败，但该历史记录未保存具体原因。";
}

export function scanQueueTaskPromptLength(task: Record<string, unknown>, prompt: string): number {
  if (typeof task.prompt_length === "number" && Number.isFinite(task.prompt_length)) {
    return task.prompt_length;
  }
  const parsed = Number(task.prompt_length);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : prompt.length;
}

export function scanQueueStatusLabel(status: ScanQueueTaskStatus): string {
  if (status === "running") return "运行中";
  if (status === "queued") return "排队中";
  if (status === "planned") return "计划中";
  if (status === "success") return "成功";
  if (status === "failure") return "失败";
  if (status === "timeout") return "超时";
  if (status === "cancelled") return "已停止";
  return "未知";
}

export function scanQueueStatusTone(status: ScanQueueTaskStatus): TaskTone {
  if (status === "running") return "cyan";
  if (status === "queued") return "amber";
  if (status === "planned") return "slate";
  if (status === "success") return "green";
  if (status === "cancelled" || status === "timeout") return "amber";
  return "red";
}
