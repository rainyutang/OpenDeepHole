import type { OpenCodeCompletedTask, OpenCodeModelTokenUsage, OpenCodePoolModelStats, OpenCodePoolStatus, OpenCodeTokenUsage } from "../types/modelPool";
import { isRecord, text, finiteNumber, recordArray } from './record';

export function normalizeTokenCounters(value: Record<string, unknown>) {
  return {
    input_tokens: finiteNumber(value.input_tokens),
    output_tokens: finiteNumber(value.output_tokens),
    reasoning_tokens: finiteNumber(value.reasoning_tokens),
    cache_read_tokens: finiteNumber(value.cache_read_tokens),
    cache_write_tokens: finiteNumber(value.cache_write_tokens),
    total_tokens: finiteNumber(value.total_tokens),
  };
}

export function normalizeTokenUsage(value: unknown): OpenCodeTokenUsage | null {
  if (!isRecord(value)) return null;
  const byModel = recordArray(value.by_model).map((item): OpenCodeModelTokenUsage => ({
    ...normalizeTokenCounters(item),
    model: text(item.model),
  }));
  return {
    ...normalizeTokenCounters(value),
    complete: value.complete === true,
    by_model: byModel,
    by_category: recordArray(value.by_category).map((item) => ({
      ...normalizeTokenCounters(item),
      category: text(item.category) || "uncategorized",
      label: text(item.label),
      complete: item.complete === true,
    })),
  };
}

export function normalizePoolModel(value: Record<string, unknown>): OpenCodePoolModelStats {
  const windows = recordArray(value.time_windows).map((window) => ({
    weekdays: Array.isArray(window.weekdays)
      ? window.weekdays.filter((item): item is number => typeof item === "number" && Number.isFinite(item))
      : [],
    start: text(window.start),
    end: text(window.end),
  }));
  return {
    ...value,
    id: text(value.id),
    model: text(value.model),
    use_default_model: value.use_default_model === true,
    capability: text(value.capability),
    weight: finiteNumber(value.weight),
    effective_weight: finiteNumber(value.effective_weight),
    health_penalty_level: finiteNumber(value.health_penalty_level),
    last_health_failure_at: text(value.last_health_failure_at),
    last_health_failure_kind: text(value.last_health_failure_kind),
    max_concurrency: finiteNumber(value.max_concurrency),
    enabled: value.enabled === true,
    available: value.available === true,
    time_windows: windows,
    queued: finiteNumber(value.queued),
    running: finiteNumber(value.running),
    total: finiteNumber(value.total),
    success: finiteNumber(value.success),
    failure: finiteNumber(value.failure),
    timeout: finiteNumber(value.timeout),
    cancelled: finiteNumber(value.cancelled),
    avg_duration_seconds: finiteNumber(value.avg_duration_seconds),
    last_status: text(value.last_status),
    last_started_at: text(value.last_started_at),
    last_finished_at: text(value.last_finished_at),
    active_tasks: recordArray(value.active_tasks),
  };
}

export function normalizeOpenCodePool(value: unknown): OpenCodePoolStatus | null {
  if (value == null) return null;
  if (
    !isRecord(value)
    || typeof value.scope_id !== "string"
    || !Array.isArray(value.queued_tasks)
    || !Array.isArray(value.models)
  ) {
    return null;
  }
  return {
    ...value,
    scope_id: text(value.scope_id),
    agent_name: text(value.agent_name) || undefined,
    agent_session_id: text(value.agent_session_id) || undefined,
    execution_revision: finiteNumber(value.execution_revision),
    global_running: finiteNumber(value.global_running),
    global_queued: finiteNumber(value.global_queued),
    total_tasks: finiteNumber(value.total_tasks),
    completed_task_count: finiteNumber(value.completed_task_count),
    planned_tasks: recordArray(value.planned_tasks),
    queued_tasks: recordArray(value.queued_tasks),
    completed_tasks: recordArray(value.completed_tasks),
    token_usage: normalizeTokenUsage(value.token_usage),
    models: recordArray(value.models).map(normalizePoolModel),
    updated_at: text(value.updated_at),
    details_truncated: value.details_truncated === true,
  } as OpenCodePoolStatus;
}

export function sameOpenCodePoolSnapshot(
  left: OpenCodePoolStatus | null | undefined,
  right: OpenCodePoolStatus | null | undefined,
): boolean {
  if (left === right) return true;
  if (!left || !right) return left == null && right == null;
  return left.scope_id === right.scope_id
    && left.execution_revision === right.execution_revision
    && left.agent_session_id === right.agent_session_id
    && left.updated_at === right.updated_at
    && left.global_running === right.global_running
    && left.global_queued === right.global_queued
    && left.completed_task_count === right.completed_task_count
    && left.total_tasks === right.total_tasks;
}

export function poolTimestamp(value: OpenCodePoolStatus): number | null {
  if (!value.updated_at) return null;
  const timestamp = Date.parse(value.updated_at);
  return Number.isFinite(timestamp) ? timestamp : null;
}

export function completedTaskIdentity(
  task: OpenCodeCompletedTask,
  index: number,
): string {
  const record = task as Record<string, unknown>;
  const taskId = text(record.task_id) || text(record.planned_task_id);
  const revision = finiteNumber(record.revision, 1);
  return taskId ? `${taskId}:${revision}` : `anonymous:${index}`;
}

export function mergePoolHistory(
  winner: OpenCodePoolStatus,
  other: OpenCodePoolStatus,
): OpenCodePoolStatus {
  const completed = new Map<string, OpenCodeCompletedTask>();
  (other.completed_tasks ?? []).forEach((task, index) => {
    completed.set(completedTaskIdentity(task, index), task);
  });
  (winner.completed_tasks ?? []).forEach((task, index) => {
    const key = completedTaskIdentity(task, index);
    const previous = completed.get(key);
    completed.set(key, previous ? { ...previous, ...task } : task);
  });
  const completedTasks = [...completed.values()];
  return {
    ...winner,
    completed_tasks: completedTasks,
    completed_task_count: Math.max(
      winner.completed_task_count,
      other.completed_task_count,
      completedTasks.length,
    ),
    total_tasks: Math.max(winner.total_tasks, other.total_tasks),
  };
}

export function selectOpenCodePoolSnapshot(
  current: OpenCodePoolStatus | null | undefined,
  incoming: OpenCodePoolStatus | null | undefined,
  options: { allowClear?: boolean } = {},
): OpenCodePoolStatus | null {
  // Keep GET hydration and SSE updates monotonic for one scan execution.
  if (incoming === undefined) return current ?? null;
  if (incoming === null) return options.allowClear ? null : current ?? null;
  if (!current) return incoming;

  const currentRevision = current.execution_revision ?? 0;
  const incomingRevision = incoming.execution_revision ?? 0;
  if (incomingRevision !== currentRevision) {
    return incomingRevision > currentRevision ? incoming : current;
  }

  const currentTimestamp = poolTimestamp(current);
  const incomingTimestamp = poolTimestamp(incoming);
  let winner = current;
  let other = incoming;
  if (
    (incomingTimestamp !== null && currentTimestamp === null)
    || (
      incomingTimestamp !== null
      && currentTimestamp !== null
      && incomingTimestamp > currentTimestamp
    )
  ) {
    winner = incoming;
    other = current;
  }
  return mergePoolHistory(winner, other);
}
