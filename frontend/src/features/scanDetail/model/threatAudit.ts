import type { ThreatAuditTask } from "../../../types/audit";
import type { ScanQueueTask, TaskTone } from "./types";
import type { StaticFilterOption } from "./staticCandidates";
import { valueOptions } from "./staticCandidates";

export function threatAuditStatusOptions(
  tasks: ThreatAuditTask[],
  runtimeByTaskId: Map<string, ScanQueueTask>,
): StaticFilterOption[] {
  const values = tasks.map((task) => {
    return effectiveThreatAuditTaskStatus(task, runtimeByTaskId.get(task.task_id));
  });
  return valueOptions(values, threatAuditStatusLabel);
}

export function effectiveThreatAuditTaskStatus(
  task: ThreatAuditTask,
  runtime: ScanQueueTask | undefined,
): string {
  const persistedStatus = String(task.status || "pending").toLowerCase();
  if (persistedStatus === "superseded") return persistedStatus;
  if (runtime?.status === "running") return "running";
  if (runtime?.status === "queued" || runtime?.status === "planned") return "queued";
  return persistedStatus;
}

export function threatAuditStatusLabel(status: string): string {
  const labels: Record<string, string> = {
    pending: "待执行",
    planned: "计划中",
    queued: "排队中",
    running: "运行中",
    completed: "已完成",
    success: "已完成",
    failed: "失败",
    failure: "失败",
    error: "异常",
    timeout: "超时",
    no_result: "无结果",
    cancelled: "已取消",
    superseded: "已取代",
  };
  return labels[status] ?? status;
}

export function threatAuditStatusTone(status: string): TaskTone {
  if (status === "running") return "cyan";
  if (status === "queued" || status === "planned") return "amber";
  if (status === "completed" || status === "success") return "green";
  if (["failed", "failure", "error", "timeout", "no_result", "cancelled"].includes(status)) return "red";
  return "slate";
}
