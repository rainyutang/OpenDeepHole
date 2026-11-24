import type { ThreatAuditTask } from "../../../types/audit";
import type { ScanQueueTask, TaskTone } from "./types";
import type { StaticFilterOption } from "./staticCandidates";
import { ALL_STATIC_FILTER, valueOptions } from "./staticCandidates";

export const UNNAMED_THREAT_FILTER_VALUE = "__unnamed__";

export interface ThreatAuditFilters {
  status: string;
  modules: ReadonlyArray<string>;
  types: ReadonlyArray<string>;
}

function compareFilterOptions(left: StaticFilterOption, right: StaticFilterOption): number {
  const leftUnnamed = left.value === UNNAMED_THREAT_FILTER_VALUE;
  const rightUnnamed = right.value === UNNAMED_THREAT_FILTER_VALUE;
  if (leftUnnamed !== rightUnnamed) return leftUnnamed ? 1 : -1;
  return left.label.localeCompare(right.label, "zh-CN", { numeric: true });
}

export function threatAuditModuleKey(task: Pick<ThreatAuditTask, "surface_name">): string {
  const value = String(task.surface_name || "").trim();
  return value || UNNAMED_THREAT_FILTER_VALUE;
}

export function threatAuditModuleLabel(value: string, patternMode: boolean): string {
  if (value === UNNAMED_THREAT_FILTER_VALUE) {
    return patternMode ? "未命名模块" : "未命名叶子节点";
  }
  return value;
}

export function threatAuditModuleOptions(
  tasks: ThreatAuditTask[],
  patternMode: boolean,
): StaticFilterOption[] {
  const counts = new Map<string, number>();
  for (const task of tasks) {
    const key = threatAuditModuleKey(task);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([value, count]) => ({
      value,
      label: threatAuditModuleLabel(value, patternMode),
      count,
    }))
    .sort(compareFilterOptions);
}

export function threatAuditTypeDisplay(
  task: Pick<ThreatAuditTask, "method_node_id" | "method_name">,
): { value: string; label: string } {
  const code = String(task.method_node_id || "").trim();
  const name = String(task.method_name || "").trim();
  if (!code && !name) {
    return { value: UNNAMED_THREAT_FILTER_VALUE, label: "未命名攻击模式" };
  }
  const label = !code
    ? name
    : !name || code === name
      ? code
      : name.startsWith(`${code} `)
        ? name
        : `${code} ${name}`;
  return { value: label, label };
}

export function threatAuditTypeKey(
  task: Pick<ThreatAuditTask, "method_node_id" | "method_name">,
): string {
  return threatAuditTypeDisplay(task).value;
}

export function threatAuditTypeOptions(tasks: ThreatAuditTask[]): StaticFilterOption[] {
  const counts = new Map<string, { label: string; count: number }>();
  for (const task of tasks) {
    const { value, label } = threatAuditTypeDisplay(task);
    const existing = counts.get(value);
    if (existing) {
      existing.count += 1;
    } else {
      counts.set(value, { label, count: 1 });
    }
  }
  return Array.from(counts.entries())
    .map(([value, entry]) => ({ value, label: entry.label, count: entry.count }))
    .sort(compareFilterOptions);
}

export function filterThreatAuditTasks(
  tasks: ThreatAuditTask[],
  runtimeByTaskId: Map<string, ScanQueueTask>,
  filters: ThreatAuditFilters,
): ThreatAuditTask[] {
  const moduleSet = filters.modules.length > 0 ? new Set(filters.modules) : null;
  const typeSet = filters.types.length > 0 ? new Set(filters.types) : null;
  return tasks.filter((task) => {
    if (
      filters.status !== ALL_STATIC_FILTER
      && effectiveThreatAuditTaskStatus(task, runtimeByTaskId.get(task.task_id)) !== filters.status
    ) {
      return false;
    }
    if (moduleSet && !moduleSet.has(threatAuditModuleKey(task))) {
      return false;
    }
    if (typeSet && !typeSet.has(threatAuditTypeKey(task))) {
      return false;
    }
    return true;
  });
}

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
