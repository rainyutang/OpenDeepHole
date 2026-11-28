import type {
  RedlineAuditTask,
  RedlineItem,
  RedlineItemInput,
  ScanRedlineItem,
} from "../../types/redlines";

export type RedlineItemAuditState =
  | "pending"
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export interface RedlineItemProgress {
  itemId: string;
  code: string;
  securityAttribute: string;
  attributeDescription: string;
  requirement: string;
  category: string;
  guidance: string;
  remark: string;
  state: RedlineItemAuditState;
  rounds: RedlineAuditTask[];
  latestRound: RedlineAuditTask | null;
  completedRounds: number;
  maxIterations: number;
  findingCount: number;
  findingVulnIndexes: number[];
  stopReason: string;
  failureReason: string;
}

export function emptyRedlineInput(): RedlineItemInput {
  return {
    code: "",
    security_attribute: "",
    attribute_description: "",
    requirement: "",
    category: "",
    guidance: "",
    remark: "",
    enabled: true,
  };
}

export function redlineInputFromItem(item: RedlineItem): RedlineItemInput {
  return {
    code: item.code,
    security_attribute: item.security_attribute,
    attribute_description: item.attribute_description,
    requirement: item.requirement,
    category: item.category,
    guidance: item.guidance,
    remark: item.remark,
    enabled: item.enabled,
  };
}

export function validateRedlineInput(input: RedlineItemInput): string | null {
  if (!input.code.trim()) return "请填写红线编号";
  if (!input.security_attribute.trim()) return "请填写安全属性";
  if (!input.attribute_description.trim()) return "请填写属性描述";
  if (!input.requirement.trim()) return "请填写红线要求";
  return null;
}

export function extractRedlineCategories(items: readonly RedlineItem[]): string[] {
  const set = new Set<string>();
  for (const item of items) {
    const category = item.category.trim();
    if (category) set.add(category);
  }
  return [...set].sort((a, b) => a.localeCompare(b, "zh-CN"));
}

export function filterRedlineItems(
  items: readonly RedlineItem[],
  {
    keyword,
    category,
    enabledFilter,
  }: {
    keyword: string;
    category: string;
    enabledFilter: "all" | "enabled" | "disabled";
  },
): RedlineItem[] {
  const needle = keyword.trim().toLowerCase();
  return items.filter((item) => {
    if (enabledFilter === "enabled" && !item.enabled) return false;
    if (enabledFilter === "disabled" && item.enabled) return false;
    if (category && item.category.trim() !== category) return false;
    if (!needle) return true;
    return [
      item.code,
      item.security_attribute,
      item.attribute_description,
      item.requirement,
      item.category,
      item.guidance,
      item.remark,
    ].some((field) => field.toLowerCase().includes(needle));
  });
}

function deriveRedlineItemState(rounds: readonly RedlineAuditTask[]): RedlineItemAuditState {
  const active = rounds.filter((task) => String(task.status || "").trim().toLowerCase() !== "superseded");
  if (active.length === 0) return "pending";
  const latest = active[active.length - 1];
  const status = String(latest.status || "pending").trim().toLowerCase();
  if (["running", "analyzing", "auditing"].includes(status)) return "running";
  if (status === "queued") return "queued";
  if (status === "pending") return "pending";
  if (["failed", "failure", "error", "timeout", "no_result"].includes(status)) return "failed";
  if (status === "cancelled") return "cancelled";
  if (status === "completed") {
    const maxIter = Math.max(1, Number(latest.max_iterations || 5));
    if (latest.found === false || Number(latest.iteration || 1) >= maxIter || Boolean(latest.stop_reason?.trim())) {
      return "completed";
    }
    return "running";
  }
  return "pending";
}

export function buildRedlineItemProgressList(
  snapshotItems: readonly ScanRedlineItem[],
  tasks: readonly RedlineAuditTask[],
): RedlineItemProgress[] {
  const tasksByItem = new Map<string, RedlineAuditTask[]>();
  for (const task of tasks) {
    const key = (task.redline_item_id || "").trim() || task.task_id;
    const bucket = tasksByItem.get(key) ?? [];
    bucket.push(task);
    tasksByItem.set(key, bucket);
  }
  for (const bucket of tasksByItem.values()) {
    bucket.sort((a, b) => (a.iteration - b.iteration) || a.task_id.localeCompare(b.task_id));
  }

  const orderedIds: string[] = [];
  const metaById = new Map<string, ScanRedlineItem>();
  for (const item of snapshotItems) {
    const id = (item.item_id || "").trim() || item.code;
    if (!id || metaById.has(id)) continue;
    orderedIds.push(id);
    metaById.set(id, item);
  }
  for (const [id, bucket] of tasksByItem.entries()) {
    if (metaById.has(id)) continue;
    const sample = bucket[0];
    orderedIds.push(id);
    metaById.set(id, {
      item_id: id,
      code: sample.item_code,
      security_attribute: sample.security_attribute,
      attribute_description: sample.attribute_description,
      requirement: sample.requirement,
      category: sample.category,
      guidance: "",
      remark: "",
    });
  }

  return orderedIds.map((itemId) => {
    const meta = metaById.get(itemId)!;
    const rounds = (tasksByItem.get(itemId) ?? []).filter(
      (task) => String(task.status || "").trim().toLowerCase() !== "superseded",
    );
    const latestRound = rounds.length > 0 ? rounds[rounds.length - 1] : null;
    const completedRounds = rounds.filter((task) => task.status === "completed").length;
    const maxIterations = Math.max(1, latestRound?.max_iterations ?? 5);
    const vulnIndexes = new Set<number>();
    let foundTrueCount = 0;
    for (const task of rounds) {
      for (const idx of task.result_vuln_indexes ?? []) {
        if (typeof idx === "number" && Number.isInteger(idx) && idx >= 0) vulnIndexes.add(idx);
      }
      if (task.found === true) foundTrueCount += 1;
    }
    const sortedIndexes = [...vulnIndexes].sort((a, b) => a - b);
    return {
      itemId,
      code: meta.code || latestRound?.item_code || itemId,
      securityAttribute: meta.security_attribute || latestRound?.security_attribute || "",
      attributeDescription: meta.attribute_description || latestRound?.attribute_description || "",
      requirement: meta.requirement || latestRound?.requirement || "",
      category: meta.category || latestRound?.category || "",
      guidance: meta.guidance || "",
      remark: meta.remark || "",
      state: deriveRedlineItemState(rounds),
      rounds,
      latestRound,
      completedRounds,
      maxIterations,
      findingCount: Math.max(sortedIndexes.length, foundTrueCount),
      findingVulnIndexes: sortedIndexes,
      stopReason: latestRound?.stop_reason || "",
      failureReason: latestRound?.failure_reason || "",
    };
  });
}

export function redlineItemStatusLabel(state: RedlineItemAuditState): string {
  switch (state) {
    case "running": return "排查中";
    case "queued": return "排队中";
    case "completed": return "已完成";
    case "failed": return "失败";
    case "cancelled": return "已取消";
    default: return "待排查";
  }
}

export function redlineRoundStatusLabel(status: string): string {
  const normalized = String(status || "pending").trim().toLowerCase();
  if (normalized === "running" || normalized === "analyzing" || normalized === "auditing") return "执行中";
  if (normalized === "queued") return "排队中";
  if (normalized === "completed") return "已完成";
  if (normalized === "timeout") return "超时";
  if (normalized === "no_result") return "无输出";
  if (normalized === "failed" || normalized === "failure" || normalized === "error") return "失败";
  if (normalized === "cancelled") return "已取消";
  if (normalized === "superseded") return "已跳过";
  return "待执行";
}

export function redlineStopReasonLabel(stopReason: string): string {
  if (stopReason === "no_finding") return "本轮未发现新问题，已提前收敛";
  if (stopReason === "max_iterations_reached") return "已达最大 5 轮审计上限";
  return stopReason;
}

export function summarizeRedlineProgress(items: readonly RedlineItemProgress[]) {
  let completed = 0;
  let running = 0;
  let queued = 0;
  let pending = 0;
  let failed = 0;
  let cancelled = 0;
  let findings = 0;
  for (const item of items) {
    findings += item.findingCount;
    if (item.state === "completed") completed += 1;
    else if (item.state === "running") running += 1;
    else if (item.state === "queued") queued += 1;
    else if (item.state === "failed") failed += 1;
    else if (item.state === "cancelled") cancelled += 1;
    else pending += 1;
  }
  return { total: items.length, completed, running, queued, pending, failed, cancelled, findings };
}
