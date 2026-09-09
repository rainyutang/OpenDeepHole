// Match the execution-time key returned by /tasks, including microseconds.
// Date.parse alone discards those digits and can reverse ties within a ms.
function normalizedTaskTime(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const parts = /^(\d{4})-(\d{2})-(\d{2})[T ]([01]\d|2[0-3]):([0-5]\d):([0-5]\d)(?:\.(\d{1,6}))?(Z|[+-]\d{2}:\d{2})?$/.exec(value);
  if (!parts) return null;
  const year = Number(parts[1]);
  const month = Number(parts[2]);
  const day = Number(parts[3]);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > days[month - 1]) return null;
  const millis = Date.parse(value.replace(" ", "T") + (parts[8] ? "" : "Z"));
  if (!Number.isFinite(millis)) return null;
  return new Date(millis).toISOString().slice(0, 19) + `.${(parts[7] || "").padEnd(6, "0")}Z`;
}

export function taskHistorySortTime(task: Record<string, unknown>): string {
  return normalizedTaskTime(task.sort_time) ?? normalizedTaskTime(task.finished_at)
    ?? normalizedTaskTime(task.started_at) ?? "-";
}

export function compareTaskHistory(left: Record<string, unknown>, right: Record<string, unknown>): number {
  const leftTime = taskHistorySortTime(left);
  const rightTime = taskHistorySortTime(right);
  if (leftTime !== rightTime) return leftTime > rightTime ? -1 : 1;
  const leftId = String(left.task_id || "");
  const rightId = String(right.task_id || "");
  return leftId === rightId ? 0 : leftId > rightId ? -1 : 1;
}

export function shouldMergeTaskHistory(previous: Record<string, unknown> | undefined, incoming: Record<string, unknown>): boolean {
  if (!previous) return true;
  const revision = Number(incoming.revision || 1) - Number(previous.revision || 1);
  return revision > 0 || (revision === 0 && taskHistorySortTime(incoming) >= taskHistorySortTime(previous));
}
