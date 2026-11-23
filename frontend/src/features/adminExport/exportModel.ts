import type { AdminIssueExportParams } from "../../api/reports";
import type { AdminUserSummary } from "../../types/auth";

export type ExportTimePreset = "all" | "last7d" | "last30d" | "thisMonth";

export interface AdminIssueExportFilter {
  startDate: string;
  endDate: string;
  username: string;
  employeeId: string;
}

export const EMPTY_EXPORT_FILTER: AdminIssueExportFilter = {
  startDate: "",
  endDate: "",
  username: "",
  employeeId: "",
};

export const EXPORT_TIME_PRESETS: ReadonlyArray<{
  id: ExportTimePreset;
  label: string;
}> = [
  { id: "all", label: "全部时间" },
  { id: "last7d", label: "近 7 天" },
  { id: "last30d", label: "近 30 天" },
  { id: "thisMonth", label: "本月" },
];

function pad2(value: number): string {
  return String(value).padStart(2, "0");
}

export function formatLocalDate(date: Date): string {
  return `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())}`;
}

export function resolveTimePresetRange(
  preset: ExportTimePreset,
  now: Date = new Date(),
): Pick<AdminIssueExportFilter, "startDate" | "endDate"> {
  if (preset === "all") {
    return { startDate: "", endDate: "" };
  }
  const end = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const start = new Date(end.getTime());
  if (preset === "last7d") {
    start.setDate(start.getDate() - 6);
  } else if (preset === "last30d") {
    start.setDate(start.getDate() - 29);
  } else if (preset === "thisMonth") {
    start.setDate(1);
  }
  return {
    startDate: formatLocalDate(start),
    endDate: formatLocalDate(end),
  };
}

export function validateExportFilter(filter: AdminIssueExportFilter): string {
  const start = filter.startDate.trim();
  const end = filter.endDate.trim();
  if (start && end && start > end) {
    return "开始日期不能晚于结束日期";
  }
  return "";
}

export function buildAdminExportParams(
  filter: AdminIssueExportFilter,
  options: {
    tzOffsetMinutes?: number;
    shareOrigin?: string;
  } = {},
): AdminIssueExportParams {
  const params: AdminIssueExportParams = {};
  const start = filter.startDate.trim();
  const end = filter.endDate.trim();
  const username = filter.username.trim();
  const employeeId = filter.employeeId.trim();
  const shareOrigin = (options.shareOrigin ?? "").trim();

  if (start) params.start_time = start;
  if (end) params.end_time = end;
  if (username) params.username = username;
  if (employeeId) params.employee_id = employeeId;
  if (
    typeof options.tzOffsetMinutes === "number" &&
    Number.isFinite(options.tzOffsetMinutes)
  ) {
    params.tz_offset_minutes = Math.trunc(options.tzOffsetMinutes);
  }
  if (shareOrigin) params.share_origin = shareOrigin;
  return params;
}

export function extractUsernameOptions(
  users: ReadonlyArray<Pick<AdminUserSummary, "username">>,
): string[] {
  const unique = new Set<string>();
  for (const item of users) {
    const value = (item.username || "").trim();
    if (value) unique.add(value);
  }
  return [...unique].sort((a, b) => a.localeCompare(b, "zh-CN"));
}

export function extractEmployeeIdOptions(
  users: ReadonlyArray<Pick<AdminUserSummary, "employee_id">>,
): string[] {
  const unique = new Set<string>();
  for (const item of users) {
    const value = (item.employee_id || "").trim();
    if (value) unique.add(value);
  }
  return [...unique].sort((a, b) => a.localeCompare(b, "zh-CN"));
}

export function activeTimePreset(
  filter: Pick<AdminIssueExportFilter, "startDate" | "endDate">,
  now: Date = new Date(),
): ExportTimePreset | null {
  for (const preset of EXPORT_TIME_PRESETS) {
    const range = resolveTimePresetRange(preset.id, now);
    if (
      filter.startDate.trim() === range.startDate &&
      filter.endDate.trim() === range.endDate
    ) {
      return preset.id;
    }
  }
  return null;
}

export function formatExportSuccessNotice(rowCount: number | null): string {
  if (rowCount === null) return "问题表格已开始下载";
  if (rowCount === 0) return "当前筛选条件下暂无匹配问题，已导出空表";
  return `已成功导出 ${rowCount} 条问题`;
}
