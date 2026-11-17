import type {
  AdminUserSummary,
  Department,
  SortDirection,
  UserSortField,
} from "../../types/auth";

export const ALL_DEPARTMENTS_FILTER = "__all__";
export const UNASSIGNED_DEPARTMENT_FILTER = "__unassigned__";

export interface UserFilterSortState {
  departmentFilter: string;
  sortField: UserSortField;
  sortDirection: SortDirection;
}

export interface UserAggregateSummary {
  userCount: number;
  totalScanCount: number;
  totalSuspectedIssueCount: number;
}

export function normalizeAdminUser(raw: Partial<AdminUserSummary> & { user_id: string; username: string; role: "admin" | "user" }): AdminUserSummary {
  return {
    user_id: raw.user_id,
    username: raw.username,
    role: raw.role,
    agent_token: raw.agent_token ?? "",
    created_at: raw.created_at ?? "",
    employee_id: raw.employee_id ?? "",
    department_id: raw.department_id ?? "",
    department_name: raw.department_name ?? "",
    scan_count: Number(raw.scan_count ?? 0),
    suspected_issue_count: Number(raw.suspected_issue_count ?? 0),
  };
}

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function filterAndSortUsers(
  users: readonly AdminUserSummary[],
  state: UserFilterSortState,
): AdminUserSummary[] {
  const { departmentFilter, sortField, sortDirection } = state;
  const filtered = users.filter((item) => {
    if (!departmentFilter || departmentFilter === ALL_DEPARTMENTS_FILTER) {
      return true;
    }
    if (departmentFilter === UNASSIGNED_DEPARTMENT_FILTER) {
      return !item.department_id;
    }
    return item.department_id === departmentFilter;
  });

  const multiplier = sortDirection === "desc" ? -1 : 1;
  return [...filtered].sort((left, right) => {
    if (sortField === "scan_count") {
      const diff = (left.scan_count - right.scan_count) * multiplier;
      if (diff !== 0) return diff;
    } else if (sortField === "suspected_issue_count") {
      const diff = (left.suspected_issue_count - right.suspected_issue_count) * multiplier;
      if (diff !== 0) return diff;
      const scanDiff = (left.scan_count - right.scan_count) * multiplier;
      if (scanDiff !== 0) return scanDiff;
    } else {
      const createdDiff = compareText(left.created_at || "", right.created_at || "") * multiplier;
      if (createdDiff !== 0) return createdDiff;
    }
    const createdFallback = compareText(left.created_at || "", right.created_at || "");
    if (createdFallback !== 0) return createdFallback;
    const nameFallback = compareText(left.username || "", right.username || "");
    if (nameFallback !== 0) return nameFallback;
    return compareText(left.user_id || "", right.user_id || "");
  });
}

export function summarizeUsers(users: readonly AdminUserSummary[]): UserAggregateSummary {
  let totalScanCount = 0;
  let totalSuspectedIssueCount = 0;
  for (const item of users) {
    totalScanCount += Number(item.scan_count || 0);
    totalSuspectedIssueCount += Number(item.suspected_issue_count || 0);
  }
  return {
    userCount: users.length,
    totalScanCount,
    totalSuspectedIssueCount,
  };
}

export function nextSortState(
  currentField: UserSortField,
  currentDirection: SortDirection,
  clickedField: "scan_count" | "suspected_issue_count",
): { sortField: UserSortField; sortDirection: SortDirection } {
  if (currentField !== clickedField) {
    return { sortField: clickedField, sortDirection: "desc" };
  }
  if (currentDirection === "desc") {
    return { sortField: clickedField, sortDirection: "asc" };
  }
  return { sortField: "created_at", sortDirection: "asc" };
}

export function reconcileDepartmentUserCounts(
  departments: readonly Department[],
  users: readonly AdminUserSummary[],
): Department[] {
  const counts = new Map<string, number>();
  for (const item of users) {
    if (item.department_id) {
      counts.set(item.department_id, (counts.get(item.department_id) ?? 0) + 1);
    }
  }
  return departments.map((dept) => ({
    ...dept,
    user_count: counts.get(dept.department_id) ?? 0,
  }));
}

export function applyDepartmentRenamed(
  departments: readonly Department[],
  users: readonly AdminUserSummary[],
  updated: Department,
): { departments: Department[]; users: AdminUserSummary[] } {
  const nextUsers = users.map((item) =>
    item.department_id === updated.department_id
      ? { ...item, department_name: updated.name }
      : item,
  );
  const nextDepartments = reconcileDepartmentUserCounts(
    departments.map((dept) =>
      dept.department_id === updated.department_id ? { ...dept, ...updated } : dept,
    ),
    nextUsers,
  );
  return { departments: nextDepartments, users: nextUsers };
}

export function applyDepartmentDeleted(
  departments: readonly Department[],
  users: readonly AdminUserSummary[],
  departmentId: string,
): { departments: Department[]; users: AdminUserSummary[] } {
  const nextUsers = users.map((item) =>
    item.department_id === departmentId
      ? { ...item, department_id: "", department_name: "" }
      : item,
  );
  const nextDepartments = reconcileDepartmentUserCounts(
    departments.filter((dept) => dept.department_id !== departmentId),
    nextUsers,
  );
  return { departments: nextDepartments, users: nextUsers };
}

