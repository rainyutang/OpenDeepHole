import { useEffect, useMemo, useState } from "react";
import {
  createUser,
  deleteUser,
  listDepartments,
  listUsers,
} from "../api/auth";
import DepartmentPoolModal, {
  type DepartmentPoolMutation,
} from "../features/userManagement/DepartmentPoolModal";
import EditUserProfileModal from "../features/userManagement/EditUserProfileModal";
import {
  ALL_DEPARTMENTS_FILTER,
  UNASSIGNED_DEPARTMENT_FILTER,
  applyDepartmentDeleted,
  applyDepartmentRenamed,
  filterAndSortUsers,
  nextSortState,
  normalizeAdminUser,
  reconcileDepartmentUserCounts,
  summarizeUsers,
} from "../features/userManagement/userManagementModel";
import type {
  AdminUserSummary,
  Department,
  SortDirection,
  User,
  UserSortField,
} from "../types/auth";
import PageHeader from "./PageHeader";
import { ThemeToggle } from "./ThemeToggle";

interface Props {
  onBack: () => void;
  user: User;
}

function SummaryMetricCard({
  label,
  value,
  subtitle,
  highlight = false,
}: {
  label: string;
  value: number;
  subtitle?: string;
  highlight?: boolean;
}) {
  return (
    <div className="rounded-xl border border-slate-700 bg-slate-800/70 px-4 py-3.5">
      <div className="text-xs font-medium text-slate-400">{label}</div>
      <div
        className={`mt-1 text-2xl font-bold tabular-nums ${
          highlight && value > 0 ? "text-amber-300" : "text-white"
        }`}
      >
        {value}
      </div>
      {subtitle && <div className="mt-0.5 truncate text-xs text-slate-500">{subtitle}</div>}
    </div>
  );
}

export default function UserManagement({ onBack, user }: Props) {
  const [users, setUsers] = useState<AdminUserSummary[]>([]);
  const [departments, setDepartments] = useState<Department[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const [showCreate, setShowCreate] = useState(false);
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("user");
  const [newEmployeeId, setNewEmployeeId] = useState("");
  const [newDepartmentId, setNewDepartmentId] = useState("");
  const [createError, setCreateError] = useState("");
  const [createLoading, setCreateLoading] = useState(false);

  const [showDepartmentPool, setShowDepartmentPool] = useState(false);
  const [editTarget, setEditTarget] = useState<AdminUserSummary | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);

  const [departmentFilter, setDepartmentFilter] = useState<string>(ALL_DEPARTMENTS_FILTER);
  const [sortField, setSortField] = useState<UserSortField>("created_at");
  const [sortDirection, setSortDirection] = useState<SortDirection>("asc");

  const refreshAll = async (manual = false) => {
    if (manual) setRefreshing(true);
    try {
      const [rawUsers, rawDepartments] = await Promise.all([
        listUsers(),
        listDepartments(),
      ]);
      setUsers((rawUsers || []).map(normalizeAdminUser));
      setDepartments(rawDepartments || []);
    } catch {
      // keep existing UI state on transient errors
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    void refreshAll();
  }, []);

  useEffect(() => {
    if (
      departmentFilter !== ALL_DEPARTMENTS_FILTER &&
      departmentFilter !== UNASSIGNED_DEPARTMENT_FILTER &&
      !departments.some((d) => d.department_id === departmentFilter)
    ) {
      setDepartmentFilter(ALL_DEPARTMENTS_FILTER);
    }
  }, [departments, departmentFilter]);

  useEffect(() => {
    if (newDepartmentId && !departments.some((d) => d.department_id === newDepartmentId)) {
      setNewDepartmentId("");
    }
  }, [departments, newDepartmentId]);

  const unassignedCount = useMemo(
    () => users.filter((u) => !u.department_id).length,
    [users],
  );

  const visibleUsers = useMemo(
    () =>
      filterAndSortUsers(users, {
        departmentFilter,
        sortField,
        sortDirection,
      }),
    [users, departmentFilter, sortField, sortDirection],
  );

  const summary = useMemo(() => summarizeUsers(visibleUsers), [visibleUsers]);

  const activeDepartmentLabel = useMemo(() => {
    if (departmentFilter === ALL_DEPARTMENTS_FILTER) return "全部部门";
    if (departmentFilter === UNASSIGNED_DEPARTMENT_FILTER) return "未分配部门";
    return departments.find((d) => d.department_id === departmentFilter)?.name || "全部部门";
  }, [departmentFilter, departments]);

  const handleSortClick = (field: "scan_count" | "suspected_issue_count") => {
    const next = nextSortState(sortField, sortDirection, field);
    setSortField(next.sortField);
    setSortDirection(next.sortDirection);
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateError("");
    setCreateLoading(true);
    try {
      const created = normalizeAdminUser(
        await createUser(newUsername, newPassword, newRole, {
          employee_id: newEmployeeId.trim(),
          department_id: newDepartmentId,
        }),
      );
      setShowCreate(false);
      setNewUsername("");
      setNewPassword("");
      setNewRole("user");
      setNewEmployeeId("");
      setNewDepartmentId("");
      setUsers((prevUsers) => {
        const nextUsers = [...prevUsers, created];
        setDepartments((prevDepts) => reconcileDepartmentUserCounts(prevDepts, nextUsers));
        return nextUsers;
      });
    } catch (err: any) {
      setCreateError(err.response?.data?.detail || "创建用户失败");
    } finally {
      setCreateLoading(false);
    }
  };

  const handleUserProfileSaved = (updatedRaw: AdminUserSummary) => {
    const updated = normalizeAdminUser(updatedRaw);
    setUsers((prevUsers) => {
      const nextUsers = prevUsers.map((item) =>
        item.user_id === updated.user_id ? updated : item,
      );
      setDepartments((prevDepts) => reconcileDepartmentUserCounts(prevDepts, nextUsers));
      return nextUsers;
    });
  };

  const handleDepartmentMutated = (mutation: DepartmentPoolMutation) => {
    if (mutation.type === "created") {
      setDepartments((prev) => [...prev, { ...mutation.department, user_count: 0 }]);
      return;
    }
    if (mutation.type === "renamed") {
      setUsers((prevUsers) => {
        const result = applyDepartmentRenamed(departments, prevUsers, mutation.department);
        setDepartments(result.departments);
        return result.users;
      });
      return;
    }
    if (mutation.type === "deleted") {
      if (departmentFilter === mutation.departmentId) {
        setDepartmentFilter(ALL_DEPARTMENTS_FILTER);
      }
      setUsers((prevUsers) => {
        const result = applyDepartmentDeleted(departments, prevUsers, mutation.departmentId);
        setDepartments(result.departments);
        return result.users;
      });
    }
  };

  const handleDelete = async () => {
    if (!deleteConfirmId) return;
    const userId = deleteConfirmId;
    setDeleteConfirmId(null);
    try {
      await deleteUser(userId);
      setUsers((prevUsers) => {
        const nextUsers = prevUsers.filter((u) => u.user_id !== userId);
        setDepartments((prevDepts) => reconcileDepartmentUserCounts(prevDepts, nextUsers));
        return nextUsers;
      });
    } catch {
      // silently fail
    }
  };

  const renderSortHeader = (
    field: "scan_count" | "suspected_issue_count",
    label: string,
  ) => {
    const active = sortField === field;
    const ariaSort = !active
      ? "none"
      : sortDirection === "asc"
        ? "ascending"
        : "descending";
    const indicator = !active ? "↕" : sortDirection === "desc" ? "↓" : "↑";
    return (
      <th
        aria-sort={ariaSort}
        className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400"
      >
        <button
          type="button"
          onClick={() => handleSortClick(field)}
          className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 transition-colors ${
            active
              ? "bg-blue-500/15 text-blue-300 hover:bg-blue-500/20"
              : "text-slate-400 hover:bg-slate-700/60 hover:text-slate-200"
          }`}
        >
          <span>{label}</span>
          <span aria-hidden="true" className="text-[11px]">
            {indicator}
          </span>
        </button>
      </th>
    );
  };

  return (
    <div className="flex min-h-screen flex-col bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      {/* Delete confirmation modal */}
      {deleteConfirmId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="delete-user-title"
            className="w-full max-w-sm rounded-xl border border-slate-700 bg-slate-800 p-5 shadow-2xl sm:p-6"
          >
            <h3 id="delete-user-title" className="mb-2 text-base font-semibold text-white">
              确认删除
            </h3>
            <p className="mb-5 text-sm text-slate-400">
              确定要删除该用户吗？此操作无法撤销。
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setDeleteConfirmId(null)}
                className="rounded-lg bg-slate-700 px-4 py-1.5 text-sm text-slate-300 transition-colors hover:bg-slate-600 hover:text-white"
              >
                取消
              </button>
              <button
                type="button"
                onClick={handleDelete}
                className="rounded-lg bg-red-600 px-4 py-1.5 text-sm font-medium text-white transition-colors hover:bg-red-500"
              >
                删除
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit user remarks modal */}
      <EditUserProfileModal
        target={editTarget}
        departments={departments}
        onClose={() => setEditTarget(null)}
        onSaved={handleUserProfileSaved}
        onOpenDepartmentPool={() => setShowDepartmentPool(true)}
      />

      {/* Department pool modal */}
      <DepartmentPoolModal
        open={showDepartmentPool}
        departments={departments}
        onClose={() => setShowDepartmentPool(false)}
        onMutated={handleDepartmentMutated}
      />

      <PageHeader
        title="用户管理"
        onBack={onBack}
        description="维护用户工号与部门池，查看每位用户的扫描次数与发现疑似问题统计"
        actions={
          <>
            <button
              type="button"
              disabled={refreshing}
              onClick={() => void refreshAll(true)}
              className="whitespace-nowrap rounded-lg border border-slate-700 bg-slate-800 px-3.5 py-2 text-sm font-medium text-slate-300 transition-colors hover:bg-slate-700 hover:text-white disabled:opacity-50"
            >
              {refreshing ? "刷新中..." : "刷新"}
            </button>
            <ThemeToggle />
            <button
              type="button"
              onClick={() => setShowDepartmentPool(true)}
              className="whitespace-nowrap rounded-lg border border-slate-600 bg-slate-800 px-3.5 py-2 text-sm font-medium text-slate-200 transition-colors hover:bg-slate-700"
            >
              部门池管理 ({departments.length})
            </button>
            <button
              type="button"
              onClick={() => setShowCreate(true)}
              className="whitespace-nowrap rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-700"
            >
              + 新建用户
            </button>
          </>
        }
      />

      {/* Create user form */}
      {showCreate && (
        <div className="mx-auto w-full max-w-7xl px-4 pt-4 sm:px-6">
          <form
            onSubmit={handleCreate}
            className="max-w-xl rounded-xl border border-slate-700 bg-slate-800/80 p-5"
          >
            <h3 className="mb-4 text-sm font-semibold text-white">新建用户</h3>

            {createError && (
              <div
                role="alert"
                className="mb-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400"
              >
                {createError}
              </div>
            )}

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-xs font-medium text-slate-400">用户名</label>
                <input
                  type="text"
                  aria-label="新建用户名"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  className="w-full rounded-lg border border-slate-600 bg-slate-700 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
                  required
                  minLength={2}
                />
              </div>

              <div>
                <label className="mb-1 block text-xs font-medium text-slate-400">密码</label>
                <input
                  type="password"
                  aria-label="新建用户密码"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full rounded-lg border border-slate-600 bg-slate-700 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
                  required
                  minLength={4}
                />
              </div>

              <div>
                <label className="mb-1 block text-xs font-medium text-slate-400">角色</label>
                <select
                  aria-label="新建用户角色"
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value)}
                  className="w-full rounded-lg border border-slate-600 bg-slate-700 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
                >
                  <option value="user">普通用户</option>
                  <option value="admin">管理员</option>
                </select>
              </div>

              <div>
                <label className="mb-1 block text-xs font-medium text-slate-400">工号备注（选填）</label>
                <input
                  type="text"
                  aria-label="新建用户工号"
                  value={newEmployeeId}
                  onChange={(e) => setNewEmployeeId(e.target.value)}
                  maxLength={64}
                  placeholder="例如：00123456"
                  className="w-full rounded-lg border border-slate-600 bg-slate-700 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
                />
              </div>

              <div className="sm:col-span-2">
                <div className="mb-1 flex items-center justify-between">
                  <label className="block text-xs font-medium text-slate-400">所属部门（选填）</label>
                  <button
                    type="button"
                    onClick={() => setShowDepartmentPool(true)}
                    className="text-xs text-blue-400 transition-colors hover:text-blue-300 hover:underline"
                  >
                    维护部门池
                  </button>
                </div>
                <select
                  aria-label="新建用户部门"
                  value={newDepartmentId}
                  onChange={(e) => setNewDepartmentId(e.target.value)}
                  className="w-full rounded-lg border border-slate-600 bg-slate-700 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
                >
                  <option value="">未分配</option>
                  {departments.map((dept) => (
                    <option key={dept.department_id} value={dept.department_id}>
                      {dept.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  setShowCreate(false);
                  setCreateError("");
                }}
                className="rounded-lg bg-slate-700 px-4 py-1.5 text-sm text-slate-300 transition-colors hover:bg-slate-600 hover:text-white"
              >
                取消
              </button>
              <button
                type="submit"
                disabled={createLoading}
                className="rounded-lg bg-blue-600 px-4 py-1.5 text-sm font-medium text-white transition-colors hover:bg-blue-700 disabled:opacity-50"
              >
                {createLoading ? "创建中..." : "创建"}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Main content */}
      <div className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6">
        {loading ? (
          <div className="flex h-48 items-center justify-center">
            <div
              role="status"
              aria-label="加载用户列表"
              className="page-spinner h-5 w-5 animate-spin rounded-full border-2"
            />
          </div>
        ) : (
          <>
            {/* Summary metric cards */}
            <div className="mb-5 grid grid-cols-1 gap-3 sm:grid-cols-3">
              <SummaryMetricCard
                label="用户数"
                value={summary.userCount}
                subtitle={`当前范围：${activeDepartmentLabel}`}
              />
              <SummaryMetricCard
                label="累计创建扫描数"
                value={summary.totalScanCount}
                subtitle="不含已删除扫描任务"
              />
              <SummaryMetricCard
                label="累计发现疑似问题数"
                value={summary.totalSuspectedIssueCount}
                subtitle="与扫描历史 / 结果看板口径一致"
                highlight
              />
            </div>

            {/* Filter & sort toolbar */}
            <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
              <div className="flex flex-wrap items-center gap-2">
                <label className="text-xs font-medium text-slate-400" htmlFor="user-dept-filter">
                  部门筛选：
                </label>
                <select
                  id="user-dept-filter"
                  aria-label="部门筛选"
                  value={departmentFilter}
                  onChange={(e) => setDepartmentFilter(e.target.value)}
                  className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 focus:border-blue-500 focus:outline-none"
                >
                  <option value={ALL_DEPARTMENTS_FILTER}>全部部门 ({users.length})</option>
                  <option value={UNASSIGNED_DEPARTMENT_FILTER}>未分配 ({unassignedCount})</option>
                  {departments.map((dept) => (
                    <option key={dept.department_id} value={dept.department_id}>
                      {dept.name} ({dept.user_count})
                    </option>
                  ))}
                </select>
                {departmentFilter !== ALL_DEPARTMENTS_FILTER && (
                  <button
                    type="button"
                    onClick={() => setDepartmentFilter(ALL_DEPARTMENTS_FILTER)}
                    className="rounded-md px-2.5 py-1 text-xs text-slate-400 transition-colors hover:bg-slate-800 hover:text-slate-200"
                  >
                    清除筛选
                  </button>
                )}
              </div>

              {sortField !== "created_at" && (
                <div className="flex items-center gap-2 text-xs text-slate-400">
                  <span>
                    当前按「{sortField === "scan_count" ? "创建扫描数" : "发现疑似问题数"}」
                    {sortDirection === "desc" ? "从高到低" : "从低到高"}排序
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      setSortField("created_at");
                      setSortDirection("asc");
                    }}
                    className="rounded px-2 py-0.5 text-blue-400 transition-colors hover:bg-blue-500/10"
                  >
                    恢复默认排序
                  </button>
                </div>
              )}
            </div>

            {/* Users table */}
            <div className="overflow-x-auto rounded-xl border border-slate-700">
              <table className="w-full min-w-[54rem] text-sm">
                <thead>
                  <tr className="border-b border-slate-700 bg-slate-800">
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">
                      用户名
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">
                      工号
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">
                      部门
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">
                      角色
                    </th>
                    {renderSortHeader("scan_count", "创建扫描数")}
                    {renderSortHeader("suspected_issue_count", "发现疑似问题数")}
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">
                      创建时间
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">
                      操作
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {visibleUsers.map((u) => (
                    <tr
                      key={u.user_id}
                      className="border-b border-slate-700/50 transition-colors hover:bg-slate-800/50"
                    >
                      <td className="px-4 py-3 text-sm text-slate-200">
                        {u.username}
                        {u.user_id === user.user_id && (
                          <span className="ml-2 text-xs text-slate-500">（当前用户）</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-sm text-slate-300">
                        {u.employee_id || <span className="text-slate-500">-</span>}
                      </td>
                      <td className="px-4 py-3">
                        {u.department_name ? (
                          <span className="inline-flex items-center rounded border border-slate-600 bg-slate-700/60 px-2 py-0.5 text-xs font-medium text-slate-200">
                            {u.department_name}
                          </span>
                        ) : (
                          <span className="text-xs text-slate-500">未分配</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`rounded border px-2 py-0.5 text-xs font-semibold ${
                            u.role === "admin"
                              ? "border-amber-500/30 bg-amber-500/20 text-amber-400"
                              : "border-blue-500/30 bg-blue-500/20 text-blue-400"
                          }`}
                        >
                          {u.role}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm tabular-nums text-slate-200">
                        {u.scan_count}
                      </td>
                      <td className="px-4 py-3 text-sm tabular-nums">
                        <span
                          className={
                            u.suspected_issue_count > 0
                              ? "font-semibold text-amber-300"
                              : "text-slate-300"
                          }
                        >
                          {u.suspected_issue_count}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">
                        {u.created_at ? new Date(u.created_at).toLocaleString() : "-"}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          <button
                            type="button"
                            onClick={() => setEditTarget(u)}
                            className="rounded px-2 py-1 text-xs text-blue-400 transition-colors hover:bg-blue-500/10"
                          >
                            编辑
                          </button>
                          {u.user_id !== user.user_id && (
                            <button
                              type="button"
                              onClick={() => setDeleteConfirmId(u.user_id)}
                              className="rounded px-2 py-1 text-xs text-red-400 transition-colors hover:bg-red-500/10"
                            >
                              删除
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                  {visibleUsers.length === 0 && (
                    <tr>
                      <td colSpan={8} className="px-4 py-8 text-center text-sm text-slate-500">
                        当前筛选条件下暂无用户
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
