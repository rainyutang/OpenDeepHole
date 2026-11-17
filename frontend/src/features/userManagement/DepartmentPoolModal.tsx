import { useState } from "react";
import {
  createDepartment,
  deleteDepartment,
  updateDepartment,
} from "../../api/auth";
import type { Department } from "../../types/auth";

export type DepartmentPoolMutation =
  | { type: "created"; department: Department }
  | { type: "renamed"; department: Department }
  | { type: "deleted"; departmentId: string };

interface Props {
  open: boolean;
  departments: Department[];
  onClose: () => void;
  onMutated: (mutation: DepartmentPoolMutation) => void;
}

export default function DepartmentPoolModal({
  open,
  departments,
  onClose,
  onMutated,
}: Props) {
  const [newName, setNewName] = useState("");
  const [creating, setCreating] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editingName, setEditingName] = useState("");
  const [savingEdit, setSavingEdit] = useState(false);
  const [confirmDeleteDept, setConfirmDeleteDept] = useState<Department | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState("");

  if (!open) return null;

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = newName.trim();
    if (!trimmed) {
      setError("部门名称不能为空");
      return;
    }
    setError("");
    setCreating(true);
    try {
      const created = await createDepartment(trimmed);
      setNewName("");
      onMutated({ type: "created", department: created });
    } catch (err: any) {
      setError(err.response?.data?.detail || "添加部门失败");
    } finally {
      setCreating(false);
    }
  };

  const beginEdit = (dept: Department) => {
    setError("");
    setConfirmDeleteDept(null);
    setEditingId(dept.department_id);
    setEditingName(dept.name);
  };

  const handleSaveEdit = async (departmentId: string) => {
    const trimmed = editingName.trim();
    if (!trimmed) {
      setError("部门名称不能为空");
      return;
    }
    setError("");
    setSavingEdit(true);
    try {
      const updated = await updateDepartment(departmentId, trimmed);
      setEditingId(null);
      setEditingName("");
      onMutated({ type: "renamed", department: updated });
    } catch (err: any) {
      setError(err.response?.data?.detail || "重命名部门失败");
    } finally {
      setSavingEdit(false);
    }
  };

  const handleConfirmDelete = async () => {
    if (!confirmDeleteDept) return;
    const targetId = confirmDeleteDept.department_id;
    setError("");
    setDeleting(true);
    try {
      await deleteDepartment(targetId);
      setConfirmDeleteDept(null);
      if (editingId === targetId) {
        setEditingId(null);
        setEditingName("");
      }
      onMutated({ type: "deleted", departmentId: targetId });
    } catch (err: any) {
      setError(err.response?.data?.detail || "删除部门失败");
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="department-pool-title"
        className="w-full max-w-lg rounded-xl border border-slate-700 bg-slate-800 p-5 shadow-2xl sm:p-6"
      >
        <div className="mb-4 flex items-center justify-between gap-3">
          <div>
            <h3 id="department-pool-title" className="text-base font-semibold text-white">
              部门池管理
            </h3>
            <p className="mt-0.5 text-xs text-slate-400">
              维护可选部门列表；重命名会自动同步已关联用户，删除部门会将关联用户置为「未分配」。
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg bg-slate-700 px-3 py-1.5 text-xs text-slate-300 transition-colors hover:bg-slate-600 hover:text-white"
          >
            关闭
          </button>
        </div>

        {error && (
          <div
            role="alert"
            className="mb-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300"
          >
            {error}
          </div>
        )}

        <form onSubmit={handleCreate} className="mb-4 flex items-center gap-2">
          <input
            type="text"
            aria-label="新部门名称"
            placeholder="输入新部门名称，例如：安全研究部"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            maxLength={64}
            className="min-w-0 flex-1 rounded-lg border border-slate-600 bg-slate-700 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
          />
          <button
            type="submit"
            disabled={creating}
            className="shrink-0 whitespace-nowrap rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-700 disabled:opacity-50"
          >
            {creating ? "添加中..." : "添加部门"}
          </button>
        </form>

        {confirmDeleteDept && (
          <div
            role="alertdialog"
            aria-label="确认删除部门"
            className="mb-4 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3.5"
          >
            <p className="text-xs leading-relaxed text-amber-200">
              {confirmDeleteDept.user_count > 0
                ? `该部门当前已关联 ${confirmDeleteDept.user_count} 名用户，删除后这些用户的部门将自动变更为「未分配」。确定要删除部门「${confirmDeleteDept.name}」吗？`
                : `确定要删除部门「${confirmDeleteDept.name}」吗？`}
            </p>
            <div className="mt-3 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setConfirmDeleteDept(null)}
                disabled={deleting}
                className="rounded-lg bg-slate-700 px-3 py-1 text-xs text-slate-200 transition-colors hover:bg-slate-600"
              >
                取消删除
              </button>
              <button
                type="button"
                onClick={handleConfirmDelete}
                disabled={deleting}
                className="rounded-lg bg-red-600 px-3 py-1 text-xs font-medium text-white transition-colors hover:bg-red-500 disabled:opacity-50"
              >
                {deleting ? "删除中..." : "确认删除"}
              </button>
            </div>
          </div>
        )}

        <div className="max-h-72 overflow-y-auto rounded-lg border border-slate-700">
          {departments.length === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-slate-400">
              暂无部门，请在上方添加部门
            </div>
          ) : (
            <ul className="divide-y divide-slate-700/70">
              {departments.map((dept) => {
                const isEditing = editingId === dept.department_id;
                return (
                  <li
                    key={dept.department_id}
                    className="flex items-center justify-between gap-2 px-3.5 py-2.5"
                  >
                    {isEditing ? (
                      <div className="flex min-w-0 flex-1 items-center gap-2">
                        <input
                          type="text"
                          aria-label="编辑部门名称"
                          value={editingName}
                          onChange={(e) => setEditingName(e.target.value)}
                          maxLength={64}
                          className="min-w-0 flex-1 rounded-md border border-slate-600 bg-slate-700 px-2.5 py-1 text-sm text-white focus:border-blue-500 focus:outline-none"
                        />
                        <button
                          type="button"
                          disabled={savingEdit}
                          onClick={() => handleSaveEdit(dept.department_id)}
                          className="rounded bg-blue-600 px-2.5 py-1 text-xs font-medium text-white transition-colors hover:bg-blue-700 disabled:opacity-50"
                        >
                          保存
                        </button>
                        <button
                          type="button"
                          disabled={savingEdit}
                          onClick={() => {
                            setEditingId(null);
                            setEditingName("");
                          }}
                          className="rounded bg-slate-700 px-2.5 py-1 text-xs text-slate-300 transition-colors hover:bg-slate-600"
                        >
                          取消
                        </button>
                      </div>
                    ) : (
                      <>
                        <div className="flex min-w-0 items-center gap-2">
                          <span className="truncate text-sm text-slate-200">{dept.name}</span>
                          <span className="shrink-0 rounded border border-slate-600 bg-slate-700/70 px-2 py-0.5 text-xs text-slate-300">
                            {dept.user_count} 人
                          </span>
                        </div>
                        <div className="flex shrink-0 items-center gap-1.5">
                          <button
                            type="button"
                            onClick={() => beginEdit(dept)}
                            className="rounded px-2 py-1 text-xs text-blue-400 transition-colors hover:bg-blue-500/10"
                          >
                            重命名
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setError("");
                              setEditingId(null);
                              setConfirmDeleteDept(dept);
                            }}
                            className="rounded px-2 py-1 text-xs text-red-400 transition-colors hover:bg-red-500/10"
                          >
                            删除
                          </button>
                        </div>
                      </>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
