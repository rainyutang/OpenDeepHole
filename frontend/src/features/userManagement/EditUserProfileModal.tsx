import { useEffect, useState } from "react";
import { updateUserProfile } from "../../api/auth";
import type { AdminUserSummary, Department } from "../../types/auth";

interface Props {
  target: AdminUserSummary | null;
  departments: Department[];
  onClose: () => void;
  onSaved: (updated: AdminUserSummary) => void;
  onOpenDepartmentPool: () => void;
}

export default function EditUserProfileModal({
  target,
  departments,
  onClose,
  onSaved,
  onOpenDepartmentPool,
}: Props) {
  const [employeeId, setEmployeeId] = useState("");
  const [departmentId, setDepartmentId] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!target) return;
    setEmployeeId(target.employee_id || "");
    setDepartmentId(target.department_id || "");
    setError("");
  }, [target]);

  useEffect(() => {
    if (!departmentId) return;
    if (!departments.some((d) => d.department_id === departmentId)) {
      setDepartmentId("");
    }
  }, [departments, departmentId]);

  if (!target) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSaving(true);
    try {
      const updated = await updateUserProfile(target.user_id, {
        employee_id: employeeId.trim(),
        department_id: departmentId,
      });
      onSaved(updated);
      onClose();
    } catch (err: any) {
      setError(err.response?.data?.detail || "保存用户备注失败");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <form
        onSubmit={handleSubmit}
        role="dialog"
        aria-modal="true"
        aria-labelledby="edit-user-profile-title"
        className="w-full max-w-md rounded-xl border border-slate-700 bg-slate-800 p-5 shadow-2xl sm:p-6"
      >
        <h3 id="edit-user-profile-title" className="mb-1 text-base font-semibold text-white">
          编辑用户备注
        </h3>
        <p className="mb-4 text-xs text-slate-400">
          账号：<span className="font-medium text-slate-200">{target.username}</span>（{target.role}）
        </p>

        {error && (
          <div
            role="alert"
            className="mb-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300"
          >
            {error}
          </div>
        )}

        <div className="mb-3">
          <label className="mb-1 block text-xs font-medium text-slate-400">工号备注</label>
          <input
            type="text"
            aria-label="编辑工号"
            value={employeeId}
            onChange={(e) => setEmployeeId(e.target.value)}
            maxLength={64}
            placeholder="例如：00123456（选填，支持自由备注）"
            className="w-full rounded-lg border border-slate-600 bg-slate-700 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
          />
        </div>

        <div className="mb-5">
          <div className="mb-1 flex items-center justify-between">
            <label className="block text-xs font-medium text-slate-400">所属部门</label>
            <button
              type="button"
              onClick={onOpenDepartmentPool}
              className="text-xs text-blue-400 transition-colors hover:text-blue-300 hover:underline"
            >
              维护部门池
            </button>
          </div>
          <select
            aria-label="编辑所属部门"
            value={departmentId}
            onChange={(e) => setDepartmentId(e.target.value)}
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

        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            disabled={saving}
            className="rounded-lg bg-slate-700 px-4 py-1.5 text-sm text-slate-300 transition-colors hover:bg-slate-600 hover:text-white"
          >
            取消
          </button>
          <button
            type="submit"
            disabled={saving}
            className="rounded-lg bg-blue-600 px-4 py-1.5 text-sm font-medium text-white transition-colors hover:bg-blue-700 disabled:opacity-50"
          >
            {saving ? "保存中..." : "保存备注"}
          </button>
        </div>
      </form>
    </div>
  );
}
