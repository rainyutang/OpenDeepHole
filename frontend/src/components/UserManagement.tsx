import { useEffect, useState } from "react";
import { listUsers, createUser, deleteUser } from "../api/client";
import type { User } from "../types";

interface Props {
  onBack: () => void;
  user: User;
}

export default function UserManagement({ onBack, user }: Props) {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("user");
  const [createError, setCreateError] = useState("");
  const [createLoading, setCreateLoading] = useState(false);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);

  const fetchUsers = async () => {
    try {
      const data = await listUsers();
      setUsers(data);
    } catch {
      // silently fail
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateError("");
    setCreateLoading(true);
    try {
      await createUser(newUsername, newPassword, newRole);
      setShowCreate(false);
      setNewUsername("");
      setNewPassword("");
      setNewRole("user");
      await fetchUsers();
    } catch (err: any) {
      setCreateError(err.response?.data?.detail || "Failed to create user");
    } finally {
      setCreateLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteConfirmId) return;
    const userId = deleteConfirmId;
    setDeleteConfirmId(null);
    try {
      await deleteUser(userId);
      setUsers((prev) => prev.filter((u) => u.user_id !== userId));
    } catch {
      // silently fail
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex flex-col">
      {/* Delete confirmation modal */}
      {deleteConfirmId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-slate-800 border border-slate-700 rounded-xl shadow-2xl p-6 w-80">
            <h3 className="text-base font-semibold text-white mb-2">Confirm Delete</h3>
            <p className="text-sm text-slate-400 mb-5">
              Are you sure you want to delete this user? This action cannot be undone.
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setDeleteConfirmId(null)}
                className="px-4 py-1.5 text-sm text-slate-300 hover:text-white bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleDelete}
                className="px-4 py-1.5 text-sm font-medium text-white bg-red-600 hover:bg-red-500 rounded-lg transition-colors"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <div className="bg-slate-800/80 backdrop-blur border-b border-slate-700 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <button
              onClick={onBack}
              className="text-sm text-slate-400 hover:text-white transition-colors"
            >
              &larr; 返回
            </button>
            <h1 className="text-lg font-bold text-white">用户管理</h1>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
          >
            + 新建用户
          </button>
        </div>
      </div>

      {/* Create user form */}
      {showCreate && (
        <div className="px-6 pt-4">
          <form
            onSubmit={handleCreate}
            className="bg-slate-800/80 border border-slate-700 rounded-xl p-5 max-w-md"
          >
            <h3 className="text-sm font-semibold text-white mb-4">Create New User</h3>

            {createError && (
              <div className="mb-3 px-3 py-2 text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg">
                {createError}
              </div>
            )}

            <div className="mb-3">
              <label className="block text-xs font-medium text-slate-400 mb-1">Username</label>
              <input
                type="text"
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
                required
                minLength={2}
              />
            </div>

            <div className="mb-3">
              <label className="block text-xs font-medium text-slate-400 mb-1">Password</label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
                required
                minLength={4}
              />
            </div>

            <div className="mb-4">
              <label className="block text-xs font-medium text-slate-400 mb-1">Role</label>
              <select
                value={newRole}
                onChange={(e) => setNewRole(e.target.value)}
                className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
              >
                <option value="user">User</option>
                <option value="admin">Admin</option>
              </select>
            </div>

            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => { setShowCreate(false); setCreateError(""); }}
                className="px-4 py-1.5 text-sm text-slate-300 hover:text-white bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={createLoading}
                className="px-4 py-1.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded-lg transition-colors"
              >
                {createLoading ? "Creating..." : "Create"}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Users table */}
      <div className="flex-1 px-6 py-6">
        {loading ? (
          <div className="flex items-center justify-center h-48">
            <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
          </div>
        ) : (
          <div className="border border-slate-700 rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-slate-800 border-b border-slate-700">
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Username</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Role</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Created</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr
                    key={u.user_id}
                    className="border-b border-slate-700/50 hover:bg-slate-800/50 transition-colors"
                  >
                    <td className="px-4 py-3 text-sm text-slate-300">
                      {u.username}
                      {u.user_id === user.user_id && (
                        <span className="ml-2 text-xs text-slate-500">(you)</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`text-xs font-semibold px-2 py-0.5 rounded border ${
                          u.role === "admin"
                            ? "bg-amber-500/20 text-amber-400 border-amber-500/30"
                            : "bg-blue-500/20 text-blue-400 border-blue-500/30"
                        }`}
                      >
                        {u.role}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">
                      {u.created_at ? new Date(u.created_at).toLocaleString() : "-"}
                    </td>
                    <td className="px-4 py-3">
                      {u.user_id !== user.user_id && (
                        <button
                          onClick={() => setDeleteConfirmId(u.user_id)}
                          className="text-xs px-2 py-1 rounded text-red-400 hover:bg-red-500/10 transition-colors"
                        >
                          Delete
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
