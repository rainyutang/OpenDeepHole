import { useEffect, useState } from "react";
import { getScans, resumeScan, deleteScan } from "../api/client";
import type { ScanSummary, ScanItemStatus, User } from "../types";

interface Props {
  onViewScan: (scanId: string) => void;
  onDownloadAgent: () => void;
  onNewScan: () => void;
  user: User;
  onLogout: () => void;
  onManageUsers: () => void;
  onCheckerDashboard: () => void;
}

const STATUS_STYLES: Record<ScanItemStatus, { label: string; cls: string }> = {
  pending: { label: "等待中", cls: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
  analyzing: { label: "分析中", cls: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
  auditing: { label: "审计中", cls: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
  complete: { label: "已完成", cls: "bg-green-500/20 text-green-400 border-green-500/30" },
  error: { label: "错误", cls: "bg-red-500/20 text-red-400 border-red-500/30" },
  cancelled: { label: "已取消", cls: "bg-amber-500/20 text-amber-400 border-amber-500/30" },
};

function isRunning(status: ScanItemStatus) {
  return status === "pending" || status === "analyzing" || status === "auditing";
}

export default function ScanHistory({ onViewScan, onDownloadAgent, onNewScan, user, onLogout, onManageUsers, onCheckerDashboard }: Props) {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);

  const fetchScans = async () => {
    try {
      const data = await getScans();
      setScans(data);
    } catch {
      // silently fail
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();

    const timer = setInterval(() => {
      fetchScans();
    }, 5000);
    return () => clearInterval(timer);
  }, []);

  const handleResume = async (scanId: string) => {
    setActionLoading(scanId);
    try {
      await resumeScan(scanId);
      onViewScan(scanId);
    } catch {
      // silently fail
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeleteConfirm = async () => {
    if (!deleteConfirmId) return;
    const scanId = deleteConfirmId;
    setDeleteConfirmId(null);
    setActionLoading(scanId);
    try {
      await deleteScan(scanId);
      setScans((prev) => prev.filter((s) => s.scan_id !== scanId));
    } catch {
      // silently fail
    } finally {
      setActionLoading(null);
    }
  };

  const formatTime = (iso: string) => {
    try {
      return new Date(iso).toLocaleString();
    } catch {
      return iso;
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex flex-col">
      {deleteConfirmId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-slate-800 border border-slate-700 rounded-xl shadow-2xl p-6 w-80">
            <h3 className="text-base font-semibold text-white mb-2">确认删除</h3>
            <p className="text-sm text-slate-400 mb-5">
              确定要删除扫描任务 <span className="font-mono text-slate-300">{deleteConfirmId.slice(0, 8)}</span> 吗？此操作无法撤销。
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setDeleteConfirmId(null)}
                className="px-4 py-1.5 text-sm text-slate-300 hover:text-white bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
              >
                取消
              </button>
              <button
                onClick={handleDeleteConfirm}
                className="px-4 py-1.5 text-sm font-medium text-white bg-red-600 hover:bg-red-500 rounded-lg transition-colors"
              >
                删除
              </button>
            </div>
          </div>
        </div>
      )}
      {/* Header */}
      <div className="bg-slate-800/80 backdrop-blur border-b border-slate-700 px-6 py-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-bold text-white">OpenDeepHole</h1>
            <p className="text-sm text-slate-400 mt-0.5">C/C++ Source Code Audit Tool</p>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-sm text-slate-400">
              {user.username}
              {user.role === "admin" && (
                <span className="ml-1.5 text-xs font-semibold px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">
                  Admin
                </span>
              )}
            </span>
            {user.role === "admin" && (
              <>
                <button
                  onClick={onCheckerDashboard}
                  className="px-3 py-2 text-sm font-medium text-slate-300 hover:text-white bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
                >
                  Dashboard
                </button>
                <button
                  onClick={onManageUsers}
                  className="px-3 py-2 text-sm font-medium text-slate-300 hover:text-white bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
                >
                  Users
                </button>
              </>
            )}
            <button
              onClick={onDownloadAgent}
              className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
            >
              Agent
            </button>
            <button
              onClick={onNewScan}
              className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
            >
              + Scan
            </button>
            <button
              onClick={onLogout}
              className="px-3 py-2 text-sm font-medium text-slate-400 hover:text-red-400 transition-colors"
            >
              Logout
            </button>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 px-6 py-6">
        <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">
          扫描历史
        </h2>

        {loading ? (
          <div className="flex items-center justify-center h-48">
            <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
          </div>
        ) : scans.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-slate-500">
            <p className="text-lg font-medium">暂无扫描记录</p>
            <p className="text-sm mt-1">点击右上角「新建扫描」开始</p>
          </div>
        ) : (
          <div className="border border-slate-700 rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-slate-800 border-b border-slate-700">
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">ID</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">状态</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">进度</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">漏洞数</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">检查项</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Agent</th>
                  {user.role === "admin" && (
                    <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">创建者</th>
                  )}
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">创建时间</th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">操作</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => {
                  const st = STATUS_STYLES[scan.status];
                  const pct = Math.round(scan.progress * 100);
                  const running = isRunning(scan.status);
                  const canResume = scan.status === "cancelled" || scan.status === "error";
                  const canDelete = !running;
                  const isLoading = actionLoading === scan.scan_id;

                  return (
                    <tr
                      key={scan.scan_id}
                      className="border-b border-slate-700/50 hover:bg-slate-800/50 transition-colors"
                    >
                      <td className="px-4 py-3 font-mono text-xs text-slate-300">
                        {scan.scan_id.slice(0, 8)}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs font-semibold px-2 py-0.5 rounded border ${st.cls}`}>
                          {st.label}
                        </span>
                        {running && (
                          <span className="ml-2 inline-block w-2 h-2 bg-blue-400 rounded-full animate-pulse" />
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full transition-all ${running ? "bg-blue-500" : "bg-green-500"}`}
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                          <span className="text-xs text-slate-400">
                            {scan.processed_candidates}/{scan.total_candidates}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm text-slate-300">
                        {scan.vulnerability_count}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {scan.scan_items.map((item) => (
                            <span
                              key={item}
                              className="text-xs bg-slate-700/50 text-slate-400 px-1.5 py-0.5 rounded"
                            >
                              {item}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        {scan.agent_name ? (
                          <span className="flex items-center gap-1.5 text-xs text-slate-300">
                            <span
                              className={`w-2 h-2 rounded-full flex-shrink-0 ${
                                scan.agent_online ? "bg-green-400" : "bg-slate-500"
                              }`}
                            />
                            {scan.agent_name}
                          </span>
                        ) : (
                          <span className="text-xs text-slate-500">-</span>
                        )}
                      </td>
                      {user.role === "admin" && (
                        <td className="px-4 py-3 text-xs text-slate-300">
                          {scan.username || "-"}
                        </td>
                      )}
                      <td className="px-4 py-3 text-xs text-slate-400">
                        {formatTime(scan.created_at)}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => onViewScan(scan.scan_id)}
                            className="text-xs px-2 py-1 rounded text-blue-400 hover:bg-blue-500/10 transition-colors"
                          >
                            查看
                          </button>
                          {canResume && (
                            <button
                              onClick={() => handleResume(scan.scan_id)}
                              disabled={isLoading || !scan.agent_online}
                              title={!scan.agent_online ? "Agent 离线，无法恢复" : undefined}
                              className="text-xs px-2 py-1 rounded text-amber-400 hover:bg-amber-500/10 disabled:opacity-50 transition-colors"
                            >
                              {isLoading ? "..." : "恢复"}
                            </button>
                          )}
                          {canDelete && (
                            <button
                              onClick={() => setDeleteConfirmId(scan.scan_id)}
                              disabled={isLoading}
                              className="text-xs px-2 py-1 rounded text-red-400 hover:bg-red-500/10 disabled:opacity-50 transition-colors"
                            >
                              {isLoading ? "..." : "删除"}
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
