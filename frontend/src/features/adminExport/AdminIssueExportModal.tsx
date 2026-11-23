import { useEffect, useId, useMemo, useState } from "react";
import { listUsers } from "../../api/auth";
import { exportAdminIssuesExcel } from "../../api/reports";
import type { AdminUserSummary } from "../../types/auth";
import { downloadBlob } from "../scanDetail/resources/downloadBlob";
import {
  EMPTY_EXPORT_FILTER,
  EXPORT_TIME_PRESETS,
  activeTimePreset,
  buildAdminExportParams,
  extractEmployeeIdOptions,
  extractUsernameOptions,
  formatExportSuccessNotice,
  resolveTimePresetRange,
  validateExportFilter,
  type AdminIssueExportFilter,
  type ExportTimePreset,
} from "./exportModel";

interface Props {
  open: boolean;
  onClose: () => void;
  users?: AdminUserSummary[];
}

export default function AdminIssueExportModal({ open, onClose, users }: Props) {
  const [filter, setFilter] = useState<AdminIssueExportFilter>(EMPTY_EXPORT_FILTER);
  const [loadedUsers, setLoadedUsers] = useState<AdminUserSummary[]>([]);
  const [usersLoaded, setUsersLoaded] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const titleId = useId();
  const usernameListId = useId();
  const employeeIdListId = useId();

  useEffect(() => {
    if (!open) return;
    setError("");
    setNotice("");
  }, [open]);

  useEffect(() => {
    if (!open || users !== undefined || usersLoaded) return;
    let cancelled = false;
    listUsers()
      .then((items) => {
        if (!cancelled) {
          setLoadedUsers(items || []);
          setUsersLoaded(true);
        }
      })
      .catch(() => {
        if (!cancelled) setUsersLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, [open, users, usersLoaded]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !exporting) {
        onClose();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, exporting, onClose]);

  const suggestionUsers = users ?? loadedUsers;
  const usernameOptions = useMemo(
    () => extractUsernameOptions(suggestionUsers),
    [suggestionUsers],
  );
  const employeeIdOptions = useMemo(
    () => extractEmployeeIdOptions(suggestionUsers),
    [suggestionUsers],
  );
  const validationError = useMemo(() => validateExportFilter(filter), [filter]);
  const selectedPreset = useMemo(() => activeTimePreset(filter), [filter]);

  if (!open) return null;

  const handlePresetClick = (preset: ExportTimePreset) => {
    const range = resolveTimePresetRange(preset);
    setFilter((prev) => ({ ...prev, ...range }));
    setError("");
    setNotice("");
  };

  const handleReset = () => {
    setFilter(EMPTY_EXPORT_FILTER);
    setError("");
    setNotice("");
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (exporting) return;
    const invalid = validateExportFilter(filter);
    if (invalid) {
      setError(invalid);
      return;
    }
    setExporting(true);
    setError("");
    setNotice("");
    try {
      const tzOffsetMinutes = -new Date().getTimezoneOffset();
      const shareOrigin =
        typeof window !== "undefined" && window.location?.origin
          ? window.location.origin
          : "";
      const params = buildAdminExportParams(filter, {
        tzOffsetMinutes,
        shareOrigin,
      });
      const result = await exportAdminIssuesExcel(params);
      downloadBlob(result.blob, result.filename);
      setNotice(formatExportSuccessNotice(result.rowCount));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "导出问题失败";
      setError(message || "导出问题失败");
    } finally {
      setExporting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm"
      onClick={() => {
        if (!exporting) onClose();
      }}
    >
      <form
        onSubmit={handleSubmit}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-lg rounded-xl border border-slate-700 bg-slate-800 p-5 shadow-2xl sm:p-6"
      >
        <div className="mb-1 flex items-start justify-between gap-3">
          <h3 id={titleId} className="text-base font-semibold text-white">
            导出问题（Excel）
          </h3>
          <button
            type="button"
            disabled={exporting}
            onClick={onClose}
            aria-label="关闭导出窗口"
            className="rounded p-1 text-slate-400 transition-colors hover:bg-slate-700 hover:text-white disabled:opacity-50"
          >
            ✕
          </button>
        </div>
        <p className="mb-4 text-xs leading-relaxed text-slate-400">
          导出全部未删除扫描中去误报最终确认的问题，包含发现用户名、工号、发现时间、所属扫描分享链接及问题详情。
        </p>

        {(error || validationError) && (
          <div
            role="alert"
            className="mb-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300"
          >
            {error || validationError}
          </div>
        )}

        {notice && !error && (
          <div
            role="status"
            className="mb-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-300"
          >
            {notice}
          </div>
        )}

        <div className="mb-4">
          <div className="mb-1.5 flex items-center justify-between gap-2">
            <span className="text-xs font-medium text-slate-300">发现时间范围</span>
            <div className="flex flex-wrap gap-1.5">
              {EXPORT_TIME_PRESETS.map((preset) => (
                <button
                  key={preset.id}
                  type="button"
                  disabled={exporting}
                  onClick={() => handlePresetClick(preset.id)}
                  className={`rounded-md border px-2 py-0.5 text-xs transition-colors ${
                    selectedPreset === preset.id
                      ? "border-blue-500/60 bg-blue-500/20 text-blue-300"
                      : "border-slate-600 bg-slate-700/60 text-slate-300 hover:bg-slate-700 hover:text-white"
                  }`}
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <label
                htmlFor="admin-export-start-date"
                className="mb-1 block text-xs text-slate-400"
              >
                开始日期（含）
              </label>
              <input
                id="admin-export-start-date"
                type="date"
                aria-label="开始日期"
                disabled={exporting}
                value={filter.startDate}
                onChange={(e) => {
                  setFilter((prev) => ({ ...prev, startDate: e.target.value }));
                  setError("");
                  setNotice("");
                }}
                className="w-full rounded-lg border border-slate-600 bg-slate-700 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none disabled:opacity-50"
              />
            </div>

            <div>
              <label
                htmlFor="admin-export-end-date"
                className="mb-1 block text-xs text-slate-400"
              >
                结束日期（含）
              </label>
              <input
                id="admin-export-end-date"
                type="date"
                aria-label="结束日期"
                disabled={exporting}
                value={filter.endDate}
                onChange={(e) => {
                  setFilter((prev) => ({ ...prev, endDate: e.target.value }));
                  setError("");
                  setNotice("");
                }}
                className="w-full rounded-lg border border-slate-600 bg-slate-700 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none disabled:opacity-50"
              />
            </div>
          </div>
        </div>

        <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label
              htmlFor="admin-export-username"
              className="mb-1 block text-xs font-medium text-slate-300"
            >
              按用户名筛选（选填）
            </label>
            <input
              id="admin-export-username"
              type="text"
              aria-label="筛选用户名"
              list={usernameListId}
              maxLength={128}
              disabled={exporting}
              value={filter.username}
              onChange={(e) => {
                setFilter((prev) => ({ ...prev, username: e.target.value }));
                setError("");
                setNotice("");
              }}
              placeholder="输入或选择用户名（模糊匹配）"
              className="w-full rounded-lg border border-slate-600 bg-slate-700 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none disabled:opacity-50"
            />
            <datalist id={usernameListId}>
              {usernameOptions.map((name) => (
                <option key={name} value={name} />
              ))}
            </datalist>
          </div>

          <div>
            <label
              htmlFor="admin-export-employee-id"
              className="mb-1 block text-xs font-medium text-slate-300"
            >
              按工号筛选（选填）
            </label>
            <input
              id="admin-export-employee-id"
              type="text"
              aria-label="筛选工号"
              list={employeeIdListId}
              maxLength={64}
              disabled={exporting}
              value={filter.employeeId}
              onChange={(e) => {
                setFilter((prev) => ({ ...prev, employeeId: e.target.value }));
                setError("");
                setNotice("");
              }}
              placeholder="输入或选择工号（模糊匹配）"
              className="w-full rounded-lg border border-slate-600 bg-slate-700 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none disabled:opacity-50"
            />
            <datalist id={employeeIdListId}>
              {employeeIdOptions.map((empId) => (
                <option key={empId} value={empId} />
              ))}
            </datalist>
          </div>
        </div>

        <p className="mb-5 text-[11px] leading-relaxed text-slate-400">
          留空条件则不限对应维度；若导出结果涉及尚未开启分享的扫描，将自动为其生成可撤销的分享链接以便审阅。
        </p>

        <div className="flex flex-wrap items-center justify-between gap-2">
          <button
            type="button"
            disabled={exporting}
            onClick={handleReset}
            className="rounded-lg px-2.5 py-1.5 text-xs text-slate-400 transition-colors hover:bg-slate-700 hover:text-slate-200 disabled:opacity-50"
          >
            重置筛选
          </button>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={exporting}
              onClick={onClose}
              className="rounded-lg bg-slate-700 px-4 py-1.5 text-sm text-slate-300 transition-colors hover:bg-slate-600 hover:text-white disabled:opacity-50"
            >
              取消
            </button>
            <button
              type="submit"
              disabled={exporting || Boolean(validationError)}
              className="rounded-lg bg-blue-600 px-4 py-1.5 text-sm font-medium text-white transition-colors hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {exporting ? "导出中..." : "导出 Excel"}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
