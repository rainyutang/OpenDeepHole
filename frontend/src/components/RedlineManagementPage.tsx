import { useCallback, useEffect, useMemo, useState } from "react";
import {
  batchDeleteAdminRedlines,
  batchSetAdminRedlinesEnabled,
  createAdminRedline,
  deleteAdminRedline,
  downloadAdminRedlineTemplate,
  importAdminRedlinesExcel,
  listAdminRedlines,
  updateAdminRedline,
} from "../api/redlines";
import type { RedlineImportResponse, RedlineItem, RedlineItemInput } from "../types/redlines";
import PageHeader from "./PageHeader";
import { ThemeToggle } from "./ThemeToggle";
import { RedlineImportModal } from "../features/redlines/RedlineImportModal";
import { RedlineItemModal } from "../features/redlines/RedlineItemModal";
import { extractRedlineCategories, filterRedlineItems } from "../features/redlines/redlinesModel";

interface Props {
  onBack: () => void;
}

function errorMessage(error: unknown, fallback: string): string {
  const detail = (error as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
  return typeof detail === "string" && detail.trim() ? detail : fallback;
}

export default function RedlineManagementPage({ onBack }: Props) {
  const [items, setItems] = useState<RedlineItem[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [enabledCount, setEnabledCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const [keyword, setKeyword] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [enabledFilter, setEnabledFilter] = useState<"all" | "enabled" | "disabled">("all");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  const [modalOpen, setModalOpen] = useState(false);
  const [editingItem, setEditingItem] = useState<RedlineItem | null>(null);
  const [saving, setSaving] = useState(false);
  const [modalError, setModalError] = useState("");

  const [importOpen, setImportOpen] = useState(false);
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState("");
  const [importResult, setImportResult] = useState<RedlineImportResponse | null>(null);

  const [busyIds, setBusyIds] = useState<Set<string>>(new Set());
  const [batchBusy, setBatchBusy] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState<{ mode: "single"; item: RedlineItem } | { mode: "batch"; ids: string[] } | null>(null);

  const loadItems = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await listAdminRedlines();
      setItems(response.items);
      setTotalCount(response.total);
      setEnabledCount(response.enabled_count);
      setSelectedIds((prev) => {
        const valid = new Set(response.items.map((item) => item.item_id));
        const next = new Set([...prev].filter((id) => valid.has(id)));
        return next.size === prev.size ? prev : next;
      });
    } catch (caught) {
      setError(errorMessage(caught, "加载网络安全红线条目失败"));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadItems();
  }, [loadItems]);

  const categories = useMemo(() => extractRedlineCategories(items), [items]);
  const visibleItems = useMemo(
    () => filterRedlineItems(items, { keyword, category: categoryFilter, enabledFilter }),
    [items, keyword, categoryFilter, enabledFilter],
  );
  const allVisibleSelected = visibleItems.length > 0 && visibleItems.every((item) => selectedIds.has(item.item_id));

  const toggleSelectAllVisible = () => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (allVisibleSelected) {
        visibleItems.forEach((item) => next.delete(item.item_id));
      } else {
        visibleItems.forEach((item) => next.add(item.item_id));
      }
      return next;
    });
  };

  const toggleRowSelect = (itemId: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(itemId)) next.delete(itemId);
      else next.add(itemId);
      return next;
    });
  };

  const toggleExpand = (itemId: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(itemId)) next.delete(itemId);
      else next.add(itemId);
      return next;
    });
  };

  const handleToggleEnabled = async (item: RedlineItem) => {
    setBusyIds((prev) => new Set(prev).add(item.item_id));
    setError("");
    setNotice("");
    try {
      const updated = await updateAdminRedline(item.item_id, { enabled: !item.enabled });
      setItems((prev) => prev.map((row) => (row.item_id === updated.item_id ? updated : row)));
      setEnabledCount((prev) => prev + (updated.enabled ? 1 : -1));
    } catch (caught) {
      setError(errorMessage(caught, "更新红线启用状态失败"));
    } finally {
      setBusyIds((prev) => {
        const next = new Set(prev);
        next.delete(item.item_id);
        return next;
      });
    }
  };

  const handleSaveModal = async (input: RedlineItemInput) => {
    setSaving(true);
    setModalError("");
    setNotice("");
    try {
      if (editingItem) {
        await updateAdminRedline(editingItem.item_id, input);
        setNotice(`已更新红线条目「${input.code}」`);
      } else {
        await createAdminRedline(input);
        setNotice(`已新增红线条目「${input.code}」`);
      }
      setModalOpen(false);
      setEditingItem(null);
      await loadItems();
    } catch (caught) {
      setModalError(errorMessage(caught, "保存红线条目失败"));
    } finally {
      setSaving(false);
    }
  };

  const handleBatchEnabled = async (enabled: boolean) => {
    const ids = [...selectedIds];
    if (ids.length === 0) return;
    setBatchBusy(true);
    setError("");
    setNotice("");
    try {
      const res = await batchSetAdminRedlinesEnabled(ids, enabled);
      setNotice(`已${enabled ? "启用" : "停用"} ${res.updated} 条红线`);
      await loadItems();
    } catch (caught) {
      setError(errorMessage(caught, "批量更新红线状态失败"));
    } finally {
      setBatchBusy(false);
    }
  };

  const handleConfirmDelete = async () => {
    if (!deleteConfirm) return;
    setBatchBusy(true);
    setError("");
    setNotice("");
    try {
      if (deleteConfirm.mode === "single") {
        await deleteAdminRedline(deleteConfirm.item.item_id);
        setNotice(`已删除红线条目「${deleteConfirm.item.code}」`);
      } else {
        const res = await batchDeleteAdminRedlines(deleteConfirm.ids);
        setNotice(`已删除 ${res.deleted} 条红线`);
        setSelectedIds(new Set());
      }
      setDeleteConfirm(null);
      await loadItems();
    } catch (caught) {
      setError(errorMessage(caught, "删除红线条目失败"));
    } finally {
      setBatchBusy(false);
    }
  };

  const handleImport = async (file: File, mode: "upsert" | "replace") => {
    setImporting(true);
    setImportError("");
    setImportResult(null);
    try {
      const res = await importAdminRedlinesExcel(file, mode);
      setImportResult(res);
      await loadItems();
    } catch (caught) {
      setImportError(errorMessage(caught, "导入 Excel 失败"));
    } finally {
      setImporting(false);
    }
  };

  const handleDownloadTemplate = async () => {
    setError("");
    try {
      const blob = await downloadAdminRedlineTemplate();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "deephole-redlines-template.xlsx";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (caught) {
      setError(errorMessage(caught, "下载导入模板失败"));
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
      <PageHeader
        title="红线管理"
        onBack={onBack}
        description="维护 DeepHole 网络安全红线条目，并勾选参与排查的条目（支持手动维护与 .xlsx 批量导入）"
        actions={
          <>
            <button
              type="button"
              onClick={() => void handleDownloadTemplate()}
              className="rounded-lg border border-slate-600 bg-slate-700 px-3 py-2 text-sm text-slate-200 transition-colors hover:bg-slate-600"
            >
              下载模板
            </button>
            <button
              type="button"
              onClick={() => {
                setImportError("");
                setImportResult(null);
                setImportOpen(true);
              }}
              className="rounded-lg border border-emerald-500/40 bg-emerald-600/20 px-3 py-2 text-sm font-medium text-emerald-200 transition-colors hover:bg-emerald-600/30"
            >
              导入 Excel
            </button>
            <button
              type="button"
              onClick={() => {
                setEditingItem(null);
                setModalError("");
                setModalOpen(true);
              }}
              className="rounded-lg bg-blue-600 px-3.5 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-500"
            >
              新增红线
            </button>
            <ThemeToggle />
          </>
        }
      />

      <main className="mx-auto max-w-7xl space-y-5 px-4 py-6 sm:px-6">
        <div className="grid gap-3 sm:grid-cols-3">
          <div className="rounded-xl border border-slate-700 bg-slate-800/80 p-4">
            <div className="text-xs text-slate-400">红线条目总数</div>
            <div className="mt-1 text-2xl font-bold text-white">{totalCount}</div>
          </div>
          <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4">
            <div className="text-xs text-rose-200/80">当前已启用排查</div>
            <div className="mt-1 text-2xl font-bold text-rose-200">{enabledCount}</div>
          </div>
          <div className="rounded-xl border border-slate-700 bg-slate-800/80 p-4">
            <div className="text-xs text-slate-400">已停用条目</div>
            <div className="mt-1 text-2xl font-bold text-slate-300">{Math.max(0, totalCount - enabledCount)}</div>
          </div>
        </div>

        {error && (
          <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        )}
        {notice && (
          <div role="status" className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
            {notice}
          </div>
        )}

        <div className="flex flex-wrap items-center gap-3 rounded-xl border border-slate-700 bg-slate-800/70 p-4">
          <input
            type="search"
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            placeholder="搜索编号、安全属性、属性描述、红线要求、解读或备注..."
            className="min-w-[240px] flex-1 rounded-lg border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-white placeholder-slate-500 outline-none focus:border-blue-500"
          />
          <select
            aria-label="按分类筛选"
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="rounded-lg border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-slate-200 outline-none focus:border-blue-500"
          >
            <option value="">全部分类</option>
            {categories.map((cat) => (
              <option key={cat} value={cat}>{cat}</option>
            ))}
          </select>
          <select
            aria-label="按启用状态筛选"
            value={enabledFilter}
            onChange={(e) => setEnabledFilter(e.target.value as "all" | "enabled" | "disabled")}
            className="rounded-lg border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-slate-200 outline-none focus:border-blue-500"
          >
            <option value="all">全部状态</option>
            <option value="enabled">仅已启用</option>
            <option value="disabled">仅已停用</option>
          </select>
          {selectedIds.size > 0 && (
            <div className="flex flex-wrap items-center gap-2 border-l border-slate-700 pl-3">
              <span className="text-xs text-slate-300">已选 {selectedIds.size} 条</span>
              <button
                type="button"
                disabled={batchBusy}
                onClick={() => void handleBatchEnabled(true)}
                className="rounded-lg border border-emerald-500/40 bg-emerald-500/15 px-2.5 py-1.5 text-xs text-emerald-200 hover:bg-emerald-500/25 disabled:opacity-50"
              >
                批量启用
              </button>
              <button
                type="button"
                disabled={batchBusy}
                onClick={() => void handleBatchEnabled(false)}
                className="rounded-lg border border-amber-500/40 bg-amber-500/15 px-2.5 py-1.5 text-xs text-amber-200 hover:bg-amber-500/25 disabled:opacity-50"
              >
                批量停用
              </button>
              <button
                type="button"
                disabled={batchBusy}
                onClick={() => setDeleteConfirm({ mode: "batch", ids: [...selectedIds] })}
                className="rounded-lg border border-red-500/40 bg-red-500/15 px-2.5 py-1.5 text-xs text-red-200 hover:bg-red-500/25 disabled:opacity-50"
              >
                批量删除
              </button>
            </div>
          )}
        </div>

        <div className="overflow-hidden rounded-xl border border-slate-700 bg-slate-800/70">
          {loading ? (
            <div className="flex h-48 items-center justify-center text-sm text-slate-400">
              正在加载网络安全红线条目...
            </div>
          ) : visibleItems.length === 0 ? (
            <div className="p-10 text-center text-sm text-slate-400">
              {items.length === 0
                ? "暂未配置任何网络安全红线条目，可点击右上角「新增红线」或「导入 Excel」快速添加。"
                : "没有符合当前筛选条件的红线条目。"}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[960px] text-left text-sm">
                <thead className="border-b border-slate-700 bg-slate-900/60 text-xs uppercase text-slate-400">
                  <tr>
                    <th className="w-10 px-3 py-3">
                      <input
                        type="checkbox"
                        aria-label="全选当前列表"
                        checked={allVisibleSelected}
                        onChange={toggleSelectAllVisible}
                      />
                    </th>
                    <th className="w-24 px-3 py-3">参与排查</th>
                    <th className="w-24 px-3 py-3">编号</th>
                    <th className="w-20 px-3 py-3">分类</th>
                    <th className="w-44 px-3 py-3">安全属性</th>
                    <th className="w-48 px-3 py-3">属性描述</th>
                    <th className="px-3 py-3">红线要求</th>
                    <th className="w-32 px-3 py-3 text-right">操作</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/70">
                  {visibleItems.map((item) => {
                    const expanded = expandedIds.has(item.item_id);
                    const hasExtra = Boolean(item.guidance.trim() || item.remark.trim());
                    return (
                      <tr key={item.item_id} className="align-top transition-colors hover:bg-slate-800/90">
                        <td className="px-3 py-3">
                          <input
                            type="checkbox"
                            aria-label={`选择红线 ${item.code}`}
                            checked={selectedIds.has(item.item_id)}
                            onChange={() => toggleRowSelect(item.item_id)}
                          />
                        </td>
                        <td className="px-3 py-3">
                          <button
                            type="button"
                            role="switch"
                            aria-label={`切换红线 ${item.code} 启用状态`}
                            aria-checked={item.enabled}
                            disabled={busyIds.has(item.item_id)}
                            onClick={() => void handleToggleEnabled(item)}
                            className={`relative inline-flex h-5 w-10 items-center rounded-full transition-colors disabled:opacity-50 ${
                              item.enabled ? "bg-emerald-500" : "bg-slate-600"
                            }`}
                          >
                            <span
                              className={`inline-block h-4 w-4 rounded-full bg-white shadow transition-transform ${
                                item.enabled ? "translate-x-5" : "translate-x-0.5"
                              }`}
                            />
                          </button>
                        </td>
                        <td className="px-3 py-3 font-mono text-xs font-semibold text-rose-300">{item.code}</td>
                        <td className="px-3 py-3">
                          {item.category ? (
                            <span className="rounded border border-slate-600 bg-slate-900 px-2 py-0.5 text-xs text-slate-200">
                              {item.category}
                            </span>
                          ) : (
                            <span className="text-xs text-slate-500">-</span>
                          )}
                        </td>
                        <td className="px-3 py-3 text-xs text-slate-200">{item.security_attribute}</td>
                        <td className="px-3 py-3 text-xs text-slate-300">{item.attribute_description}</td>
                        <td className="px-3 py-3 text-xs leading-relaxed text-slate-100">
                          <div>{item.requirement}</div>
                          {hasExtra && (
                            <button
                              type="button"
                              onClick={() => toggleExpand(item.item_id)}
                              className="mt-1.5 text-[11px] text-blue-400 hover:text-blue-300"
                            >
                              {expanded ? "收起解读与备注 ▴" : "查看解读与备注 ▾"}
                            </button>
                          )}
                          {expanded && hasExtra && (
                            <div className="mt-2 space-y-1.5 rounded-lg border border-slate-700 bg-slate-900/70 p-2.5 text-xs text-slate-300">
                              {item.guidance.trim() && (
                                <div>
                                  <span className="font-semibold text-slate-200">解读及指导：</span>
                                  <span className="whitespace-pre-wrap">{item.guidance}</span>
                                </div>
                              )}
                              {item.remark.trim() && (
                                <div>
                                  <span className="font-semibold text-slate-200">备注：</span>
                                  <span className="whitespace-pre-wrap">{item.remark}</span>
                                </div>
                              )}
                            </div>
                          )}
                        </td>
                        <td className="px-3 py-3 text-right whitespace-nowrap">
                          <button
                            type="button"
                            onClick={() => {
                              setEditingItem(item);
                              setModalError("");
                              setModalOpen(true);
                            }}
                            className="mr-2 text-xs text-blue-400 hover:text-blue-300"
                          >
                            编辑
                          </button>
                          <button
                            type="button"
                            onClick={() => setDeleteConfirm({ mode: "single", item })}
                            className="text-xs text-red-400 hover:text-red-300"
                          >
                            删除
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </main>

      <RedlineItemModal
        open={modalOpen}
        editingItem={editingItem}
        saving={saving}
        error={modalError}
        onClose={() => {
          setModalOpen(false);
          setEditingItem(null);
        }}
        onSave={handleSaveModal}
      />

      <RedlineImportModal
        open={importOpen}
        importing={importing}
        error={importError}
        result={importResult}
        onClose={() => setImportOpen(false)}
        onImport={handleImport}
        onDownloadTemplate={handleDownloadTemplate}
      />

      {deleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="delete-redline-title"
            className="w-full max-w-sm rounded-xl border border-slate-700 bg-slate-800 p-5 shadow-2xl"
          >
            <h3 id="delete-redline-title" className="mb-2 text-base font-semibold text-white">
              确认删除
            </h3>
            <p className="mb-5 text-sm text-slate-300">
              {deleteConfirm.mode === "single"
                ? `确定要删除红线条目「${deleteConfirm.item.code}」吗？已有历史扫描快照不受影响。`
                : `确定要删除已选中的 ${deleteConfirm.ids.length} 条红线吗？已有历史扫描快照不受影响。`}
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                disabled={batchBusy}
                onClick={() => setDeleteConfirm(null)}
                className="rounded-lg bg-slate-700 px-4 py-1.5 text-sm text-slate-300 hover:bg-slate-600"
              >
                取消
              </button>
              <button
                type="button"
                disabled={batchBusy}
                onClick={() => void handleConfirmDelete()}
                className="rounded-lg bg-red-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-red-500 disabled:opacity-50"
              >
                {batchBusy ? "删除中..." : "删除"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
