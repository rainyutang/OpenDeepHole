import { useEffect, useState } from "react";
import type { RedlineImportResponse } from "../../types/redlines";

interface Props {
  open: boolean;
  importing: boolean;
  error: string;
  result: RedlineImportResponse | null;
  onClose: () => void;
  onImport: (file: File, mode: "upsert" | "replace") => Promise<void>;
  onDownloadTemplate: () => Promise<void>;
}

const COLUMNS = ["编号", "安全属性", "属性描述", "红线要求", "分类", "解读及指导", "备注"];

export function RedlineImportModal({
  open,
  importing,
  error,
  result,
  onClose,
  onImport,
  onDownloadTemplate,
}: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [mode, setMode] = useState<"upsert" | "replace">("upsert");
  const [localError, setLocalError] = useState("");

  useEffect(() => {
    if (!open) return;
    setFile(null);
    setMode("upsert");
    setLocalError("");
  }, [open]);

  if (!open) return null;

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!file) {
      setLocalError("请先选择要导入的 .xlsx 文件");
      return;
    }
    setLocalError("");
    await onImport(file, mode);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="redline-import-title"
        className="w-full max-w-xl rounded-xl border border-slate-700 bg-slate-800 shadow-2xl"
      >
        <div className="flex items-center justify-between border-b border-slate-700 px-5 py-4">
          <h2 id="redline-import-title" className="text-base font-semibold text-white">
            导入网络安全红线 Excel（.xlsx）
          </h2>
          <button
            type="button"
            onClick={onClose}
            disabled={importing}
            className="text-sm text-slate-400 hover:text-white disabled:opacity-50"
          >
            关闭
          </button>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4 px-5 py-4">
          <div className="rounded-lg border border-slate-700 bg-slate-900/60 p-3 text-xs text-slate-300">
            <div className="flex items-center justify-between gap-2">
              <span className="font-semibold text-slate-200">列顺序说明（严格按第 1～7 列位置解析）</span>
              <button
                type="button"
                onClick={() => void onDownloadTemplate()}
                className="text-blue-400 underline hover:text-blue-300"
              >
                下载示例模板
              </button>
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {COLUMNS.map((col, idx) => (
                <span
                  key={col}
                  className="rounded border border-slate-600 bg-slate-800 px-2 py-0.5 text-[11px] text-slate-200"
                >
                  第{idx + 1}列：{col}
                </span>
              ))}
            </div>
            <p className="mt-2 text-slate-400">
              首行若为表头会自动跳过；第 1～4 列（编号、安全属性、属性描述、红线要求）必填，红线要求建议不含编号前缀。
            </p>
          </div>

          <label className="block">
            <span className="mb-1.5 block text-xs font-medium text-slate-300">选择 Excel 文件（仅支持 .xlsx）</span>
            <input
              type="file"
              accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
              onChange={(event) => {
                setFile(event.target.files?.[0] ?? null);
                setLocalError("");
              }}
              className="w-full rounded-lg border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-slate-200 file:mr-3 file:rounded file:border-0 file:bg-blue-600 file:px-3 file:py-1 file:text-xs file:font-medium file:text-white hover:file:bg-blue-500"
            />
          </label>

          <div className="space-y-2">
            <div className="text-xs font-medium text-slate-300">导入模式</div>
            <div className="grid gap-2 sm:grid-cols-2">
              <label
                className={`cursor-pointer rounded-lg border p-3 text-xs ${
                  mode === "upsert"
                    ? "border-blue-500 bg-blue-500/10 text-slate-100"
                    : "border-slate-600 text-slate-300"
                }`}
              >
                <input
                  type="radio"
                  name="redline-import-mode"
                  checked={mode === "upsert"}
                  onChange={() => setMode("upsert")}
                  className="mr-2"
                />
                <span className="font-medium">按编号增量更新（推荐）</span>
                <p className="mt-1 pl-5 text-slate-400">同编号覆盖内容并保留原启用状态，新编号自动新增启用。</p>
              </label>
              <label
                className={`cursor-pointer rounded-lg border p-3 text-xs ${
                  mode === "replace"
                    ? "border-amber-500 bg-amber-500/10 text-slate-100"
                    : "border-slate-600 text-slate-300"
                }`}
              >
                <input
                  type="radio"
                  name="redline-import-mode"
                  checked={mode === "replace"}
                  onChange={() => setMode("replace")}
                  className="mr-2"
                />
                <span className="font-medium">全量替换</span>
                <p className="mt-1 pl-5 text-slate-400">清空现有红线条目并替换为本次 Excel 中的条目。</p>
              </label>
            </div>
          </div>

          {(localError || error) && (
            <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300">
              {localError || error}
            </div>
          )}

          {result && (
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs text-emerald-200">
              <div className="font-medium">
                导入完成：新增 {result.created} 条，更新 {result.updated} 条
                {result.replaced > 0 ? `，替换 ${result.replaced} 条` : ""}
                （当前共 {result.total} 条，已启用 {result.enabled_count} 条）
              </div>
            </div>
          )}

          <div className="flex justify-end gap-2 border-t border-slate-700 pt-4">
            <button
              type="button"
              onClick={onClose}
              disabled={importing}
              className="rounded-lg bg-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-600 disabled:opacity-50"
            >
              {result ? "完成" : "取消"}
            </button>
            <button
              type="submit"
              disabled={importing || !file}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {importing ? "导入中..." : "开始导入"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
