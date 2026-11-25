import { useEffect, useState } from "react";
import {
  getAdminKnowledgeBaseConfig,
  updateAdminKnowledgeBaseConfig,
} from "../api/knowledgeBase";
import type { AdminKnowledgeBaseConfig } from "../api/knowledgeBase";

interface HeaderRow {
  id: number;
  key: string;
  value: string;
  preserved: boolean;
}

interface Props {
  open: boolean;
  onClose: () => void;
}

const INPUT_CLASS =
  "w-full rounded-lg border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-white placeholder-slate-500 outline-none transition-colors focus:border-blue-500";

export default function AdminKnowledgeBaseModal({ open, onClose }: Props) {
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [config, setConfig] = useState<AdminKnowledgeBaseConfig | null>(null);
  const [url, setUrl] = useState("");
  const [name, setName] = useState("knowledge-base");
  const [timeoutSeconds, setTimeoutSeconds] = useState("300");
  const [headers, setHeaders] = useState<HeaderRow[]>([]);
  const [nextRowId, setNextRowId] = useState(1);
  const [advancedOpen, setAdvancedOpen] = useState(false);

  const hydrate = (loaded: AdminKnowledgeBaseConfig) => {
    setConfig(loaded);
    setUrl(loaded.url || "");
    setName(loaded.name || "knowledge-base");
    setTimeoutSeconds(String(loaded.timeout_seconds || 300));
    const initialRows = loaded.header_keys.map((key, index) => ({
      id: index + 1,
      key,
      value: "",
      preserved: true,
    }));
    setHeaders(initialRows);
    setNextRowId(initialRows.length + 1);
    setAdvancedOpen(
      loaded.header_keys.length > 0
      || (loaded.name !== "" && loaded.name !== "knowledge-base")
      || loaded.timeout_seconds !== 300,
    );
  };

  useEffect(() => {
    if (!open) return;
    let disposed = false;
    setLoading(true);
    setError("");
    setNotice("");
    getAdminKnowledgeBaseConfig()
      .then((loaded) => {
        if (!disposed) hydrate(loaded);
      })
      .catch((caught: unknown) => {
        if (disposed) return;
        const detail = (caught as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
        setError(typeof detail === "string" ? detail : "读取知识库配置失败，请稍后重试");
      })
      .finally(() => {
        if (!disposed) setLoading(false);
      });
    return () => { disposed = true; };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !saving) onClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [open, saving, onClose]);

  if (!open) return null;

  const addHeaderRow = () => {
    setHeaders((current) => [...current, { id: nextRowId, key: "", value: "", preserved: false }]);
    setNextRowId((value) => value + 1);
  };

  const updateHeaderRow = (id: number, patch: Partial<HeaderRow>) => {
    setHeaders((current) => current.map((row) => {
      if (row.id !== id) return row;
      const next = { ...row, ...patch };
      if (patch.key !== undefined && patch.key !== row.key) {
        next.preserved = false;
      }
      return next;
    }));
  };

  const removeHeaderRow = (id: number) => {
    setHeaders((current) => current.filter((row) => row.id !== id));
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (saving || loading) return;
    setError("");
    setNotice("");

    const trimmedUrl = url.trim();
    if (trimmedUrl && !/^https?:\/\/\S+$/i.test(trimmedUrl)) {
      setError("知识库 MCP 链接必须是有效的 http:// 或 https:// URL");
      return;
    }

    const parsedTimeout = Number(timeoutSeconds);
    if (!Number.isInteger(parsedTimeout) || parsedTimeout < 1 || parsedTimeout > 3600) {
      setError("超时秒数必须是 1 到 3600 之间的整数");
      return;
    }

    const nonEmptyRows = headers.filter((row) => row.key.trim() !== "" || row.value !== "");
    const headerPayload: Record<string, string> = {};
    for (const row of nonEmptyRows) {
      const key = row.key.trim();
      if (!key) {
        setError("请求头名称不能为空");
        return;
      }
      if (!row.preserved && row.value === "") {
        setError(`请填写请求头 ${key} 的值`);
        return;
      }
      headerPayload[key] = row.value;
    }

    const hadHeaders = (config?.header_keys.length ?? 0) > 0;
    const clearHeaders = nonEmptyRows.length === 0 && hadHeaders;

    setSaving(true);
    try {
      const saved = await updateAdminKnowledgeBaseConfig({
        url: trimmedUrl,
        name: name.trim() || "knowledge-base",
        timeout_seconds: parsedTimeout,
        ...(clearHeaders
          ? { clear_headers: true }
          : nonEmptyRows.length > 0
            ? { headers: headerPayload }
            : {}),
      });
      hydrate(saved);
      setNotice(
        saved.configured
          ? "知识库 MCP 配置已保存并推送至所有在线客户端，对后续新启动的任务生效。"
          : "已清空知识库 MCP 链接，后续新启动的任务将跳过知识库挂载。",
      );
    } catch (caught: unknown) {
      const detail = (caught as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
      setError(typeof detail === "string" ? detail : "保存知识库配置失败，请稍后重试");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div
        role="dialog"
        aria-modal="true"
        aria-label="知识库配置"
        className="w-full max-w-xl rounded-xl border border-slate-700 bg-slate-800 shadow-2xl"
      >
        <div className="flex items-start justify-between gap-4 border-b border-slate-700 px-5 py-4">
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-semibold text-white">知识库 MCP 配置</h3>
              {config && (
                <span className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${config.configured
                  ? "bg-emerald-500/15 text-emerald-300"
                  : "bg-slate-700 text-slate-400"}`}
                >
                  {config.configured ? "已配置" : "未配置"}
                </span>
              )}
            </div>
            <p className="mt-1 text-xs leading-5 text-slate-400">
              配置全局远端知识库 MCP 链接（支持 Streamable HTTP / SSE）。保存后将自动推送至所有在线客户端，仅对后续新启动的任务生效，不中断正在执行的单次任务。
            </p>
          </div>
          <button
            type="button"
            disabled={saving}
            onClick={onClose}
            aria-label="关闭知识库配置"
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-slate-400 transition-colors hover:bg-slate-700 hover:text-white disabled:opacity-50"
          >
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18 18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 p-5">
          {loading ? (
            <div className="flex h-32 items-center justify-center">
              <div role="status" aria-label="加载知识库配置" className="page-spinner h-5 w-5 animate-spin rounded-full border-2" />
            </div>
          ) : (
            <>
              <label className="block">
                <span className="mb-1.5 block text-sm font-medium text-slate-200">
                  知识库 MCP 链接
                  <span className="ml-1 text-xs font-normal text-slate-400">（留空保存可清空停用）</span>
                </span>
                <input
                  type="text"
                  aria-label="知识库 MCP 链接"
                  className={INPUT_CLASS}
                  value={url}
                  placeholder="http://host:port/mcp"
                  onChange={(event) => setUrl(event.target.value)}
                />
              </label>

              <div className="rounded-lg border border-slate-700 bg-slate-900/50">
                <button
                  type="button"
                  onClick={() => setAdvancedOpen((value) => !value)}
                  aria-expanded={advancedOpen}
                  className="flex w-full items-center justify-between px-3.5 py-2.5 text-xs font-medium text-slate-300 transition-colors hover:text-white"
                >
                  <span>高级选项（MCP 名称、超时、自定义请求头）</span>
                  <span className="text-slate-400">{advancedOpen ? "收起" : "展开"}</span>
                </button>
                {advancedOpen && (
                  <div className="space-y-4 border-t border-slate-700 p-3.5">
                    <div className="grid gap-3 sm:grid-cols-2">
                      <label className="block">
                        <span className="mb-1.5 block text-xs font-medium text-slate-300">MCP 名称</span>
                        <input
                          type="text"
                          aria-label="MCP 名称"
                          className={INPUT_CLASS}
                          value={name}
                          placeholder="knowledge-base"
                          onChange={(event) => setName(event.target.value)}
                        />
                      </label>
                      <label className="block">
                        <span className="mb-1.5 block text-xs font-medium text-slate-300">超时秒数</span>
                        <input
                          type="number"
                          aria-label="超时秒数"
                          min={1}
                          max={3600}
                          className={INPUT_CLASS}
                          value={timeoutSeconds}
                          onChange={(event) => setTimeoutSeconds(event.target.value)}
                        />
                      </label>
                    </div>

                    <div>
                      <div className="mb-2 flex items-center justify-between">
                        <div>
                          <div className="text-xs font-medium text-slate-300">自定义请求头（可选）</div>
                          <div className="text-[11px] text-slate-500">已保存的请求头原值脱敏不回显，留空将保持原值不变。</div>
                        </div>
                        <button
                          type="button"
                          onClick={addHeaderRow}
                          className="rounded border border-slate-600 px-2.5 py-1 text-xs text-slate-200 transition-colors hover:bg-slate-700"
                        >
                          添加请求头
                        </button>
                      </div>
                      {headers.length > 0 ? (
                        <div className="space-y-2">
                          {headers.map((row) => (
                            <div key={row.id} className="flex items-center gap-2">
                              <input
                                type="text"
                                aria-label="请求头名称"
                                className={INPUT_CLASS}
                                placeholder="例如 Authorization"
                                value={row.key}
                                onChange={(event) => updateHeaderRow(row.id, { key: event.target.value })}
                              />
                              <input
                                type="password"
                                aria-label="请求头值"
                                className={INPUT_CLASS}
                                placeholder={row.preserved ? "已保存，留空保持不变" : "Bearer ..."}
                                value={row.value}
                                onChange={(event) => updateHeaderRow(row.id, { value: event.target.value })}
                              />
                              <button
                                type="button"
                                onClick={() => removeHeaderRow(row.id)}
                                className="shrink-0 rounded border border-slate-600 px-2.5 py-2 text-xs text-red-300 transition-colors hover:bg-red-500/10"
                              >
                                删除
                              </button>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-xs text-slate-500">未配置自定义请求头</p>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {error && (
                <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300">
                  {error}
                </div>
              )}
              {notice && (
                <div role="status" className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-300">
                  {notice}
                </div>
              )}
            </>
          )}

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              disabled={saving}
              onClick={onClose}
              className="rounded-lg bg-slate-700 px-4 py-2 text-sm text-slate-300 transition-colors hover:bg-slate-600 hover:text-white disabled:opacity-50"
            >
              关闭
            </button>
            <button
              type="submit"
              disabled={loading || saving}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {saving ? "保存中..." : "保存配置"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
