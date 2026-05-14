import { useEffect, useMemo, useState } from "react";
import { getCheckerCatalog } from "../api/client";
import type { CheckerCatalogItem } from "../types";

interface Props {
  onBack: () => void;
}

export default function CheckerCatalogPage({ onBack }: Props) {
  const [items, setItems] = useState<CheckerCatalogItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeChecker, setActiveChecker] = useState<string | null>(null);

  const refresh = async () => {
    setLoading(true);
    setError("");
    try {
      const next = await getCheckerCatalog();
      setItems(next);
      setActiveChecker((current) => current ?? next[0]?.name ?? null);
    } catch (err: any) {
      setError(err.response?.data?.detail || "加载 SKILL 列表失败");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  const selected = useMemo(() => {
    if (!activeChecker) return null;
    return items.find((item) => item.name === activeChecker) ?? null;
  }, [items, activeChecker]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      <div className="bg-slate-900/90 border-b border-slate-800 px-6 py-4">
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <button
              onClick={onBack}
              className="text-sm text-slate-400 hover:text-white transition-colors"
            >
              &larr; 返回
            </button>
            <div>
              <h1 className="text-lg font-bold text-white">SKILL / Checker</h1>
              <p className="text-sm text-slate-400 mt-0.5">
                查看当前可用 SKILL 的检测范围和使用说明
              </p>
            </div>
          </div>
          <button
            onClick={refresh}
            className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 transition-colors"
          >
            刷新
          </button>
        </div>
      </div>

      <div className="flex-1 px-6 py-6">
        {loading ? (
          <div className="flex items-center justify-center h-64">
            <div className="w-6 h-6 border-2 border-slate-600 border-t-blue-400 rounded-full animate-spin" />
          </div>
        ) : error ? (
          <div className="border border-red-500/30 bg-red-500/10 text-red-300 rounded-lg px-4 py-3 text-sm">
            {error}
          </div>
        ) : (
          <div className="max-w-7xl mx-auto grid grid-cols-1 xl:grid-cols-[24rem_1fr] gap-5">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  SKILL 列表
                </h2>
                <span className="text-xs text-slate-500">共 {items.length} 个</span>
              </div>
              <div className="space-y-2">
                {items.map((item) => (
                  <CheckerListItem
                    key={item.name}
                    item={item}
                    active={item.name === activeChecker}
                    onClick={() => setActiveChecker(item.name)}
                  />
                ))}
              </div>
            </div>

            <div className="min-w-0">
              {selected ? (
                <CheckerIntro item={selected} />
              ) : (
                <div className="border border-slate-800 rounded-lg p-8 text-center text-slate-500">
                  暂无可展示的 SKILL
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function CheckerListItem({
  item,
  active,
  onClick,
}: {
  item: CheckerCatalogItem;
  active: boolean;
  onClick: () => void;
}) {
  const activeCls = active
    ? "border-blue-500/60 bg-blue-500/10"
    : "border-slate-800 bg-slate-900/60 hover:bg-slate-900 hover:border-slate-700";

  return (
    <button
      onClick={onClick}
      className={`w-full rounded-lg border px-4 py-3 text-left transition-colors ${activeCls}`}
    >
      <div className="flex items-center gap-2 mb-1">
        <span className="min-w-0 text-sm font-semibold text-white truncate">{item.label}</span>
        <span className="shrink-0 text-[11px] font-semibold text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded">
          {item.name.toUpperCase()}
        </span>
      </div>
      <p className="text-xs text-slate-500 line-clamp-2 min-h-8">
        {item.description || "暂无描述"}
      </p>
    </button>
  );
}

function CheckerIntro({ item }: { item: CheckerCatalogItem }) {
  return (
    <div className="border border-slate-800 bg-slate-900/70 rounded-lg overflow-hidden">
      <div className="px-5 py-4 border-b border-slate-800">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <h2 className="text-lg font-semibold text-white truncate">{item.label}</h2>
              <span className="text-xs font-semibold text-slate-400 bg-slate-800 px-2 py-0.5 rounded">
                {item.name.toUpperCase()}
              </span>
            </div>
            <p className="text-sm text-slate-400 max-w-3xl">{item.description || "暂无描述"}</p>
          </div>
          <span className="text-xs text-slate-400 bg-slate-800 border border-slate-700 rounded px-2 py-1">
            {item.introduction_source || "checker.yaml"}
          </span>
        </div>
      </div>
      <div className="p-5">
        <pre className="text-sm text-slate-300 whitespace-pre-wrap leading-relaxed font-mono overflow-x-auto">
          {item.introduction || item.description || "暂无介绍"}
        </pre>
      </div>
    </div>
  );
}
