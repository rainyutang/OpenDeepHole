import { useEffect, useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
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
              <h1 className="text-lg font-bold text-white">SKILL概览</h1>
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
        {item.enabled && (
          <span className="shrink-0 text-[11px] font-semibold text-emerald-300 bg-emerald-500/10 border border-emerald-500/30 rounded px-1.5 py-0.5">
            已启用
          </span>
        )}
        {item.visibility === "admin" && (
          <span className="shrink-0 text-[11px] font-semibold text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded px-1.5 py-0.5">
            管理员测试
          </span>
        )}
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
              {item.enabled && (
                <span className="text-xs font-semibold text-emerald-300 bg-emerald-500/10 border border-emerald-500/30 rounded px-2 py-0.5">
                  已启用
                </span>
              )}
              {item.visibility === "admin" && (
                <span className="text-xs font-semibold text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded px-2 py-0.5">
                  管理员测试
                </span>
              )}
            </div>
            <p className="text-sm text-slate-400 max-w-3xl">{item.description || "暂无描述"}</p>
          </div>
          <span className="text-xs text-slate-400 bg-slate-800 border border-slate-700 rounded px-2 py-1">
            {item.introduction_source || "checker.yaml"}
          </span>
        </div>
      </div>
      <div className="p-5">
        <MarkdownContent content={item.introduction || item.description || "暂无介绍"} />
      </div>
    </div>
  );
}

function MarkdownContent({ content }: { content: string }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={{
        h1: ({ children }) => <h1 className="mt-1 mb-5 text-2xl font-semibold text-white">{children}</h1>,
        h2: ({ children }) => <h2 className="mt-8 mb-3 text-lg font-semibold text-white">{children}</h2>,
        h3: ({ children }) => <h3 className="mt-6 mb-2 text-base font-semibold text-slate-100">{children}</h3>,
        h4: ({ children }) => <h4 className="mt-5 mb-2 text-sm font-semibold text-slate-200">{children}</h4>,
        p: ({ children }) => <p className="my-3 text-sm leading-7 text-slate-300">{children}</p>,
        ul: ({ children }) => <ul className="my-3 space-y-1.5 pl-5 text-sm leading-relaxed text-slate-300 list-disc marker:text-blue-400">{children}</ul>,
        ol: ({ children }) => <ol className="my-3 space-y-1.5 pl-5 text-sm leading-relaxed text-slate-300 list-decimal marker:text-blue-400">{children}</ol>,
        li: ({ children }) => <li>{children}</li>,
        blockquote: ({ children }) => (
          <blockquote className="my-4 border-l-2 border-blue-500/70 bg-blue-500/5 px-4 py-3 text-sm leading-relaxed text-slate-300">
            {children}
          </blockquote>
        ),
        hr: () => <hr className="my-6 border-slate-800" />,
        table: ({ children }) => (
          <div className="my-4 overflow-x-auto rounded-lg border border-slate-800">
            <table className="w-full min-w-max text-sm">{children}</table>
          </div>
        ),
        thead: ({ children }) => <thead className="bg-slate-950/70">{children}</thead>,
        th: ({ children }) => (
          <th className="border-b border-slate-800 px-3 py-2 text-left text-xs font-semibold text-slate-400">
            {children}
          </th>
        ),
        tr: ({ children }) => <tr className="border-t border-slate-800/70 first:border-t-0">{children}</tr>,
        td: ({ children }) => <td className="px-3 py-2 text-slate-300">{children}</td>,
        pre: ({ children }) => (
          <pre className="my-4 overflow-x-auto rounded-lg border border-slate-700 bg-slate-950 p-4 text-xs leading-relaxed text-slate-300 [&_code]:border-0 [&_code]:bg-transparent [&_code]:p-0 [&_code]:text-slate-300">
            {children}
          </pre>
        ),
        code: ({ className, children }) => (
          <code className={`${className ?? ""} rounded border border-slate-700 bg-slate-950 px-1.5 py-0.5 text-[0.85em] text-blue-200`}>
            {children}
          </code>
        ),
        strong: ({ children }) => <strong className="font-semibold text-slate-100">{children}</strong>,
      }}
    >
      {content}
    </ReactMarkdown>
  );
}
