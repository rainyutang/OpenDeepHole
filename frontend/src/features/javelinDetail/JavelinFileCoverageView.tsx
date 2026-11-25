import { useEffect, useState } from "react";
import { getJavelinFileCoverage } from "../../api/javelin";
import type { JavelinCoverageFileItem, JavelinFileCoverageResponse } from "../../api/javelin";

interface Props {
  scanId: string;
  onBackToWorkbench: () => void;
}

const PAGE_SIZE = 100;

const STATUS_BADGES: Record<string, { label: string; cls: string }> = {
  covered: { label: "已覆盖", cls: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300" },
  pending: { label: "任务进行中", cls: "border-blue-500/30 bg-blue-500/10 text-blue-300" },
  uncovered: { label: "待覆盖", cls: "border-amber-500/30 bg-amber-500/10 text-amber-300" },
  out_of_scope: { label: "范围外", cls: "border-slate-600 bg-slate-700/40 text-slate-400" },
};

export default function JavelinFileCoverageView({ scanId, onBackToWorkbench }: Props) {
  const [query, setQuery] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<JavelinFileCoverageResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setDebouncedQuery(query.trim());
      setOffset(0);
    }, 250);
    return () => window.clearTimeout(timer);
  }, [query]);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    getJavelinFileCoverage(
      scanId,
      { q: debouncedQuery || undefined, status: statusFilter || undefined, offset, limit: PAGE_SIZE },
      controller.signal,
    )
      .then((res) => {
        if (!controller.signal.aborted) setData(res);
      })
      .catch((err: unknown) => {
        if (!controller.signal.aborted) {
          setError(err instanceof Error ? err.message : "读取文件覆盖范围失败");
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [scanId, debouncedQuery, statusFilter, offset]);

  const summary = data?.summary;

  return (
    <div className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 text-slate-200">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-white">源码文件覆盖详情</h2>
          <p className="mt-1 text-xs text-slate-400">
            数据源自已入库源码基线（source-baseline）与任务看板关联引用，客户端离线仍可完整检索。
          </p>
        </div>
        <button
          type="button"
          onClick={onBackToWorkbench}
          className="rounded-lg border border-slate-600 bg-slate-800 px-3.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
        >
          ← 返回审计工作台
        </button>
      </div>

      {summary && (
        <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-5">
          <div className="rounded-xl border border-slate-700 bg-slate-800/80 p-4">
            <div className="text-xs text-slate-400">范围内文件</div>
            <div className="mt-1 text-xl font-semibold text-white">{summary.eligible_files}</div>
          </div>
          <div className="rounded-xl border border-slate-700 bg-slate-800/80 p-4">
            <div className="text-xs text-slate-400">已覆盖文件</div>
            <div className="mt-1 text-xl font-semibold text-emerald-300">{summary.covered_files}</div>
          </div>
          <div className="rounded-xl border border-slate-700 bg-slate-800/80 p-4">
            <div className="text-xs text-slate-400">进行中文件</div>
            <div className="mt-1 text-xl font-semibold text-blue-300">{summary.pending_files}</div>
          </div>
          <div className="rounded-xl border border-slate-700 bg-slate-800/80 p-4">
            <div className="text-xs text-slate-400">待覆盖文件</div>
            <div className="mt-1 text-xl font-semibold text-amber-300">{summary.uncovered_files}</div>
          </div>
          <div className="rounded-xl border border-slate-700 bg-slate-800/80 p-4">
            <div className="text-xs text-slate-400">覆盖率</div>
            <div className="mt-1 text-xl font-semibold text-cyan-300">{summary.coverage_percent}%</div>
          </div>
        </div>
      )}

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="搜索文件路径或文件编号..."
          className="min-w-[16rem] flex-1 rounded-lg border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-white placeholder-slate-500 outline-none focus:border-blue-500"
        />
        <select
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value);
            setOffset(0);
          }}
          className="rounded-lg border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-slate-200 outline-none focus:border-blue-500"
        >
          <option value="">全部状态</option>
          <option value="covered">已覆盖</option>
          <option value="pending">任务进行中</option>
          <option value="uncovered">待覆盖</option>
          <option value="out_of_scope">范围外</option>
        </select>
      </div>

      {error ? (
        <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
          {error}
        </div>
      ) : loading && !data ? (
        <div className="flex h-48 items-center justify-center">
          <div role="status" aria-label="加载文件覆盖详情" className="page-spinner h-5 w-5 animate-spin rounded-full border-2" />
        </div>
      ) : data && !data.baseline_ready ? (
        <div className="rounded-xl border border-slate-700 bg-slate-800/60 p-8 text-center text-sm text-slate-400">
          源码范围基线（source-baseline）尚未生成或上报，待范围冻结完成后自动展示。
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-slate-700 bg-slate-800/50">
          <table className="w-full min-w-[48rem] text-sm">
            <thead>
              <tr className="border-b border-slate-700 bg-slate-800 text-left text-xs uppercase text-slate-400">
                <th className="px-4 py-3">文件路径</th>
                <th className="px-4 py-3">覆盖状态</th>
                <th className="px-4 py-3">关联任务数</th>
                <th className="px-4 py-3">发现问题数</th>
                <th className="px-4 py-3">关联任务</th>
              </tr>
            </thead>
            <tbody>
              {(data?.items || []).map((item: JavelinCoverageFileItem) => {
                const badge = STATUS_BADGES[item.status] || STATUS_BADGES.uncovered;
                return (
                  <tr key={`${item.file_id}-${item.path}`} className="border-b border-slate-700/50 hover:bg-slate-800/70">
                    <td className="px-4 py-2.5 font-mono text-xs text-slate-200">{item.path}</td>
                    <td className="px-4 py-2.5">
                      <span className={`inline-flex rounded border px-2 py-0.5 text-xs font-medium ${badge.cls}`}>
                        {badge.label}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-xs text-slate-300">{item.task_count}</td>
                    <td className="px-4 py-2.5 text-xs text-emerald-300">{item.finding_count}</td>
                    <td className="px-4 py-2.5 text-xs text-slate-400">
                      {item.tasks.length === 0
                        ? "-"
                        : item.tasks
                            .slice(0, 3)
                            .map((t) => `${t.task_id} (${t.status})`)
                            .join("，")}
                    </td>
                  </tr>
                );
              })}
              {data && data.items.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-sm text-slate-500">
                    无匹配的文件记录
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {data && data.total > PAGE_SIZE && (
        <div className="mt-4 flex items-center justify-between text-xs text-slate-400">
          <span>
            显示 {data.offset + 1} - {Math.min(data.offset + PAGE_SIZE, data.total)} / 共 {data.total} 个文件
          </span>
          <div className="flex gap-2">
            <button
              type="button"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
              className="rounded border border-slate-600 px-3 py-1.5 text-slate-200 disabled:opacity-40"
            >
              上一页
            </button>
            <button
              type="button"
              disabled={data.next_offset === null}
              onClick={() => {
                if (data.next_offset !== null) setOffset(data.next_offset);
              }}
              className="rounded border border-slate-600 px-3 py-1.5 text-slate-200 disabled:opacity-40"
            >
              下一页
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
