import type { OpenCodeCategoryTokenUsage, OpenCodeTokenUsage } from "../types";

const fields = [
  ["输入", "input_tokens"], ["输出", "output_tokens"], ["推理", "reasoning_tokens"],
  ["缓存读取", "cache_read_tokens"], ["缓存写入", "cache_write_tokens"],
] as const;
const format = (value: number) => new Intl.NumberFormat("zh-CN").format(value || 0);

export function ScanTokenUsagePanel({ usage }: { usage: OpenCodeTokenUsage | null }) {
  if (!usage) return <section className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
    <h3 className="text-sm font-semibold text-slate-200">Token 统计</h3>
    <p className="mt-2 text-xs text-slate-500">暂无已采集的 Token 用量。</p>
  </section>;

  let categories: OpenCodeCategoryTokenUsage[] = [...(usage.by_category ?? [])];
  // Old API responses have totals but no categories. Keep their unclassified
  // balance visible without inventing zero usage for the named business types.
  const remaining = Object.fromEntries(fields.map(([, key]) => [key,
    usage[key] - categories.reduce((sum, item) => sum + (item[key] || 0), 0),
  ])) as Record<typeof fields[number][1], number>;
  if (fields.some(([, key]) => remaining[key] < 0)) {
    categories = [];
    fields.forEach(([, key]) => { remaining[key] = usage[key]; });
  }
  const remainder = fields.reduce((sum, [, key]) => sum + remaining[key], 0);
  if (remainder > 0 || (!categories.length && usage.total_tokens > 0)) {
    const unknown = categories.find((item) => item.category === "uncategorized");
    const item: OpenCodeCategoryTokenUsage = {
      category: "uncategorized", label: "未分类", complete: usage.complete,
      ...remaining, total_tokens: remainder || usage.total_tokens,
    };
    if (unknown) {
      fields.forEach(([, key]) => { item[key] += unknown[key]; });
      item.total_tokens += unknown.total_tokens;
      item.complete = item.complete && unknown.complete;
      categories = categories.filter((value) => value.category !== "uncategorized");
    }
    categories.push(item);
  }
  categories.sort((left, right) => Number(left.category === "uncategorized") - Number(right.category === "uncategorized")
    || right.total_tokens - left.total_tokens || left.category.localeCompare(right.category));
  const hasUnknown = categories.some((item) => item.category === "uncategorized" && item.total_tokens > 0);

  return <section className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <div>
        <h3 className="text-sm font-semibold text-slate-200">Token 统计</h3>
        <p className="mt-1 text-xs text-slate-500">累计整个扫描生命周期的用量，包含续扫和重试，完成模型调用后更新。</p>
      </div>
      {!usage.complete && <span className="rounded border border-amber-700 px-2 py-1 text-xs text-amber-300">统计可能不完整</span>}
    </div>
    <div className="mt-4 grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-6">
      {[...fields, ["总计", "total_tokens"] as const].map(([label, key]) => <div key={key} className="rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2">
        <div className="text-[11px] text-slate-500">{label}</div>
        <div className="mt-1 font-mono text-sm text-slate-200">{format(usage[key])}</div>
      </div>)}
    </div>
    {categories.length > 0 && <div className="mt-4 overflow-x-auto">
      <table aria-label="按任务类别统计 Token" className="w-full whitespace-nowrap text-left text-xs">
        <thead className="border-b border-slate-700 text-slate-400"><tr>
          {["任务类别", "总 Token", "占比", ...fields.map(([label]) => label)].map((label) => <th key={label} className="px-3 py-2 font-medium">{label}</th>)}
        </tr></thead>
        <tbody>{categories.map((item) => <tr key={item.category} className="border-b border-slate-800 text-slate-300">
          <td className="px-3 py-2">{item.category === "uncategorized" ? "未分类" : item.label || item.category}
            {!item.complete && <span className="ml-2 text-amber-400">统计可能不完整</span>}</td>
          <td className="px-3 py-2 font-mono text-slate-100">{format(item.total_tokens)}</td>
          <td className="px-3 py-2 font-mono">{usage.total_tokens > 0 ? (item.total_tokens / usage.total_tokens * 100).toFixed(1) : "0.0"}%</td>
          {fields.map(([, key]) => <td key={key} className="px-3 py-2 font-mono">{format(item[key])}</td>)}
        </tr>)}</tbody>
      </table>
    </div>}
    {hasUnknown && <p className="mt-2 text-xs text-amber-400">部分用量缺少可确认的任务分类，已保留在“未分类”中。</p>}
    {(usage.by_model ?? []).length > 1 && <div className="mt-3 flex flex-wrap gap-2">
      {[...usage.by_model].sort((left, right) => right.total_tokens - left.total_tokens).map((item) => (
        <span key={item.model} className="rounded border border-slate-700 bg-slate-950/60 px-2 py-1 font-mono text-[11px] text-slate-400">
          {item.model}: {format(item.total_tokens)}
        </span>
      ))}
    </div>}
  </section>;
}
