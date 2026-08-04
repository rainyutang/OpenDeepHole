import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { getCheckerDashboard } from "../api/client";
import type {
  CheckerDashboardResponse,
  CheckerDashboardStats,
  CheckerDashboardTokenUsage,
  CheckerScanDashboardStats,
  ScanItemStatus,
  User,
} from "../types";
import { ThemeToggle } from "./ThemeToggle";

interface Props {
  onBack: () => void;
  onViewScan: (scanId: string) => void;
  user: User;
}

const STATUS_STYLES: Record<ScanItemStatus, { label: string; cls: string }> = {
  pending: { label: "等待中", cls: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
  analyzing: { label: "分析中", cls: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30" },
  auditing: { label: "审计中", cls: "bg-violet-500/20 text-violet-300 border-violet-500/30" },
  complete: { label: "已完成", cls: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" },
  error: { label: "错误", cls: "bg-red-500/20 text-red-400 border-red-500/30" },
  cancelled: { label: "已取消", cls: "bg-amber-500/20 text-amber-400 border-amber-500/30" },
};

const UNCONFIGURED_PRODUCT = "__unconfigured__";

export default function CheckerDashboardPage({ onBack, onViewScan, user }: Props) {
  const [data, setData] = useState<CheckerDashboardResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeChecker, setActiveChecker] = useState<string | null>(null);
  const [productFilter, setProductFilter] = useState("");

  const refresh = async (nextProduct = productFilter) => {
    setLoading(true);
    setError("");
    try {
      const next = await getCheckerDashboard(nextProduct);
      setData(next);
      setActiveChecker((current) => current ?? next.checkers[0]?.checker ?? null);
    } catch (err: any) {
      setError(err.response?.data?.detail || "加载看板失败");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh("");
  }, []);

  const handleProductFilterChange = (value: string) => {
    setProductFilter(value);
    refresh(value);
  };

  const selected = useMemo(() => {
    if (!data || !activeChecker) return null;
    return data.checkers.find((checker) => checker.checker === activeChecker) ?? null;
  }, [data, activeChecker]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      <div className="bg-slate-900/90 border-b border-slate-800 px-4 py-4 sm:px-6">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4">
          <div className="flex min-w-0 items-center gap-4">
            <button
              onClick={onBack}
              className="text-sm text-slate-400 hover:text-white transition-colors"
            >
              &larr; 返回
            </button>
            <div>
              <h1 className="text-lg font-bold text-white">结果看板</h1>
              <p className="text-sm text-slate-400 mt-0.5">
                {user.role === "admin"
                  ? "汇总全部用户的扫描结果、问题确认和 Token 用量"
                  : "汇总你创建的扫描结果、问题确认和 Token 用量"}
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 sm:gap-3">
            <select
              value={productFilter}
              onChange={(e) => handleProductFilterChange(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value="">全部产品</option>
              {data?.has_unconfigured_product && <option value={UNCONFIGURED_PRODUCT}>未配置</option>}
              {(data?.products || []).map((product) => (
                <option key={product} value={product}>
                  {product}
                </option>
              ))}
            </select>
            <button
              onClick={() => refresh()}
              className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 transition-colors"
            >
              刷新
            </button>
            <ThemeToggle />
          </div>
        </div>
      </div>

      <div className="flex-1 px-4 py-6 sm:px-6">
        {loading ? (
          <div className="flex items-center justify-center h-64">
            <div className="w-6 h-6 border-2 border-slate-600 border-t-blue-400 rounded-full animate-spin" />
          </div>
        ) : error ? (
          <div role="alert" className="border border-red-500/30 bg-red-500/10 text-red-300 rounded-lg px-4 py-3 text-sm">
            {error}
          </div>
        ) : data ? (
          <div className="max-w-7xl mx-auto">
            <DashboardTokenUsagePanel
              data={data.token_usage}
              showOwner={user.role === "admin"}
            />

            <div className="grid grid-cols-2 md:grid-cols-5 xl:grid-cols-10 gap-3 mb-6">
              <MetricTile label="SKILL" value={data.summary.checker_count} />
              <MetricTile label="扫描次数" value={data.summary.scan_count} />
              <MetricTile label="静态发现" value={data.summary.static_issue_count} />
              <MetricTile label="LLM 确认" value={data.summary.llm_issue_count} />
              <MetricTile label="复核确认" value={data.summary.fp_review_issue_count} />
              <MetricTile label="有效问题" value={data.summary.total_issue_count} />
              <MetricTile label="人工确认" value={data.summary.human_confirmed_count} />
              <MetricTile label="已提单" value={data.summary.ticket_submitted_count} />
              <MetricTile
                label="人工准确率"
                value={formatAccuracy(data.summary.accuracy)}
                sub={`${data.summary.human_confirmed_count}/${data.summary.accuracy_basis_count}`}
                tone="emerald"
              />
              <MetricTile
                label="提单准确率"
                value={formatAccuracy(data.summary.ticket_accuracy)}
                sub={`${data.summary.ticket_submitted_count}/${data.summary.accuracy_basis_count}`}
                tone="blue"
              />
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-[24rem_1fr] gap-5">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    SKILL 列表
                  </h2>
                  <span className="text-xs text-slate-500">点击查看详情</span>
                </div>
                <div className="space-y-2">
                  {data.checkers.filter((c) => !c.user_created).map((checker) => (
                    <CheckerCard
                      key={checker.checker}
                      checker={checker}
                      active={checker.checker === activeChecker}
                      onClick={() => setActiveChecker(checker.checker)}
                    />
                  ))}
                  {data.checkers.some((c) => c.user_created) && (
                    <>
                      <div className="flex items-center gap-3 py-2">
                        <div className="flex-1 border-t border-slate-700" />
                        <span className="text-xs font-semibold text-slate-500 whitespace-nowrap">用户创建</span>
                        <div className="flex-1 border-t border-slate-700" />
                      </div>
                      {data.checkers.filter((c) => c.user_created).map((checker) => (
                        <CheckerCard
                          key={checker.checker}
                          checker={checker}
                          active={checker.checker === activeChecker}
                          onClick={() => setActiveChecker(checker.checker)}
                        />
                      ))}
                    </>
                  )}
                </div>
              </div>

              <div className="min-w-0">
                {selected ? (
                  <CheckerDetail
                    checker={selected}
                    onViewScan={onViewScan}
                    showCreator={user.role === "admin"}
                  />
                ) : (
                  <div className="border border-slate-800 rounded-lg p-8 text-center text-slate-500">
                    暂无可展示的 SKILL
                  </div>
                )}
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

function DashboardTokenUsagePanel({
  data,
  showOwner,
}: {
  data: CheckerDashboardTokenUsage;
  showOwner: boolean;
}) {
  const metrics = [
    ["总 Token", data.usage.total_tokens],
    ["输入", data.usage.input_tokens],
    ["输出", data.usage.output_tokens],
    ["推理", data.usage.reasoning_tokens],
    ["缓存读取", data.usage.cache_read_tokens],
    ["缓存写入", data.usage.cache_write_tokens],
  ] as const;
  const columns = showOwner ? 10 : 9;

  return (
    <section className="mb-6 overflow-hidden rounded-xl border border-slate-800 bg-slate-900/70">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-800 px-5 py-4">
        <div>
          <h2 className="text-base font-semibold text-white">Token 总计</h2>
          <p className="mt-1 text-xs text-slate-400">
            覆盖当前权限范围内的全部扫描，不受产品筛选影响，并按 Agent 分组。
          </p>
        </div>
        <span className={`rounded-full border px-2.5 py-1 text-xs ${data.usage.complete
          ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
          : "border-amber-500/30 bg-amber-500/10 text-amber-300"}`}>
          已统计 {data.tracked_scan_count}/{data.scan_count} 个扫描
        </span>
      </div>
      {!data.usage.complete && data.scan_count > 0 && (
        <div className="border-b border-amber-500/20 bg-amber-500/10 px-5 py-3 text-xs text-amber-200">
          部分历史扫描没有 Token 数据或会话统计不完整，当前总数仅包含可用记录，不会回填升级前数据。
        </div>
      )}
      <div className="grid grid-cols-2 gap-px bg-slate-800 sm:grid-cols-3 xl:grid-cols-6">
        {metrics.map(([label, value]) => (
          <div key={label} className="bg-slate-900/90 px-4 py-4">
            <div className="text-xs text-slate-500">{label}</div>
            <div className="mt-1 font-mono text-xl font-semibold text-slate-100">
              {formatTokenCount(value)}
            </div>
          </div>
        ))}
      </div>
      <div className="overflow-x-auto border-t border-slate-800">
        <table className="w-full min-w-[64rem] text-sm">
          <thead className="bg-slate-950/50 text-left text-xs text-slate-500">
            <tr>
              <Th>Agent</Th>
              {showOwner && <Th>所属用户</Th>}
              <Th>扫描覆盖</Th>
              <Th>输入</Th>
              <Th>输出</Th>
              <Th>推理</Th>
              <Th>缓存读取</Th>
              <Th>缓存写入</Th>
              <Th>总计</Th>
              <Th>状态</Th>
            </tr>
          </thead>
          <tbody>
            {data.agents.length === 0 ? (
              <tr>
                <td colSpan={columns} className="px-4 py-8 text-center text-sm text-slate-500">
                  暂无扫描 Token 数据
                </td>
              </tr>
            ) : data.agents.map((agent, index) => (
              <tr key={agent.agent_key || `${agent.owner_user_id}:${agent.agent_name}:${index}`} className="border-t border-slate-800">
                <td className="px-4 py-3">
                  <div className="text-sm font-medium text-slate-200">{agent.machine_name || agent.agent_name || "未知 Agent"}</div>
                  <div className="mt-0.5 text-xs text-slate-500">{agent.ip || agent.agent_name || "无客户端信息"}</div>
                </td>
                {showOwner && <td className="px-4 py-3 text-xs text-slate-400">{agent.owner_username || "-"}</td>}
                <td className="px-4 py-3 font-mono text-xs text-slate-300">{agent.tracked_scan_count}/{agent.scan_count}</td>
                {[
                  agent.usage.input_tokens,
                  agent.usage.output_tokens,
                  agent.usage.reasoning_tokens,
                  agent.usage.cache_read_tokens,
                  agent.usage.cache_write_tokens,
                  agent.usage.total_tokens,
                ].map((value, valueIndex) => (
                  <td key={valueIndex} className="px-4 py-3 font-mono text-xs text-slate-300">{formatTokenCount(value)}</td>
                ))}
                <td className={`px-4 py-3 text-xs ${agent.usage.complete ? "text-emerald-300" : "text-amber-300"}`}>
                  {agent.usage.complete ? "完整" : "不完整"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function MetricTile({
  label,
  value,
  sub,
  tone = "slate",
}: {
  label: string;
  value: number | string;
  sub?: string;
  tone?: "slate" | "emerald" | "blue";
}) {
  const valueCls =
    tone === "emerald"
      ? "text-emerald-300"
      : tone === "blue"
        ? "text-blue-300"
        : "text-white";
  return (
    <div className="border border-slate-800 bg-slate-900/70 rounded-lg px-4 py-3">
      <div className="text-xs text-slate-500 mb-1">{label}</div>
      <div className={`text-2xl font-semibold ${valueCls}`}>{value}</div>
      {sub && <div className="text-xs text-slate-500 mt-1">{sub}</div>}
    </div>
  );
}

function CheckerCard({
  checker,
  active,
  onClick,
}: {
  checker: CheckerDashboardStats;
  active: boolean;
  onClick: () => void;
}) {
  const activeCls = active
    ? "border-blue-500/60 bg-blue-500/10"
    : "border-slate-800 bg-slate-900/60 hover:bg-slate-900 hover:border-slate-700";

  return (
    <button
      onClick={onClick}
      aria-pressed={active}
      className={`w-full rounded-lg border px-4 py-3 text-left transition-colors ${activeCls}`}
    >
      <div className="flex items-center gap-2 mb-1">
        <span className="min-w-0 text-sm font-semibold text-white truncate">{checker.label}</span>
        <span className="shrink-0 text-[11px] font-semibold text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded">
          {checker.checker.toUpperCase()}
        </span>
        {checker.user_created && (
          <span className="shrink-0 text-[11px] font-semibold text-purple-300 bg-purple-500/10 border border-purple-500/30 rounded px-1.5 py-0.5">
            用户创建
          </span>
        )}
      </div>
      <p className="text-xs text-slate-500 line-clamp-2 min-h-8">{checker.description || "暂无描述"}</p>
    </button>
  );
}

function CheckerDetail({
  checker,
  onViewScan,
  showCreator,
}: {
  checker: CheckerDashboardStats;
  onViewScan: (scanId: string) => void;
  showCreator: boolean;
}) {
  return (
    <div className="border border-slate-800 bg-slate-900/70 rounded-lg overflow-hidden">
      <div className="px-5 py-4 border-b border-slate-800">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <h2 className="text-lg font-semibold text-white">{checker.label}</h2>
              <span className="text-xs font-semibold text-slate-400 bg-slate-800 px-2 py-0.5 rounded">
                {checker.checker.toUpperCase()}
              </span>
            </div>
            <p className="text-sm text-slate-400 max-w-3xl">{checker.description || "暂无描述"}</p>
          </div>
          <div className="flex flex-wrap justify-end gap-5 text-right">
            <div>
              <div className="text-3xl font-semibold text-emerald-300">
                {formatAccuracy(checker.accuracy)}
              </div>
              <div className="text-xs text-slate-500">
                人工准确率：{checker.human_confirmed_count}/{checker.accuracy_basis_count}
              </div>
            </div>
            <div>
              <div className="text-3xl font-semibold text-blue-300">
                {formatAccuracy(checker.ticket_accuracy)}
              </div>
              <div className="text-xs text-slate-500">
                提单准确率：{checker.ticket_submitted_count}/{checker.accuracy_basis_count}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-7 border-b border-slate-800">
        <DetailStat label="扫描项目" value={checker.project_count} />
        <DetailStat label="扫描次数" value={checker.scan_count} />
        <DetailStat label="静态报告问题" value={checker.static_issue_count} />
        <DetailStat label="LLM 判定问题" value={checker.llm_issue_count} />
        <DetailStat label="FP 复核真问题" value={checker.fp_review_issue_count} tone="red" />
        <DetailStat label="FP 复核误报" value={checker.fp_review_false_positive_count} tone="amber" />
        <DetailStat label="已提单" value={checker.ticket_submitted_count} tone="blue" />
      </div>

      <div className="px-5 py-4 border-b border-slate-800">
        <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">扫描过的项目</h3>
        {checker.projects.length === 0 ? (
          <span className="text-sm text-slate-500">暂无项目</span>
        ) : (
          <div className="flex flex-wrap gap-2">
            {checker.projects.map((project) => (
              <span
                key={project}
                className="text-xs text-slate-300 bg-slate-800 border border-slate-700 rounded px-2 py-1 max-w-xs truncate"
                title={project}
              >
                {project}
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="overflow-x-auto">
        <table className={`w-full text-sm ${showCreator ? "min-w-[76rem]" : "min-w-[70rem]"}`}>
          <thead>
            <tr className="bg-slate-950/40 border-b border-slate-800">
              <Th>扫描</Th>
              <Th className="w-24 min-w-[6rem]">状态</Th>
              <Th>项目</Th>
              <Th>产品</Th>
              <Th>静态</Th>
              <Th>LLM 问题</Th>
              <Th>FP 真/误</Th>
              <Th>人工真/误</Th>
              <Th>已提单</Th>
              <Th>人工准确率</Th>
              <Th>提单准确率</Th>
              {showCreator && <Th>创建者</Th>}
              <Th>时间</Th>
            </tr>
          </thead>
          <tbody>
            {checker.scans.length === 0 ? (
              <tr>
                <td colSpan={showCreator ? 13 : 12} className="px-4 py-10 text-center text-sm text-slate-500">
                  这个 SKILL 还没有扫描记录
                </td>
              </tr>
            ) : (
              checker.scans.map((scan) => (
                <ScanRow key={scan.scan_id} scan={scan} onViewScan={onViewScan} showCreator={showCreator} />
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ScanRow({
  scan,
  onViewScan,
  showCreator,
}: {
  scan: CheckerScanDashboardStats;
  onViewScan: (scanId: string) => void;
  showCreator: boolean;
}) {
  const st = STATUS_STYLES[scan.status];
  const project = scan.scan_name || scan.project_id;
  return (
    <tr className="border-b border-slate-800/70 hover:bg-slate-800/40 transition-colors">
      <td className="px-4 py-3">
        <button
          onClick={() => onViewScan(scan.scan_id)}
          className="font-mono text-xs text-blue-400 hover:text-blue-300"
        >
          {scan.scan_id.slice(0, 8)}
        </button>
      </td>
      <td className="px-4 py-3 w-24 min-w-[6rem]">
        <span className={`inline-flex min-w-[3.5rem] justify-center whitespace-nowrap text-xs font-semibold px-2 py-0.5 rounded border ${st.cls}`}>
          {st.label}
        </span>
      </td>
      <td className="px-4 py-3 text-xs text-slate-300 max-w-[12rem] truncate" title={scan.project_path || project}>
        {project || "-"}
      </td>
      <td className="px-4 py-3 text-xs text-slate-300 whitespace-nowrap">{scan.product || "未配置"}</td>
      <td className="px-4 py-3 text-slate-300">{scan.static_issue_count}</td>
      <td className="px-4 py-3 text-slate-300">{scan.llm_issue_count}</td>
      <td className="px-4 py-3 text-xs">
        <span className="text-red-300">{scan.fp_review_issue_count}</span>
        <span className="text-slate-600 mx-1">/</span>
        <span className="text-amber-300">{scan.fp_review_false_positive_count}</span>
      </td>
      <td className="px-4 py-3 text-xs">
        <span className="text-emerald-300">{scan.human_confirmed_count}</span>
        <span className="text-slate-600 mx-1">/</span>
        <span className="text-slate-400">{scan.human_false_positive_count}</span>
      </td>
      <td className="px-4 py-3 text-blue-300">{scan.ticket_submitted_count}</td>
      <td className="px-4 py-3">
        <span className={hasAccuracy(scan.accuracy) ? "text-xs font-semibold text-emerald-300" : "text-xs text-slate-500"}>
          {formatAccuracy(scan.accuracy)}
        </span>
      </td>
      <td className="px-4 py-3">
        <span className={hasAccuracy(scan.ticket_accuracy) ? "text-xs font-semibold text-blue-300" : "text-xs text-slate-500"}>
          {formatAccuracy(scan.ticket_accuracy)}
        </span>
      </td>
      {showCreator && <td className="px-4 py-3 text-xs text-slate-400">{scan.username || "-"}</td>}
      <td className="px-4 py-3 text-xs text-slate-500 whitespace-nowrap">{formatTime(scan.created_at)}</td>
    </tr>
  );
}

function DetailStat({
  label,
  value,
  tone = "slate",
}: {
  label: string;
  value: number;
  tone?: "slate" | "red" | "amber" | "blue";
}) {
  const valueCls =
    tone === "red"
      ? "text-red-300"
      : tone === "amber"
        ? "text-amber-300"
        : tone === "blue"
          ? "text-blue-300"
          : "text-white";
  return (
    <div className="px-5 py-4 border-r border-slate-800 last:border-r-0">
      <div className="text-xs text-slate-500 mb-1">{label}</div>
      <div className={`text-xl font-semibold ${valueCls}`}>{value}</div>
    </div>
  );
}

function Th({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <th className={`text-left px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider whitespace-nowrap ${className}`}>
      {children}
    </th>
  );
}

function hasAccuracy(value: number | null | undefined): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function formatAccuracy(value: number | null | undefined) {
  if (!hasAccuracy(value)) return "-";
  return `${Math.round(value * 100)}%`;
}

function formatTime(iso: string) {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function formatTokenCount(value: number) {
  return new Intl.NumberFormat("zh-CN").format(value || 0);
}
