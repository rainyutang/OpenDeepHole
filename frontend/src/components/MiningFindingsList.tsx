import { useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { markVulnerability } from "../api/client";
import type { Vulnerability } from "../types";

const SEVERITY_STYLES: Record<string, string> = {
  high: "bg-red-500/20 text-red-400 border-red-500/30",
  medium: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  low: "bg-green-500/20 text-green-400 border-green-500/30",
};

const SEVERITY_LABEL: Record<string, string> = { high: "高危", medium: "中危", low: "低危" };

function severityStyle(sev: string): string {
  return SEVERITY_STYLES[sev] || "bg-slate-600/30 text-slate-300 border-slate-500/30";
}

interface Props {
  scanId: string;
  vulnerabilities: Vulnerability[];
  onChanged?: () => void;
}

type SevFilter = "all" | "high" | "medium" | "low";
type ConfFilter = "all" | "pending" | "confirmed" | "not_confirmed";

function verdictBadge(v: Vulnerability): { label: string; cls: string } {
  if (v.ai_verdict === "pending_verify") {
    return { label: "待验证", cls: "bg-sky-500/20 text-sky-300 border-sky-500/30" };
  }
  if (v.confirmed) {
    return { label: "是问题", cls: "bg-red-500/20 text-red-300 border-red-500/30" };
  }
  return { label: "非问题", cls: "bg-slate-600/30 text-slate-400 border-slate-500/30" };
}

export default function MiningFindingsList({ scanId, vulnerabilities, onChanged }: Props) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const [sevFilter, setSevFilter] = useState<SevFilter>("all");
  const [confFilter, setConfFilter] = useState<ConfFilter>("all");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [marking, setMarking] = useState<number | null>(null);

  const vulnTypes = useMemo(
    () => Array.from(new Set(vulnerabilities.map((v) => v.vuln_type).filter(Boolean))).sort(),
    [vulnerabilities],
  );

  const rows = useMemo(() => {
    return vulnerabilities
      .map((v, index) => ({ v, index }))
      .filter(({ v }) => {
        if (sevFilter !== "all" && v.severity !== sevFilter) return false;
        if (typeFilter !== "all" && v.vuln_type !== typeFilter) return false;
        const pending = v.ai_verdict === "pending_verify";
        if (confFilter === "pending" && !pending) return false;
        if (confFilter === "confirmed" && (!v.confirmed || pending)) return false;
        if (confFilter === "not_confirmed" && (v.confirmed || pending)) return false;
        return true;
      });
  }, [vulnerabilities, sevFilter, confFilter, typeFilter]);

  const confirmedCount = vulnerabilities.filter((v) => v.confirmed).length;
  const pendingCount = vulnerabilities.filter((v) => v.ai_verdict === "pending_verify").length;

  const toggle = (i: number) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(i) ? next.delete(i) : next.add(i);
      return next;
    });

  const mark = async (index: number, verdict: "confirmed" | "false_positive") => {
    setMarking(index);
    try {
      await markVulnerability(scanId, index, verdict, "");
      onChanged?.();
    } catch {
      /* ignore */
    } finally {
      setMarking(null);
    }
  };

  if (vulnerabilities.length === 0) {
    return (
      <div className="rounded-xl border border-slate-700 bg-slate-800/50 px-6 py-16 text-center text-slate-500">
        暂无发现。挖掘进行中时，验证 Agent 确认或否定的结论会实时出现在这里。
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <span className="text-slate-400">
          共 {vulnerabilities.length} 条，确认 <span className="text-red-400 font-semibold">{confirmedCount}</span> 条
          ，待验证 <span className="text-sky-300 font-semibold">{pendingCount}</span> 条
        </span>
        <select
          value={confFilter}
          onChange={(e) => setConfFilter(e.target.value as ConfFilter)}
          className="bg-slate-900 border border-slate-600 rounded-lg px-2 py-1 text-xs text-slate-200"
        >
          <option value="all">全部判定</option>
          <option value="pending">待验证</option>
          <option value="confirmed">是问题</option>
          <option value="not_confirmed">非问题</option>
        </select>
        <select
          value={sevFilter}
          onChange={(e) => setSevFilter(e.target.value as SevFilter)}
          className="bg-slate-900 border border-slate-600 rounded-lg px-2 py-1 text-xs text-slate-200"
        >
          <option value="all">全部严重度</option>
          <option value="high">高危</option>
          <option value="medium">中危</option>
          <option value="low">低危</option>
        </select>
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="bg-slate-900 border border-slate-600 rounded-lg px-2 py-1 text-xs text-slate-200"
        >
          <option value="all">全部类型</option>
          {vulnTypes.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
      </div>

      {/* Findings */}
      <div className="space-y-2">
        {rows.map(({ v, index }) => {
          const open = expanded.has(index);
          return (
            <div key={index} className="rounded-xl border border-slate-700 bg-slate-800/60 overflow-hidden">
              <button
                onClick={() => toggle(index)}
                className="w-full flex items-start gap-3 px-4 py-3 text-left hover:bg-slate-800 transition-colors"
              >
                <span className={`mt-0.5 text-[11px] font-semibold px-2 py-0.5 rounded border ${severityStyle(v.severity)}`}>
                  {SEVERITY_LABEL[v.severity] || v.severity}
                </span>
                <span className="mt-0.5 text-[11px] font-semibold px-2 py-0.5 rounded border bg-cyan-500/10 text-cyan-200 border-cyan-500/30">
                  {v.vuln_type}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-slate-200 truncate">
                    <span className="font-mono">{v.file}:{v.line}</span>
                    <span className="text-slate-500"> · </span>
                    <span className="text-slate-300">{v.function}</span>
                  </div>
                  {v.description && (
                    <div className="text-xs text-slate-400 mt-0.5 truncate">{v.description}</div>
                  )}
                </div>
                {(() => {
                  const b = verdictBadge(v);
                  return (
                    <span className={`mt-0.5 text-[11px] font-semibold px-2 py-0.5 rounded border ${b.cls}`}>
                      {b.label}
                    </span>
                  );
                })()}
                {v.user_verdict === "confirmed" && (
                  <span className="mt-0.5 text-[11px] text-red-300">已人工确认</span>
                )}
                {v.user_verdict === "false_positive" && (
                  <span className="mt-0.5 text-[11px] text-green-300">已标误报</span>
                )}
                <span className="mt-0.5 text-slate-500 text-xs">{open ? "▲" : "▼"}</span>
              </button>

              {open && (
                <div className="px-4 pb-4 pt-1 space-y-3 border-t border-slate-700/60">
                  {v.description && (
                    <div>
                      <div className="text-xs font-semibold text-slate-400 mb-1">摘要</div>
                      <div className="text-sm text-slate-300">{v.description}</div>
                    </div>
                  )}
                  {v.ai_analysis && (
                    <div>
                      <div className="text-xs font-semibold text-slate-400 mb-1">分析推理</div>
                      <div className="prose prose-invert prose-sm max-w-none bg-slate-900 rounded-lg px-3 py-2 max-h-96 overflow-auto">
                        <ReactMarkdown remarkPlugins={[remarkGfm]}>{v.ai_analysis}</ReactMarkdown>
                      </div>
                    </div>
                  )}
                  {v.function_source && (
                    <div>
                      <div className="text-xs font-semibold text-slate-400 mb-1">
                        函数源码{v.function_start_line ? `（起始行 ${v.function_start_line}）` : ""}
                      </div>
                      <pre className="text-xs bg-slate-900 rounded-lg px-3 py-2 max-h-96 overflow-auto text-slate-300">
                        {v.function_source}
                      </pre>
                    </div>
                  )}
                  <div className="flex gap-2 pt-1">
                    <button
                      disabled={marking === index}
                      onClick={() => mark(index, "confirmed")}
                      className="px-3 py-1.5 text-xs font-medium text-red-200 bg-red-500/10 border border-red-500/30 rounded-lg hover:bg-red-500/20 disabled:opacity-50"
                    >
                      确认为真实漏洞
                    </button>
                    <button
                      disabled={marking === index}
                      onClick={() => mark(index, "false_positive")}
                      className="px-3 py-1.5 text-xs font-medium text-green-200 bg-green-500/10 border border-green-500/30 rounded-lg hover:bg-green-500/20 disabled:opacity-50"
                    >
                      标记为误报
                    </button>
                  </div>
                  {v.user_verdict_reason && (
                    <div className="text-xs text-slate-500">人工备注：{v.user_verdict_reason}</div>
                  )}
                </div>
              )}
            </div>
          );
        })}
        {rows.length === 0 && (
          <div className="text-center text-sm text-slate-500 py-8">没有符合筛选条件的发现。</div>
        )}
      </div>
    </div>
  );
}
