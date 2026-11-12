import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import type { FpReviewResult } from "../../types/fpReview";
import type { OutputSource } from "../../types/issues";
import type { FilterOption } from "./model";
import { isEffectiveFpReviewResult } from "../../fpReview";
import { ALL_FILTER } from "./model";

export function hasOutputSource(source?: OutputSource | null): boolean {
  return Boolean(source && (
    source.agent_name
    || source.agent_id
    || source.model
    || source.model_id
    || source.tool
    || source.serve_session_id
  ));
}

export function formatOutputSource(source?: OutputSource | null): string {
  if (!hasOutputSource(source)) return "";
  const agent = source?.agent_name || source?.agent_id || "未知 Agent";
  const tool = source?.tool || source?.backend || "AI";
  const model = source?.model
    || (source?.use_default_model ? "CLI 默认模型" : (source?.model_id || "默认模型"));
  const modelId = source?.model_id && source.model_id !== model ? `${source.model_id} / ${model}` : model;
  const sessionId = source?.serve_session_id?.trim();
  return [
    `${agent} · ${tool} · ${modelId}`,
    sessionId ? `OpenCode Session ID: ${sessionId}` : "",
  ].filter(Boolean).join(" · ");
}

export function OutputSourceLine({ source }: { source?: OutputSource | null }) {
  if (!hasOutputSource(source)) return null;
  const title = [
    source?.agent_id ? `Agent ID: ${source.agent_id}` : "",
    source?.agent_session_id ? `Agent Session ID: ${source.agent_session_id}` : "",
    source?.serve_session_id ? `OpenCode Session ID: ${source.serve_session_id}` : "",
    source?.task_id ? `Task: ${source.task_id}` : "",
    source?.attempt ? `Attempt: ${source.attempt}` : "",
    source?.capability ? `Capability: ${source.capability}` : "",
  ].filter(Boolean).join("\n");
  return (
    <div className="mb-2 text-[11px] text-cyan-300" title={title}>
      输出来源：{formatOutputSource(source)}
    </div>
  );
}

export function FpStatusBadge({
  fpResult,
  fpReviewRunning,
}: {
  fpResult?: FpReviewResult | null;
  fpReviewRunning?: boolean;
}) {
  if (!fpResult) return null;
  const hasFinal = isEffectiveFpReviewResult(fpResult);
  if (!hasFinal) {
    return (
      <span
        className={`text-[11px] font-semibold px-1.5 py-0.5 rounded border ${
          fpReviewRunning
            ? "bg-blue-500/20 text-blue-300 border-blue-500/30"
            : "bg-slate-600/30 text-slate-400 border-slate-500/40"
        }`}
      >
        {fpReviewRunning ? "复核中" : "复核失败"}
      </span>
    );
  }
  return (
    <span
      className={`text-[11px] font-semibold px-1.5 py-0.5 rounded border ${
        fpResult.verdict === "fp"
          ? "bg-amber-500/20 text-amber-400 border-amber-500/30"
          : "bg-red-500/20 text-red-400 border-red-500/30"
      }`}
    >
      {fpResult.verdict === "fp" ? "去误报：非问题" : "去误报：确认问题"}
    </span>
  );
}

export function MarkdownReport({ content }: { content: string }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={{
        h1: ({ children }) => <h1 className="mb-4 text-xl font-semibold text-white">{children}</h1>,
        h2: ({ children }) => <h2 className="mt-6 mb-2 text-base font-semibold text-blue-100">{children}</h2>,
        h3: ({ children }) => <h3 className="mt-4 mb-2 text-sm font-semibold text-slate-100">{children}</h3>,
        p: ({ children }) => <p className="my-2 whitespace-pre-wrap text-sm leading-7 text-slate-300">{children}</p>,
        ul: ({ children }) => <ul className="my-2 list-disc space-y-1 pl-5 text-sm leading-relaxed text-slate-300 marker:text-blue-400">{children}</ul>,
        ol: ({ children }) => <ol className="my-2 list-decimal space-y-1 pl-5 text-sm leading-relaxed text-slate-300 marker:text-blue-400">{children}</ol>,
        li: ({ children }) => <li>{children}</li>,
        table: ({ children }) => (
          <div className="my-3 overflow-x-auto rounded-lg border border-slate-800">
            <table className="w-full min-w-max text-sm">{children}</table>
          </div>
        ),
        thead: ({ children }) => <thead className="bg-slate-900">{children}</thead>,
        th: ({ children }) => <th className="border-b border-slate-800 px-3 py-2 text-left text-xs font-semibold text-slate-400">{children}</th>,
        tr: ({ children }) => <tr className="border-t border-slate-800/70 first:border-t-0">{children}</tr>,
        td: ({ children }) => <td className="px-3 py-2 text-slate-300">{children}</td>,
        pre: ({ children }) => (
          <pre className="my-3 overflow-x-auto rounded-lg border border-slate-700 bg-slate-950 p-4 text-xs leading-relaxed text-slate-300 [&_code]:border-0 [&_code]:bg-transparent [&_code]:p-0 [&_code]:text-slate-300">
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

export function FilterSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: FilterOption[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="inline-flex items-center gap-1.5 text-xs text-slate-400">
      <span>{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-1.5 text-xs text-slate-200 focus:border-blue-500 focus:outline-none"
      >
        <option value={ALL_FILTER}>全部</option>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label} ({option.count})
          </option>
        ))}
      </select>
    </label>
  );
}
