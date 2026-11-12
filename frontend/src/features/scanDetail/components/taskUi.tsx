import type { ScanEvent } from "../../../types/scans";
import { toneBg, toneBorder, toneFill, toneText } from "../model/formatting";
import { percent } from "../model/scan";
import type { TaskTone } from "../model/types";

export function TaskPanel({
  title,
  status,
  tone,
  summary,
  children,
}: {
  title: string;
  status: string;
  tone: TaskTone;
  summary: string;
  children: React.ReactNode;
}) {
  return (
    <section className="space-y-4 rounded-lg border border-slate-700 bg-slate-900/50 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-white">{title}</h2>
          <p className="mt-1 text-sm text-slate-400">{summary}</p>
        </div>
        <StatusPill label={status} tone={tone} />
      </div>
      {children}
    </section>
  );
}

export function TaskSummaryRow({
  label,
  status,
  tone,
  detail,
  progress,
}: {
  label: string;
  status: string;
  tone: TaskTone;
  detail: string;
  progress?: number;
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-sm font-medium text-slate-200">{label}</div>
          <div className="mt-0.5 text-xs text-slate-500">{detail}</div>
        </div>
        <StatusPill label={status} tone={tone} />
      </div>
      {progress !== undefined && <ProgressBar value={progress} tone={tone} className="mt-3" />}
    </div>
  );
}

export function ProgressBlock({
  label,
  current,
  total,
  fallback,
  percentOverride,
}: {
  label: string;
  current: number;
  total: number;
  fallback: string;
  percentOverride?: number;
}) {
  const value = percentOverride ?? percent(current, total);
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-xs text-slate-400">
        <span>{total > 0 ? `${label}: ${current}/${total}` : fallback}</span>
        {total > 0 || percentOverride !== undefined ? <span>{value}%</span> : null}
      </div>
      <ProgressBar value={total > 0 || percentOverride !== undefined ? value : 0} tone="blue" />
    </div>
  );
}

function ProgressBar({ value, tone, className = "" }: { value: number; tone: TaskTone; className?: string; }) {
  return (
    <div className={`h-1.5 overflow-hidden rounded-full bg-slate-800 ${className}`}>
      <div className={`h-full rounded-full transition-all duration-500 ${toneFill(tone)}`} style={{ width: `${value}%` }} />
    </div>
  );
}

export function EventList({ events, empty }: { events: ScanEvent[]; empty: string; }) {
  const visible = events.slice(-80);
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/50">
      <div className="border-b border-slate-800 px-3 py-2 text-xs font-semibold uppercase tracking-wider text-slate-500">任务日志</div>
      <div className="max-h-80 overflow-y-auto p-3 font-mono text-xs">
        {visible.length === 0 ? (
          <p className="text-slate-600">{empty}</p>
        ) : (
          <div className="space-y-1">
            {visible.map((event, index) => <EventLine key={`${event.timestamp}-${index}`} event={event} />)}
          </div>
        )}
      </div>
    </div>
  );
}

export function EmptyState({ text }: { text: string; }) {
  return <div className="rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-6 text-center text-sm text-slate-500">{text}</div>;
}

export function MiniMetric({ label, value, tone = "slate" }: { label: string; value: number; tone?: TaskTone; }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/50 px-3 py-3">
      <div className="text-xs text-slate-500">{label}</div>
      <div className={`mt-1 text-xl font-semibold ${toneText(tone)}`}>{value}</div>
    </div>
  );
}

export function StatusPill({ label, tone }: { label: string; tone: TaskTone; }) {
  return (
    <span className={`inline-flex rounded border px-2 py-0.5 text-xs font-semibold ${toneBorder(tone)} ${toneBg(tone)} ${toneText(tone)}`}>
      {label}
    </span>
  );
}

export function PanelIcon({ name }: { name: "target" | "alert" | "history" | "queue"; }) {
  if (name === "alert") {
    return (
      <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v4m0 4h.01M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      </svg>
    );
  }
  if (name === "history") {
    return (
      <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12a9 9 0 1 0 3-6.7M3 4v6h6m3-2v5l4 2" />
      </svg>
    );
  }
  if (name === "queue") {
    return (
      <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7h16M4 12h16M4 17h10" />
      </svg>
    );
  }
  return (
    <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6l4 2m5-2a9 9 0 1 1-18 0 9 9 0 0 1 18 0z" />
    </svg>
  );
}

export function EventLine({ event }: { event: ScanEvent; }) {
  const time = new Date(event.timestamp).toLocaleTimeString();

  const phaseColor: Record<string, string> = {
    init: "text-yellow-400",
    mcp_ready: "text-green-400",
    threat_analysis: "text-emerald-300",
    threat_audit: "text-cyan-300",
    static_analysis: "text-cyan-400",
    git_history: "text-purple-300",
    variant_hunt: "text-purple-400",
    auditing: "text-blue-400",
    opencode_output: "text-slate-500",
    fp_review: "text-amber-300",
    complete: "text-green-400",
    error: "text-red-400",
  };

  return (
    <div className="flex gap-2 leading-5">
      <span className="text-slate-600 shrink-0">{time}</span>
      <span className={`shrink-0 ${phaseColor[event.phase] ?? "text-slate-400"}`}>
        [{event.phase}]
      </span>
      <span className="text-slate-400 break-all">{event.message}</span>
    </div>
  );
}
