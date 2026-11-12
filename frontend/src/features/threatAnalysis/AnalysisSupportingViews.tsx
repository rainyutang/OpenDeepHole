import type { ScanEvent } from "../../types/scans";
import type { ThreatAnalysis } from "../../types/threatAnalysis";

import { displayValue, isRecord } from './analysisModel';

export function ThreatAnalysisError({
  methodLabel,
  message,
}: {
  methodLabel: string;
  message: string;
}) {
  return (
    <section className="threat-analysis-viewer__error" role="alert">
      <strong>{methodLabel}执行失败</strong>
      <p>{message}</p>
    </section>
  );
}

export function PanelHeading({
  title,
  count,
  unit,
}: {
  title: string;
  count: number;
  unit: "项" | "棵";
}) {
  return (
    <div className="threat-analysis-viewer__panel-heading">
      <h3>{title}</h3>
      <output>{count} {unit}</output>
    </div>
  );
}

export function ArtifactPaths({ analysis }: { analysis: ThreatAnalysis }) {
  const artifacts = isRecord(analysis.artifacts) ? analysis.artifacts : {};
  return (
    <details className="rounded-lg border border-slate-800 bg-slate-900/60">
      <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-slate-300">
        原生产物
      </summary>
      <div className="space-y-2 border-t border-slate-800 p-4">
        {Object.entries(artifacts).map(([key, artifact]) => (
          isRecord(artifact) && (
            <div key={key} className="flex flex-wrap gap-2 text-xs">
              <span className="text-slate-500">{key}</span>
              <code className="break-all text-cyan-200">{displayValue(artifact.path)}</code>
            </div>
          )
        ))}
      </div>
    </details>
  );
}

export function ThreatEventList({ events }: { events: ScanEvent[] }) {
  if (events.length === 0) return null;
  return (
    <details className="rounded-lg border border-slate-800 bg-slate-900/60">
      <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-slate-300">
        运行日志 · {events.length}
      </summary>
      <div className="max-h-64 divide-y divide-slate-800 overflow-auto border-t border-slate-800 px-4">
        {events.map((event, index) => (
          <div key={`${event.timestamp}-${index}`} className="py-2 text-xs">
            <span className="mr-2 text-slate-600">{event.timestamp}</span>
            <span className="mr-2 text-cyan-300">{event.phase}</span>
            <span className="text-slate-300">{event.message}</span>
          </div>
        ))}
      </div>
    </details>
  );
}

export function EmptyState({ text }: { text: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-5 text-sm text-slate-400">
      {text}
    </div>
  );
}
