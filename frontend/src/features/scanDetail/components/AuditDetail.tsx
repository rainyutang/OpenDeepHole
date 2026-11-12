import { useEffect, useRef, useState } from "react";
import { getScanTaskDetail, getScanTasksPage } from "../../../api/scanDetails";
import { compareTaskHistory } from "../../../taskOrder";
import type { ScanStatus as ScanStatusType } from "../../../types/scans";
import { scanQueueTaskPrompt } from "../model/taskQueue";
import type { ScanQueueTask } from "../model/types";

export function AuditPromptSection({ scan, taskName, runtime, pending = false, taskRevision = "" }: {
  scan: ScanStatusType;
  taskName: string;
  runtime: ScanQueueTask | null;
  pending?: boolean;
  taskRevision?: string;
}) {
  const inlinePrompt = runtime ? scanQueueTaskPrompt(runtime.task) : "";
  const notGenerated = runtime?.status === "planned" || (!runtime && pending);
  const canLoadHistory = Boolean(scan.detail_counts) && !inlinePrompt && !notGenerated
    && !["queued", "running"].includes(runtime?.status ?? "");
  const lookupKey = JSON.stringify([scan.scan_id, taskName, runtime?.id, runtime?.task.revision,
  runtime?.task.record_id, runtime?.status, taskRevision]);
  const runtimeRef = useRef(runtime);
  runtimeRef.current = runtime;
  const [attempt, setAttempt] = useState(0);
  const [history, setHistory] = useState<{ key: string; task: Record<string, unknown> | null; error: boolean; } | null>(null);
  useEffect(() => {
    if (!canLoadHistory) return;
    const controller = new AbortController();
    setHistory(null);
    const load = async () => {
      let task = runtimeRef.current?.task ?? null;
      if (!task) {
        const matches: Record<string, unknown>[] = [];
        let cursor: string | null = null;
        do {
          const page = await getScanTasksPage(scan.scan_id, cursor, taskName, controller.signal);
          matches.push(...page.items.filter((item) => item.task_name === taskName
            && (!item.scope_id || item.scope_id === scan.scan_id)));
          if (page.next_cursor && page.next_cursor === cursor) throw new Error("任务游标未前进");
          cursor = page.next_cursor;
        } while (cursor && !controller.signal.aborted);
        task = matches.sort(compareTaskHistory)[0] ?? null;
      }
      const detail = task && !controller.signal.aborted
        ? await getScanTaskDetail(scan.scan_id, task, controller.signal) : null;
      if (!controller.signal.aborted) setHistory({ key: lookupKey, task: detail, error: false });
    };
    void load().catch(() => {
      if (!controller.signal.aborted) setHistory({ key: lookupKey, task: null, error: true });
    });
    return () => controller.abort();
  }, [canLoadHistory, lookupKey, scan.scan_id, taskName, attempt]);
  const loaded = history?.key === lookupKey ? history : null;
  const prompt = inlinePrompt || (canLoadHistory && loaded?.task ? scanQueueTaskPrompt(loaded.task) : "");
  return (
    <AuditDetailSection title="Prompt">
      {prompt ? (
        <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words rounded border border-slate-800 bg-slate-950 p-3 font-mono text-xs leading-relaxed text-slate-300 [overflow-wrap:anywhere]">
          {prompt}
        </pre>
      ) : canLoadHistory && !loaded ? (
        <p className="text-xs text-slate-400">正在读取完整 Prompt…</p>
      ) : canLoadHistory && loaded?.error ? (
        <button type="button" className="text-xs text-amber-300" onClick={() => setAttempt((value) => value + 1)}>
          完整 Prompt 加载失败，点击重试
        </button>
      ) : (
        <div className="rounded border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-500">
          {notGenerated ? "Prompt 尚未生成，进入排队或运行后显示。"
            : runtime || loaded?.task ? "该任务记录未保存完整 Prompt。" : "尚未匹配到该任务的 OpenCode 队列或历史记录。"}
        </div>
      )}
    </AuditDetailSection>
  );
}

export function AuditDetailSection({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section>
      <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">{title}</h4>
      {children}
    </section>
  );
}

export function DetailGrid({ items }: { items: Array<[string, string]>; }) {
  return (
    <dl className="grid grid-cols-1 gap-2 sm:grid-cols-2">
      {items.map(([label, value]) => (
        <div key={label} className="rounded border border-slate-800 bg-slate-950/60 px-3 py-2">
          <dt className="text-[10px] uppercase tracking-wide text-slate-600">{label}</dt>
          <dd className="mt-1 break-all text-xs text-slate-300">{value}</dd>
        </div>
      ))}
    </dl>
  );
}
