import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { getScanPatternTaskDetail, getScanTaskDetail, getScanTasksPage } from "../../api/client";
import { compareTaskHistory } from "../../taskOrder";
import type { ThreatAuditTask, ThreatPatternAuditTask } from "../../types";

export interface IterativeAuditDetailCache {
  tasks: Map<string, ThreatPatternAuditTask>;
  history: Map<string, Record<string, unknown> | null>;
  prompts: Map<string, Record<string, unknown>>;
}

export function createIterativeAuditDetailCache(): IterativeAuditDetailCache {
  return { tasks: new Map(), history: new Map(), prompts: new Map() };
}

interface RuntimeTask {
  id: string;
  status: string;
  modelId: string;
  task: Record<string, unknown>;
}

function stringValue(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const [failed, setFailed] = useState(false);
  return <button type="button" aria-label={label}
    className="shrink-0 text-xs text-cyan-300 hover:text-cyan-200"
    onClick={() => {
      void Promise.resolve().then(() => navigator.clipboard.writeText(value)).then(() => { setCopied(true); setFailed(false); })
        .catch(() => setFailed(true));
    }}>{failed ? "复制失败" : copied ? "已复制" : "复制"}</button>;
}

export function IterativeAuditTaskDetail({
  scanId, historyAvailable, task, runtime, statusLabel, statusBadge, results,
  nextTask, cache, onSelectTask,
}: {
  scanId: string;
  historyAvailable: boolean;
  task: ThreatAuditTask;
  runtime: RuntimeTask | null;
  statusLabel: string;
  statusBadge: ReactNode;
  results: ReactNode;
  nextTask?: ThreatAuditTask;
  cache: IterativeAuditDetailCache;
  onSelectTask: (taskId: string, loaded?: ThreatPatternAuditTask) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [executionExpanded, setExecutionExpanded] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [details, setDetails] = useState<ThreatPatternAuditTask | null>(null);
  const [parent, setParent] = useState<ThreatPatternAuditTask | null>(null);
  const [detailError, setDetailError] = useState(false);
  const [navigationLoading, setNavigationLoading] = useState(false);
  const navigationController = useRef<AbortController | null>(null);
  useEffect(() => () => navigationController.current?.abort(), []);
  const [history, setHistory] = useState<{ key: string; task: Record<string, unknown> | null; error: boolean } | null>(null);
  const [body, setBody] = useState<{ key: string; task: Record<string, unknown> | null; error: boolean } | null>(null);
  const runtimeRef = useRef(runtime);
  runtimeRef.current = runtime;
  const lookupKey = JSON.stringify([scanId, task.task_id, task.updated_at, task.status,
    runtime?.id, runtime?.task.revision, runtime?.task.record_id, runtime?.status]);
  const notGenerated = runtime?.status === "planned" || (!runtime && task.status === "pending");

  useEffect(() => {
    if (!historyAvailable) return;
    const controller = new AbortController();
    setDetailError(false);
    const load = async (id: string, revision?: string): Promise<ThreatPatternAuditTask> => {
      const cached = cache.tasks.get(`${scanId}:${id}`);
      // The child can be created after its completed parent's last update.
      const childNotCreatedYet = cached?.has_more_findings === true && (cached.iteration || 1) < 3
        && Boolean(cached.followup_clues?.trim()) && !cached.next_task_id;
      if (cached && !childNotCreatedYet && (!revision || cached.updated_at === revision)) return cached;
      const loaded = await getScanPatternTaskDetail(scanId, id, controller.signal);
      if (!controller.signal.aborted) cache.tasks.set(`${scanId}:${id}`, loaded);
      return loaded;
    };
    void Promise.allSettled([
      load(task.task_id, task.updated_at),
      task.parent_task_id ? load(task.parent_task_id) : Promise.resolve(null),
    ]).then(([own, previous]) => {
      if (controller.signal.aborted) return;
      if (own.status === "fulfilled") setDetails(own.value);
      if (previous.status === "fulfilled") setParent(previous.value);
      setDetailError(own.status === "rejected" || previous.status === "rejected");
    });
    return () => controller.abort();
  }, [scanId, task.task_id, task.updated_at, task.parent_task_id, historyAvailable, cache, attempt]);

  useEffect(() => {
    if (!historyAvailable || runtimeRef.current || notGenerated) return;
    if (cache.history.has(lookupKey)) {
      setHistory({ key: lookupKey, task: cache.history.get(lookupKey) ?? null, error: false });
      return;
    }
    const controller = new AbortController();
    const load = async () => {
      let cursor: string | null = null;
      let matched: Record<string, unknown> | null = null;
      do {
        const page = await getScanTasksPage(scanId, cursor, task.task_id, controller.signal);
        matched = page.items.filter((item) => item.task_name === task.task_id
          && (!item.scope_id || item.scope_id === scanId)).sort(compareTaskHistory)[0] ?? null;
        if (page.next_cursor && page.next_cursor === cursor) throw new Error("任务游标未前进");
        cursor = page.next_cursor;
      } while (!matched && cursor && !controller.signal.aborted);
      if (!controller.signal.aborted) {
        cache.history.set(lookupKey, matched);
        setHistory({ key: lookupKey, task: matched, error: false });
      }
    };
    void load().catch(() => {
      if (!controller.signal.aborted) setHistory({ key: lookupKey, task: null, error: true });
    });
    return () => controller.abort();
  }, [lookupKey, scanId, task.task_id, historyAvailable, notGenerated, cache, attempt]);

  const loadedHistory = history?.key === lookupKey ? history : null;
  const record = runtime ? { ...runtime.task, task_id: runtime.id } : loadedHistory?.task;
  const recordRef = useRef(record);
  recordRef.current = record;
  const recordKey = record ? JSON.stringify([scanId, record.task_id, record.record_id, record.revision,
    // Older records without a revision still need invalidation when this task changes.
    record.record_id || record.revision ? null : lookupKey]) : "";
  const inlinePrompt = stringValue(record?.prompt);
  useEffect(() => {
    if ((!expanded && !executionExpanded) || !recordKey || !recordRef.current) return;
    if ((!expanded || inlinePrompt) && (!executionExpanded || recordRef.current.token_usage)) return;
    const cached = cache.prompts.get(recordKey);
    if (cached) { setBody({ key: recordKey, task: cached, error: false }); return; }
    const controller = new AbortController();
    void getScanTaskDetail(scanId, recordRef.current, controller.signal).then((loaded) => {
      if (controller.signal.aborted) return;
      cache.prompts.set(recordKey, loaded);
      setBody({ key: recordKey, task: loaded, error: false });
    }).catch(() => {
      if (!controller.signal.aborted) setBody({ key: recordKey, task: null, error: true });
    });
    return () => controller.abort();
  }, [expanded, executionExpanded, inlinePrompt, recordKey, scanId, cache, attempt]);

  const loadedBody = body?.key === recordKey ? body : null;
  const prompt = inlinePrompt || stringValue(loadedBody?.task?.prompt);
  const selected = details?.task_id === task.task_id ? details : task;
  const sessionId = stringValue(record?.serve_session_id) || selected.output_source?.serve_session_id || "";
  const model = runtime?.modelId || stringValue(record?.model) || stringValue(record?.model_id)
    || selected.output_source?.model || selected.output_source?.model_id || "—";
  const inputClues = parent?.followup_clues || "";
  const outputClues = selected.followup_clues || "";
  const nextId = nextTask?.task_id || details?.next_task_id;
  const rawTokenUsage = loadedBody?.task?.token_usage || record?.token_usage;
  const tokenUsage = rawTokenUsage && typeof rawTokenUsage === "object"
    ? rawTokenUsage as Record<string, unknown> : null;
  const retry = () => setAttempt((value) => value + 1);
  const navigate = async (id: string, loaded?: ThreatPatternAuditTask | null) => {
    if (loaded) { onSelectTask(id, loaded); return; }
    const cached = cache.tasks.get(`${scanId}:${id}`);
    if (cached) { onSelectTask(id, cached); return; }
    navigationController.current?.abort();
    const controller = new AbortController();
    navigationController.current = controller;
    setNavigationLoading(true);
    try {
      const target = await getScanPatternTaskDetail(scanId, id, controller.signal);
      if (controller.signal.aborted) return;
      cache.tasks.set(`${scanId}:${id}`, target);
      onSelectTask(id, target);
    } catch { if (!controller.signal.aborted) setDetailError(true); }
    finally { if (!controller.signal.aborted) setNavigationLoading(false); }
  };
  return <div className="max-h-[72vh] space-y-4 overflow-y-auto p-4">
    <div className="space-y-2 border-b border-slate-800 pb-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="shrink-0 rounded bg-cyan-500/15 px-2 py-0.5 text-xs font-medium text-cyan-300">第 {task.iteration || 1} 轮</span>
        {statusBadge}
        <span className="break-words text-sm font-semibold text-slate-100">{task.method_name}</span>
      </div>
      <div className="break-words text-sm text-slate-300">{task.surface_name}</div>
      <div className="text-xs text-slate-400">模型：<span className="break-all text-slate-200">{model}</span></div>
      <div className="flex items-start gap-2 text-xs text-slate-400">
        <span className="shrink-0">Session：</span>
        <span className="min-w-0 break-all font-mono text-slate-200">{sessionId || "尚无记录"}</span>
        {sessionId && <CopyButton value={sessionId} label="复制 Session ID" />}
      </div>
      {(task.parent_task_id || nextId) && <div className="flex flex-wrap gap-4 text-xs text-cyan-300">
        {task.parent_task_id && <button type="button" disabled={navigationLoading} onClick={() => void navigate(task.parent_task_id!, parent)}>上一轮 · 第 {Math.max(1, (task.iteration || 1) - 1)} 轮</button>}
        {nextId && <button type="button" disabled={navigationLoading} onClick={() => nextTask ? onSelectTask(nextTask.task_id) : void navigate(nextId)}>下一轮 · 第 {nextTask?.iteration || (task.iteration || 1) + 1} 轮</button>}
      </div>}
    </div>
    <section><h4 className="mb-2 text-xs font-semibold text-slate-400">审计结果</h4>{results}</section>
    {selected.has_more_findings != null && <p className="text-xs text-slate-400">
      其他同类问题：{selected.has_more_findings ? "可能存在" : "未发现"}
    </p>}
    {inputClues.trim() && <Clue title="审计时参考线索" value={inputClues} />}
    {outputClues.trim() && <Clue title="后续线索" value={outputClues} />}
    {selected.failure_reason && <p className="whitespace-pre-wrap break-words text-xs text-red-300">{selected.failure_reason}</p>}
    {(detailError || loadedHistory?.error) && <button type="button" onClick={retry} className="text-xs text-amber-300">部分任务详情加载失败，点击重试</button>}
    <details open={expanded} onToggle={(event) => setExpanded(event.currentTarget.open)} className="rounded border border-slate-800 p-3">
      <summary className="cursor-pointer text-xs font-semibold text-slate-400">完整 Prompt</summary>
      {expanded && <div className="mt-3">
        {prompt ? <>
          <div className="mb-2 flex justify-end"><CopyButton value={prompt} label="复制完整 Prompt" /></div>
          <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words font-mono text-xs leading-relaxed text-slate-300 [overflow-wrap:anywhere]">{prompt}</pre>
        </> : loadedBody?.error || loadedHistory?.error ? <button type="button" onClick={retry} className="text-xs text-amber-300">完整 Prompt 加载失败，点击重试</button>
          : notGenerated ? <p className="text-xs text-slate-500">Prompt 尚未生成，进入排队或运行后显示。</p>
            : record && !loadedBody || historyAvailable && !runtime && !loadedHistory ? <p className="text-xs text-slate-400">正在读取完整 Prompt…</p>
              : <p className="text-xs text-slate-500">该任务记录未保存完整 Prompt。</p>}
      </div>}
    </details>
    <details open={executionExpanded} onToggle={(event) => setExecutionExpanded(event.currentTarget.open)} className="rounded border border-slate-800 p-3">
      <summary className="cursor-pointer text-xs font-semibold text-slate-400">执行信息与 Token</summary>
      <dl className="mt-3 space-y-2 break-all text-xs text-slate-400">
        {[["任务", task.task_id], ["状态", statusLabel], ["开始时间", selected.started_at], ["结束时间", selected.finished_at],
          ["代码路径", (selected.code_paths || []).map((item) => item.path).join("\n")],
          ["记录", record?.record_id], ["修订", record?.revision],
        ].filter(([, value]) => value != null && value !== "").map(([label, value]) => <div key={String(label)}>
          <dt className="mb-1 text-slate-500">{String(label)}</dt><dd className="whitespace-pre-wrap">{String(value)}</dd>
        </div>)}
        {tokenUsage && <div><dt className="mb-1 text-slate-500">Token</dt><dd className="flex flex-wrap gap-x-4 gap-y-1">
          {[["输入", "input_tokens"], ["输出", "output_tokens"], ["推理", "reasoning_tokens"], ["缓存读", "cache_read_tokens"], ["缓存写", "cache_write_tokens"], ["总计", "total_tokens"]]
            .map(([label, field]) => <span key={field}>{label} {Number(tokenUsage[field] || 0).toLocaleString("zh-CN")}</span>)}
        </dd></div>}
        {executionExpanded && !tokenUsage && <div><dt className="mb-1 text-slate-500">Token</dt><dd>
          {loadedBody?.error ? <button type="button" onClick={retry} className="text-amber-300">加载失败，点击重试</button>
            : record && !loadedBody ? "正在读取 Token 用量…" : "未记录 Token 用量"}
        </dd></div>}
      </dl>
    </details>
  </div>;
}

function Clue({ title, value }: { title: string; value: string }) {
  return <section><h4 className="mb-2 text-xs font-semibold text-slate-400">{title}</h4>
    <p className="whitespace-pre-wrap break-words rounded border border-slate-800 bg-slate-950/50 p-3 text-xs text-slate-300">{value}</p>
  </section>;
}
