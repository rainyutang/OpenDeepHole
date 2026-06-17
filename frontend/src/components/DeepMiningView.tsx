import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getScanStatus, stopScan, downloadScanReport, listAgentRuns, getAgentRun } from "../api/client";
import type {
  FpReviewJob,
  IndexStatus,
  ScanItemStatus,
  ScanStatus as ScanStatusType,
  ScanEvent,
  MiningTask,
  MiningAgentRun,
} from "../types";
import { useScanSSE } from "../hooks/useScanSSE";
import type { ScanSSEHandlers, SSEStateSetters } from "../hooks/useScanSSE";
import MiningFindingsList from "./MiningFindingsList";

interface Props {
  scanId: string;
  onBack: () => void;
}

type Tab = "overview" | "agents" | "findings" | "log";

const STATUS_STYLES: Record<string, { cls: string; label: string }> = {
  pending: { cls: "bg-slate-600/30 text-slate-300 border-slate-500/30", label: "等待中" },
  analyzing: { cls: "bg-blue-500/20 text-blue-400 border-blue-500/30", label: "运行中" },
  auditing: { cls: "bg-blue-500/20 text-blue-400 border-blue-500/30", label: "挖掘中" },
  complete: { cls: "bg-green-500/20 text-green-400 border-green-500/30", label: "已完成" },
  error: { cls: "bg-red-500/20 text-red-400 border-red-500/30", label: "出错" },
  cancelled: { cls: "bg-slate-600/30 text-slate-400 border-slate-500/30", label: "已取消" },
};

const PHASE_LABEL: Record<string, string> = {
  indexing: "索引中", threat: "威胁分析", mining: "挖掘中", coverage: "覆盖率补扫", done: "已完成",
};

const KIND_META: Record<string, { label: string; cls: string }> = {
  threat: { label: "威胁分析", cls: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30" },
  analyze: { label: "挖掘", cls: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30" },
  verify: { label: "验证", cls: "bg-amber-500/15 text-amber-300 border-amber-500/30" },
};

const RUN_STATUS_META: Record<string, { label: string; cls: string }> = {
  running: { label: "运行中", cls: "text-blue-400" },
  done: { label: "完成", cls: "text-green-400" },
  error: { label: "失败", cls: "text-red-400" },
};

const MAX_LOG_LINES = 500;

function pct(n: number, d: number): number {
  if (!d) return 0;
  return Math.min(100, Math.round((n / d) * 100));
}

function elapsed(started?: string): string {
  if (!started) return "";
  const ms = Date.now() - new Date(started).getTime();
  if (Number.isNaN(ms) || ms < 0) return "";
  const s = Math.floor(ms / 1000);
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
}

function kindMeta(kind: string) {
  return KIND_META[kind] || { label: kind, cls: "bg-slate-600/30 text-slate-300 border-slate-500/30" };
}

export default function DeepMiningView({ scanId, onBack }: Props) {
  const [scan, setScan] = useState<ScanStatusType | null>(null);
  const [tab, setTab] = useState<Tab>("overview");
  const [stopping, setStopping] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [, setTick] = useState(0);
  const [, setFpReview] = useState<FpReviewJob | null>(null);
  const [, setIndexStatus] = useState<IndexStatus | null>(null);
  const [runs, setRuns] = useState<MiningAgentRun[]>([]);
  const [openRunId, setOpenRunId] = useState<string | null>(null);
  const [runDetail, setRunDetail] = useState<MiningAgentRun | null>(null);
  const logRef = useRef<HTMLDivElement>(null);
  const runOutRef = useRef<HTMLDivElement>(null);

  const dm = scan?.deep_mining_status ?? null;
  const isRunning = scan && (scan.status === "pending" || scan.status === "analyzing" || scan.status === "auditing");

  useEffect(() => {
    getScanStatus(scanId).then(setScan).catch(() => {});
    listAgentRuns(scanId).then(setRuns).catch(() => {});
  }, [scanId]);

  // 每秒重渲染，刷新"已运行时长"
  useEffect(() => {
    if (!isRunning) return;
    const id = window.setInterval(() => setTick((t) => t + 1), 1000);
    return () => window.clearInterval(id);
  }, [isRunning]);

  const upsertRun = useCallback((summary: Partial<MiningAgentRun> & { run_id: string }) => {
    setRuns((prev) => {
      const idx = prev.findIndex((r) => r.run_id === summary.run_id);
      if (idx === -1) {
        return [...prev, { output: "", final_output: "", ...summary } as MiningAgentRun];
      }
      const next = [...prev];
      next[idx] = { ...next[idx], ...summary };
      return next;
    });
  }, []);

  const sseHandlers = useMemo<ScanSSEHandlers>(() => ({
    onScanStatus: (data) => {
      setScan((prev) => {
        if (!prev) return prev;
        const patch: Partial<ScanStatusType> = {};
        if (data.status != null) patch.status = data.status as ScanItemStatus;
        if (data.progress != null) patch.progress = data.progress;
        if (data.deep_mining_status !== undefined) patch.deep_mining_status = data.deep_mining_status;
        return { ...prev, ...patch };
      });
    },
    onScanVulnerability: (data) => {
      setScan((prev) => {
        if (!prev) return prev;
        const vulns = [...prev.vulnerabilities];
        vulns[data.index] = data.vulnerability;
        return { ...prev, vulnerabilities: vulns };
      });
    },
    onScanEvent: (data) => {
      setScan((prev) => {
        if (!prev) return prev;
        const events = [...prev.events, data.event];
        if (events.length > MAX_LOG_LINES) events.splice(0, events.length - MAX_LOG_LINES);
        return { ...prev, events };
      });
    },
    onScanFinish: (data) => {
      setScan((prev) => (prev ? { ...prev, status: data.status as ScanItemStatus } : prev));
    },
    onAgentRun: (data) => upsertRun(data),
  }), [upsertRun]);

  const stateSetters = useMemo<SSEStateSetters>(() => ({ setScan, setFpReview, setIndexStatus }), []);
  useScanSSE(scanId, sseHandlers, stateSetters);

  useEffect(() => {
    if (tab === "log" && logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [scan?.events.length, tab]);

  // 打开的 Agent 运行详情：拉取一次；运行中则每 2s 轮询
  useEffect(() => {
    if (!openRunId) {
      setRunDetail(null);
      return;
    }
    let cancelled = false;
    const fetchDetail = () => {
      getAgentRun(scanId, openRunId)
        .then((d) => { if (!cancelled) setRunDetail(d); })
        .catch(() => {});
    };
    fetchDetail();
    const summary = runs.find((r) => r.run_id === openRunId);
    let timer: number | undefined;
    if (summary && summary.status === "running") {
      timer = window.setInterval(fetchDetail, 2000);
    }
    return () => { cancelled = true; if (timer) window.clearInterval(timer); };
  }, [openRunId, scanId, runs]);

  useEffect(() => {
    if (runOutRef.current) runOutRef.current.scrollTop = runOutRef.current.scrollHeight;
  }, [runDetail?.output]);

  const refetch = () => getScanStatus(scanId).then(setScan).catch(() => {});

  const handleStop = async () => {
    setStopping(true);
    try { await stopScan(scanId); } catch { /* ignore */ } finally { setStopping(false); }
  };

  const handleDownload = async () => {
    setDownloading(true);
    try {
      const blob = await downloadScanReport(scanId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `mining-${scanId}.csv`;
      document.body.appendChild(a); a.click(); a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch { /* ignore */ } finally { setDownloading(false); }
  };

  if (!scan) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center">
        <div className="w-6 h-6 border-2 border-white/30 border-t-white rounded-full animate-spin" />
      </div>
    );
  }

  const st = STATUS_STYLES[scan.status] || STATUS_STYLES.pending;
  const findingsCount = scan.vulnerabilities.length;
  const runningRuns = runs.filter((r) => r.status === "running").length;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex flex-col">
      {/* Header */}
      <div className="bg-slate-800/80 backdrop-blur border-b border-slate-700 px-6 py-4">
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-semibold text-purple-300 bg-purple-500/10 border border-purple-500/30 rounded px-1.5 py-0.5">
                深度挖掘
              </span>
              <h1 className="text-lg font-bold text-white truncate">{scan.project_id || scanId.slice(0, 8)}</h1>
              <span className={`text-xs font-semibold px-2 py-0.5 rounded border ${st.cls}`}>{st.label}</span>
              {dm?.phase && <span className="text-xs text-slate-400">· {PHASE_LABEL[dm.phase] || dm.phase}</span>}
              {scan.agent_online === false && <span className="text-xs text-amber-400">Agent 离线</span>}
            </div>
            <p className="text-xs text-slate-500 mt-0.5">
              {dm?.updated_at ? `最后更新：${new Date(dm.updated_at).toLocaleString()}` : "等待挖掘状态..."}
            </p>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            {isRunning && (
              <button onClick={handleStop} disabled={stopping}
                className="px-3 py-2 text-sm font-medium text-red-200 bg-red-500/10 border border-red-500/30 rounded-lg hover:bg-red-500/20 disabled:opacity-50">
                {stopping ? "停止中..." : "停止"}
              </button>
            )}
            <button onClick={handleDownload} disabled={downloading}
              className="px-3 py-2 text-sm font-medium text-slate-300 bg-slate-700 hover:bg-slate-600 rounded-lg disabled:opacity-50">
              下载 CSV
            </button>
            <button onClick={onBack} className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white bg-slate-700 hover:bg-slate-600 rounded-lg">
              返回
            </button>
          </div>
        </div>

        <div className="flex gap-1 mt-4">
          {([["overview", "概览"], ["agents", `Agent 任务 (${runs.length})`], ["findings", `发现 (${findingsCount})`], ["log", "日志"]] as [Tab, string][]).map(
            ([key, label]) => (
              <button key={key} onClick={() => setTab(key)}
                className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
                  tab === key ? "bg-slate-700 text-white" : "text-slate-400 hover:text-slate-200"
                }`}>
                {label}
              </button>
            ),
          )}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 px-6 py-6 max-w-6xl mx-auto w-full">
        {scan.error_message && (
          <div className="mb-4 bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400">
            {scan.error_message}
          </div>
        )}

        {tab === "overview" && (
          <Overview dm={dm} runningRuns={runningRuns} findingsCount={findingsCount} />
        )}
        {tab === "agents" && (
          <AgentRunList runs={runs} onOpen={setOpenRunId} />
        )}
        {tab === "findings" && (
          <MiningFindingsList scanId={scanId} vulnerabilities={scan.vulnerabilities} onChanged={refetch} />
        )}
        {tab === "log" && (
          <div ref={logRef} className="bg-slate-900 border border-slate-700 rounded-xl p-4 max-h-[70vh] overflow-auto font-mono text-xs space-y-0.5">
            {scan.events.length === 0 ? (
              <div className="text-slate-500">暂无日志</div>
            ) : (
              scan.events.map((e, i) => <EventLine key={i} event={e} />)
            )}
          </div>
        )}
      </div>

      {/* Agent run drawer */}
      {openRunId && (
        <RunDrawer run={runDetail} runId={openRunId} runOutRef={runOutRef} onClose={() => setOpenRunId(null)} />
      )}
    </div>
  );
}

function Overview({ dm, runningRuns, findingsCount }: {
  dm: ScanStatusType["deep_mining_status"];
  runningRuns: number;
  findingsCount: number;
}) {
  if (!dm) {
    return (
      <div className="rounded-xl border border-slate-700 bg-slate-800/50 px-6 py-16 text-center text-slate-500">
        正在初始化挖掘引擎，稍候即可看到实时任务与指标...
      </div>
    );
  }
  const running = dm.running_tasks || [];
  const queued = dm.queued_preview || [];
  const queuedExtra = Math.max(0, dm.queued_total - queued.length);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <Metric label="进行中" value={running.length || runningRuns} tone="cyan" />
        <Metric label="排队中" value={dm.queued_total} tone="slate" />
        <Metric label="函数覆盖" value={`${dm.covered_functions}/${dm.total_functions}`} tone="slate" />
        <Metric label="调用预算" value={`${dm.calls_made}/${dm.call_budget}`} tone="amber" />
        <Metric label="待验证" value={dm.findings_pending} tone="cyan" />
        <Metric label="已确认" value={dm.findings_confirmed} tone="red" />
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <ProgressBar label="调用预算消耗" value={pct(dm.calls_made, dm.call_budget)} color="bg-amber-500" />
        <ProgressBar label="函数覆盖率" value={pct(dm.covered_functions, dm.total_functions)} color="bg-cyan-500" />
      </div>

      <section>
        <h3 className="text-sm font-semibold text-slate-300 mb-2">进行中的任务（{running.length}）</h3>
        {running.length === 0 ? (
          <div className="text-sm text-slate-500 bg-slate-800/50 border border-slate-700 rounded-xl px-4 py-6 text-center">
            当前没有进行中的任务
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
            {running.map((t, i) => <TaskCard key={i} task={t} running />)}
          </div>
        )}
      </section>

      <section>
        <div className="flex items-center gap-3 mb-2">
          <h3 className="text-sm font-semibold text-slate-300">即将进行的任务（{dm.queued_total}）</h3>
          <span className="text-xs text-slate-500">挖掘 {dm.queued_analyze} · 验证 {dm.queued_verify}</span>
        </div>
        {queued.length === 0 ? (
          <div className="text-sm text-slate-500 bg-slate-800/50 border border-slate-700 rounded-xl px-4 py-6 text-center">
            队列为空
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
            {queued.map((t, i) => <TaskCard key={i} task={t} />)}
            {queuedExtra > 0 && (
              <div className="text-sm text-slate-500 flex items-center justify-center bg-slate-800/40 border border-dashed border-slate-700 rounded-xl px-4 py-3">
                还有 {queuedExtra} 个任务排队中…
              </div>
            )}
          </div>
        )}
      </section>

      <p className="text-xs text-slate-500">已发现 {findingsCount} 条（含待验证）。验证完成后会更新为"是问题/非问题"。</p>
    </div>
  );
}

function AgentRunList({ runs, onOpen }: { runs: MiningAgentRun[]; onOpen: (id: string) => void }) {
  if (runs.length === 0) {
    return (
      <div className="rounded-xl border border-slate-700 bg-slate-800/50 px-6 py-16 text-center text-slate-500">
        暂无 Agent 任务。挖掘开始后，每个威胁分析/挖掘/验证 Agent 都会在这里出现，点击可查看其输出。
      </div>
    );
  }
  const sorted = [...runs].sort((a, b) => {
    if (a.status === "running" && b.status !== "running") return -1;
    if (b.status === "running" && a.status !== "running") return 1;
    return (b.started_at || "").localeCompare(a.started_at || "");
  });
  return (
    <div className="space-y-2">
      {sorted.map((r) => {
        const meta = kindMeta(r.kind);
        const stm = RUN_STATUS_META[r.status] || { label: r.status, cls: "text-slate-400" };
        return (
          <button key={r.run_id} onClick={() => onOpen(r.run_id)}
            className="w-full flex items-center gap-3 bg-slate-800/60 border border-slate-700 rounded-lg px-4 py-3 text-left hover:bg-slate-800">
            {r.status === "running" && <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse flex-shrink-0" />}
            <span className={`text-[11px] font-semibold px-2 py-0.5 rounded border flex-shrink-0 ${meta.cls}`}>{meta.label}</span>
            <div className="flex-1 min-w-0">
              <div className="text-sm text-slate-200 truncate">
                <span className="text-slate-300">{r.function || "(threat)"}</span>
                {r.file && <span className="font-mono text-slate-500"> {r.file}{r.line ? `:${r.line}` : ""}</span>}
              </div>
              <div className="text-[11px] text-slate-500">
                {r.vuln_type && <span className="text-cyan-300/80">{r.vuln_type} · </span>}
                {r.started_at ? new Date(r.started_at).toLocaleTimeString() : ""}
              </div>
            </div>
            <span className={`text-xs ${stm.cls} flex-shrink-0`}>{stm.label}</span>
          </button>
        );
      })}
    </div>
  );
}

function RunDrawer({ run, runId, runOutRef, onClose }: {
  run: MiningAgentRun | null;
  runId: string;
  runOutRef: React.RefObject<HTMLDivElement>;
  onClose: () => void;
}) {
  const meta = run ? kindMeta(run.kind) : null;
  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className="relative w-full max-w-2xl h-full bg-slate-900 border-l border-slate-700 flex flex-col">
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-700">
          <div className="flex items-center gap-2 min-w-0">
            {meta && <span className={`text-[11px] font-semibold px-2 py-0.5 rounded border ${meta.cls}`}>{meta.label}</span>}
            <span className="text-sm text-slate-200 truncate">{run?.function || runId}</span>
            {run && (
              <span className={`text-xs ${(RUN_STATUS_META[run.status] || {}).cls || "text-slate-400"}`}>
                {(RUN_STATUS_META[run.status] || {}).label || run.status}
              </span>
            )}
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white text-sm">关闭</button>
        </div>
        <div className="flex-1 overflow-hidden flex flex-col">
          {!run ? (
            <div className="flex-1 flex items-center justify-center text-slate-500">加载中...</div>
          ) : (
            <>
              <div className="px-5 py-2 text-xs text-slate-500 border-b border-slate-800">
                {run.file && <span className="font-mono">{run.file}{run.line ? `:${run.line}` : ""}</span>}
                {run.vuln_type && <span className="ml-2 text-cyan-300/80">{run.vuln_type}</span>}
              </div>
              <div className="px-5 py-2 text-xs font-semibold text-slate-400">Agent 输出</div>
              <div ref={runOutRef} className="flex-1 overflow-auto px-5 pb-3">
                <pre className="text-xs text-slate-300 whitespace-pre-wrap break-words">
                  {run.output || (run.status === "running" ? "（等待输出…）" : "（无输出）")}
                </pre>
              </div>
              {run.final_output && (
                <div className="border-t border-slate-700 max-h-60 overflow-auto px-5 py-3">
                  <div className="text-xs font-semibold text-slate-400 mb-1">最终产物</div>
                  <pre className="text-xs text-emerald-200/90 whitespace-pre-wrap break-words">{run.final_output}</pre>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function TaskCard({ task, running }: { task: MiningTask; running?: boolean }) {
  const meta = kindMeta(task.kind);
  return (
    <div className="flex items-center gap-3 bg-slate-800/60 border border-slate-700 rounded-lg px-3 py-2">
      {running && <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse flex-shrink-0" />}
      <span className={`text-[11px] font-semibold px-2 py-0.5 rounded border flex-shrink-0 ${meta.cls}`}>{meta.label}</span>
      <div className="flex-1 min-w-0">
        <div className="text-sm text-slate-200 truncate">
          <span className="text-slate-300">{task.function || "(未知函数)"}</span>
          {task.file && <span className="font-mono text-slate-500"> {task.file}{task.line ? `:${task.line}` : ""}</span>}
        </div>
        <div className="text-[11px] text-slate-500">
          {task.vuln_type && <span className="text-cyan-300/80">{task.vuln_type} · </span>}
          {running && task.started_at ? `已运行 ${elapsed(task.started_at)}` : "排队中"}
        </div>
      </div>
    </div>
  );
}

function Metric({ label, value, tone }: { label: string; value: string | number; tone: "slate" | "cyan" | "amber" | "red" }) {
  const tones: Record<string, string> = {
    slate: "text-slate-200", cyan: "text-cyan-300", amber: "text-amber-300", red: "text-red-300",
  };
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl px-4 py-3">
      <div className="text-xs text-slate-500">{label}</div>
      <div className={`text-xl font-bold mt-1 ${tones[tone]}`}>{value}</div>
    </div>
  );
}

function ProgressBar({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl px-4 py-3">
      <div className="flex items-center justify-between text-xs mb-2">
        <span className="text-slate-400">{label}</span>
        <span className="text-slate-300">{value}%</span>
      </div>
      <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${value}%` }} />
      </div>
    </div>
  );
}

function EventLine({ event }: { event: ScanEvent }) {
  const time = new Date(event.timestamp).toLocaleTimeString();
  const phaseColor: Record<string, string> = {
    init: "text-yellow-400", mcp_ready: "text-green-400", threat: "text-emerald-400",
    auditing: "text-blue-400", coverage: "text-cyan-400", complete: "text-green-400", error: "text-red-400",
  };
  return (
    <div className="text-slate-400">
      <span className="text-slate-600">[{time}]</span>{" "}
      <span className={phaseColor[event.phase] || "text-slate-500"}>[{event.phase}]</span>{" "}
      <span>{event.message}</span>
    </div>
  );
}
