import { useEffect, useRef, useState } from "react";
import { getScanStatus, stopScan, getReportUrl, getCheckers, updateScanFeedback } from "../api/client";
import type { ScanItemStatus, ScanStatus as ScanStatusType, ScanEvent, CheckerInfo } from "../types";
import VulnerabilityList from "./VulnerabilityList";
import FeedbackManager from "./FeedbackManager";

const PHASES = [
  { key: "init", label: "初始化" },
  { key: "static_analysis", label: "静态分析" },
  { key: "auditing", label: "AI 审计" },
  { key: "complete", label: "完成" },
] as const;

function statusToPhaseIndex(status: ScanItemStatus): number {
  if (status === "pending") return 0;
  if (status === "analyzing") return 1;
  if (status === "auditing") return 2;
  return 3;
}

interface Props {
  scanId: string;
  onBack: () => void;
}

export default function ScanStatus({ scanId, onBack }: Props) {
  const [scan, setScan] = useState<ScanStatusType | null>(null);
  const [stopping, setStopping] = useState(false);
  const [logOpen, setLogOpen] = useState(false);
  const [lastSeenEvents, setLastSeenEvents] = useState(0);
  const logRef = useRef<HTMLDivElement>(null);

  // Feedback panel state
  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const [checkers, setCheckers] = useState<CheckerInfo[]>([]);
  const [selectedFeedbackIds, setSelectedFeedbackIds] = useState<Set<string> | null>(null);

  const isRunning = scan && (scan.status === "pending" || scan.status === "analyzing" || scan.status === "auditing");
  const isDone = scan && (scan.status === "complete" || scan.status === "error" || scan.status === "cancelled");

  useEffect(() => {
    getCheckers().then(setCheckers).catch(() => {});
  }, []);

  useEffect(() => {
    let timer: ReturnType<typeof setInterval>;

    const poll = async () => {
      try {
        const data = await getScanStatus(scanId);
        setScan(data);
        // Initialize selectedFeedbackIds from scan data on first load
        if (selectedFeedbackIds === null && data.feedback_ids) {
          setSelectedFeedbackIds(new Set(data.feedback_ids));
        }
        if (data.status === "complete" || data.status === "error" || data.status === "cancelled") {
          clearInterval(timer);
        }
      } catch (err: unknown) {
        if (
          err &&
          typeof err === "object" &&
          "response" in err &&
          (err as { response: { status: number } }).response?.status === 404
        ) {
          clearInterval(timer);
          setScan((prev) =>
            prev
              ? { ...prev, status: "error", error_message: "扫描状态丢失（后端已重启），请重新开始扫描。" }
              : null
          );
        }
      }
    };

    poll();
    timer = setInterval(poll, 2000);
    return () => clearInterval(timer);
  }, [scanId]);

  const handleStop = async () => {
    setStopping(true);
    try {
      await stopScan(scanId);
    } catch {
      setStopping(false);
    }
  };

  // Handle feedback selection change — update backend and refresh skills
  const handleFeedbackChange = async (ids: Set<string>) => {
    setSelectedFeedbackIds(ids);
    try {
      await updateScanFeedback(scanId, [...ids]);
    } catch {
      // ignore
    }
  };

  // Auto-scroll log
  useEffect(() => {
    if (logRef.current && logOpen) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [scan?.events.length, logOpen]);

  // Track unseen events
  useEffect(() => {
    if (logOpen && scan) {
      setLastSeenEvents(scan.events.length);
    }
  }, [logOpen, scan?.events.length]);

  if (!scan) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
        <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
      </div>
    );
  }

  const activePhase = statusToPhaseIndex(scan.status);
  const pct = Math.round(scan.progress * 100);
  const unseenCount = scan.events.length - lastSeenEvents;
  const feedbackCount = selectedFeedbackIds?.size ?? scan.feedback_ids?.length ?? 0;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex flex-col">
      {/* Top bar */}
      <div className="bg-slate-800/80 backdrop-blur border-b border-slate-700 px-6 py-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-4">
            <button
              onClick={onBack}
              className="text-sm text-slate-400 hover:text-slate-200 transition-colors flex items-center gap-1"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
              返回
            </button>
            <h1 className="text-lg font-bold text-white">OpenDeepHole</h1>
            <span className="text-sm text-slate-400">
              {scan.status === "cancelled" ? "已取消" : isDone ? "扫描完成" : "扫描中..."}
            </span>
          </div>
          <div className="flex items-center gap-3">
            {/* Feedback button with count badge */}
            <button
              onClick={() => setFeedbackOpen(true)}
              className="px-3 py-1.5 text-sm font-medium text-slate-300 border border-slate-600 rounded-lg hover:bg-slate-700 transition-colors flex items-center gap-1.5"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
              </svg>
              经验库
              {feedbackCount > 0 && (
                <span className="bg-blue-500 text-white text-xs rounded-full px-1.5 py-0.5 min-w-[1.25rem] text-center">
                  {feedbackCount}
                </span>
              )}
            </button>
            {isDone && (
              <a
                href={getReportUrl(scan.scan_id)}
                download
                className="px-3 py-1.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
              >
                下载 CSV
              </a>
            )}
            {isRunning && (
              <button
                onClick={handleStop}
                disabled={stopping}
                className="px-3 py-1.5 text-sm font-medium text-red-400 border border-red-500/50 rounded-lg hover:bg-red-500/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {stopping ? "停止中..." : "停止扫描"}
              </button>
            )}
          </div>
        </div>

        {/* Stepper + Progress */}
        <div className="flex items-center gap-6">
          {/* Phase stepper */}
          <div className="flex items-center flex-shrink-0">
            {PHASES.map((phase, i) => (
              <div key={phase.key} className="flex items-center">
                <div className="flex flex-col items-center">
                  <div
                    className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold transition-colors ${
                      i < activePhase
                        ? "bg-green-500 text-white"
                        : i === activePhase
                          ? "bg-blue-500 text-white ring-2 ring-blue-500/30"
                          : "bg-slate-600 text-slate-400"
                    }`}
                  >
                    {i < activePhase ? "\u2713" : i + 1}
                  </div>
                  <span
                    className={`text-xs mt-1 whitespace-nowrap ${
                      i <= activePhase ? "text-slate-300 font-medium" : "text-slate-500"
                    }`}
                  >
                    {phase.label}
                  </span>
                </div>
                {i < PHASES.length - 1 && (
                  <div
                    className={`w-8 h-0.5 mx-1.5 mt-[-1rem] ${
                      i < activePhase ? "bg-green-500" : "bg-slate-600"
                    }`}
                  />
                )}
              </div>
            ))}
          </div>

          {/* Progress bar */}
          {(scan.status === "auditing" || isDone) && (
            <div className="flex-1 min-w-0">
              <div className="flex justify-between text-xs text-slate-400 mb-1">
                <span>
                  {scan.processed_candidates} / {scan.total_candidates} 候选点
                </span>
                <span>{pct}%</span>
              </div>
              <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${isDone ? "bg-green-500" : "bg-blue-500"}`}
                  style={{ width: `${pct}%` }}
                />
              </div>
              {scan.current_candidate && (
                <p className="text-xs text-slate-500 mt-1 truncate">
                  正在审计：
                  <span className="font-mono text-slate-400">
                    {scan.current_candidate.file}:{scan.current_candidate.line}
                  </span>
                  {" — "}
                  <span className="text-slate-400">{scan.current_candidate.function}</span>
                </p>
              )}
            </div>
          )}
        </div>

        {/* Error */}
        {scan.error_message && (
          <div className="mt-3 p-2.5 bg-red-500/10 border border-red-500/30 rounded-lg text-sm text-red-400">
            {scan.error_message}
          </div>
        )}
      </div>

      {/* Main content — Results table */}
      <div className="flex-1 overflow-auto px-6 py-4">
        {scan.vulnerabilities.length === 0 && isDone ? (
          <div className="flex items-center justify-center h-64 text-slate-400">
            <div className="text-center">
              <p className="text-lg font-medium">未发现漏洞</p>
              <p className="text-sm mt-1 text-slate-500">代码看起来很安全</p>
            </div>
          </div>
        ) : (
          <VulnerabilityList
            scanId={scanId}
            vulnerabilities={scan.vulnerabilities}
            isScanning={!!isRunning}
            currentCandidate={scan.current_candidate}
            totalCandidates={scan.total_candidates}
            processedCandidates={scan.processed_candidates}
          />
        )}
      </div>

      {/* Log floating button */}
      <button
        onClick={() => { setLogOpen(true); setLastSeenEvents(scan.events.length); }}
        className="fixed bottom-6 right-6 px-4 py-2.5 bg-slate-700 hover:bg-slate-600 text-slate-300 text-sm font-medium rounded-full shadow-lg border border-slate-600 transition-colors z-40 flex items-center gap-2"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
        日志
        {unseenCount > 0 && (
          <span className="bg-blue-500 text-white text-xs rounded-full px-1.5 py-0.5 min-w-[1.25rem] text-center">
            {unseenCount > 99 ? "99+" : unseenCount}
          </span>
        )}
      </button>

      {/* Log slide-over panel */}
      {logOpen && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-black/30 z-40"
            onClick={() => setLogOpen(false)}
          />
          {/* Panel */}
          <div className="fixed right-0 top-0 bottom-0 w-[32rem] max-w-full bg-slate-900 border-l border-slate-700 z-50 flex flex-col shadow-2xl">
            <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
              <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
                处理日志
              </h3>
              <button
                onClick={() => setLogOpen(false)}
                className="text-slate-500 hover:text-slate-300 transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div
              ref={logRef}
              className="flex-1 overflow-y-auto p-3 space-y-1 font-mono text-xs"
            >
              {scan.events.length === 0 ? (
                <p className="text-slate-500">等待事件...</p>
              ) : (
                scan.events.map((event, i) => (
                  <EventLine key={i} event={event} />
                ))
              )}
            </div>
          </div>
        </>
      )}

      {/* Feedback Manager Panel */}
      {feedbackOpen && scan.project_id && (
        <FeedbackManager
          checkers={checkers.filter((c) => scan.scan_items.includes(c.name))}
          initialTypes={scan.scan_items}
          scanId={scanId}
          projectId={scan.project_id}
          selectedIds={selectedFeedbackIds ?? new Set(scan.feedback_ids)}
          onSelectionChange={handleFeedbackChange}
          onClose={() => setFeedbackOpen(false)}
        />
      )}
    </div>
  );
}

function EventLine({ event }: { event: ScanEvent }) {
  const time = new Date(event.timestamp).toLocaleTimeString();

  const phaseColor: Record<string, string> = {
    init: "text-yellow-400",
    mcp_ready: "text-green-400",
    static_analysis: "text-cyan-400",
    auditing: "text-blue-400",
    opencode_output: "text-slate-500",
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
