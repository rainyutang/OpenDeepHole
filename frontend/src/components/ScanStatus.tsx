import { useEffect, useRef, useState } from "react";
import { getScanStatus, stopScan } from "../api/client";
import type { ScanItemStatus, ScanStatus as ScanStatusType, ScanEvent } from "../types";

const PHASES = [
  { key: "init", label: "Initialize" },
  { key: "static_analysis", label: "Static Analysis" },
  { key: "auditing", label: "AI Audit" },
  { key: "complete", label: "Complete" },
] as const;

function statusToPhaseIndex(status: ScanItemStatus): number {
  if (status === "pending") return 0;
  if (status === "analyzing") return 1;
  if (status === "auditing") return 2;
  return 3; // complete / cancelled / error
}

interface Props {
  scanId: string;
  onComplete: (scan: ScanStatusType) => void;
}

export default function ScanStatus({ scanId, onComplete }: Props) {
  const [scan, setScan] = useState<ScanStatusType | null>(null);
  const [stopping, setStopping] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let timer: ReturnType<typeof setInterval>;

    const poll = async () => {
      try {
        const data = await getScanStatus(scanId);
        setScan(data);
        if (data.status === "complete" || data.status === "error" || data.status === "cancelled") {
          clearInterval(timer);
          onComplete(data);
        }
      } catch (err: unknown) {
        // Stop polling on 404 — backend restarted and lost in-memory state
        if (
          err &&
          typeof err === "object" &&
          "response" in err &&
          (err as { response: { status: number } }).response?.status === 404
        ) {
          clearInterval(timer);
          localStorage.removeItem("odh_scan_state");
          setScan((prev) =>
            prev
              ? { ...prev, status: "error", error_message: "Scan state lost (backend was restarted). Please start a new scan." }
              : null
          );
        }
        // other errors: keep polling
      }
    };

    poll();
    timer = setInterval(poll, 2000);
    return () => clearInterval(timer);
  }, [scanId, onComplete]);

  const handleStop = async () => {
    setStopping(true);
    try {
      await stopScan(scanId);
    } catch {
      setStopping(false);
    }
  };

  // Auto-scroll log
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [scan?.events.length]);

  if (!scan) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
        <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
      </div>
    );
  }

  const activePhase = statusToPhaseIndex(scan.status);
  const pct = Math.round(scan.progress * 100);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center p-6">
      <div className="w-full max-w-2xl bg-white/95 backdrop-blur rounded-2xl shadow-2xl p-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold text-slate-900">
            {scan.status === "cancelled" ? "Scan Cancelled" : "Scanning..."}
          </h2>
          {(scan.status === "analyzing" || scan.status === "auditing") && (
            <button
              onClick={handleStop}
              disabled={stopping}
              className="px-3 py-1.5 text-sm font-medium text-red-600 border border-red-300 rounded-lg hover:bg-red-50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {stopping ? "Stopping..." : "Stop"}
            </button>
          )}
        </div>

        {/* Stepper */}
        <div className="flex items-center mb-8">
          {PHASES.map((phase, i) => (
            <div key={phase.key} className="flex items-center flex-1 last:flex-none">
              <div className="flex flex-col items-center">
                <div
                  className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold transition-colors ${
                    i < activePhase
                      ? "bg-green-500 text-white"
                      : i === activePhase
                        ? "bg-blue-600 text-white ring-4 ring-blue-600/20"
                        : "bg-slate-200 text-slate-400"
                  }`}
                >
                  {i < activePhase ? "\u2713" : i + 1}
                </div>
                <span
                  className={`text-xs mt-1.5 whitespace-nowrap ${
                    i <= activePhase ? "text-slate-700 font-medium" : "text-slate-400"
                  }`}
                >
                  {phase.label}
                </span>
              </div>
              {i < PHASES.length - 1 && (
                <div
                  className={`flex-1 h-0.5 mx-2 mt-[-1rem] ${
                    i < activePhase ? "bg-green-500" : "bg-slate-200"
                  }`}
                />
              )}
            </div>
          ))}
        </div>

        {/* Progress bar (during auditing) */}
        {scan.status === "auditing" && (
          <div className="mb-6">
            <div className="flex justify-between text-xs text-slate-500 mb-1.5">
              <span>
                {scan.processed_candidates} / {scan.total_candidates} candidates
              </span>
              <span>{pct}%</span>
            </div>
            <div className="h-2 bg-slate-200 rounded-full overflow-hidden">
              <div
                className="h-full bg-blue-600 rounded-full transition-all duration-500"
                style={{ width: `${pct}%` }}
              />
            </div>
            {scan.current_candidate && (
              <p className="text-xs text-slate-500 mt-2 truncate">
                Auditing:{" "}
                <span className="font-mono text-slate-700">
                  {scan.current_candidate.file}:{scan.current_candidate.line}
                </span>
                {" — "}
                <span className="text-slate-600">{scan.current_candidate.function}</span>
              </p>
            )}
          </div>
        )}

        {/* Event log */}
        <div className="border border-slate-200 rounded-xl overflow-hidden">
          <div className="px-4 py-2.5 bg-slate-50 border-b border-slate-200">
            <h3 className="text-xs font-semibold text-slate-600 uppercase tracking-wider">
              Process Log
            </h3>
          </div>
          <div
            ref={logRef}
            className="max-h-64 overflow-y-auto p-3 space-y-1 bg-slate-900 font-mono text-xs"
          >
            {scan.events.length === 0 ? (
              <p className="text-slate-500">Waiting for events...</p>
            ) : (
              scan.events.map((event, i) => (
                <EventLine key={i} event={event} />
              ))
            )}
          </div>
        </div>

        {/* Error */}
        {scan.error_message && (
          <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
            {scan.error_message}
          </div>
        )}
      </div>
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
      <span className="text-slate-500 shrink-0">{time}</span>
      <span className={`shrink-0 ${phaseColor[event.phase] ?? "text-slate-400"}`}>
        [{event.phase}]
      </span>
      <span className="text-slate-300">{event.message}</span>
    </div>
  );
}
