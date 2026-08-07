import { useEffect, useRef, useState, useCallback } from "react";
import { scanSSEUrl, getScanOverview, getFpReview, getAgentIndexStatus } from "../api/client";
import { getScanThreatAnalysis } from "../features/threatAnalysis/api";
import {
  isRecord,
  normalizeScanCandidate,
  normalizeScanEvent,
  normalizeThreatTask,
  normalizeValidation,
  normalizeVulnerability,
} from "../scanRuntime";
import type {
  FpReviewJob,
  FpReviewMethod,
  FpReviewStatus,
  IndexStatus,
  MiningEngineRunStatus,
  OutputSource,
  ScanCandidate,
  ScanEvent,
  ScanStatus,
  ThreatAnalysis,
  ThreatAnalysisRunStatus,
  ThreatAuditTask,
  Vulnerability,
  VulnerabilityValidation,
} from "../types";

const SCAN_STATUSES = new Set(["pending", "analyzing", "auditing", "complete", "error", "cancelled"]);
const FP_REVIEW_STATUSES = new Set(["pending", "running", "complete", "error", "cancelled"]);

/* ------------------------------------------------------------------ */
/*  SSE event payload types (mirror backend publish() shapes)          */
/* ------------------------------------------------------------------ */

interface ScanStatusEvent {
  status: string | null;
  progress: number | null;
  total_candidates: number | null;
  processed_candidates: number | null;
  static_total_files?: number | null;
  static_scanned_files?: number | null;
  static_analysis_done?: boolean | null;
  opencode_pool?: ScanStatus["opencode_pool"];
}

interface ScanVulnerabilityEvent {
  index: number;
  vulnerability: Vulnerability;
}

interface ScanCandidatesEvent {
  candidates: ScanCandidate[];
}

interface ScanCandidatesChangedEvent {
  offset: number;
  count: number;
  total_candidates: number;
  final: boolean;
}

interface ScanEventPayload {
  event: ScanEvent;
}

interface ScanFinishEvent {
  status: string;
  error_message: string | null;
}

interface FpReviewStartedEvent {
  review_id: string;
  status: FpReviewStatus;
  total: number;
  processed?: number;
  method?: FpReviewMethod;
}

interface FpReviewProgressEvent {
  review_id: string;
  vuln_index: number;
  active_indices?: number[] | null;
  processed?: number | null;
  total: number;
}

interface FpReviewResultEvent {
  review_id: string;
  vuln_index: number;
  verdict: "tp" | "fp";
  severity: "high" | "medium" | "low";
  reason: string;
  vulnerability_report?: string;
  stage_outputs?: Record<string, string>;
  match_reference?: string;
  match_type?: string;
  stage_output_sources?: Record<string, OutputSource>;
  output_source?: OutputSource;
}

interface FpReviewStageOutputEvent {
  review_id: string;
  vuln_index: number;
  stage: string;
  markdown: string;
  output_source?: OutputSource;
}

interface FpReviewFinishEvent {
  review_id: string;
  status: FpReviewStatus;
  error_message: string | null;
  method?: FpReviewMethod;
}

interface VulnerabilityValidationEvent {
  validation: VulnerabilityValidation;
}

interface ThreatAnalysisEvent {
  analysis: ThreatAnalysis;
}

interface ThreatAnalysisRunEvent {
  run: ThreatAnalysisRunStatus;
}

interface ThreatAuditTaskEvent {
  task: ThreatAuditTask;
}

interface MiningEngineRunEvent {
  run: MiningEngineRunStatus;
  runs: MiningEngineRunStatus[];
}

/* ------------------------------------------------------------------ */
/*  Handler map                                                        */
/* ------------------------------------------------------------------ */

export interface ScanSSEHandlers {
  onScanStatus?: (data: ScanStatusEvent) => void;
  onScanCandidates?: (data: ScanCandidatesEvent) => void;
  onScanCandidatesChanged?: (data: ScanCandidatesChangedEvent) => void;
  onScanVulnerability?: (data: ScanVulnerabilityEvent) => void;
  onScanEvent?: (data: ScanEventPayload) => void;
  onScanEvents?: (events: ScanEvent[]) => void;
  onScanFinish?: (data: ScanFinishEvent) => void;
  onFpReviewStarted?: (data: FpReviewStartedEvent) => void;
  onFpReviewProgress?: (data: FpReviewProgressEvent) => void;
  onFpReviewStageOutput?: (data: FpReviewStageOutputEvent) => void;
  onFpReviewResult?: (data: FpReviewResultEvent) => void;
  onFpReviewFinish?: (data: FpReviewFinishEvent) => void;
  onVulnerabilityValidation?: (data: VulnerabilityValidationEvent) => void;
  onThreatAnalysis?: (data: ThreatAnalysisEvent) => void;
  onThreatAnalysisRun?: (data: ThreatAnalysisRunEvent) => void;
  onThreatAuditTask?: (data: ThreatAuditTaskEvent) => void;
  onMiningEngineRun?: (data: MiningEngineRunEvent) => void;
  onIndexStatus?: (data: IndexStatus) => void;
}

/* ------------------------------------------------------------------ */
/*  Full-state refresh helpers (used on connect and reconnect)         */
/* ------------------------------------------------------------------ */

export interface SSEStateSetters {
  setScan: React.Dispatch<React.SetStateAction<ScanStatus | null>>;
  setFpReview: React.Dispatch<React.SetStateAction<FpReviewJob | null>>;
  setIndexStatus: React.Dispatch<React.SetStateAction<IndexStatus | null>>;
}

async function refreshFullState(
  scanId: string,
  { setScan, setFpReview, setIndexStatus }: SSEStateSetters,
  isCurrent: () => boolean,
) {
  try {
    const data = await getScanOverview(scanId);
    if (!isCurrent() || data.scan_id !== scanId) return;
    setScan((previous) => {
      if (!isCurrent()) return previous;
      if (!previous || previous.scan_id !== scanId) return data;
      return {
        ...data,
        candidates: previous.candidates,
        vulnerabilities: previous.vulnerabilities,
        skill_reports: previous.skill_reports,
        threat_analysis: previous.threat_analysis,
        threat_audit_tasks: previous.threat_audit_tasks,
        validations: previous.validations,
        events: previous.events,
        detail_pages: previous.detail_pages,
        opencode_pool: data.opencode_pool ?? previous.opencode_pool,
      };
    });
  } catch {
    // transient — SSE will keep pushing
  }
  if (!isCurrent()) return;
  try {
    const job = await getFpReview(scanId);
    if (!isCurrent() || job.scan_id !== scanId) return;
    // Merge with existing state to preserve in-progress stage_outputs
    // that arrived via SSE but are not yet part of a completed result.
    setFpReview((prev) => {
      if (!isCurrent()) return prev;
      if (!prev) return job;
      if (prev.review_id !== job.review_id) return job;
      const mergedResults = job.results.map((r) => {
        const existing = prev.results.find((p) => p.vuln_index === r.vuln_index);
        if (existing) {
          return {
            ...r,
            stage_outputs: { ...(existing.stage_outputs ?? {}), ...(r.stage_outputs ?? {}) },
            stage_output_sources: { ...(existing.stage_output_sources ?? {}), ...(r.stage_output_sources ?? {}) },
          };
        }
        return r;
      });
      // Keep entries that only exist locally (in-progress, not yet in DB).
      const inProgressOnly = prev.results.filter(
        (p) =>
          !job.results.some((r) => r.vuln_index === p.vuln_index) &&
          Object.keys(p.stage_outputs ?? {}).length > 0,
      );
      return { ...job, results: [...mergedResults, ...inProgressOnly] };
    });
  } catch {
    // 404 = no review yet
  }
  if (!isCurrent()) return;
  try {
    const index = await getAgentIndexStatus(scanId);
    if (!isCurrent()) return;
    setIndexStatus(index);
  } catch {
    // transient — index_status SSE may still arrive later
  }
  if (!isCurrent()) return;
  try {
    const analysis = await getScanThreatAnalysis(scanId);
    if (!isCurrent()) return;
    setScan((prev) => prev?.scan_id === scanId ? { ...prev, threat_analysis: analysis } : prev);
  } catch {
    // 404 = no threat analysis snapshot yet
  }
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

function isRecordArray(value: unknown): boolean {
  return Array.isArray(value) && value.every(isRecord);
}

function isCandidate(value: unknown): boolean {
  return isRecord(value)
    && isString(value.file)
    && isFiniteNumber(value.line)
    && isString(value.function)
    && isString(value.description)
    && isString(value.vuln_type);
}

function isVulnerability(value: unknown): boolean {
  return isCandidate(value)
    && isRecord(value)
    && isString(value.severity)
    && isString(value.ai_analysis);
}

function isValidPayload(eventType: string, value: unknown): value is Record<string, unknown> {
  if (!isRecord(value)) return false;
  switch (eventType) {
    case "scan_status":
      return (value.status == null || (isString(value.status) && SCAN_STATUSES.has(value.status)))
        && (value.progress == null || isFiniteNumber(value.progress))
        && (value.total_candidates == null || isFiniteNumber(value.total_candidates))
        && (value.processed_candidates == null || isFiniteNumber(value.processed_candidates))
        && (value.static_total_files == null || isFiniteNumber(value.static_total_files))
        && (value.static_scanned_files == null || isFiniteNumber(value.static_scanned_files))
        && (value.static_analysis_done == null || typeof value.static_analysis_done === "boolean")
        && (value.opencode_pool === undefined || value.opencode_pool === null || isRecord(value.opencode_pool));
    case "scan_candidates":
      return Array.isArray(value.candidates) && value.candidates.every(isCandidate);
    case "scan_candidates_changed":
      return isFiniteNumber(value.offset)
        && isFiniteNumber(value.count)
        && isFiniteNumber(value.total_candidates)
        && typeof value.final === "boolean";
    case "scan_vulnerability":
      return Number.isInteger(value.index) && Number(value.index) >= 0 && isVulnerability(value.vulnerability);
    case "scan_event":
      return normalizeScanEvent(value.event) !== null;
    case "scan_finish":
      return isString(value.status) && SCAN_STATUSES.has(value.status)
        && (value.error_message == null || isString(value.error_message));
    case "fp_review_started":
      return isString(value.review_id)
        && isString(value.status)
        && FP_REVIEW_STATUSES.has(value.status)
        && isFiniteNumber(value.total)
        && (value.processed == null || isFiniteNumber(value.processed));
    case "fp_review_progress":
      return isString(value.review_id)
        && isFiniteNumber(value.vuln_index)
        && isFiniteNumber(value.total)
        && (value.processed == null || isFiniteNumber(value.processed))
        && (value.active_indices == null
          || (Array.isArray(value.active_indices) && value.active_indices.every(isFiniteNumber)));
    case "fp_review_stage_output":
      return isString(value.review_id)
        && isFiniteNumber(value.vuln_index)
        && isString(value.stage)
        && isString(value.markdown);
    case "fp_review_result":
      return isString(value.review_id)
        && isFiniteNumber(value.vuln_index)
        && (value.verdict === "tp" || value.verdict === "fp")
        && (value.severity === "high" || value.severity === "medium" || value.severity === "low")
        && isString(value.reason)
        && (value.stage_outputs === undefined || isRecord(value.stage_outputs))
        && (value.stage_output_sources === undefined || isRecord(value.stage_output_sources));
    case "fp_review_finish":
      return isString(value.review_id)
        && isString(value.status)
        && FP_REVIEW_STATUSES.has(value.status)
        && (value.error_message == null || isString(value.error_message));
    case "vulnerability_validation":
      return isRecord(value.validation) && isFiniteNumber(value.validation.vuln_index);
    case "threat_analysis":
      return isRecord(value.analysis);
    case "threat_analysis_run":
      return isRecord(value.run) && isString(value.run.status);
    case "threat_audit_task":
      return isRecord(value.task)
        && isString(value.task.task_id)
        && isString(value.task.status)
        && isString(value.task.code_path);
    case "mining_engine_run":
      return isRecord(value.run) && isRecordArray(value.runs);
    case "index_status":
      return isString(value.status);
    default:
      return false;
  }
}

/* ------------------------------------------------------------------ */
/*  Hook                                                               */
/* ------------------------------------------------------------------ */

export function useScanSSE(
  scanId: string,
  handlers: ScanSSEHandlers,
  stateSetters: SSEStateSetters,
): { connected: boolean } {
  const [connected, setConnected] = useState(false);
  // Use a ref so the EventSource listeners always see the latest handlers
  // without re-creating the connection on every render.
  const handlersRef = useRef(handlers);
  handlersRef.current = handlers;

  const stateSettersRef = useRef(stateSetters);
  stateSettersRef.current = stateSetters;

  const activeScanIdRef = useRef(scanId);
  activeScanIdRef.current = scanId;

  const refreshState = useCallback(() => {
    void refreshFullState(
      scanId,
      stateSettersRef.current,
      () => activeScanIdRef.current === scanId,
    );
  }, [scanId]);

  useEffect(() => {
    const url = scanSSEUrl(scanId);
    const es = new EventSource(url);
    let disposed = false;
    let eventFlushTimer: number | null = null;
    let queuedEvents: ScanEvent[] = [];
    let statusFlushTimer: number | null = null;
    let pendingStatus: ScanStatusEvent | null = null;

    const flushQueuedEvents = () => {
      eventFlushTimer = null;
      if (disposed || queuedEvents.length === 0) return;
      const events = queuedEvents;
      queuedEvents = [];
      const currentHandlers = handlersRef.current;
      try {
        if (currentHandlers.onScanEvents) {
          currentHandlers.onScanEvents(events);
        } else {
          events.forEach((event) => currentHandlers.onScanEvent?.({ event }));
        }
      } catch (error) {
        console.error("处理扫描日志事件失败", error);
      }
    };

    const queueScanEvent = (event: ScanEvent) => {
      queuedEvents.push(event);
      if (eventFlushTimer == null) {
        eventFlushTimer = window.setTimeout(flushQueuedEvents, 50);
      }
    };

    const flushPendingStatus = () => {
      if (statusFlushTimer != null) window.clearTimeout(statusFlushTimer);
      statusFlushTimer = null;
      if (disposed || !pendingStatus) return;
      const status = pendingStatus;
      pendingStatus = null;
      try {
        handlersRef.current.onScanStatus?.(status);
      } catch (error) {
        console.error("处理扫描状态事件失败", error);
      }
    };

    const queueScanStatus = (status: ScanStatusEvent) => {
      pendingStatus = {
        status: status.status ?? pendingStatus?.status ?? null,
        progress: status.progress ?? pendingStatus?.progress ?? null,
        total_candidates: status.total_candidates ?? pendingStatus?.total_candidates ?? null,
        processed_candidates: status.processed_candidates ?? pendingStatus?.processed_candidates ?? null,
        static_total_files: status.static_total_files ?? pendingStatus?.static_total_files ?? null,
        static_scanned_files: status.static_scanned_files ?? pendingStatus?.static_scanned_files ?? null,
        static_analysis_done: status.static_analysis_done ?? pendingStatus?.static_analysis_done ?? null,
        opencode_pool: status.opencode_pool !== undefined
          ? status.opencode_pool
          : pendingStatus?.opencode_pool,
      };
      if (statusFlushTimer == null) {
        statusFlushTimer = window.setTimeout(flushPendingStatus, 75);
      }
    };

    function handle<T>(eventType: string, handler: ((data: T) => void) | undefined) {
      es.addEventListener(eventType, ((e: MessageEvent) => {
        if (disposed) return;
        let parsed: unknown;
        try {
          parsed = JSON.parse(e.data);
        } catch (error) {
          console.warn(`忽略无法解析的 SSE 事件: ${eventType}`, error);
          return;
        }
        if (!isValidPayload(eventType, parsed)) {
          console.warn(`忽略结构无效的 SSE 事件: ${eventType}`);
          return;
        }
        try {
          handler?.(parsed as T);
        } catch (error) {
          console.error(`处理 SSE 事件失败: ${eventType}`, error);
        }
      }) as EventListener);
    }

    es.addEventListener("connected", () => {
      setConnected(true);
    });

    // Register typed event listeners
    handle<ScanStatusEvent>("scan_status", queueScanStatus);
    handle<ScanCandidatesEvent>("scan_candidates", (d) => handlersRef.current.onScanCandidates?.({
      candidates: d.candidates.map((candidate, index) => normalizeScanCandidate(candidate, index)),
    }));
    handle<ScanCandidatesChangedEvent>("scan_candidates_changed", (d) => handlersRef.current.onScanCandidatesChanged?.(d));
    handle<ScanVulnerabilityEvent>("scan_vulnerability", (d) => handlersRef.current.onScanVulnerability?.({
      index: d.index,
      vulnerability: normalizeVulnerability(d.vulnerability),
    }));
    handle<ScanEventPayload>("scan_event", (d) => {
      const event = normalizeScanEvent(d.event);
      if (event) queueScanEvent(event);
    });
    handle<ScanFinishEvent>("scan_finish", (d) => {
      flushPendingStatus();
      handlersRef.current.onScanFinish?.(d);
    });
    handle<FpReviewStartedEvent>("fp_review_started", (d) => handlersRef.current.onFpReviewStarted?.(d));
    handle<FpReviewProgressEvent>("fp_review_progress", (d) => handlersRef.current.onFpReviewProgress?.(d));
    handle<FpReviewStageOutputEvent>("fp_review_stage_output", (d) => handlersRef.current.onFpReviewStageOutput?.(d));
    handle<FpReviewResultEvent>("fp_review_result", (d) => handlersRef.current.onFpReviewResult?.(d));
    handle<FpReviewFinishEvent>("fp_review_finish", (d) => handlersRef.current.onFpReviewFinish?.(d));
    handle<VulnerabilityValidationEvent>("vulnerability_validation", (d) => handlersRef.current.onVulnerabilityValidation?.({
      validation: normalizeValidation(d.validation),
    }));
    handle<ThreatAnalysisEvent>("threat_analysis", (d) => handlersRef.current.onThreatAnalysis?.(d));
    handle<ThreatAnalysisRunEvent>("threat_analysis_run", (d) => handlersRef.current.onThreatAnalysisRun?.(d));
    handle<ThreatAuditTaskEvent>("threat_audit_task", (d) => handlersRef.current.onThreatAuditTask?.({
      task: normalizeThreatTask(d.task),
    }));
    handle<MiningEngineRunEvent>("mining_engine_run", (d) => handlersRef.current.onMiningEngineRun?.(d));
    handle<IndexStatus>("index_status", (d) => handlersRef.current.onIndexStatus?.(d));

    es.onopen = () => {
      setConnected(true);
    };

    es.onerror = () => {
      setConnected(false);
      // EventSource auto-reconnects. On reconnect (next onopen) we do a full
      // state refresh to catch events missed during the gap.
      const origOnOpen = es.onopen;
      es.onopen = (evt) => {
        setConnected(true);
        refreshState();
        es.onopen = origOnOpen;
        origOnOpen?.call(es, evt);
      };
    };

    // Fallback poll every 30s as safety net
    const fallbackTimer = setInterval(refreshState, 30_000);

    return () => {
      disposed = true;
      es.close();
      clearInterval(fallbackTimer);
      if (eventFlushTimer != null) window.clearTimeout(eventFlushTimer);
      if (statusFlushTimer != null) window.clearTimeout(statusFlushTimer);
      queuedEvents = [];
      pendingStatus = null;
      setConnected(false);
    };
  }, [scanId, refreshState]);

  return { connected };
}
