import { useEffect, useRef, useState, useCallback } from "react";
import { scanSSEUrl, getScanOverview, getFpReview, getAgentIndexStatus } from "../api/client";
import { getScanThreatAnalysis } from "../features/threatAnalysis/api";
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
  summary_status?: FpReviewStatus | null;
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
  summary_markdown?: string;
  summary_output_source?: OutputSource;
}

interface FpReviewSummaryEvent {
  review_id: string;
  status: FpReviewStatus;
  error_message?: string | null;
  summary_markdown?: string | null;
  summary_output_source?: OutputSource | null;
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
  onScanFinish?: (data: ScanFinishEvent) => void;
  onFpReviewStarted?: (data: FpReviewStartedEvent) => void;
  onFpReviewProgress?: (data: FpReviewProgressEvent) => void;
  onFpReviewStageOutput?: (data: FpReviewStageOutputEvent) => void;
  onFpReviewResult?: (data: FpReviewResultEvent) => void;
  onFpReviewFinish?: (data: FpReviewFinishEvent) => void;
  onFpReviewSummaryStarted?: (data: FpReviewSummaryEvent) => void;
  onFpReviewSummaryFinish?: (data: FpReviewSummaryEvent) => void;
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
) {
  try {
    const data = await getScanOverview(scanId);
    setScan((previous) => previous ? {
      ...data,
      candidates: previous.candidates,
      vulnerabilities: previous.vulnerabilities,
      skill_reports: previous.skill_reports,
      threat_analysis: previous.threat_analysis,
      threat_audit_tasks: previous.threat_audit_tasks,
      validations: previous.validations,
      events: previous.events,
      detail_pages: previous.detail_pages,
    } : data);
  } catch {
    // transient — SSE will keep pushing
  }
  try {
    const job = await getFpReview(scanId);
    // Merge with existing state to preserve in-progress stage_outputs
    // that arrived via SSE but are not yet part of a completed result.
    setFpReview((prev) => {
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
  try {
    const index = await getAgentIndexStatus(scanId);
    setIndexStatus(index);
  } catch {
    // transient — index_status SSE may still arrive later
  }
  try {
    const analysis = await getScanThreatAnalysis(scanId);
    setScan((prev) => prev ? { ...prev, threat_analysis: analysis } : prev);
  } catch {
    // 404 = no threat analysis snapshot yet
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

  const refreshState = useCallback(() => {
    refreshFullState(scanId, stateSettersRef.current);
  }, [scanId]);

  useEffect(() => {
    const url = scanSSEUrl(scanId);
    const es = new EventSource(url);

    function handle<T>(eventType: string, handler: ((data: T) => void) | undefined) {
      es.addEventListener(eventType, ((e: MessageEvent) => {
        try {
          const data = JSON.parse(e.data) as T;
          handler?.(data);
        } catch {
          // malformed JSON — ignore
        }
      }) as EventListener);
    }

    es.addEventListener("connected", () => {
      setConnected(true);
    });

    // Register typed event listeners
    handle<ScanStatusEvent>("scan_status", (d) => handlersRef.current.onScanStatus?.(d));
    handle<ScanCandidatesEvent>("scan_candidates", (d) => handlersRef.current.onScanCandidates?.(d));
    handle<ScanCandidatesChangedEvent>("scan_candidates_changed", (d) => handlersRef.current.onScanCandidatesChanged?.(d));
    handle<ScanVulnerabilityEvent>("scan_vulnerability", (d) => handlersRef.current.onScanVulnerability?.(d));
    handle<ScanEventPayload>("scan_event", (d) => handlersRef.current.onScanEvent?.(d));
    handle<ScanFinishEvent>("scan_finish", (d) => handlersRef.current.onScanFinish?.(d));
    handle<FpReviewStartedEvent>("fp_review_started", (d) => handlersRef.current.onFpReviewStarted?.(d));
    handle<FpReviewProgressEvent>("fp_review_progress", (d) => handlersRef.current.onFpReviewProgress?.(d));
    handle<FpReviewStageOutputEvent>("fp_review_stage_output", (d) => handlersRef.current.onFpReviewStageOutput?.(d));
    handle<FpReviewResultEvent>("fp_review_result", (d) => handlersRef.current.onFpReviewResult?.(d));
    handle<FpReviewFinishEvent>("fp_review_finish", (d) => handlersRef.current.onFpReviewFinish?.(d));
    handle<FpReviewSummaryEvent>("fp_review_summary_started", (d) => handlersRef.current.onFpReviewSummaryStarted?.(d));
    handle<FpReviewSummaryEvent>("fp_review_summary_finish", (d) => handlersRef.current.onFpReviewSummaryFinish?.(d));
    handle<VulnerabilityValidationEvent>("vulnerability_validation", (d) => handlersRef.current.onVulnerabilityValidation?.(d));
    handle<ThreatAnalysisEvent>("threat_analysis", (d) => handlersRef.current.onThreatAnalysis?.(d));
    handle<ThreatAnalysisRunEvent>("threat_analysis_run", (d) => handlersRef.current.onThreatAnalysisRun?.(d));
    handle<ThreatAuditTaskEvent>("threat_audit_task", (d) => handlersRef.current.onThreatAuditTask?.(d));
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
      es.close();
      clearInterval(fallbackTimer);
      setConnected(false);
    };
  }, [scanId, refreshState]);

  return { connected };
}
