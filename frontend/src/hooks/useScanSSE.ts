import { useEffect, useRef, useState, useCallback } from "react";
import { scanSSEUrl, getScanOverview, getScanDetailItem, getFpReviewOverview, getAgentIndexStatus, notifyShareUnavailable } from "../api/client";
import { isScanDetailResource, refreshScanResource, SCAN_DETAIL_RESOURCES } from "../scanResourceRefresh";
import type { ScanDetailResource } from "../scanResourceRefresh";
import {
  isRecord,
  isOlderScanExecution,
  scanExecutionRevision,
  mergeScanOverview,
  normalizeScanCandidate,
  normalizeScanEvent,
  normalizeThreatTask,
  normalizePatternTask,
  normalizeValidation,
  normalizeVulnerability,
} from "../scanRuntime";
import type {
  FpReviewJob,
  FpReviewMethod,
  FpReviewStatus,
  IndexStatus,
  MiningEngineRunStatus,
  OpenCodeCompletedTask,
  OutputSource,
  ScanCandidate,
  ScanEvent,
  ScanStatus,
  ThreatAnalysis,
  ThreatAnalysisRunStatus,
  ThreatAuditTask,
  ThreatPatternAuditTask,
  Vulnerability,
  VulnerabilityValidation,
} from "../types";

const SCAN_STATUSES = new Set(["pending", "analyzing", "auditing", "complete", "error", "cancelled"]);
const FP_REVIEW_STATUSES = new Set(["pending", "running", "complete", "error", "cancelled"]);

/* ------------------------------------------------------------------ */
/*  SSE event payload types (mirror backend publish() shapes)          */
/* ------------------------------------------------------------------ */

interface ScanStatusEvent {
  execution_revision?: number;
  status: string | null;
  progress: number | null;
  total_candidates: number | null;
  processed_candidates: number | null;
  static_total_files?: number | null;
  static_scanned_files?: number | null;
  static_analysis_done?: boolean | null;
  error_message?: string | null;
  opencode_pool?: ScanStatus["opencode_pool"];
}

interface OpenCodeTaskReportEvent {
  task?: OpenCodeCompletedTask;
  task_id?: string;
  revision?: number;
  completed_task_count: number;
  total_tasks: number;
}

interface ScanVulnerabilityEvent {
  index: number;
  vulnerability: Vulnerability;
}

interface ScanVulnerabilitiesChangedEvent {
  count: number;
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

interface ScanCandidateAuditEvent {
  candidate: ScanCandidate;
}

interface ScanEventPayload {
  event: ScanEvent;
}

interface ScanFinishEvent {
  execution_revision?: number;
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
  onDetailRefreshState?: (resources: readonly ScanDetailResource[], refreshing: boolean) => void;
  onStateRefresh?: () => void;
  onScanStatus?: (data: ScanStatusEvent) => void;
  onOpenCodeTaskReport?: (data: OpenCodeTaskReportEvent) => void;
  onScanCandidates?: (data: ScanCandidatesEvent) => void;
  onScanCandidatesChanged?: (data: ScanCandidatesChangedEvent) => void;
  onScanCandidateAudit?: (data: ScanCandidateAuditEvent) => void;
  onScanVulnerability?: (data: ScanVulnerabilityEvent) => void;
  onScanVulnerabilitiesChanged?: (data: ScanVulnerabilitiesChangedEvent) => void;
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
  onThreatAnalysisRefresh?: (force?: boolean) => void;
  onThreatCoverageRefresh?: () => void;
  onThreatAnalysisRun?: (data: ThreatAnalysisRunEvent) => void;
  onThreatAuditTask?: (data: ThreatAuditTaskEvent) => void;
  onThreatPatternAuditTask?: (data: { task: ThreatPatternAuditTask }) => void;
  onMiningEngineRun?: (data: MiningEngineRunEvent) => void;
  onIndexStatus?: (data: IndexStatus) => void;
}

/* ------------------------------------------------------------------ */
/*  Full-state refresh helpers (used on connect and reconnect)         */
/* ------------------------------------------------------------------ */

export interface SSEStateSetters {
  getScan: () => ScanStatus | null;
  getFpReview: () => FpReviewJob | null;
  setScan: React.Dispatch<React.SetStateAction<ScanStatus | null>>;
  setFpReview: React.Dispatch<React.SetStateAction<FpReviewJob | null>>;
  setIndexStatus: React.Dispatch<React.SetStateAction<IndexStatus | null>>;
}

async function refreshFullState(
  scanId: string,
  { getScan, setScan, setFpReview, setIndexStatus }: SSEStateSetters,
  isCurrent: () => boolean,
) {
  const requestedFrom = getScan();
  try {
    const data = await getScanOverview(scanId);
    if (!isCurrent() || data.scan_id !== scanId) return;
    setScan((previous) => {
      if (!isCurrent()) return previous;
      if (!previous || previous.scan_id !== scanId) return data;
      return mergeScanOverview(previous, data, requestedFrom);
    });
  } catch {
    // transient — SSE will keep pushing
  }
  if (!isCurrent()) return;
  try {
    const job = await getFpReviewOverview(scanId);
    if (!isCurrent()) return;
    if (job) setFpReview((previous) => previous ? { ...previous, ...job, results: previous.results } : job);
  } catch {
    // Retain loaded results on transient failures.
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
        && (value.execution_revision == null || isFiniteNumber(value.execution_revision))
        && (value.progress == null || isFiniteNumber(value.progress))
        && (value.total_candidates == null || isFiniteNumber(value.total_candidates))
        && (value.processed_candidates == null || isFiniteNumber(value.processed_candidates))
        && (value.static_total_files == null || isFiniteNumber(value.static_total_files))
        && (value.static_scanned_files == null || isFiniteNumber(value.static_scanned_files))
        && (value.static_analysis_done == null || typeof value.static_analysis_done === "boolean")
        && (value.opencode_pool === undefined || value.opencode_pool === null || isRecord(value.opencode_pool));
    case "opencode_task_report":
      return (isString(value.task_id) || isRecord(value.task) && isString(value.task.task_id))
        && isFiniteNumber(value.completed_task_count)
        && isFiniteNumber(value.total_tasks);
    case "scan_candidates":
      return Array.isArray(value.candidates) && value.candidates.every(isCandidate);
    case "scan_candidates_changed":
      return isFiniteNumber(value.offset)
        && isFiniteNumber(value.count)
        && isFiniteNumber(value.total_candidates)
        && typeof value.final === "boolean";
    case "scan_candidate_audit":
      return isCandidate(value.candidate);
    case "scan_vulnerability":
      return Number.isInteger(value.index) && Number(value.index) >= 0 && isVulnerability(value.vulnerability);
    case "scan_vulnerabilities_changed":
      return Number.isInteger(value.count) && Number(value.count) >= 0;
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
    case "file_inventory":
      return isString(value.snapshot_id) && isString(value.status);
    case "threat_analysis_run":
      return isRecord(value.run) && isString(value.run.status);
    case "threat_pattern_audit_task":
      return isRecord(value.task)
        && isString(value.task.task_id)
        && isString(value.task.status)
        && isString(value.task.module_name)
        && Array.isArray(value.task.code_paths)
        && value.task.code_paths.every((path) => isRecord(path) && isString(path.path));
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
): { connected: boolean; failedResources: ReadonlySet<ScanDetailResource>; refreshDetails: (resources?: readonly ScanDetailResource[]) => void } {
  const [connected, setConnected] = useState(false);
  const [failedResources, setFailedResources] = useState<Set<ScanDetailResource>>(new Set());
  const requestDetailsRef = useRef<(resources: readonly ScanDetailResource[]) => void>(() => {});
  const refreshDetails = useCallback((resources: readonly ScanDetailResource[] = SCAN_DETAIL_RESOURCES) => {
    requestDetailsRef.current(resources);
  }, []);
  // Use a ref so the EventSource listeners always see the latest handlers
  // without re-creating the connection on every render.
  const handlersRef = useRef(handlers);
  handlersRef.current = handlers;

  const stateSettersRef = useRef(stateSetters);
  stateSettersRef.current = stateSetters;

  const activeScanIdRef = useRef(scanId);
  activeScanIdRef.current = scanId;

  const refreshInFlight = useRef<string | null>(null);
  const refreshState = useCallback(() => {
    if (document.hidden || refreshInFlight.current === scanId) return;
    refreshInFlight.current = scanId;
    void refreshFullState(
      scanId,
      stateSettersRef.current,
      () => activeScanIdRef.current === scanId,
    ).finally(() => {
      if (refreshInFlight.current === scanId) refreshInFlight.current = null;
      if (activeScanIdRef.current === scanId) handlersRef.current.onStateRefresh?.();
    });
  }, [scanId]);

  useEffect(() => {
    const url = scanSSEUrl(scanId);
    const es = new EventSource(url);
    es.addEventListener("share_unavailable", () => {
      es.close();
      setConnected(false);
      notifyShareUnavailable(scanId, new URL(url).searchParams.get("token") ?? "");
    });
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
      if (isOlderScanExecution(pendingStatus, status)
        || isOlderScanExecution(stateSettersRef.current.getScan(), status)) return;
      if ((scanExecutionRevision(status) ?? 0) > (scanExecutionRevision(pendingStatus) ?? 0)) {
        pendingStatus = null;
      }
      pendingStatus = {
        execution_revision: scanExecutionRevision(status) ?? scanExecutionRevision(pendingStatus),
        status: status.status ?? pendingStatus?.status ?? null,
        progress: status.progress ?? pendingStatus?.progress ?? null,
        total_candidates: status.total_candidates ?? pendingStatus?.total_candidates ?? null,
        processed_candidates: status.processed_candidates ?? pendingStatus?.processed_candidates ?? null,
        static_total_files: status.static_total_files ?? pendingStatus?.static_total_files ?? null,
        static_scanned_files: status.static_scanned_files ?? pendingStatus?.static_scanned_files ?? null,
        static_analysis_done: status.static_analysis_done ?? pendingStatus?.static_analysis_done ?? null,
        error_message: status.error_message !== undefined ? status.error_message : pendingStatus?.error_message,
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

    let resourceTimer: number | null = null;
    const pendingResources = new Map<string, { resource: string; index?: number }>();
    const resourceVersions = new Map<ScanDetailResource, number>();
    const resourceController = new AbortController();
    setFailedResources(new Set());
    let fullRefresh = false;
    let resourceRunning = false;
    const reloadResources = async () => {
      resourceTimer = null;
      if (disposed || document.hidden || resourceRunning) return;
      resourceRunning = true;
      const reloadAll = fullRefresh;
      fullRefresh = false;
      const notices = [...pendingResources.values()];
      pendingResources.clear();
      const collections = reloadAll ? [...SCAN_DETAIL_RESOURCES] : Array.from(new Set(
        notices.filter((notice) => typeof notice.index !== "number").map((notice) => notice.resource).filter(isScanDetailResource),
      ));
      const versions = new Map(collections.map((resource) => [resource, resourceVersions.get(resource)]));
      // Artifact invalidations also apply when another notice requires a full
      // scan refresh. The overview itself intentionally has no artifact body.
      if (reloadAll || notices.some((notice) => notice.resource === "threat-analysis")) {
        handlersRef.current.onThreatAnalysisRefresh?.(true);
      }
      if (reloadAll || notices.some((notice) => ["threat-analysis", "file-inventory"].includes(notice.resource))) {
        handlersRef.current.onThreatCoverageRefresh?.();
      }
      handlersRef.current.onDetailRefreshState?.(collections, true);
      try {
        const source = stateSettersRef.current.getScan();
        const review = stateSettersRef.current.getFpReview();
        if (source?.scan_id === scanId && collections.length) {
          const results = await Promise.allSettled(collections.map((resource) => (
            refreshScanResource(resource, source, review, resourceController.signal)
          )));
          if (disposed) return;
          const failed = new Set(collections.filter((_, index) => results[index].status === "rejected"));
          const stale = new Set(collections.filter((resource) => versions.get(resource) !== resourceVersions.get(resource)
            || scanExecutionRevision(source) !== scanExecutionRevision(stateSettersRef.current.getScan())));
          // Findings, reviews and validations form one visible issue snapshot.
          // A busy or failing task collection must not restart that snapshot.
          const issueResources = collections.filter((resource) => ["vulnerabilities", "validations", "fp-review"].includes(resource));
          if (issueResources.some((resource) => stale.has(resource))) issueResources.forEach((resource) => stale.add(resource));
          if (issueResources.some((resource) => failed.has(resource))) issueResources.forEach((resource) => failed.add(resource));
          for (const resource of stale) pendingResources.set(`${resource}:collection`, { resource });
          const updates = results.flatMap((result, index) => result.status === "fulfilled"
            && !stale.has(collections[index]) && !failed.has(collections[index]) ? [result.value] : []);
          if (updates.length) {
            stateSettersRef.current.setScan((previous) => previous?.scan_id === scanId
              ? updates.reduce((current, update) => update.scan?.(current) ?? current, previous) : previous);
            stateSettersRef.current.setFpReview((previous) => updates.reduce((current, update) => update.review?.(current) ?? current, previous));
          }
          setFailedResources((previous) => new Set([
            ...[...previous].filter((resource) => !collections.includes(resource)), ...failed,
          ]));
        }
        for (const notice of notices) {
          if (disposed) break;
          if (typeof notice.index !== "number" || !["candidates", "vulnerabilities", "validations", "fp-review"].includes(notice.resource)) continue;
          try {
            const item = await getScanDetailItem(scanId, notice.resource, notice.index, notice.resource !== "validations", resourceController.signal);
            if (disposed) break;
            if (notice.resource === "candidates") handlersRef.current.onScanCandidateAudit?.({ candidate: normalizeScanCandidate(item, notice.index) });
            if (notice.resource === "vulnerabilities") handlersRef.current.onScanVulnerability?.({ index: notice.index, vulnerability: normalizeVulnerability(item) });
            if (notice.resource === "validations") handlersRef.current.onVulnerabilityValidation?.({ validation: normalizeValidation(item) });
            if (notice.resource === "fp-review") {
              if (!stateSettersRef.current.getFpReview()) requestCollections(["fp-review"]);
              else stateSettersRef.current.setFpReview((previous) => previous ? { ...previous, results: [...previous.results.filter((result) => result.vuln_index !== notice.index), item] } : previous);
            }
          } catch {
            // A deleted detail or transient read failure invalidates only its collection.
            if (!disposed && isScanDetailResource(notice.resource)) requestCollections([notice.resource]);
          }
        }
      } catch {
        if (!disposed) setFailedResources((previous) => new Set([...previous, ...collections]));
      } finally {
        resourceRunning = false;
        if (!disposed) {
          handlersRef.current.onDetailRefreshState?.(collections, false);
          refreshState();
          if (fullRefresh || pendingResources.size) scheduleResources();
        }
      }
    };
    const scheduleResources = () => { if (!resourceRunning && resourceTimer == null) resourceTimer = window.setTimeout(reloadResources, 150); };
    const requestCollections = (resources: readonly ScanDetailResource[]) => {
      for (const resource of resources) {
        resourceVersions.set(resource, (resourceVersions.get(resource) ?? 0) + 1);
        pendingResources.set(`${resource}:collection`, { resource });
      }
      scheduleResources();
    };
    requestDetailsRef.current = requestCollections;
    const requestFullRefresh = () => {
      fullRefresh = true;
      requestCollections(SCAN_DETAIL_RESOURCES);
    };
    es.addEventListener("resource_changed", ((event: MessageEvent) => {
      try {
        const notice = JSON.parse(event.data);
        if (!isRecord(notice) || typeof notice.resource !== "string") throw new Error("Invalid resource notice");
        if (typeof notice.index !== "number" && isScanDetailResource(notice.resource)) {
          requestCollections([notice.resource]);
          return;
        }
        pendingResources.set(`${notice.resource}:${notice.index}`, {
          resource: notice.resource, index: typeof notice.index === "number" ? notice.index : undefined,
        });
        if (pendingResources.size > 100) { pendingResources.clear(); requestFullRefresh(); }
        scheduleResources();
      } catch { requestFullRefresh(); }
    }) as EventListener);
    es.addEventListener("resync_required", requestFullRefresh);
    const onVisible = () => { if (!document.hidden) { requestFullRefresh(); refreshState(); } };
    document.addEventListener("visibilitychange", onVisible);

    // Register typed event listeners
    handle<ScanStatusEvent>("scan_status", queueScanStatus);
    handle<OpenCodeTaskReportEvent>("opencode_task_report", (d) => (
      handlersRef.current.onOpenCodeTaskReport?.(d)
    ));
    handle<ScanCandidatesEvent>("scan_candidates", (d) => handlersRef.current.onScanCandidates?.({
      candidates: d.candidates.map((candidate, index) => normalizeScanCandidate(candidate, index)),
    }));
    handle<ScanCandidatesChangedEvent>("scan_candidates_changed", (d) => handlersRef.current.onScanCandidatesChanged?.(d));
    handle<ScanCandidateAuditEvent>("scan_candidate_audit", (d) => handlersRef.current.onScanCandidateAudit?.({
      candidate: normalizeScanCandidate(d.candidate, d.candidate.idx),
    }));
    handle<ScanVulnerabilityEvent>("scan_vulnerability", (d) => handlersRef.current.onScanVulnerability?.({
      index: d.index,
      vulnerability: normalizeVulnerability(d.vulnerability),
    }));
    handle<ScanVulnerabilitiesChangedEvent>("scan_vulnerabilities_changed", (d) => {
      requestCollections(["vulnerabilities"]);
      handlersRef.current.onScanVulnerabilitiesChanged?.(d);
    });
    handle<ScanEventPayload>("scan_event", (d) => {
      const event = normalizeScanEvent(d.event);
      if (event) queueScanEvent(event);
    });
    handle<ScanFinishEvent>("scan_finish", (d) => {
      if (isOlderScanExecution(pendingStatus, d)
        || isOlderScanExecution(stateSettersRef.current.getScan(), d)) return;
      flushPendingStatus();
      handlersRef.current.onScanFinish?.(d);
      handlersRef.current.onThreatAnalysisRefresh?.();
    });
    handle<FpReviewStartedEvent>("fp_review_started", (d) => handlersRef.current.onFpReviewStarted?.(d));
    handle<FpReviewProgressEvent>("fp_review_progress", (d) => handlersRef.current.onFpReviewProgress?.(d));
    handle<FpReviewStageOutputEvent>("fp_review_stage_output", (d) => handlersRef.current.onFpReviewStageOutput?.(d));
    handle<FpReviewResultEvent>("fp_review_result", (d) => handlersRef.current.onFpReviewResult?.(d));
    handle<FpReviewFinishEvent>("fp_review_finish", (d) => handlersRef.current.onFpReviewFinish?.(d));
    handle<VulnerabilityValidationEvent>("vulnerability_validation", (d) => handlersRef.current.onVulnerabilityValidation?.({
      validation: normalizeValidation(d.validation),
    }));
    handle<ThreatAnalysisEvent>("threat_analysis", (d) => {
      handlersRef.current.onThreatAnalysis?.(d);
      handlersRef.current.onThreatCoverageRefresh?.();
    });
    handle<{ status: string }>("file_inventory", () => handlersRef.current.onThreatCoverageRefresh?.());
    handle<ThreatAnalysisRunEvent>("threat_analysis_run", (d) => {
      handlersRef.current.onThreatAnalysisRun?.(d);
      if (d.run.status === "success") {
        handlersRef.current.onThreatAnalysisRefresh?.(true);
        handlersRef.current.onThreatCoverageRefresh?.();
      }
    });
    handle<{ task: ThreatPatternAuditTask }>("threat_pattern_audit_task", (d) => handlersRef.current.onThreatPatternAuditTask?.({
      task: normalizePatternTask(d.task),
    }));
    handle<ThreatAuditTaskEvent>("threat_audit_task", (d) => handlersRef.current.onThreatAuditTask?.({
      task: normalizeThreatTask(d.task),
    }));
    handle<MiningEngineRunEvent>("mining_engine_run", (d) => handlersRef.current.onMiningEngineRun?.(d));
    handle<IndexStatus>("index_status", (d) => handlersRef.current.onIndexStatus?.(d));

    es.onopen = () => {
      setConnected(true);
      refreshState();
      handlersRef.current.onThreatAnalysisRefresh?.(true);
      handlersRef.current.onThreatCoverageRefresh?.();
    };

    es.onerror = () => {
      setConnected(false);
    };

    // Fallback poll every 30s as safety net
    const fallbackTimer = setInterval(() => {
      refreshState();
      handlersRef.current.onThreatAnalysisRefresh?.();
    }, 30_000);

    return () => {
      disposed = true;
      resourceController.abort();
      requestDetailsRef.current = () => {};
      document.removeEventListener("visibilitychange", onVisible);
      if (resourceTimer != null) window.clearTimeout(resourceTimer);
      es.close();
      clearInterval(fallbackTimer);
      if (eventFlushTimer != null) window.clearTimeout(eventFlushTimer);
      if (statusFlushTimer != null) window.clearTimeout(statusFlushTimer);
      queuedEvents = [];
      pendingStatus = null;
      setConnected(false);
    };
  }, [scanId, refreshState]);

  return { connected, failedResources, refreshDetails };
}
