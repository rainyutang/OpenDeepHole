import { scanSSEUrl, notifyShareUnavailable } from "../../api/accessPolicy";

import type { ScanDetailResource } from "../../scanResourceRefresh";
import { isOlderScanExecution, normalizeScanEvent } from "../../scanRuntime/scanSnapshots";
import { normalizeScanCandidate } from "../../scanRuntime/candidates";
import { normalizeThreatTask, normalizePatternTask } from "../../scanRuntime/audit";
import { normalizeValidation, normalizeVulnerability } from "../../scanRuntime/issues";
import type { IndexStatus } from "../../types/scans";
import type { ThreatPatternAuditTask } from "../../types/audit";
import {
  ScanStatusEvent,
  OpenCodeTaskReportEvent,
  ScanVulnerabilityEvent,
  ScanVulnerabilitiesChangedEvent,
  ScanCandidatesEvent,
  ScanCandidatesChangedEvent,
  ScanCandidateAuditEvent,
  ScanEventPayload,
  ScanFinishEvent,
  FpReviewStartedEvent,
  FpReviewProgressEvent,
  FpReviewResultEvent,
  FpReviewStageOutputEvent,
  FpReviewFinishEvent,
  VulnerabilityValidationEvent,
  ThreatAnalysisEvent,
  ThreatAnalysisRunEvent,
  ThreatAuditTaskEvent,
  MiningEngineRunEvent,
  ScanSSEHandlers,
  SSEStateSetters,
  isValidPayload,
} from './protocol';

import type { StateResource } from './refreshState';
import type { MutableRefObject, Dispatch, SetStateAction } from 'react';

import { createScanEventBatcher } from './eventBatching';
import { createScanResourceCoordinator } from './resourceCoordinator';

export function connectScanStream({
  scanId,
  handlersRef,
  stateSettersRef,
  activeScanIdRef,
  setConnected,
  setOverviewFailed,
  setFailedResources,
  requestStateRef,
  requestDetailsRef,
  refreshState,
}: {
  scanId: string;
  handlersRef: MutableRefObject<ScanSSEHandlers>;
  stateSettersRef: MutableRefObject<SSEStateSetters>;
  activeScanIdRef: MutableRefObject<string>;
  setConnected: Dispatch<SetStateAction<boolean>>;
  setOverviewFailed: Dispatch<SetStateAction<boolean>>;
  setFailedResources: Dispatch<SetStateAction<Set<ScanDetailResource>>>;
  requestStateRef: MutableRefObject<(resources: readonly StateResource[]) => void>;
  requestDetailsRef: MutableRefObject<(resources: readonly ScanDetailResource[]) => void>;
  refreshState: () => void;
}) {
  setOverviewFailed(false);
  const url = scanSSEUrl(scanId);
  const es = new EventSource(url);
  es.addEventListener("share_unavailable", () => {
    es.close();
    setConnected(false);
    notifyShareUnavailable(scanId, new URL(url).searchParams.get("token") ?? "");
  });
  const lifetime = { disposed: false };
  const batcher = createScanEventBatcher({ handlersRef, stateSettersRef, lifetime });
  const { queueScanEvent, queueScanStatus, flushPendingStatus } = batcher;
  function handle<T>(eventType: string, handler: ((data: T) => void) | undefined) {
    es.addEventListener(eventType, ((e: MessageEvent) => {
      if (lifetime.disposed) return;
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

  const coordinator = createScanResourceCoordinator({ scanId, handlersRef, stateSettersRef, activeScanIdRef, lifetime, setOverviewFailed, setFailedResources });
  const { requestCollections, queueCoverageIssues } = coordinator;
  requestStateRef.current = coordinator.requestState;
  requestDetailsRef.current = requestCollections;
  es.addEventListener('resource_changed', coordinator.onResourceChanged as EventListener);
  es.addEventListener('resync_required', coordinator.requestFullRefresh);
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
  handle<ScanVulnerabilityEvent>("scan_vulnerability", (d) => {
    queueCoverageIssues();
    handlersRef.current.onScanVulnerability?.({ index: d.index, vulnerability: normalizeVulnerability(d.vulnerability) });
  });
  handle<ScanVulnerabilitiesChangedEvent>("scan_vulnerabilities_changed", (d) => {
    queueCoverageIssues();
    requestCollections(["vulnerabilities"]);
    handlersRef.current.onScanVulnerabilitiesChanged?.(d);
  });
  handle<ScanEventPayload>("scan_event", (d) => {
    const event = normalizeScanEvent(d.event);
    if (event) queueScanEvent(event);
  });
  handle<ScanFinishEvent>("scan_finish", (d) => {
    if (isOlderScanExecution(batcher.pendingStatus(), d)
      || isOlderScanExecution(stateSettersRef.current.getScan(), d)) return;
    flushPendingStatus();
    handlersRef.current.onScanFinish?.(d);
    handlersRef.current.onThreatAnalysisRefresh?.();
  });
  handle<FpReviewStartedEvent>("fp_review_started", (d) => handlersRef.current.onFpReviewStarted?.(d));
  handle<FpReviewProgressEvent>("fp_review_progress", (d) => handlersRef.current.onFpReviewProgress?.(d));
  handle<FpReviewStageOutputEvent>("fp_review_stage_output", (d) => handlersRef.current.onFpReviewStageOutput?.(d));
  handle<FpReviewResultEvent>("fp_review_result", (d) => { queueCoverageIssues(); handlersRef.current.onFpReviewResult?.(d); });
  handle<FpReviewFinishEvent>("fp_review_finish", (d) => { queueCoverageIssues(); handlersRef.current.onFpReviewFinish?.(d); });
  handle<VulnerabilityValidationEvent>("vulnerability_validation", (d) => handlersRef.current.onVulnerabilityValidation?.({
    validation: normalizeValidation(d.validation),
  }));
  handle<ThreatAnalysisEvent>("threat_analysis", (d) => {
    handlersRef.current.onThreatAnalysis?.(d);
    handlersRef.current.onThreatCoverageRefresh?.();
    handlersRef.current.onCoverageIssuesRefresh?.();
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
    coordinator.onOpen();
    refreshState();
  };

  es.onerror = () => {
    setConnected(false);
    coordinator.onError();
  };

  // Fallback poll every 30s as safety net
  const fallbackTimer = setInterval(() => {
    refreshState();
    handlersRef.current.onThreatAnalysisRefresh?.();
  }, 30_000);

  return () => {
    lifetime.disposed = true;
    coordinator.dispose();
    requestDetailsRef.current = () => { };
    requestStateRef.current = () => { };
    es.close();
    clearInterval(fallbackTimer);
    batcher.dispose();
    setConnected(false);
  };
}
