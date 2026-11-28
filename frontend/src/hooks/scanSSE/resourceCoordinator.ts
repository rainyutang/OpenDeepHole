import { getScanDetailItem } from "../../api/scanDetails";
import { getFpReviewOverview } from "../../api/fpReview";
import { isScanDetailResource, refreshScanResource, SCAN_DETAIL_RESOURCES } from "../../scanResourceRefresh";

import type { RefreshedScanResource, ScanDetailResource } from "../../scanResourceRefresh";
import { isRecord } from "../../scanRuntime/record";
import { scanExecutionRevision } from "../../scanRuntime/scanSnapshots";
import { normalizeScanCandidate } from "../../scanRuntime/candidates";
import { normalizeValidation, normalizeVulnerability } from "../../scanRuntime/issues";
import type { FpReviewJob } from "../../types/fpReview";
import { ScanSSEHandlers, SSEStateSetters } from './protocol';
import { refreshFullState, STATE_RESOURCES } from './refreshState';
import type { StateResource } from './refreshState';
import type { RefObject, Dispatch, SetStateAction } from 'react';
interface StreamLifetime { disposed: boolean }

export function createScanResourceCoordinator({ scanId, handlersRef, stateSettersRef, activeScanIdRef, lifetime, setOverviewFailed, setFailedResources, pendingExecutionRevision }: {
  scanId: string;
  handlersRef: RefObject<ScanSSEHandlers>;
  stateSettersRef: RefObject<SSEStateSetters>;
  activeScanIdRef: RefObject<string>;
  lifetime: StreamLifetime;
  setOverviewFailed: Dispatch<SetStateAction<boolean>>;
  setFailedResources: Dispatch<SetStateAction<Set<ScanDetailResource>>>;
  pendingExecutionRevision: () => number | undefined;
}) {
  let resourceTimer: number | null = null;
  type Notice = { resource: string; index?: number; resultsChanged?: boolean; taskSummaryPending?: boolean; delegated?: boolean };
  const pendingResources = new Map<string, Notice>();
  const taskCollections = new Set(["threat-audit-tasks", "threat-pattern-audit-tasks"]);
  const taskIsVisible = (resource: string) => !handlersRef.current.activeTaskCollections
    || handlersRef.current.activeTaskCollections().includes(resource as ScanDetailResource);
  const taskIsDelegated = (resource: string) => resource === "threat-pattern-audit-tasks" && handlersRef.current.ownsPatternTaskPages?.();
  const needsRead = (notice: Notice) => !taskCollections.has(notice.resource) || notice.taskSummaryPending
    || (taskIsVisible(notice.resource) && (!taskIsDelegated(notice.resource) || !notice.delegated));
  const lastTaskRefresh = new Map<string, number>();
  let resourceTimerAt = Infinity;
  let finalRefreshKey = "";
  let taskExecutionRevision = scanExecutionRevision(stateSettersRef.current.getScan());
  const resourceVersions = new Map<ScanDetailResource, number>();
  const resourceController = new AbortController();
  setFailedResources(new Set());
  let fullRefresh = false;
  let resourceRunning = false;
  let coverageIssuesDirty = false;
  let connectionRefresh = false;
  let connectionInterrupted = false;
  const pendingState = new Set<StateResource>();
  let pendingResultRefresh = false;
  let stateRunning = false;
  const startStateRefresh = (resources: ReadonlySet<StateResource>, reviewRequest?: Promise<FpReviewJob | null>) => {
    if (!resources.size || stateRunning) return;
    resources.forEach((resource) => pendingState.delete(resource));
    const refreshResults = resources.has("overview") && pendingResultRefresh;
    if (resources.has("overview")) pendingResultRefresh = false;
    stateRunning = true;
    const isCurrent = () => !lifetime.disposed && activeScanIdRef.current === scanId;
    void refreshFullState(scanId, stateSettersRef.current, isCurrent,
      resources, resourceController.signal, reviewRequest).then((ok) => {
        if (isCurrent() && resources.has("overview")) {
          setOverviewFailed(!ok);
          if (refreshResults) handlersRef.current.onStateRefresh?.();
        }
      }).finally(() => {
        stateRunning = false;
        if (!lifetime.disposed && pendingState.size) scheduleResources();
      });
  };
  const reloadResources = async () => {
    resourceTimer = null;
    resourceTimerAt = Infinity;
    if (lifetime.disposed || document.hidden) return;
    if (resourceRunning) {
      // Progress and time estimates must keep advancing while a large
      // finding collection is still paging in the background.
      startStateRefresh(new Set(pendingState));
      return;
    }
    resourceRunning = true;
    const reloadAll = fullRefresh;
    fullRefresh = false;
    const refreshCoverageIssues = coverageIssuesDirty;
    coverageIssuesDirty = false;
    const refreshConnectionArtifacts = connectionRefresh;
    connectionRefresh = false;
    const notices = [...pendingResources.entries()].filter(([, notice]) => needsRead(notice) && (!taskCollections.has(notice.resource)
      || Date.now() >= (lastTaskRefresh.get(notice.resource) ?? -Infinity) + 1000));
    notices.forEach(([key, notice]) => {
      if (taskCollections.has(notice.resource) && (!taskIsVisible(notice.resource) || taskIsDelegated(notice.resource))) {
        // An engine-specific page can consume the notice without validating
        // the separate shared cache. Keep that cache dirty until it is read.
        pendingResources.set(key, { ...notice, taskSummaryPending: false,
          delegated: taskIsVisible(notice.resource) && Boolean(taskIsDelegated(notice.resource)) });
      } else pendingResources.delete(key);
    });
    const readyNotices = notices.map(([, notice]) => notice);
    const visibleTaskResultsChanged = readyNotices.some((notice) => taskCollections.has(notice.resource)
      && taskIsVisible(notice.resource) && notice.resultsChanged);
    if (readyNotices.some((notice) => notice.taskSummaryPending) || visibleTaskResultsChanged) {
      pendingState.add("overview");
      pendingResultRefresh ||= visibleTaskResultsChanged;
    }
    const stateResources = stateRunning ? new Set<StateResource>() : new Set(pendingState);
    const collections = (reloadAll ? [...SCAN_DETAIL_RESOURCES] : Array.from(new Set(
      readyNotices.filter((notice) => typeof notice.index !== "number").map((notice) => notice.resource).filter(isScanDetailResource),
    ))).filter((resource) => !taskCollections.has(resource) || taskIsVisible(resource));
    readyNotices.filter((notice) => taskCollections.has(notice.resource)).forEach((notice) => lastTaskRefresh.set(notice.resource, Date.now()));
    const versions = new Map(collections.map((resource) => [resource, resourceVersions.get(resource)]));
    // Artifact invalidations also apply when another notice requires a full
    // scan refresh. The overview itself intentionally has no artifact body.
    if (reloadAll || refreshConnectionArtifacts || readyNotices.some((notice) => notice.resource === "threat-analysis")) {
      handlersRef.current.onThreatAnalysisRefresh?.(true);
    }
    if (reloadAll || refreshConnectionArtifacts || readyNotices.some((notice) => ["threat-analysis", "file-inventory"].includes(notice.resource))) {
      handlersRef.current.onThreatCoverageRefresh?.();
    }
    if (reloadAll || refreshConnectionArtifacts || refreshCoverageIssues || readyNotices.some((notice) => notice.resource === "file-inventory")) {
      handlersRef.current.onCoverageIssuesRefresh?.();
    }
    handlersRef.current.onDetailRefreshState?.(collections, true);
    // Share only within this batch: the same scan-owned signal cancels both
    // consumers, without letting another component cancel a shared request.
    const source = stateSettersRef.current.getScan();
    const review = stateSettersRef.current.getFpReview();
    const reviewRequest = stateResources.has("fp-review") || (source?.scan_id === scanId && collections.includes("fp-review"))
      ? getFpReviewOverview(scanId, resourceController.signal) : undefined;
    startStateRefresh(stateResources, reviewRequest);
    try {
      if (source?.scan_id === scanId && collections.length) {
        const results = await Promise.allSettled(collections.map((resource) => (
          resource === "threat-pattern-audit-tasks" && handlersRef.current.ownsPatternTaskPages?.()
            ? Promise.resolve<RefreshedScanResource>({})
            : refreshScanResource(resource, source, review, resourceController.signal, reviewRequest)
        )));
        if (lifetime.disposed) return;
        const failed = new Set(collections.filter((_, index) => results[index].status === "rejected"));
        const stale = new Set(collections.filter((resource) => versions.get(resource) !== resourceVersions.get(resource)
          || scanExecutionRevision(source) !== scanExecutionRevision(stateSettersRef.current.getScan())));
        // Findings, reviews and validations form one visible issue snapshot.
        // A busy or failing task collection must not restart that snapshot.
        const issueResources = collections.filter((resource) => ["vulnerabilities", "validations", "fp-review"].includes(resource));
        if (issueResources.some((resource) => stale.has(resource))) issueResources.forEach((resource) => stale.add(resource));
        if (issueResources.some((resource) => failed.has(resource))) issueResources.forEach((resource) => failed.add(resource));
        for (const resource of stale) {
          const key = `${resource}:collection`;
          pendingResources.set(key, { ...pendingResources.get(key), resource });
        }
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
      for (const notice of readyNotices) {
        if (lifetime.disposed) break;
        if (typeof notice.index !== "number" || !["candidates", "vulnerabilities", "validations", "fp-review"].includes(notice.resource)) continue;
        try {
          const item = await getScanDetailItem(scanId, notice.resource, notice.index, notice.resource !== "validations", resourceController.signal);
          if (lifetime.disposed) break;
          if (notice.resource === "candidates") handlersRef.current.onScanCandidateAudit?.({ candidate: normalizeScanCandidate(item, notice.index) });
          if (notice.resource === "vulnerabilities") handlersRef.current.onScanVulnerability?.({ index: notice.index, vulnerability: normalizeVulnerability(item) });
          if (notice.resource === "validations") handlersRef.current.onVulnerabilityValidation?.({ validation: normalizeValidation(item) });
          if (notice.resource === "fp-review") {
            if (!stateSettersRef.current.getFpReview()) requestCollections(["fp-review"]);
            else stateSettersRef.current.setFpReview((previous) => previous ? { ...previous, results: [...previous.results.filter((result) => result.vuln_index !== notice.index), item] } : previous);
          }
        } catch {
          // A deleted detail or transient read failure invalidates only its collection.
          if (!lifetime.disposed && isScanDetailResource(notice.resource)) requestCollections([notice.resource]);
        }
      }
    } catch {
      if (!lifetime.disposed) setFailedResources((previous) => new Set([...previous, ...collections]));
    } finally {
      resourceRunning = false;
      if (!lifetime.disposed) {
        handlersRef.current.onDetailRefreshState?.(collections, false);
        if (fullRefresh || pendingResources.size || pendingState.size || coverageIssuesDirty || connectionRefresh) scheduleResources();
      }
    }
  };
  const scheduleResources = () => {
    const readable = [...pendingResources.values()].filter(needsRead);
    const detailsReady = !resourceRunning && (fullRefresh || readable.length || coverageIssuesDirty || connectionRefresh);
    if (!detailsReady && (stateRunning || !pendingState.size)) return;
    const normalReady = fullRefresh || coverageIssuesDirty || connectionRefresh
      || (!stateRunning && pendingState.size) || readable.some((notice) => !taskCollections.has(notice.resource));
    const nextTask = Math.min(...readable.map((notice) => (lastTaskRefresh.get(notice.resource) ?? -Infinity) + 1000));
    const due = normalReady ? Date.now() + 150 : Math.max(Date.now() + 150, nextTask);
    if (resourceTimer != null && resourceTimerAt <= due) return;
    if (resourceTimer != null) window.clearTimeout(resourceTimer);
    resourceTimerAt = due;
    resourceTimer = window.setTimeout(reloadResources, Math.max(0, due - Date.now()));
  };
  const requestState = (resources: readonly StateResource[]) => {
    for (const resource of resources) pendingState.add(resource);
    if (resources.includes("fp-review")) pendingResultRefresh = true;
    scheduleResources();
  };
  const requestCollections = (resources: readonly ScanDetailResource[], resultsChanged = true) => {
    const revision = scanExecutionRevision(stateSettersRef.current.getScan());
    if (revision !== taskExecutionRevision) {
      if (taskExecutionRevision !== undefined && revision !== undefined && revision > taskExecutionRevision) {
        // Automatic resume can change the execution before any task notice.
        // Preserve the displayed rows but invalidate both audit caches.
        resources = [...new Set<ScanDetailResource>([...resources, "threat-audit-tasks", "threat-pattern-audit-tasks"])];
      }
      taskExecutionRevision = revision;
      lastTaskRefresh.clear();
    }
    for (const resource of resources) {
      resourceVersions.set(resource, (resourceVersions.get(resource) ?? 0) + 1);
      const previous = pendingResources.get(`${resource}:collection`);
      pendingResources.set(`${resource}:collection`, { resource, resultsChanged: resultsChanged || previous?.resultsChanged,
        taskSummaryPending: taskCollections.has(resource) });
    }
    if (resources.some((resource) => !taskCollections.has(resource))) {
      pendingState.add("overview");
      pendingResultRefresh ||= resultsChanged;
    }
    if (resources.includes("fp-review")) pendingState.add("fp-review");
    scheduleResources();
  };
  const requestFullRefresh = () => {
    fullRefresh = true;
    lastTaskRefresh.clear();
    handlersRef.current.onTaskHistoryRefresh?.();
    STATE_RESOURCES.forEach((resource) => pendingState.add(resource));
    requestCollections(SCAN_DETAIL_RESOURCES);
  };
  const queueCoverageIssues = () => { coverageIssuesDirty = true; scheduleResources(); };
  const onResourceChanged = (event: MessageEvent) => {
    try {
      const notice = JSON.parse(event.data);
      if (!isRecord(notice) || typeof notice.resource !== "string") throw new Error("Invalid resource notice");
      if (typeof notice.execution_revision === "number"
        && notice.execution_revision < Math.max(scanExecutionRevision(stateSettersRef.current.getScan()) ?? 0,
          pendingExecutionRevision() ?? 0)) return;
      // A large task-pool update invalidates the overview only. It does not
      // imply that finding, review, validation or audit collections changed.
      if (notice.resource === "overview") {
        requestState(["overview"]);
        return;
      }
      if (taskCollections.has(notice.resource)) {
        requestCollections([notice.resource as ScanDetailResource], notice.change !== "task_status");
        return;
      }
      pendingState.add("overview");
      pendingResultRefresh = true;
      if (notice.resource === "fp-review") pendingState.add("fp-review");
      if (notice.resource === "vulnerabilities" || (notice.resource === "fp-review" && notice.change !== "stage_output")) {
        coverageIssuesDirty = true;
      }
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
  };
  const onVisible = () => {
    if (document.hidden) return;
    if (connectionInterrupted) requestFullRefresh();
    // Hidden tabs keep their dirty notices. A healthy connection needs only
    // those resources, while an explicit resync still reloads every detail.
    requestState(STATE_RESOURCES);
    // The artifact loader also retains invalidations received while hidden
    // (for example a typed threat-analysis completion event).
    handlersRef.current.onThreatAnalysisRefresh?.();
  };
  document.addEventListener("visibilitychange", onVisible);

  return {
    requestState, requestCollections, requestFullRefresh, queueCoverageIssues, onResourceChanged,
    requestFinalRefresh(revision: number | undefined) {
      const key = String(revision ?? scanExecutionRevision(stateSettersRef.current.getScan()) ?? 0);
      if (key === finalRefreshKey) return;
      finalRefreshKey = key;
      pendingState.add("overview");
      // Terminal ETA/status reconciliation must not wait for detail throttling.
      if (!document.hidden) startStateRefresh(new Set<StateResource>(["overview"]));
      handlersRef.current.onTaskHistoryRefresh?.();
    },
    onOpen() {
      if (connectionInterrupted) requestFullRefresh();
      connectionInterrupted = false;
      connectionRefresh = true;
    },
    onError() { connectionInterrupted = true; },
    dispose() {
      resourceController.abort();
      document.removeEventListener('visibilitychange', onVisible);
      if (resourceTimer != null) window.clearTimeout(resourceTimer);
    },
  };
}
