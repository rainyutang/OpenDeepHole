import { getScanDetailItem } from "../../api/scanDetails";
import { getFpReviewOverview } from "../../api/fpReview";
import { isScanDetailResource, refreshScanResource, SCAN_DETAIL_RESOURCES } from "../../scanResourceRefresh";

import type { ScanDetailResource } from "../../scanResourceRefresh";
import { isRecord } from "../../scanRuntime/record";
import { scanExecutionRevision } from "../../scanRuntime/scanSnapshots";
import { normalizeScanCandidate } from "../../scanRuntime/candidates";
import { normalizeValidation, normalizeVulnerability } from "../../scanRuntime/issues";
import type { FpReviewJob } from "../../types/fpReview";
import { ScanSSEHandlers, SSEStateSetters } from './protocol';
import { refreshFullState, STATE_RESOURCES } from './refreshState';
import type { StateResource } from './refreshState';
import type { MutableRefObject, Dispatch, SetStateAction } from 'react';
interface StreamLifetime { disposed: boolean }

export function createScanResourceCoordinator({ scanId, handlersRef, stateSettersRef, activeScanIdRef, lifetime, setOverviewFailed, setFailedResources }: {
  scanId: string;
  handlersRef: MutableRefObject<ScanSSEHandlers>;
  stateSettersRef: MutableRefObject<SSEStateSetters>;
  activeScanIdRef: MutableRefObject<string>;
  lifetime: StreamLifetime;
  setOverviewFailed: Dispatch<SetStateAction<boolean>>;
  setFailedResources: Dispatch<SetStateAction<Set<ScanDetailResource>>>;
}) {
  let resourceTimer: number | null = null;
  const pendingResources = new Map<string, { resource: string; index?: number }>();
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
    const stateResources = stateRunning ? new Set<StateResource>() : new Set(pendingState);
    const notices = [...pendingResources.values()];
    pendingResources.clear();
    const collections = reloadAll ? [...SCAN_DETAIL_RESOURCES] : Array.from(new Set(
      notices.filter((notice) => typeof notice.index !== "number").map((notice) => notice.resource).filter(isScanDetailResource),
    ));
    const versions = new Map(collections.map((resource) => [resource, resourceVersions.get(resource)]));
    // Artifact invalidations also apply when another notice requires a full
    // scan refresh. The overview itself intentionally has no artifact body.
    if (reloadAll || refreshConnectionArtifacts || notices.some((notice) => notice.resource === "threat-analysis")) {
      handlersRef.current.onThreatAnalysisRefresh?.(true);
    }
    if (reloadAll || refreshConnectionArtifacts || notices.some((notice) => ["threat-analysis", "file-inventory"].includes(notice.resource))) {
      handlersRef.current.onThreatCoverageRefresh?.();
    }
    if (reloadAll || refreshConnectionArtifacts || refreshCoverageIssues || notices.some((notice) => notice.resource === "file-inventory")) {
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
          refreshScanResource(resource, source, review, resourceController.signal, reviewRequest)
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
    const detailsReady = !resourceRunning && (fullRefresh || pendingResources.size || coverageIssuesDirty || connectionRefresh);
    if (resourceTimer == null && (detailsReady || (!stateRunning && pendingState.size))) {
      resourceTimer = window.setTimeout(reloadResources, 150);
    }
  };
  const requestState = (resources: readonly StateResource[]) => {
    for (const resource of resources) pendingState.add(resource);
    if (resources.includes("fp-review")) pendingResultRefresh = true;
    scheduleResources();
  };
  const requestCollections = (resources: readonly ScanDetailResource[]) => {
    for (const resource of resources) {
      resourceVersions.set(resource, (resourceVersions.get(resource) ?? 0) + 1);
      pendingResources.set(`${resource}:collection`, { resource });
    }
    pendingState.add("overview");
    pendingResultRefresh = true;
    if (resources.includes("fp-review")) pendingState.add("fp-review");
    scheduleResources();
  };
  const requestFullRefresh = () => {
    fullRefresh = true;
    STATE_RESOURCES.forEach((resource) => pendingState.add(resource));
    requestCollections(SCAN_DETAIL_RESOURCES);
  };
  const queueCoverageIssues = () => { coverageIssuesDirty = true; scheduleResources(); };
  const onResourceChanged = (event: MessageEvent) => {
    try {
      const notice = JSON.parse(event.data);
      if (!isRecord(notice) || typeof notice.resource !== "string") throw new Error("Invalid resource notice");
      // A large task-pool update invalidates the overview only. It does not
      // imply that finding, review, validation or audit collections changed.
      if (notice.resource === "overview") {
        requestState(["overview"]);
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
