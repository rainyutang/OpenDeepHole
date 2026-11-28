import { useEffect, useMemo } from "react";
import type { ScanSSEHandlers, SSEStateSetters } from "../../../hooks/scanSSE/protocol";
import { useScanSSE } from "../../../hooks/scanSSE/useScanSSE";
import type { ScanDetailResource } from "../../../scanResourceRefresh";
import { useThreatAnalysisResult } from "../../threatAnalysis/useThreatAnalysisResult";
import { createFindingHandlers } from "../events/createFindingHandlers";
import { createFpReviewHandlers } from "../events/createFpReviewHandlers";
import { createScanLifecycleHandlers } from "../events/createScanLifecycleHandlers";
import { createThreatHandlers } from "../events/createThreatHandlers";
import type { DetailResources } from "./useDetailResources";
import type { ScanSnapshotState } from "./useScanSnapshotState";

export function useScanEvents(
  scanId: string,
  state: ScanSnapshotState,
  resources: DetailResources,
  analysis: Pick<ReturnType<typeof useThreatAnalysisResult>, "refresh" | "acceptAnalysis">,
  ownsPatternTaskPages = false,
  activeTaskResource?: ScanDetailResource,
) {
  const { setScan, scanRef, setFpReview, fpReviewRef, setIndexStatus } = state;
  const { scheduleOverviewSummaryRefresh } = resources;
  const { refresh: refreshThreatAnalysis, acceptAnalysis: acceptThreatAnalysis } = analysis;

  // SSE event handlers — update state incrementally
  const sseHandlers = useMemo<ScanSSEHandlers>(() => ({
    ownsPatternTaskPages: () => ownsPatternTaskPages,
    ownsRedlineTaskPages: () => activeTaskResource === "redline-audit-tasks",
    activeTaskCollections: () => activeTaskResource ? [activeTaskResource] : [],
    ...createScanLifecycleHandlers({ scanId, state, resources, analysis }),
    ...createFindingHandlers({ scanId, state, resources, analysis }),
    ...createThreatHandlers({ scanId, state, resources, analysis }),
    ...createFpReviewHandlers({ scanId, state, resources, analysis }),
  }), [scanId, scheduleOverviewSummaryRefresh, refreshThreatAnalysis, acceptThreatAnalysis, ownsPatternTaskPages, activeTaskResource]);

  const sseStateSetters = useMemo<SSEStateSetters>(() => ({
    getScan: () => scanRef.current,
    getFpReview: () => fpReviewRef.current,
    setScan,
    setFpReview,
    setIndexStatus,
  }), []);

  const { failedResources: refreshFailures, refreshDetails, overviewFailed, refreshOverview, refreshStopped } = useScanSSE(scanId, sseHandlers, sseStateSetters);
  useEffect(() => {
    // Wake deferred invalidations on entry without dirtying an otherwise
    // current cache when navigating between pages.
    refreshDetails([]);
  }, [scanId, ownsPatternTaskPages, activeTaskResource, state.scan?.execution_revision, refreshDetails]);
  return { refreshFailures, refreshDetails, overviewFailed, refreshOverview, refreshStopped };
}

export type ScanEvents = ReturnType<typeof useScanEvents>;
