import { useEffect } from "react";
import { getAgentIndexStatus, getScanGitHistory } from "../../../api/scans";
import { getFpReview } from "../../../api/fpReview";
import { getScanStatusRequest } from "../../../api/scanSnapshots";
import { mergeScanSnapshot } from "../../../scanRuntime/scanSnapshots";
import { selectOpenCodePoolSnapshot } from "../../../scanRuntime/modelPool";
import type { ScanMetadata } from "../../../types/scans";
import type { ScanSnapshotState } from "./useScanSnapshotState";

export function useScanHydration(
  scanId: string,
  state: ScanSnapshotState,
  ui: { setSelectedFeedbackIds: React.Dispatch<React.SetStateAction<Set<string> | null>>; setEditingScan: React.Dispatch<React.SetStateAction<Pick<ScanMetadata, "scan_id" | "scan_name" | "product"> | null>>; },
) {
  const {
    setScan,
    setScanLoadFailed,
    scanLoadAttempt,
    scanRef,
    pendingInitialOpenCodePoolRef,
    setFpReview,
    setFpReviewHydrated,
    setIndexStatus,
    setGitHistory,
  } = state;
  const { setSelectedFeedbackIds, setEditingScan } = ui;

  // Initial full-state hydration on mount
  useEffect(() => {
    let cancelled = false;
    setScanLoadFailed(false);
    pendingInitialOpenCodePoolRef.current = undefined;
    setScan((previous) => previous?.scan_id === scanId ? previous : null);
    setSelectedFeedbackIds(null);
    setEditingScan(null);
    setFpReview(null);
    setFpReviewHydrated(false);
    setIndexStatus(null);
    setGitHistory([]);
    const request = getScanStatusRequest(scanId, scanRef.current);
    request.promise
      .then((data) => {
        if (cancelled || data.scan_id !== scanId) return;
        setScan((previous) => {
          const previousPool = previous?.scan_id === scanId
            ? previous.opencode_pool
            : undefined;
          let opencodePool = selectOpenCodePoolSnapshot(
            data.opencode_pool,
            previousPool,
          );
          const pendingPool = pendingInitialOpenCodePoolRef.current;
          pendingInitialOpenCodePoolRef.current = undefined;
          opencodePool = selectOpenCodePoolSnapshot(
            opencodePool,
            pendingPool,
            { allowClear: pendingPool === null },
          );
          return {
            ...mergeScanSnapshot(previous, data, request.requestedFrom),
            opencode_pool: opencodePool,
          };
        });
        setSelectedFeedbackIds(new Set(data.feedback_ids ?? []));
      })
      .catch(() => { if (!cancelled) setScanLoadFailed(true); });
    getFpReview(scanId)
      .then((job) => {
        if (!cancelled && job?.scan_id === scanId) setFpReview(job);
      })
      .catch(() => { })
      .finally(() => {
        if (!cancelled) setFpReviewHydrated(true);
      });
    getAgentIndexStatus(scanId)
      .then((status) => {
        if (!cancelled) setIndexStatus(status);
      })
      .catch(() => { });
    getScanGitHistory(scanId)
      .then((history) => {
        if (!cancelled) setGitHistory(Array.isArray(history) ? history : []);
      })
      .catch(() => { });
    return () => {
      cancelled = true;
    };
  }, [scanId, scanLoadAttempt]);
}

export type ScanHydration = ReturnType<typeof useScanHydration>;
