import { useCallback, useEffect, useRef, useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import type { ScanStatus, ThreatAnalysis } from "../../types";
import { getScanThreatAnalysis } from "./api";
import { isThreatAnalysisResultReady } from "./ThreatAnalysisPanel";

interface ResultRequestState {
  scanId: string;
  disposed: boolean;
  inFlight: boolean;
  attempted: boolean;
  rerun: boolean;
  needsRefresh: boolean;
  version: number;
  controller?: AbortController;
}

/** Share artifact loading across initial hydration, SSE invalidations and polling. */
export function useThreatAnalysisResult(
  scanId: string,
  scan: ScanStatus | null,
  setScan: Dispatch<SetStateAction<ScanStatus | null>>,
) {
  const [loading, setLoading] = useState(false);
  const scanRef = useRef(scan);
  scanRef.current = scan;
  const requestRef = useRef<ResultRequestState | null>(null);

  useEffect(() => {
    const state: ResultRequestState = {
      scanId, disposed: false, inFlight: false, attempted: false, rerun: false, needsRefresh: false, version: 0,
    };
    requestRef.current = state;
    setLoading(false);
    return () => {
      state.disposed = true;
      state.controller?.abort();
      if (requestRef.current === state) requestRef.current = null;
    };
  }, [scanId]);

  const refresh = useCallback((force = false) => {
    const state = requestRef.current;
    const current = scanRef.current;
    if (!state || state.disposed || state.scanId !== scanId || current?.scan_id !== scanId) return;
    const selected = current.threat_analysis_enabled
      || current.scan_mode === "threat_analysis_only"
      || current.threat_analysis_run != null
      || current.threat_analysis != null;
    // Historical scans may have artifacts without lifecycle metadata. Always
    // allow their first lookup, while skipping idle polls for disabled scans.
    if (!force && ((state.attempted && !selected) || (!state.needsRefresh && isThreatAnalysisResultReady(current.threat_analysis)))) return;
    state.needsRefresh = true;
    if (force) state.version += 1;
    if (document.hidden) return;
    if (state.inFlight) {
      // An invalidation may describe a result newer than the pending response.
      // Coalesce all such notices into one follow-up instead of racing GETs.
      if (force) state.rerun = true;
      return;
    }

    const isCurrent = () => !state.disposed
      && requestRef.current === state
      && scanRef.current?.scan_id === scanId;
    state.inFlight = true;
    state.attempted = true;
    setLoading(true);
    void (async () => {
      try {
        do {
          state.rerun = false;
          const version = state.version;
          state.controller = new AbortController();
          try {
            const analysis = await getScanThreatAnalysis(scanId, state.controller.signal);
            if (!isCurrent()) return;
            if (version === state.version && analysis) {
              state.needsRefresh = !isThreatAnalysisResultReady(analysis);
              setScan((previous) => isCurrent() && previous?.scan_id === scanId
                ? { ...previous, threat_analysis: analysis }
                : previous);
            }
          } catch {
            // 404 means no artifact yet. Keep existing results on all failures;
            // the 30-second fallback can retry without reloading every resource.
          }
        } while (isCurrent() && state.rerun && !document.hidden);
      } finally {
        state.inFlight = false;
        if (isCurrent()) setLoading(false);
      }
    })();
  }, [scanId, setScan]);

  const acceptAnalysis = useCallback((analysis: ThreatAnalysis) => {
    const state = requestRef.current;
    if (!state || state.disposed || state.scanId !== scanId || scanRef.current?.scan_id !== scanId) return;
    // Legacy SSE can still carry a full result. It supersedes any older GET.
    state.version += 1;
    state.rerun = false;
    state.needsRefresh = !isThreatAnalysisResultReady(analysis);
    state.controller?.abort();
    setScan((previous) => !state.disposed && previous?.scan_id === scanId
      ? { ...previous, threat_analysis: analysis }
      : previous);
  }, [scanId, setScan]);

  // Wait for the scan identity before fetching so a fast artifact response is
  // never discarded while the initial scan snapshot is still loading.
  useEffect(() => {
    refresh();
  }, [refresh, scan?.scan_id, scan?.threat_analysis_enabled, scan?.threat_analysis_run?.status]);

  return { loading, refresh, acceptAnalysis };
}
