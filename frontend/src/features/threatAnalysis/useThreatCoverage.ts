import { useEffect, useMemo, useRef, useState } from "react";
import { getCoverageIssues, getThreatCoverage } from "./api";
import { buildCoverageTree } from "./coverage";

/** Retain one snapshot per mounted scan; invalidations stay dirty while disabled. */
function useCoverageResource<T>(scanId: string, revision: number | string, enabled: boolean,
  load: (scanId: string, signal?: AbortSignal) => Promise<T>, isSettled: (data: T) => boolean, polling = false) {
  const [result, setResult] = useState<{ scanId: string; data: T } | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const refreshRef = useRef<(force?: boolean) => void>(() => {});
  const revisionRef = useRef(revision);
  const options = useRef({ enabled, isSettled, polling });
  options.current = { enabled, isSettled, polling };

  useEffect(() => {
    let disposed = false;
    let inFlight = false;
    let rerun = false;
    let version = 0;
    let settled = false;
    let controller: AbortController | undefined;
    revisionRef.current = revision;
    setResult(null);
    setError("");
    setLoading(false);
    const refresh = (force = false) => {
      if (disposed) return;
      if (force) { version++; settled = false; }
      if (!options.current.enabled || document.hidden || (!force && settled)) return;
      if (inFlight) { if (force) rerun = true; return; }
      inFlight = true;
      setLoading(true);
      void (async () => {
        try {
          do {
            rerun = false;
            const requested = version;
            controller = new AbortController();
            try {
              const data = await load(scanId, controller.signal);
              if (disposed) return;
              if (requested === version) {
                setResult({ scanId, data });
                setError("");
                settled = options.current.isSettled(data);
              }
            } catch {
              if (!disposed && requested === version) setError("覆盖数据加载失败，请重试。已加载的图仍然保留。");
            }
          } while (!disposed && rerun && !document.hidden && options.current.enabled);
        } finally {
          inFlight = false;
          if (!disposed) setLoading(false);
        }
      })();
    };
    refreshRef.current = refresh;
    refresh();
    const onVisible = () => { if (!document.hidden) refresh(true); };
    document.addEventListener("visibilitychange", onVisible);
    const timer = setInterval(() => refresh(options.current.polling), 30_000);
    return () => {
      disposed = true;
      controller?.abort();
      clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
    // Revision invalidations below reuse the same in-flight/coalescing state.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId, load]);

  useEffect(() => {
    if (revisionRef.current !== revision) {
      revisionRef.current = revision;
      refreshRef.current(true);
    }
  }, [revision]);

  useEffect(() => { if (enabled) refreshRef.current(); }, [enabled]);

  return { data: result?.scanId === scanId ? result.data : null, loading, error, refresh: () => refreshRef.current(true) };
}

export function useThreatCoverage(scanId: string, revision: number, enabled = true, analysisExpected = true) {
  const state = useCoverageResource(scanId, revision, enabled, getThreatCoverage,
    (data) => data.inventory?.status === "complete" && (data.analysis_ready || !analysisExpected));
  const tree = useMemo(() => state.data ? buildCoverageTree(state.data) : null, [state.data]);
  return { ...state, tree };
}

export function useCoverageIssues(scanId: string, revision: string, snapshotId: string | undefined, enabled: boolean, polling = false) {
  const state = useCoverageResource(scanId, `${revision}:${snapshotId ?? ""}`, enabled && !!snapshotId,
    getCoverageIssues, () => true, polling);
  return { ...state, data: state.data && (state.data.total_issue_count === 0 || state.data.inventory_snapshot_id === snapshotId) ? state.data : null };
}
