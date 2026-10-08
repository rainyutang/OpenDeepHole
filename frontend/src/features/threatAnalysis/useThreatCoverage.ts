import { useEffect, useRef, useState } from "react";
import { getThreatCoverage } from "./api";
import type { ThreatCoverage } from "./coverage";

/** Mounted only on the threat page. Inventory and analysis invalidate separately. */
export function useThreatCoverage(scanId: string, revision: number) {
  const [result, setResult] = useState<{ scanId: string; data: ThreatCoverage } | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const refreshRef = useRef<(force?: boolean) => void>(() => {});
  const revisionRef = useRef(revision);

  useEffect(() => {
    let disposed = false;
    let inFlight = false;
    let rerun = false;
    let version = 0;
    let settled = false;
    let controller: AbortController | undefined;
    revisionRef.current = revision;
    setError("");
    const refresh = (force = false) => {
      if (disposed) return;
      if (force) { version++; settled = false; }
      if (document.hidden || (!force && settled)) return;
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
              const data = await getThreatCoverage(scanId, controller.signal);
              if (disposed) return;
              if (requested === version) {
                setResult({ scanId, data });
                setError("");
                settled = data.analysis_ready && data.inventory?.status === "complete";
              }
            } catch {
              if (!disposed && requested === version) setError("覆盖数据加载失败，请重试。已加载的图仍然保留。");
            }
          } while (!disposed && rerun && !document.hidden);
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
    const timer = setInterval(() => refresh(), 30_000);
    return () => {
      disposed = true;
      controller?.abort();
      clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
    // Revision invalidations below reuse the same in-flight/coalescing state.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);

  useEffect(() => {
    if (revisionRef.current !== revision) {
      revisionRef.current = revision;
      refreshRef.current(true);
    }
  }, [revision]);

  return { data: result?.scanId === scanId ? result.data : null, loading, error, refresh: () => refreshRef.current(true) };
}
