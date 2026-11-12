import { useCallback, useEffect, useRef, useState } from "react";
import { getScanOverviewRequest } from "../../../api/scanSnapshots";
import type { ScanDetailResource } from "../../../scanResourceRefresh";
import { mergeScanOverview } from "../../../scanRuntime/scanSnapshots";
import type { LoadedDetailPage } from "../model/detailPages";
import { DETAIL_REFRESH_RESOURCE, detailCursor, mergeDetailPage } from "../model/detailPages";
import type { DetailResource } from "../model/types";
import { fetchDetailPage } from "../resources/fetchDetailPage";
import type { ScanSnapshotState } from "./useScanSnapshotState";

export function useDetailResources(scanId: string, state: ScanSnapshotState) {
  const { scanRef, setScan } = state;

  const [detailLoadingResources, setDetailLoadingResources] = useState<Set<DetailResource>>(new Set());

  const [detailFailedResources, setDetailFailedResources] = useState<Set<DetailResource>>(new Set());

  const detailLoadingRef = useRef<Set<DetailResource>>(new Set());

  const detailAbortControllerRef = useRef(new AbortController());

  const detailGenerationRef = useRef(new Map<DetailResource, number>());

  const refreshingResourcesRef = useRef(new Set<ScanDetailResource>());

  const [refreshingResources, setRefreshingResources] = useState(new Set<ScanDetailResource>());

  const summaryRefreshTimerRef = useRef<number | null>(null);

  const summaryRefreshInFlightRef = useRef(false);

  useEffect(() => {
    detailAbortControllerRef.current.abort();
    detailAbortControllerRef.current = new AbortController();
    detailGenerationRef.current.clear();
    refreshingResourcesRef.current.clear();
    setRefreshingResources(new Set());
    detailLoadingRef.current.clear();
    setDetailLoadingResources(new Set());
    setDetailFailedResources(new Set());
    if (summaryRefreshTimerRef.current != null) {
      window.clearTimeout(summaryRefreshTimerRef.current);
      summaryRefreshTimerRef.current = null;
    }
    summaryRefreshInFlightRef.current = false;
    return () => {
      detailAbortControllerRef.current.abort();
      if (summaryRefreshTimerRef.current != null) {
        window.clearTimeout(summaryRefreshTimerRef.current);
        summaryRefreshTimerRef.current = null;
      }
    };
  }, [scanId]);

  const refreshOverviewSummary = useCallback(async () => {
    const current = scanRef.current;
    if (!current?.detail_counts || summaryRefreshInFlightRef.current) return;
    summaryRefreshInFlightRef.current = true;
    try {
      const request = getScanOverviewRequest(scanId, current);
      const overview = await request.promise;
      setScan((previous) => {
        if (!previous || previous.scan_id !== overview.scan_id) return previous;
        return mergeScanOverview(previous, overview, request.requestedFrom);
      });
    } catch {
      // SSE and the running-scan fallback poll will try again.
    } finally {
      summaryRefreshInFlightRef.current = false;
    }
  }, [scanId]);

  const scheduleOverviewSummaryRefresh = useCallback((delayMs = 1000) => {
    if (summaryRefreshTimerRef.current != null) {
      window.clearTimeout(summaryRefreshTimerRef.current);
    }
    summaryRefreshTimerRef.current = window.setTimeout(() => {
      summaryRefreshTimerRef.current = null;
      void refreshOverviewSummary();
    }, delayMs);
  }, [refreshOverviewSummary]);

  const loadDetailResource = useCallback(async (resource: DetailResource) => {
    if (detailLoadingRef.current.has(resource) || refreshingResourcesRef.current.has(DETAIL_REFRESH_RESOURCE[resource])) return;
    const current = scanRef.current;
    const cursor = current ? detailCursor(current, resource) : null;
    if (cursor == null) return;

    detailLoadingRef.current.add(resource);
    setDetailLoadingResources(new Set(detailLoadingRef.current));
    setDetailFailedResources((previous) => {
      if (!previous.has(resource)) return previous;
      const next = new Set(previous);
      next.delete(resource);
      return next;
    });
    const signal = detailAbortControllerRef.current.signal;
    const generation = detailGenerationRef.current.get(resource);
    const isCurrentGeneration = () => !signal.aborted && generation === detailGenerationRef.current.get(resource);
    let failed = false;
    try {
      if (cursor != null && !signal.aborted && isCurrentGeneration()) {
        let page: LoadedDetailPage | null = null;
        let lastError: unknown = null;
        for (let attempt = 0; attempt < 4 && !signal.aborted; attempt += 1) {
          try {
            page = await fetchDetailPage(scanId, resource, cursor, signal);
            break;
          } catch (error) {
            lastError = error;
            if (signal.aborted) break;
            if (attempt < 3) {
              await new Promise((resolve) => window.setTimeout(resolve, 250 * (2 ** attempt)));
            }
          }
        }
        if (signal.aborted || !isCurrentGeneration()) return;
        if (!page) throw lastError ?? new Error("详情分页加载失败");
        if (page.nextCursor != null && (page.nextCursor === cursor
          || (resource !== "events" && typeof cursor === "number" && typeof page.nextCursor === "number" && page.nextCursor < cursor))) {
          throw new Error(`详情游标未前进: ${resource}`);
        }
        setScan((previous) => isCurrentGeneration() && previous?.scan_id === scanId && detailCursor(previous, resource) === cursor
          ? mergeDetailPage(previous, page) : previous);
      }
    } catch (error) {
      if (!signal.aborted && isCurrentGeneration()) {
        failed = true;
        console.warn(`自动加载扫描详情失败 (${resource})`, error);
        setDetailFailedResources((previous) => new Set(previous).add(resource));
      }
    } finally {
      if (isCurrentGeneration()) {
        detailLoadingRef.current.delete(resource);
        setDetailLoadingResources(new Set(detailLoadingRef.current));
        if (!failed) {
          setDetailFailedResources((previous) => {
            if (!previous.has(resource)) return previous;
            const next = new Set(previous);
            next.delete(resource);
            return next;
          });
        }
      }
    }
  }, [scanId]);
  return {
    detailLoadingResources,
    setDetailLoadingResources,
    detailFailedResources,
    setDetailFailedResources,
    detailLoadingRef,
    detailAbortControllerRef,
    detailGenerationRef,
    refreshingResourcesRef,
    refreshingResources,
    setRefreshingResources,
    summaryRefreshTimerRef,
    summaryRefreshInFlightRef,
    refreshOverviewSummary,
    scheduleOverviewSummaryRefresh,
    loadDetailResource,
  };
}

export type DetailResources = ReturnType<typeof useDetailResources>;
