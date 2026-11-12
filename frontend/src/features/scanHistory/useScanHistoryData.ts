import { useEffect, useRef, useState } from "react";

import { getScansPage, resumeScan, stopScan, deleteScan } from "../../api/scans";
import type { ScanSummary } from "../../types/scans";
import { mergeScanMetadata } from "../../scanRuntime/scanSnapshots";

import { isRunning, projectName } from './historyModel';

export function useScanHistoryData(onViewScan: (scanId: string) => void, onVisible: () => void) {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const loadedOlderPagesRef = useRef(false);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const fetchScans = async (initial = false) => {
    try {
      const data = await getScansPage(50);
      setScans((previous) => {
        const previousById = new Map(previous.map((item) => [item.scan_id, item]));
        const refreshed = data.items.map((item) => mergeScanMetadata(previousById.get(item.scan_id), item));
        if (initial || !loadedOlderPagesRef.current) return refreshed;
        const refreshedIds = new Set(data.items.map((item) => item.scan_id));
        return [
          ...refreshed,
          ...previous.filter((item) => !refreshedIds.has(item.scan_id)),
        ];
      });
      if (initial || !loadedOlderPagesRef.current) {
        setNextCursor(data.next_cursor);
      }
    } catch {
      // silently fail
    } finally {
      setLoading(false);
    }
  };

  // 自适应轮询：有运行中扫描时 5s，全部空闲时降为 30s；页面不可见时暂停，
  // 重新可见时立即刷新一次。
  const hasRunningScans = scans.some((s) => isRunning(s.status) || s.fp_review_running);
  const hasRunningRef = useRef(hasRunningScans);
  hasRunningRef.current = hasRunningScans;

  useEffect(() => {
    fetchScans(true);
    let lastFetch = Date.now();
    const timer = setInterval(() => {
      if (document.visibilityState === "hidden") return;
      const interval = hasRunningRef.current ? 5000 : 30000;
      if (Date.now() - lastFetch < interval) return;
      lastFetch = Date.now();
      fetchScans();
    }, 5000);

    const onVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        lastFetch = Date.now();
        fetchScans();
        onVisible();
      }
    };
    document.addEventListener("visibilitychange", onVisibilityChange);

    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, []);

  const handleLoadMore = async () => {
    if (!nextCursor || loadingMore) return;
    setLoadingMore(true);
    try {
      const data = await getScansPage(50, nextCursor);
      setScans((previous) => {
        const existing = new Set(previous.map((item) => item.scan_id));
        return [
          ...previous,
          ...data.items.filter((item) => !existing.has(item.scan_id)),
        ];
      });
      loadedOlderPagesRef.current = true;
      setNextCursor(data.next_cursor);
    } catch {
      // Keep the current page; the operator can retry.
    } finally {
      setLoadingMore(false);
    }
  };

  const handleContinue = async (scanId: string) => {
    setActionLoading(scanId);
    try {
      await resumeScan(scanId);
      onViewScan(scanId);
    } catch (err: unknown) {
      const message = err && typeof err === "object" && "response" in err
        ? (err as { response?: { data?: { detail?: string } } }).response?.data?.detail
        : undefined;
      alert(`续扫失败：${message || "未知错误，请稍后重试"}`);
    } finally {
      setActionLoading(null);
    }
  };

  const handleStop = async (scanId: string) => {
    setActionLoading(scanId);
    try {
      const result = await stopScan(scanId);
      if (result.agent_stop_state === "pending") {
        alert("已记录停止请求，但 Agent 暂未确认；重连后将继续停止。");
      }
      await fetchScans();
    } catch {
      // silently fail
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeleteConfirm = async () => {
    if (!deleteConfirmId) return;
    const scanId = deleteConfirmId;
    setDeleteConfirmId(null);
    setActionLoading(scanId);
    try {
      await deleteScan(scanId);
      setScans((prev) => prev.filter((s) => s.scan_id !== scanId));
    } catch {
      // silently fail
    } finally {
      setActionLoading(null);
    }
  };

  const deleteTarget = deleteConfirmId
    ? scans.find((scan) => scan.scan_id === deleteConfirmId)
    : null;
  const deleteTargetName = deleteTarget
    ? projectName(deleteTarget)
    : deleteConfirmId?.slice(0, 8);

  return {
    scans,
    nextCursor,
    loadingMore,
    loading,
    actionLoading,
    deleteConfirmId,
    setDeleteConfirmId,
    handleLoadMore,
    handleContinue,
    handleStop,
    handleDeleteConfirm,
    deleteTargetName,
  };
}
