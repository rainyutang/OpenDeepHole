import { normalizeScanProgressEstimate, selectScanProgressEstimate } from "../../scanProgress";

import { isOlderScanExecution, scanExecutionRevision } from "../../scanRuntime/scanSnapshots";
import type { ScanEvent } from "../../types/scans";
import { ScanStatusEvent, ScanSSEHandlers, SSEStateSetters } from './protocol';

import type { MutableRefObject } from 'react';
interface StreamLifetime { disposed: boolean }

export function createScanEventBatcher({ handlersRef, stateSettersRef, lifetime }: { handlersRef: MutableRefObject<ScanSSEHandlers>; stateSettersRef: MutableRefObject<SSEStateSetters>; lifetime: StreamLifetime }) {
  let eventFlushTimer: number | null = null;
  let queuedEvents: ScanEvent[] = [];
  let statusFlushTimer: number | null = null;
  let pendingStatus: ScanStatusEvent | null = null;

  const flushQueuedEvents = () => {
    eventFlushTimer = null;
    if (lifetime.disposed || queuedEvents.length === 0) return;
    const events = queuedEvents;
    queuedEvents = [];
    const currentHandlers = handlersRef.current;
    try {
      if (currentHandlers.onScanEvents) {
        currentHandlers.onScanEvents(events);
      } else {
        events.forEach((event) => currentHandlers.onScanEvent?.({ event }));
      }
    } catch (error) {
      console.error("处理扫描日志事件失败", error);
    }
  };

  const queueScanEvent = (event: ScanEvent) => {
    queuedEvents.push(event);
    if (eventFlushTimer == null) {
      eventFlushTimer = window.setTimeout(flushQueuedEvents, 50);
    }
  };

  const flushPendingStatus = () => {
    if (statusFlushTimer != null) window.clearTimeout(statusFlushTimer);
    statusFlushTimer = null;
    if (lifetime.disposed || !pendingStatus) return;
    const status = pendingStatus;
    pendingStatus = null;
    try {
      handlersRef.current.onScanStatus?.(status);
    } catch (error) {
      console.error("处理扫描状态事件失败", error);
    }
  };

  const queueScanStatus = (status: ScanStatusEvent) => {
    if (isOlderScanExecution(pendingStatus, status)
      || isOlderScanExecution(stateSettersRef.current.getScan(), status)) return;
    if ((scanExecutionRevision(status) ?? 0) > (scanExecutionRevision(pendingStatus) ?? 0)) {
      pendingStatus = null;
    }
    pendingStatus = {
      execution_revision: scanExecutionRevision(status) ?? scanExecutionRevision(pendingStatus),
      status: status.status ?? pendingStatus?.status ?? null,
      progress: status.progress ?? pendingStatus?.progress ?? null,
      progress_estimate: selectScanProgressEstimate(pendingStatus?.progress_estimate,
        normalizeScanProgressEstimate(status.progress_estimate),
        scanExecutionRevision(status) ?? scanExecutionRevision(pendingStatus)),
      total_candidates: status.total_candidates ?? pendingStatus?.total_candidates ?? null,
      processed_candidates: status.processed_candidates ?? pendingStatus?.processed_candidates ?? null,
      static_total_files: status.static_total_files ?? pendingStatus?.static_total_files ?? null,
      static_scanned_files: status.static_scanned_files ?? pendingStatus?.static_scanned_files ?? null,
      static_analysis_done: status.static_analysis_done ?? pendingStatus?.static_analysis_done ?? null,
      error_message: status.error_message !== undefined ? status.error_message : pendingStatus?.error_message,
      opencode_pool: status.opencode_pool !== undefined
        ? status.opencode_pool
        : pendingStatus?.opencode_pool,
    };
    if (statusFlushTimer == null) {
      statusFlushTimer = window.setTimeout(flushPendingStatus, 75);
    }
  };

  return {
    queueScanEvent, queueScanStatus, flushPendingStatus,
    pendingStatus: () => pendingStatus,
    dispose() {
      if (eventFlushTimer != null) window.clearTimeout(eventFlushTimer);
      if (statusFlushTimer != null) window.clearTimeout(statusFlushTimer);
      queuedEvents = [];
      pendingStatus = null;
    },
  };
}
