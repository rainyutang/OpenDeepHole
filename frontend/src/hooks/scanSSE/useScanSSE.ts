import { useEffect, useRef, useState, useCallback } from "react";

import { SCAN_DETAIL_RESOURCES } from "../../scanResourceRefresh";

import type { ScanDetailResource } from "../../scanResourceRefresh";

import { ScanSSEHandlers, SSEStateSetters } from './protocol';
import { STATE_RESOURCES } from './refreshState';
import type { StateResource } from './refreshState';
import { connectScanStream } from './transport';

/* ------------------------------------------------------------------ */
/*  Hook                                                               */
/* ------------------------------------------------------------------ */

export function useScanSSE(
  scanId: string,
  handlers: ScanSSEHandlers,
  stateSetters: SSEStateSetters,
): { connected: boolean; overviewFailed: boolean; refreshOverview: () => void; failedResources: ReadonlySet<ScanDetailResource>; refreshDetails: (resources?: readonly ScanDetailResource[]) => void } {
  const [connected, setConnected] = useState(false);
  const [overviewFailed, setOverviewFailed] = useState(false);
  const [failedResources, setFailedResources] = useState<Set<ScanDetailResource>>(new Set());
  const requestDetailsRef = useRef<(resources: readonly ScanDetailResource[]) => void>(() => { });
  const refreshDetails = useCallback((resources: readonly ScanDetailResource[] = SCAN_DETAIL_RESOURCES) => {
    requestDetailsRef.current(resources);
  }, []);
  // Use a ref so the EventSource listeners always see the latest handlers
  // without re-creating the connection on every render.
  const handlersRef = useRef(handlers);
  handlersRef.current = handlers;

  const stateSettersRef = useRef(stateSetters);
  stateSettersRef.current = stateSetters;

  const activeScanIdRef = useRef(scanId);
  activeScanIdRef.current = scanId;
  const requestStateRef = useRef<(resources: readonly StateResource[]) => void>(() => { });
  const refreshState = useCallback(() => requestStateRef.current(STATE_RESOURCES), []);

  useEffect(() => connectScanStream({
    scanId,
    handlersRef,
    stateSettersRef,
    activeScanIdRef,
    setConnected,
    setOverviewFailed,
    setFailedResources,
    requestStateRef,
    requestDetailsRef,
    refreshState,
  }), [scanId, refreshState]);

  return { connected, overviewFailed, refreshOverview: refreshState, failedResources, refreshDetails };
}
