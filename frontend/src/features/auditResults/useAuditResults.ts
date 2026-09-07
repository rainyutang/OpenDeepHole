import { useCallback, useEffect, useRef, useState } from "react";
import { getScanCandidateAuditResults, getScanThreatAuditResults } from "../../api/client";
import type { CandidateAuditTaskResult, FpReviewJob, ScanStatus, ThreatAuditTaskResult } from "../../types";

interface ResultState<K, R> {
  scanId: string;
  key: string;
  results: Map<K, R>;
  loading: boolean;
  error: string;
}

function useAuditResults<K extends string | number, R>(
  scanId: string,
  ids: K[],
  request: (scanId: string, ids: K[], signal: AbortSignal) => Promise<R[]>,
  identify: (result: R) => K,
  inputs: readonly unknown[],
) {
  const key = JSON.stringify([...new Set(ids)].sort());
  const [state, setState] = useState<ResultState<K, R>>({
    scanId: "", key: "", results: new Map(), loading: true, error: "",
  });
  const refreshRef = useRef<() => void>(() => {});
  const inputsRef = useRef<readonly unknown[]>([]);
  const retry = useCallback(() => refreshRef.current(), []);

  useEffect(() => {
    const requestedIds: K[] = JSON.parse(key);
    inputsRef.current = inputs;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | null = null;
    let inFlight = false;
    let dirty = false;
    const schedule = () => {
      if (controller.signal.aborted) return;
      dirty = true;
      if (!inFlight && timer === null) timer = setTimeout(() => { void load(); }, 300);
    };
    const load = async () => {
      timer = null;
      dirty = false;
      inFlight = true;
      setState((previous) => ({
        scanId, key,
        results: previous.scanId === scanId && previous.key === key ? previous.results : new Map(),
        loading: true, error: "",
      }));
      try {
        const results = await request(scanId, requestedIds, controller.signal);
        if (!controller.signal.aborted) setState({
          scanId, key, results: new Map(results.map((result) => [identify(result), result])),
          loading: false, error: "",
        });
      } catch {
        if (!controller.signal.aborted) setState({
          scanId, key, results: new Map(), loading: false, error: "审计结果读取失败",
        });
      } finally {
        inFlight = false;
        if (dirty) schedule();
      }
    };
    refreshRef.current = schedule;
    void load();
    return () => {
      controller.abort();
      if (timer !== null) clearTimeout(timer);
      refreshRef.current = () => {};
    };
  }, [scanId, key, request, identify]);

  useEffect(() => {
    if (inputs.some((input, index) => input !== inputsRef.current[index])) {
      inputsRef.current = inputs;
      refreshRef.current();
    }
  }, [inputs]);

  const current = state.scanId === scanId && state.key === key;
  return {
    results: current ? state.results : new Map<K, R>(),
    loading: !current || state.loading,
    error: current ? state.error : "",
    retry,
  };
}

const threatId = (result: ThreatAuditTaskResult) => result.task_id;
const candidateId = (result: CandidateAuditTaskResult) => result.candidate_index;

export function useThreatAuditResults(scan: ScanStatus, taskIds: string[], fpReview: FpReviewJob | null, revision: number) {
  return useAuditResults(scan.scan_id, taskIds, getScanThreatAuditResults, threatId,
    [scan.threat_audit_tasks, scan.vulnerabilities, fpReview?.results, revision]);
}

export function useCandidateAuditResults(scan: ScanStatus, indexes: number[], fpReview: FpReviewJob | null, revision: number) {
  return useAuditResults(scan.scan_id, indexes, getScanCandidateAuditResults, candidateId,
    [scan.candidates, scan.vulnerabilities, fpReview?.results, revision]);
}
