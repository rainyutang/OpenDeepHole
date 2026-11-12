import type { ScanStatus } from "../types/scans";
import { mergeIndexedVulnerabilities } from "../scanRuntime/issues";
import { normalizeScanStatus } from "../scanRuntime/scanSnapshots";
import { isPublicScan, publicParams, scanV2Path } from "./accessPolicy";
import { getScanPatternTasksPage, getScanThreatTasksPage } from "./audit";
import { getScanValidationsPage, getScanVulnerabilitiesPage } from "./issues";
import { getScanCandidatesPage, getScanEventsPage } from "./scanDetails";
import { SCAN_READ_TIMEOUT_MS, api } from "./transport";

export interface ScanSnapshotRequest {
  promise: Promise<ScanStatus>;
  requestedFrom: ScanStatus | null;
}

export function getScanStatus(scanId: string): Promise<ScanStatus> {
  return getScanStatusRequest(scanId).promise;
}

export function getScanStatusRequest(
  scanId: string,
  requestedFrom: ScanStatus | null = null,
): ScanSnapshotRequest {
  const overviewRequest = getScanOverviewRequest(scanId, requestedFrom);
  return {
    promise: hydrateScanStatus(scanId, overviewRequest.promise),
    requestedFrom: overviewRequest.requestedFrom,
  };
}

async function hydrateScanStatus(scanId: string, overviewPromise: Promise<ScanStatus>): Promise<ScanStatus> {
  const [overview, candidates, vulnerabilities, events, threatTasks, validations, patternTasks] = await Promise.all([
    overviewPromise,
    getScanCandidatesPage(scanId),
    getScanVulnerabilitiesPage(scanId),
    getScanEventsPage(scanId),
    getScanThreatTasksPage(scanId),
    getScanValidationsPage(scanId),
    getScanPatternTasksPage(scanId),
  ]);
  const indexedVulnerabilities = mergeIndexedVulnerabilities([], vulnerabilities.items);
  const normalized = normalizeScanStatus({
    ...overview,
    total_candidates: Math.max(
      overview.total_candidates,
      overview.detail_counts?.candidates ?? 0,
    ),
    candidates: candidates.items,
    vulnerabilities: indexedVulnerabilities,
    events: events.items,
    threat_audit_tasks: threatTasks.items,
    threat_pattern_audit_tasks: patternTasks.items,
    validations: validations.items,
    detail_pages: {
      candidates_next_cursor: candidates.next_cursor,
      vulnerabilities_next_cursor: vulnerabilities.next_cursor,
      events_next_cursor: events.next_cursor,
      threat_tasks_next_cursor: threatTasks.next_cursor,
      pattern_tasks_next_cursor: patternTasks.next_cursor,
      validations_next_cursor: validations.next_cursor,
    },
  });
  if (!normalized || normalized.scan_id !== scanId) {
    throw new Error("扫描状态响应无效");
  }
  return normalized;
}

const overviewRequests = new Map<string, ScanSnapshotRequest>();

export function getScanOverview(scanId: string): Promise<ScanStatus> {
  return getScanOverviewRequest(scanId).promise;
}

/** Every consumer of a shared GET must merge from its original state snapshot. */
export function getScanOverviewRequest(
  scanId: string,
  requestedFrom: ScanStatus | null = null,
): ScanSnapshotRequest {
  const path = scanV2Path(scanId, "/overview");
  const params = isPublicScan(scanId) ? publicParams() : undefined;
  const key = path + JSON.stringify(params ?? {});
  const pending = overviewRequests.get(key);
  if (pending) return pending;
  const promise = (async () => {
    try {
      const { data } = await api.get<unknown>(path, { params, timeout: SCAN_READ_TIMEOUT_MS });
      const normalized = normalizeScanStatus(data);
      if (!normalized || normalized.scan_id !== scanId) throw new Error("扫描概览响应无效");
      return normalized;
    } finally {
      overviewRequests.delete(key);
    }
  })();
  const request = { promise, requestedFrom };
  overviewRequests.set(key, request);
  return request;
}
