import { SCAN_READ_TIMEOUT_MS, api } from "../../api/transport";
import { isPublicScan, publicParams, publicScanPath } from "../../api/accessPolicy";
import { isMissingOptionalResult } from "../../api/errors";
import type { ThreatAnalysis } from "../../types/threatAnalysis";
import type { CoverageIssues, ThreatCoverage } from "./coverage";

export async function getCoverageIssues(scanId: string, signal?: AbortSignal): Promise<CoverageIssues> {
  const { data } = await api.get<CoverageIssues>(
    isPublicScan(scanId) ? publicScanPath("/threat-coverage/issues") : `/api/scan/${scanId}/threat-coverage/issues`,
    { params: isPublicScan(scanId) ? publicParams() : undefined, signal, timeout: SCAN_READ_TIMEOUT_MS },
  );
  return data;
}

export async function getThreatCoverage(scanId: string, signal?: AbortSignal): Promise<ThreatCoverage> {
  const { data } = await api.get<ThreatCoverage>(
    isPublicScan(scanId) ? publicScanPath("/threat-coverage") : `/api/scan/${scanId}/threat-coverage`,
    { params: isPublicScan(scanId) ? publicParams() : undefined, signal, timeout: SCAN_READ_TIMEOUT_MS },
  );
  return data;
}

export async function getScanThreatAnalysis(scanId: string, signal?: AbortSignal): Promise<ThreatAnalysis | null> {
  const { data } = await api.get<ThreatAnalysis | null>(
    isPublicScan(scanId) ? publicScanPath("/threat-analysis") : `/api/scan/${scanId}/threat-analysis`,
    { params: { ...(isPublicScan(scanId) ? publicParams() : {}), allow_missing: true }, signal, timeout: SCAN_READ_TIMEOUT_MS },
  ).catch((error) => {
    if (isMissingOptionalResult(error, ["No threat analysis found for this scan"])) return { data: null };
    throw error;
  });
  return data;
}
