import { api, isMissingOptionalResult, isPublicScan, publicParams, publicScanPath } from "../../api/client";
import type { ThreatAnalysis } from "../../types";
import type { ThreatCoverage } from "./coverage";

export async function getThreatCoverage(scanId: string, signal?: AbortSignal): Promise<ThreatCoverage> {
  const { data } = await api.get<ThreatCoverage>(
    isPublicScan(scanId) ? publicScanPath("/threat-coverage") : `/api/scan/${scanId}/threat-coverage`,
    { params: isPublicScan(scanId) ? publicParams() : undefined, signal, timeout: 30_000 },
  );
  return data;
}

export async function getScanThreatAnalysis(scanId: string, signal?: AbortSignal): Promise<ThreatAnalysis | null> {
  const { data } = await api.get<ThreatAnalysis | null>(
    isPublicScan(scanId) ? publicScanPath("/threat-analysis") : `/api/scan/${scanId}/threat-analysis`,
    { params: { ...(isPublicScan(scanId) ? publicParams() : {}), allow_missing: true }, signal },
  ).catch((error) => {
    if (isMissingOptionalResult(error, ["No threat analysis found for this scan"])) return { data: null };
    throw error;
  });
  return data;
}
