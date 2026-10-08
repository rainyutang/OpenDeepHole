import { api, isPublicScan, publicParams, publicScanPath } from "../../api/client";
import type { ThreatAnalysis } from "../../types";
import type { ThreatCoverage } from "./coverage";

export async function getThreatCoverage(scanId: string, signal?: AbortSignal): Promise<ThreatCoverage> {
  const { data } = await api.get<ThreatCoverage>(
    isPublicScan(scanId) ? publicScanPath("/threat-coverage") : `/api/scan/${scanId}/threat-coverage`,
    { params: isPublicScan(scanId) ? publicParams() : undefined, signal, timeout: 30_000 },
  );
  return data;
}

export async function getScanThreatAnalysis(scanId: string, signal?: AbortSignal): Promise<ThreatAnalysis> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<ThreatAnalysis>(
      publicScanPath("/threat-analysis"),
      { params: publicParams(), signal },
    );
    return data;
  }
  const { data } = await api.get<ThreatAnalysis>(`/api/scan/${scanId}/threat-analysis`, { signal });
  return data;
}
