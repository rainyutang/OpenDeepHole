import { isPublicScan, publicParams, publicScanPath } from "./accessPolicy";
import { api } from "./transport";

export type ReportFpReviewState = "no_conclusion" | "tp" | "fp";

export async function downloadScanReport(scanId: string): Promise<Blob> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<Blob>(
      publicScanPath("/report"),
      { params: publicParams(), responseType: "blob" },
    );
    return data;
  }
  const { data } = await api.get<Blob>(`/api/scan/${scanId}/report`, { responseType: "blob" });
  return data;
}

export async function downloadVulnerabilityReport(scanId: string, idx: number): Promise<Blob> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<Blob>(
      publicScanPath(`/vulnerability/${idx}/report`),
      { params: publicParams(), responseType: "blob" },
    );
    return data;
  }
  const { data } = await api.get<Blob>(
    `/api/scan/${scanId}/vulnerability/${idx}/report`,
    { responseType: "blob" },
  );
  return data;
}

export async function downloadScanReportZip(scanId: string): Promise<Blob> {
  if (isPublicScan(scanId)) {
    const { data } = await api.get<Blob>(
      publicScanPath("/report.zip"),
      { params: publicParams(), responseType: "blob" },
    );
    return data;
  }
  const { data } = await api.get<Blob>(`/api/scan/${scanId}/report.zip`, { responseType: "blob" });
  return data;
}
