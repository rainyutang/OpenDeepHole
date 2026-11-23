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

export interface AdminIssueExportParams {
  start_time?: string;
  end_time?: string;
  username?: string;
  employee_id?: string;
  tz_offset_minutes?: number;
  share_origin?: string;
}

export interface AdminIssueExportResult {
  blob: Blob;
  filename: string;
  rowCount: number | null;
}

function readHeader(headers: unknown, name: string): string {
  if (!headers || typeof headers !== "object") return "";
  const candidate = headers as { get?: (key: string) => unknown } & Record<string, unknown>;
  if (typeof candidate.get === "function") {
    const value = candidate.get(name);
    if (value != null) return String(value);
  }
  const lower = name.toLowerCase();
  for (const [key, value] of Object.entries(candidate)) {
    if (key.toLowerCase() === lower && value != null) return String(value);
  }
  return "";
}

function filenameFromDisposition(header: string, fallback: string): string {
  const utf8Match = header.match(/filename\*\s*=\s*UTF-8''([^;\r\n]+)/i);
  if (utf8Match?.[1]) {
    try {
      const decoded = decodeURIComponent(utf8Match[1].trim());
      if (decoded) return decoded;
    } catch {
      // fall back to quoted filename
    }
  }
  const quotedMatch = header.match(/filename\s*=\s*"([^"\r\n]+)"/i);
  if (quotedMatch?.[1]?.trim()) return quotedMatch[1].trim();
  const bareMatch = header.match(/filename\s*=\s*([^;\r\n]+)/i);
  if (bareMatch?.[1]?.trim()) return bareMatch[1].trim();
  return fallback;
}

async function resolveBlobErrorDetail(err: unknown, fallback: string): Promise<string> {
  const response = (err as { response?: { data?: unknown } } | null)?.response;
  const payload = response?.data;
  if (payload && typeof payload === "object") {
    if ("detail" in payload && typeof (payload as { detail?: unknown }).detail === "string") {
      return (payload as { detail: string }).detail;
    }
    if ("text" in payload && typeof (payload as Blob).text === "function") {
      try {
        const rawText = (await (payload as Blob).text()).trim();
        if (rawText) {
          try {
            const parsed = JSON.parse(rawText);
            if (parsed && typeof parsed.detail === "string" && parsed.detail.trim()) {
              return parsed.detail.trim();
            }
          } catch {
            return rawText;
          }
        }
      } catch {
        // ignore unreadable blob
      }
    }
  }
  if (err instanceof Error && err.message) return err.message;
  return fallback;
}

export async function exportAdminIssuesExcel(
  params: AdminIssueExportParams = {},
): Promise<AdminIssueExportResult> {
  try {
    const response = await api.get<Blob>("/api/admin/issues/export", {
      params,
      responseType: "blob",
    });
    const disposition = readHeader(response.headers, "content-disposition");
    const rawCount = readHeader(response.headers, "x-export-row-count");
    const parsedCount = /^\d+$/.test(rawCount.trim()) ? Number(rawCount.trim()) : null;
    return {
      blob: response.data,
      filename: filenameFromDisposition(disposition, "deephole-issues.xlsx"),
      rowCount: parsedCount,
    };
  } catch (err: unknown) {
    throw new Error(await resolveBlobErrorDetail(err, "导出问题失败"));
  }
}
