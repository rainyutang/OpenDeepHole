import axios from "axios";
import type { CheckerInfo, ScanStatus, ScanStartResponse, UploadResponse } from "../types";

const api = axios.create({ baseURL: "/" });

export async function getCheckers(): Promise<CheckerInfo[]> {
  const { data } = await api.get<CheckerInfo[]>("/api/checkers");
  return data;
}

export async function uploadSource(file: File): Promise<UploadResponse> {
  const form = new FormData();
  form.append("file", file);
  const { data } = await api.post<UploadResponse>("/api/upload", form);
  return data;
}

export async function startScan(
  projectId: string,
  scanItems: string[],
): Promise<ScanStartResponse> {
  const { data } = await api.post<ScanStartResponse>("/api/scan", {
    project_id: projectId,
    scan_items: scanItems,
  });
  return data;
}

export async function getScanStatus(scanId: string): Promise<ScanStatus> {
  const { data } = await api.get<ScanStatus>(`/api/scan/${scanId}`);
  return data;
}

export async function stopScan(scanId: string): Promise<void> {
  await api.post(`/api/scan/${scanId}/stop`);
}

export function getReportUrl(scanId: string): string {
  return `/api/scan/${scanId}/report`;
}
