import type { ReviewNote, ScanReviewNotes } from "../types/reviewNotes";
import { isPublicScan } from "./accessPolicy";
import { api } from "./transport";

export async function getReviewNotes(signal?: AbortSignal): Promise<ReviewNote[]> {
  const { data } = await api.get<ReviewNote[]>("/api/review-notes", { signal });
  return data;
}

export async function saveReviewNote(body: Pick<ReviewNote, "title" | "content">, id?: string): Promise<ReviewNote & Pick<ScanReviewNotes, "sync_status">> {
  const { data } = id
    ? await api.put<ReviewNote>(`/api/review-notes/${encodeURIComponent(id)}`, body)
    : await api.post<ReviewNote>("/api/review-notes", body);
  return data;
}

export async function deleteReviewNote(id: string): Promise<Pick<ScanReviewNotes, "sync_status">> {
  const { data } = await api.delete<Pick<ScanReviewNotes, "sync_status">>(`/api/review-notes/${encodeURIComponent(id)}`);
  return data;
}

export async function getScanReviewNotes(scanId: string, signal?: AbortSignal): Promise<ScanReviewNotes> {
  if (isPublicScan(scanId)) throw new Error("当前访问方式不支持管理问题判定依据");
  const { data } = await api.get<ScanReviewNotes>(`/api/scan/${encodeURIComponent(scanId)}/review-notes`, { signal });
  return data;
}

export async function updateScanReviewNotes(scanId: string, body: Pick<ScanReviewNotes, "enabled" | "note_ids">): Promise<ScanReviewNotes> {
  if (isPublicScan(scanId)) throw new Error("当前访问方式不支持管理问题判定依据");
  const { data } = await api.put<ScanReviewNotes>(`/api/scan/${encodeURIComponent(scanId)}/review-notes`, body);
  return data;
}
