export interface ReviewNote {
  id: string;
  title: string;
  content: string;
  created_at: string;
  updated_at: string;
}

export interface ScanReviewNotes {
  enabled: boolean;
  note_ids: string[];
  revision: number;
  entries: ReviewNote[];
  sync_status?: "synced" | "pending" | "error";
}
