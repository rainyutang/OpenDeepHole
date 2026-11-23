import type { Announcement } from "../types/announcements";
import { api } from "./transport";

export async function getAnnouncements(): Promise<Announcement[]> {
  const { data } = await api.get<Announcement[]>("/api/announcements");
  return data;
}

export async function getAdminAnnouncements(): Promise<Announcement[]> {
  const { data } = await api.get<Announcement[]>("/api/admin/announcements");
  return data;
}

export async function createAnnouncement(
  content: string,
  published: boolean,
): Promise<Announcement> {
  const { data } = await api.post<Announcement>("/api/admin/announcements", {
    content,
    published,
  });
  return data;
}

export async function updateAnnouncement(
  announcementId: string,
  content: string,
  published: boolean,
): Promise<Announcement> {
  const { data } = await api.put<Announcement>(
    `/api/admin/announcements/${announcementId}`,
    { content, published },
  );
  return data;
}

export async function deleteAnnouncement(announcementId: string): Promise<void> {
  await api.delete(`/api/admin/announcements/${announcementId}`);
}
