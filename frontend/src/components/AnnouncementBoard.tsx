import { useEffect, useState } from "react";
import {
  createAnnouncement,
  deleteAnnouncement,
  getAdminAnnouncements,
  getAnnouncements,
  updateAnnouncement,
} from "../api/client";
import type { Announcement, User } from "../types";


function announcementDate(value: string) {
  if (!value) return "";
  try {
    return new Date(value).toLocaleDateString();
  } catch {
    return value;
  }
}


export default function AnnouncementBoard({
  user,
  open,
  onClose,
}: {
  user: User;
  open: boolean;
  onClose: () => void;
}) {
  const [announcements, setAnnouncements] = useState<Announcement[]>([]);
  const [managing, setManaging] = useState(false);
  const [adminAnnouncements, setAdminAnnouncements] = useState<Announcement[]>([]);
  const [adminLoading, setAdminLoading] = useState(false);
  const [editingId, setEditingId] = useState("");
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [published, setPublished] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const loadPublished = async () => {
    try {
      setAnnouncements(await getAnnouncements());
    } catch {
      setAnnouncements([]);
    }
  };

  const loadAdmin = async () => {
    setAdminLoading(true);
    setError("");
    try {
      setAdminAnnouncements(await getAdminAnnouncements());
    } catch (err: any) {
      setError(err?.response?.data?.detail || "加载公告失败");
    } finally {
      setAdminLoading(false);
    }
  };

  useEffect(() => {
    void loadPublished();
  }, []);

  const resetForm = () => {
    setEditingId("");
    setTitle("");
    setContent("");
    setPublished(true);
    setError("");
  };

  const openManager = () => {
    resetForm();
    onClose();
    setManaging(true);
    void loadAdmin();
  };

  const editAnnouncement = (announcement: Announcement) => {
    setEditingId(announcement.announcement_id);
    setTitle(announcement.title);
    setContent(announcement.content);
    setPublished(announcement.published);
    setError("");
  };

  const saveAnnouncement = async (event: React.FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      if (editingId) {
        await updateAnnouncement(editingId, title, content, published);
      } else {
        await createAnnouncement(title, content, published);
      }
      resetForm();
      await Promise.all([loadAdmin(), loadPublished()]);
    } catch (err: any) {
      setError(err?.response?.data?.detail || "保存公告失败");
    } finally {
      setSaving(false);
    }
  };

  const togglePublished = async (announcement: Announcement) => {
    setError("");
    try {
      await updateAnnouncement(
        announcement.announcement_id,
        announcement.title,
        announcement.content,
        !announcement.published,
      );
      await Promise.all([loadAdmin(), loadPublished()]);
    } catch (err: any) {
      setError(err?.response?.data?.detail || "更新发布状态失败");
    }
  };

  const removeAnnouncement = async (announcement: Announcement) => {
    if (!window.confirm(`确定删除公告“${announcement.title}”吗？`)) return;
    setError("");
    try {
      await deleteAnnouncement(announcement.announcement_id);
      if (editingId === announcement.announcement_id) resetForm();
      await Promise.all([loadAdmin(), loadPublished()]);
    } catch (err: any) {
      setError(err?.response?.data?.detail || "删除公告失败");
    }
  };

  return (
    <>
      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/65 p-4 backdrop-blur-sm">
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="announcement-viewer-title"
            className="max-h-[85vh] w-full max-w-3xl overflow-y-auto rounded-xl border border-slate-700 bg-slate-900 shadow-2xl"
          >
            <div className="sticky top-0 z-10 flex flex-wrap items-center justify-between gap-3 border-b border-slate-700 bg-slate-900 px-5 py-4">
              <div className="flex items-center gap-2">
                <span aria-hidden="true" className="text-blue-300">◈</span>
                <h2 id="announcement-viewer-title" className="font-semibold text-white">更新公告</h2>
              </div>
              <div className="flex items-center gap-2">
                {user.role === "admin" && (
                  <button
                    type="button"
                    onClick={openManager}
                    className="rounded-md border border-blue-400/30 bg-blue-500/10 px-3 py-1.5 text-xs font-medium text-blue-200 transition-colors hover:bg-blue-500/20"
                  >
                    管理公告
                  </button>
                )}
                <button
                  type="button"
                  onClick={onClose}
                  className="rounded-md px-2 py-1 text-slate-400 hover:bg-slate-800 hover:text-white"
                  aria-label="关闭公告"
                >
                  ✕
                </button>
              </div>
            </div>
            {announcements.length === 0 ? (
              <p className="px-5 py-8 text-center text-sm text-slate-500">暂无已发布公告。</p>
            ) : (
              <div className="divide-y divide-slate-700/70">
                {announcements.map((announcement) => (
                  <article key={announcement.announcement_id} className="grid gap-1 px-5 py-4 md:grid-cols-[10rem_1fr] md:gap-4">
                    <div>
                      <p className="text-sm font-medium text-slate-100">{announcement.title}</p>
                      <time className="text-xs text-slate-500">
                        {announcementDate(announcement.published_at)}
                      </time>
                    </div>
                    <p className="whitespace-pre-wrap text-sm leading-6 text-slate-300">{announcement.content}</p>
                  </article>
                ))}
              </div>
            )}
          </section>
        </div>
      )}

      {managing && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/65 p-4 backdrop-blur-sm">
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="announcement-manager-title"
            className="max-h-[90vh] w-full max-w-4xl overflow-y-auto rounded-xl border border-slate-700 bg-slate-900 shadow-2xl"
          >
            <div className="sticky top-0 z-10 flex items-center justify-between border-b border-slate-700 bg-slate-900 px-5 py-4">
              <h3 id="announcement-manager-title" className="font-semibold text-white">管理公告</h3>
              <button
                type="button"
                onClick={() => setManaging(false)}
                className="rounded-md px-2 py-1 text-slate-400 hover:bg-slate-800 hover:text-white"
                aria-label="关闭公告管理"
              >
                ✕
              </button>
            </div>

            <div className="grid gap-5 p-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
              <form onSubmit={saveAnnouncement} className="h-fit rounded-xl border border-slate-700 bg-slate-800/70 p-4">
                <div className="mb-4 flex items-center justify-between gap-3">
                  <h4 className="text-sm font-semibold text-white">{editingId ? "编辑公告" : "新增公告"}</h4>
                  {editingId && (
                    <button type="button" onClick={resetForm} className="text-xs text-slate-400 hover:text-white">
                      取消编辑
                    </button>
                  )}
                </div>
                <label className="mb-3 block">
                  <span className="mb-1 block text-xs font-medium text-slate-400">标题</span>
                  <input
                    value={title}
                    onChange={(event) => setTitle(event.target.value)}
                    maxLength={120}
                    required
                    className="w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-white outline-none focus:border-blue-500"
                  />
                </label>
                <label className="mb-3 block">
                  <span className="mb-1 block text-xs font-medium text-slate-400">正文</span>
                  <textarea
                    value={content}
                    onChange={(event) => setContent(event.target.value)}
                    maxLength={4000}
                    required
                    rows={7}
                    className="w-full resize-y rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm leading-6 text-white outline-none focus:border-blue-500"
                  />
                </label>
                <label className="mb-4 flex items-center gap-2 text-sm text-slate-300">
                  <input
                    type="checkbox"
                    checked={published}
                    onChange={(event) => setPublished(event.target.checked)}
                    className="h-4 w-4 rounded border-slate-600 bg-slate-950"
                  />
                  保存后发布
                </label>
                {error && (
                  <div role="alert" className="mb-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300">
                    {error}
                  </div>
                )}
                <button
                  type="submit"
                  disabled={saving}
                  className="w-full rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-500 disabled:opacity-50"
                >
                  {saving ? "保存中…" : editingId ? "保存修改" : "创建公告"}
                </button>
              </form>

              <div>
                <h4 className="mb-3 text-sm font-semibold text-slate-300">全部公告</h4>
                {adminLoading ? (
                  <div role="status" className="py-12 text-center text-sm text-slate-500">加载中…</div>
                ) : adminAnnouncements.length === 0 ? (
                  <div className="rounded-xl border border-dashed border-slate-700 py-12 text-center text-sm text-slate-500">暂无公告</div>
                ) : (
                  <div className="space-y-3">
                    {adminAnnouncements.map((announcement) => (
                      <article key={announcement.announcement_id} className="rounded-xl border border-slate-700 bg-slate-800/60 p-4">
                        <div className="mb-2 flex flex-wrap items-start justify-between gap-2">
                          <div>
                            <h5 className="text-sm font-medium text-white">{announcement.title}</h5>
                            <p className="mt-0.5 text-xs text-slate-500">
                              {announcement.published
                                ? `已发布 · ${announcementDate(announcement.published_at)}`
                                : "草稿"}
                            </p>
                          </div>
                          <span className={`rounded border px-2 py-0.5 text-xs ${
                            announcement.published
                              ? "border-green-500/30 bg-green-500/10 text-green-300"
                              : "border-slate-600 bg-slate-700 text-slate-400"
                          }`}>
                            {announcement.published ? "已发布" : "草稿"}
                          </span>
                        </div>
                        <p className="mb-3 whitespace-pre-wrap text-xs leading-5 text-slate-400">{announcement.content}</p>
                        <div className="flex flex-wrap gap-2">
                          <button type="button" onClick={() => editAnnouncement(announcement)} className="rounded bg-slate-700 px-2.5 py-1.5 text-xs text-slate-200 hover:bg-slate-600">
                            编辑
                          </button>
                          <button type="button" onClick={() => void togglePublished(announcement)} className="rounded bg-blue-500/10 px-2.5 py-1.5 text-xs text-blue-300 hover:bg-blue-500/20">
                            {announcement.published ? "下线" : "发布"}
                          </button>
                          <button type="button" onClick={() => void removeAnnouncement(announcement)} className="rounded bg-red-500/10 px-2.5 py-1.5 text-xs text-red-300 hover:bg-red-500/20">
                            删除
                          </button>
                        </div>
                      </article>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
