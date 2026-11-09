import { useCallback, useEffect, useId, useRef, useState } from "react";
import { deleteReviewNote, getReviewNotes, getScanReviewNotes, saveReviewNote, updateScanReviewNotes } from "../api/client";
import type { ReviewNote, ScanReviewNotes } from "../types";
import { ThemeToggle } from "./ThemeToggle";
import PageHeader from "./PageHeader";

const buttonClass = "rounded-lg border border-slate-600 px-3 py-2 text-sm text-slate-200 hover:bg-slate-700 disabled:opacity-50";
const primaryClass = "rounded-lg bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-500 disabled:opacity-50";
const inputClass = "mt-2 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-slate-200 disabled:opacity-50";

function errorMessage(error: unknown): string {
  const detail = (error as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
  return typeof detail === "string" ? detail : "操作失败，请重试";
}

function syncMessage(status: ScanReviewNotes["sync_status"]): string {
  return status === "error" ? "已保存，同步失败；客户端重连后会补同步。"
    : status === "pending" ? "已保存，等待客户端同步。" : "已保存，后续复核将使用最新依据。";
}

function NoteList({ notes, selected, onSelect, onEdit, onDelete, disabled = false }: {
  notes: ReviewNote[];
  selected?: string[];
  onSelect?: (ids: string[]) => void;
  onEdit?: (note: ReviewNote) => void;
  onDelete?: (note: ReviewNote) => void;
  disabled?: boolean;
}) {
  if (!notes.length) return <p className="py-4 text-sm text-slate-400">暂无问题判定依据</p>;
  return <div className="space-y-3">{notes.map((note) => <div key={note.id} className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
    <div className="flex items-start justify-between gap-3">
      <label className="flex min-w-0 items-start gap-2 text-sm font-medium text-slate-100">
        {onSelect && <input type="checkbox" aria-label={note.title} disabled={disabled} checked={selected?.includes(note.id) ?? false}
          onChange={(event) => onSelect(event.target.checked ? [...(selected ?? []), note.id] : (selected ?? []).filter((id) => id !== note.id))} className="mt-1" />}
        <span className="break-words">{note.title}</span>
      </label>
      {(onEdit || onDelete) && <div className="flex shrink-0 gap-2">
        {onEdit && <button type="button" aria-label={`编辑 ${note.title}`} disabled={disabled} className={buttonClass} onClick={() => onEdit(note)}>编辑</button>}
        {onDelete && <button type="button" aria-label={`删除 ${note.title}`} disabled={disabled} className={buttonClass} onClick={() => onDelete(note)}>删除</button>}
      </div>}
    </div>
    <details className="mt-2 text-sm text-slate-400"><summary className="cursor-pointer">查看内容</summary><p className="mt-3 whitespace-pre-wrap break-words leading-6">{note.content}</p></details>
  </div>)}</div>;
}

function EnabledSwitch({ enabled, onChange, disabled = false }: { enabled: boolean; onChange: (value: boolean) => void; disabled?: boolean }) {
  return <label className="flex items-center gap-2 text-sm text-slate-200"><input type="checkbox" role="switch" aria-label="启用问题判定依据" aria-checked={enabled} checked={enabled} disabled={disabled} onChange={(event) => onChange(event.target.checked)} />启用问题判定依据</label>;
}

/** The create form only loads the personal library when this optional capability is enabled. */
export function ReviewNotesSelector({ enabled, noteIds, onEnabledChange, onSelectionChange, onValidityChange }: {
  enabled: boolean; noteIds: string[]; onEnabledChange: (value: boolean) => void; onSelectionChange: (ids: string[]) => void;
  onValidityChange?: (valid: boolean) => void;
}) {
  const [notes, setNotes] = useState<ReviewNote[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [retry, setRetry] = useState(0);
  const missingIds = noteIds.filter((id) => !notes.some((note) => note.id === id));
  const valid = !enabled || (!loading && !error && missingIds.length === 0);
  useEffect(() => { onValidityChange?.(valid); }, [valid, onValidityChange]);
  useEffect(() => {
    if (!enabled) return;
    const controller = new AbortController();
    setLoading(true); setError("");
    getReviewNotes(controller.signal).then((items) => { if (!controller.signal.aborted) setNotes(items); })
      .catch((error: unknown) => { if (!controller.signal.aborted) setError(errorMessage(error)); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [enabled, retry]);
  return <div className="rounded-xl border border-slate-700 bg-slate-800 p-5">
    <EnabledSwitch enabled={enabled} onChange={onEnabledChange} />
    {enabled && <div className="mt-4 space-y-3">
      <p className="text-xs text-slate-400">勾选本次扫描使用的依据，也可在扫描运行时添加。</p>
      {loading ? <p role="status" className="text-sm text-slate-400">加载中…</p> : error ? <p role="alert" className="text-sm text-red-300">{error} <button type="button" className={buttonClass} onClick={() => setRetry((value) => value + 1)}>重试</button></p>
        : <NoteList notes={notes} selected={noteIds} onSelect={onSelectionChange} />}
      {!loading && !error && missingIds.length > 0 && <div role="alert" className="text-sm text-amber-300">
        <p>以下问题判定依据已不可用，请取消选择后创建扫描：</p>
        {missingIds.map((id) => <label key={id} className="mt-2 block break-all"><input type="checkbox" checked aria-label={`取消不可用依据 ${id}`} onChange={() => onSelectionChange(noteIds.filter((selected) => selected !== id))} /> {id}</label>)}
      </div>}
      {!loading && !error && !notes.length && <p className="text-xs text-slate-400">可先在主页的「问题判定依据」中新增。</p>}
    </div>}
  </div>;
}

function NoteEditor({ note, scanMode, onSave, onClose }: {
  note: ReviewNote | null; scanMode: boolean;
  onSave: (body: Pick<ReviewNote, "title" | "content">, id?: string) => Promise<void>; onClose: () => void;
}) {
  const [title, setTitle] = useState(note?.title ?? "");
  const [content, setContent] = useState(note?.content ?? "");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const savingRef = useRef(false);
  const dialogRef = useRef<HTMLDivElement>(null);
  const titleRef = useRef<HTMLInputElement>(null);
  const labelId = useId();
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    titleRef.current?.focus();
    const keydown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !savingRef.current) onClose();
      if (event.key !== "Tab") return;
      const elements = dialogRef.current?.querySelectorAll<HTMLElement>("button:not(:disabled), input:not(:disabled), textarea:not(:disabled)");
      if (!elements?.length) return;
      const first = elements[0], last = elements[elements.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    window.addEventListener("keydown", keydown);
    return () => { window.removeEventListener("keydown", keydown); opener?.focus?.(); };
  }, [onClose]);
  return <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/60 p-4">
    <div ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby={labelId} className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-xl border border-slate-600 bg-slate-900 p-5 shadow-xl">
      <h2 id={labelId} className="text-base font-semibold text-white">{note ? "编辑依据" : "新增依据"}</h2>
      <form className="mt-4 space-y-4" onSubmit={async (event) => {
        event.preventDefault();
        if (savingRef.current) return;
        if (!title.trim() || !content.trim()) { setError("标题和内容不能为空"); return; }
        savingRef.current = true; setSaving(true); setError("");
        try { await onSave({ title: title.trim(), content }, note?.id); onClose(); }
        catch (error) { setError(errorMessage(error)); }
        finally { savingRef.current = false; setSaving(false); }
      }}>
        <label className="block text-sm text-slate-300">标题<input ref={titleRef} aria-label="标题" value={title} maxLength={120} onChange={(event) => setTitle(event.target.value)} disabled={saving} className={inputClass} /></label>
        <label className="block text-sm text-slate-300">内容<textarea aria-label="内容" value={content} maxLength={100000} onChange={(event) => setContent(event.target.value)} disabled={saving} rows={10} className={inputClass} placeholder="描述判断这类问题时需要考虑的条件，支持 Markdown。" /></label>
        {scanMode && note && <p className="text-xs text-slate-400">修改会同步到个人库及选用该条目的扫描。</p>}
        {error && <p role="alert" className="text-sm text-red-300">{error}</p>}
        <div className="flex justify-end gap-3"><button type="button" className={buttonClass} disabled={saving} onClick={onClose}>取消</button><button type="submit" className={primaryClass} disabled={saving}>{saving ? "保存中…" : scanMode && !note ? "新增并选用" : "保存"}</button></div>
      </form>
    </div>
  </div>;
}

export function ReviewNotesManager({ scanId, showHeading = true }: { scanId?: string; showHeading?: boolean }) {
  const [notes, setNotes] = useState<ReviewNote[]>([]);
  const [selection, setSelection] = useState<ScanReviewNotes | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [noteIds, setNoteIds] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [retry, setRetry] = useState(0);
  const [editing, setEditing] = useState<ReviewNote | "new" | null>(null);
  const closeEditor = useCallback(() => setEditing(null), []);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true); setError(""); setMessage("");
    Promise.all([getReviewNotes(controller.signal), scanId ? getScanReviewNotes(scanId, controller.signal) : Promise.resolve(null)])
      .then(([items, config]) => {
        if (controller.signal.aborted) return;
        setNotes([...new Map([...(config?.entries ?? []), ...items].map((note) => [note.id, note])).values()]);
        setSelection(config); setEnabled(config?.enabled ?? false); setNoteIds(config?.note_ids ?? []);
      }).catch((error: unknown) => { if (!controller.signal.aborted) setError(errorMessage(error)); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [scanId, retry]);

  const persistSelection = async (nextEnabled: boolean, ids: string[]) => {
    const result = await updateScanReviewNotes(scanId!, { enabled: nextEnabled, note_ids: ids });
    setSelection(result); setEnabled(result.enabled); setNoteIds(result.note_ids);
    setMessage(syncMessage(result.sync_status));
  };
  const changed = selection && (enabled !== selection.enabled || [...noteIds].sort().join("\n") !== [...selection.note_ids].sort().join("\n"));

  return <section className="space-y-4" aria-label="问题判定依据管理">
    <div className={`flex flex-wrap items-start gap-3 ${showHeading ? "justify-between" : "justify-end"}`}>
      {showHeading && <div><h1 className="text-lg font-semibold text-white">问题判定依据</h1><p className="mt-1 text-sm text-slate-400">{scanId ? "选择本次扫描使用的依据，保存后供后续复核参考。" : "记录判断问题时需要考虑的条件，供扫描选用。"}</p></div>}
      <button type="button" className={primaryClass} disabled={loading || saving || Boolean(scanId && !selection)} onClick={() => setEditing("new")}>{scanId ? "新增并选用" : "新增依据"}</button>
    </div>
    {loading ? <p role="status" className="py-6 text-sm text-slate-400">加载中…</p> : <>
      {scanId && selection && <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-700 bg-slate-800 p-4">
        <EnabledSwitch enabled={enabled} onChange={setEnabled} disabled={saving} />
        <button type="button" className={primaryClass} disabled={saving || !changed} onClick={async () => {
          setSaving(true); setError(""); setMessage("");
          try { await persistSelection(enabled, noteIds); } catch (error) { setError(errorMessage(error)); } finally { setSaving(false); }
        }}>{saving ? "保存中…" : "保存选择"}</button>
      </div>}
      {scanId && selection && <p className="text-xs text-slate-400">勾选或取消勾选下方个人条目，保存后应用到本扫描。</p>}
      <NoteList notes={notes} selected={scanId ? noteIds : undefined} onSelect={scanId && selection ? setNoteIds : undefined}
        onEdit={setEditing} disabled={saving} onDelete={scanId ? undefined : async (note) => {
          if (!window.confirm(`确定删除「${note.title}」？选用它的扫描也会移除此依据。`)) return;
          setSaving(true); setError(""); setMessage("");
          try {
            const result = await deleteReviewNote(note.id);
            setNotes((current) => current.filter((item) => item.id !== note.id));
            if (result?.sync_status === "error" || result?.sync_status === "pending") setMessage(syncMessage(result.sync_status));
          }
          catch (error) { setError(errorMessage(error)); } finally { setSaving(false); }
        }} />
    </>}
    {error && <p role="alert" className="text-sm text-red-300">{error} {!notes.length && <button type="button" className={buttonClass} onClick={() => setRetry((value) => value + 1)}>重试</button>}</p>}
    {message && <p role="status" className="text-sm text-amber-200">{message}</p>}
    {editing && <NoteEditor note={editing === "new" ? null : editing} scanMode={Boolean(scanId)} onClose={closeEditor} onSave={async (body, id) => {
      setError(""); setMessage("");
      const saved = await saveReviewNote(body, id);
      setNotes((current) => [...current.filter((item) => item.id !== saved.id), saved]);
      if (saved.sync_status === "error" || saved.sync_status === "pending") setMessage(syncMessage(saved.sync_status));
      if (scanId && !id) {
        // Keep the created entry and selection if linking fails; retry only the scan save.
        setNoteIds((current) => [...new Set([...current, saved.id])]); setEnabled(true);
        try { await persistSelection(true, [...new Set([...noteIds, saved.id])]); }
        catch (error) { setError(`依据已创建，选用失败：${errorMessage(error)}。请点击「保存选择」重试。`); }
      }
    }} />}
  </section>;
}

export default function ReviewNotesPage({ onBack }: { onBack: () => void }) {
  return <div className="min-h-screen bg-slate-950 text-slate-100">
    <PageHeader title="问题判定依据" onBack={onBack} description="记录判断问题时需要考虑的条件，供扫描选用。" actions={<ThemeToggle />} />
    <main className="mx-auto max-w-5xl px-4 py-6"><ReviewNotesManager showHeading={false} /></main>
  </div>;
}
