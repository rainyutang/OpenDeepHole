import { useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { createScanShare, revokeScanShare } from "../api/client";

export default function ScanShareButton({ scanId, compact = false }: { scanId: string; compact?: boolean }) {
  const [open, setOpen] = useState(false);
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const requestVersion = useRef(0);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const titleId = useId();

  useEffect(() => () => { requestVersion.current += 1; }, [scanId]);
  useEffect(() => {
    if (!open) return;
    dialogRef.current?.focus();
    const keydown = (event: KeyboardEvent) => {
      if (event.key === "Escape") { setOpen(false); buttonRef.current?.focus(); }
      if (event.key === "Tab") {
        const elements = dialogRef.current?.querySelectorAll<HTMLElement>("button:not(:disabled), input");
        if (!elements?.length) return;
        const first = elements[0], last = elements[elements.length - 1];
        if (event.shiftKey && (document.activeElement === first || document.activeElement === dialogRef.current)) {
          event.preventDefault(); last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault(); first.focus();
        }
      }
    };
    window.addEventListener("keydown", keydown);
    return () => window.removeEventListener("keydown", keydown);
  }, [open]);

  const generate = async () => {
    const version = ++requestVersion.current;
    setOpen(true); setBusy(true); setError(""); setNotice(""); setUrl("");
    try {
      const link = await createScanShare(scanId);
      if (requestVersion.current === version) setUrl(link);
    } catch {
      if (requestVersion.current === version) setError("生成分享链接失败，请重试");
    } finally {
      if (requestVersion.current === version) setBusy(false);
    }
  };

  const revoke = async () => {
    const version = ++requestVersion.current;
    setBusy(true); setError(""); setNotice("");
    try {
      await revokeScanShare(scanId);
      if (requestVersion.current === version) { setUrl(""); setNotice("分享已关闭，原链接已失效"); }
    } catch { if (requestVersion.current === version) setError("关闭分享失败，请重试"); }
    finally { if (requestVersion.current === version) setBusy(false); }
  };

  const copy = async () => {
    try { await navigator.clipboard.writeText(url); setNotice("链接已复制"); }
    catch { setNotice("自动复制不可用，请选中上方链接手动复制"); }
  };

  const dialog = open && <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1}
        className="w-full max-w-xl rounded-xl border border-slate-600 bg-slate-900 p-5 text-left shadow-xl">
        <h2 id={titleId} className="text-base font-semibold text-white">分享扫描</h2>
        <p className="mt-2 text-sm text-slate-400">持有链接即可查看实时状态、标记问题和下载报告。链接长期有效，可随时关闭分享。</p>
        {busy && <p role="status" className="mt-4 text-sm text-slate-300">处理中...</p>}
        {url && <label className="mt-4 block text-sm text-slate-300">分享链接
          <input value={url} readOnly onFocus={(event) => event.target.select()}
            className="mt-2 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-slate-200" />
        </label>}
        {error && <p role="alert" className="mt-3 text-sm text-red-300">{error}</p>}
        {notice && <p role="status" className="mt-3 text-sm text-cyan-300">{notice}</p>}
        <div className="mt-5 flex flex-wrap justify-end gap-3 text-sm">
          {url && <>
            <button type="button" disabled={busy} onClick={() => { void revoke(); }} className="rounded-lg border border-red-500/40 px-3 py-2 text-red-300 disabled:opacity-50">关闭分享</button>
            <button type="button" disabled={busy} onClick={() => { void copy(); }} className="rounded-lg bg-blue-600 px-3 py-2 text-white disabled:opacity-50">复制链接</button>
          </>}
          {!url && !busy && <button type="button" onClick={() => { void generate(); }} className="rounded-lg bg-blue-600 px-3 py-2 text-white">{error ? "重试" : "重新开启分享"}</button>}
          <button type="button" onClick={() => { setOpen(false); buttonRef.current?.focus(); }} className="rounded-lg border border-slate-600 px-3 py-2 text-slate-300">关闭窗口</button>
        </div>
      </div>
    </div>;

  return <>
    <button ref={buttonRef} type="button" disabled={busy} onClick={() => { void generate(); }} className={compact
      ? "rounded px-2 py-1 text-xs text-cyan-300 transition-colors hover:bg-cyan-500/10"
      : "rounded-lg border border-cyan-500/40 px-3 py-1.5 text-sm font-medium text-cyan-300 transition-colors hover:bg-cyan-500/10"}>
      分享
    </button>
    {dialog && (typeof document !== "undefined" && document.body ? createPortal(dialog, document.body) : dialog)}
  </>;
}
