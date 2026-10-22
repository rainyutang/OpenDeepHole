import { useEffect, useId, useRef, useState } from "react";
import { updateScanMetadata } from "../api/client";
import type { ScanMetadata, ScanMetadataUpdate } from "../types";

interface Props {
  scan: Pick<ScanMetadata, "scan_id" | "scan_name" | "product">;
  onSaved: (metadata: ScanMetadata) => void;
  onClose: () => void;
}

export default function EditScanMetadataDialog({ scan, onSaved, onClose }: Props) {
  const [scanName, setScanName] = useState(scan.scan_name);
  const [product, setProduct] = useState(scan.product);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const savingRef = useRef(false);
  const mountedRef = useRef(true);
  const dialogRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const titleId = useId();
  const changedName = scanName.trim() !== scan.scan_name.trim();
  const changedProduct = product.trim() !== scan.product.trim();
  const hasChanges = changedName || changedProduct;

  useEffect(() => {
    mountedRef.current = true;
    const opener = document.activeElement as HTMLElement | null;
    inputRef.current?.focus();
    return () => { mountedRef.current = false; opener?.focus?.(); };
  }, []);

  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !savingRef.current) onClose();
      if (event.key !== "Tab") return;
      const elements = dialogRef.current?.querySelectorAll<HTMLElement>("button:not(:disabled), input:not(:disabled)");
      if (!elements?.length) return;
      const first = elements[0], last = elements[elements.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault(); last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault(); first.focus();
      }
    };
    window.addEventListener("keydown", keydown);
    return () => window.removeEventListener("keydown", keydown);
  }, [onClose]);

  const save = async (event: React.FormEvent) => {
    event.preventDefault();
    if (savingRef.current || !hasChanges) return;
    const body: ScanMetadataUpdate = {};
    if (changedName) {
      if (!scanName.trim()) { setError("扫描名称不能为空"); return; }
      body.scan_name = scanName.trim();
    }
    if (changedProduct) {
      if (!product.trim()) { setError("产品名不能为空"); return; }
      body.product = product.trim();
    }
    savingRef.current = true;
    setSaving(true);
    setError("");
    try {
      const metadata = await updateScanMetadata(scan.scan_id, body);
      if (!mountedRef.current) return;
      onSaved(metadata);
      onClose();
    } catch (caught: unknown) {
      if (!mountedRef.current) return;
      const detail = (caught as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
      setError(typeof detail === "string" ? detail : "保存失败，请稍后重试");
    } finally {
      savingRef.current = false;
      if (mountedRef.current) setSaving(false);
    }
  };

  const inputClass = "mt-2 w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-slate-200 disabled:opacity-50";
  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby={titleId}
        className="w-full max-w-lg rounded-xl border border-slate-600 bg-slate-900 p-5 text-left shadow-xl">
        <h2 id={titleId} className="text-base font-semibold text-white">编辑名称</h2>
        <form onSubmit={(event) => { void save(event); }} className="mt-5 space-y-4">
          <label className="block text-sm text-slate-300">产品名
            <input aria-label="产品名" value={product} disabled={saving} onChange={(event) => setProduct(event.target.value)} className={inputClass} />
          </label>
          <label className="block text-sm text-slate-300">扫描名称
            <input ref={inputRef} aria-label="扫描名称" value={scanName} disabled={saving} onChange={(event) => setScanName(event.target.value)} className={inputClass} />
          </label>
          {error && <p role="alert" className="text-sm text-red-300">{error}</p>}
          <div className="flex justify-end gap-3 pt-1">
            <button type="button" disabled={saving} onClick={onClose} className="rounded-lg border border-slate-600 px-4 py-2 text-sm text-slate-300 disabled:opacity-50">取消</button>
            <button type="submit" disabled={saving || !hasChanges} className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50">{saving ? "保存中..." : "保存"}</button>
          </div>
        </form>
      </div>
    </div>
  );
}
