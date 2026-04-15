import { useState, useRef, useEffect, type DragEvent } from "react";
import { getCheckers, uploadSource, startScan } from "../api/client";
import type { CheckerInfo } from "../types";

interface Props {
  onScanStarted: (scanId: string) => void;
}

export default function UploadForm({ onScanStarted }: Props) {
  const [checkers, setCheckers] = useState<CheckerInfo[]>([]);
  const [file, setFile] = useState<File | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Fetch available checkers on mount
  useEffect(() => {
    getCheckers().then((list) => {
      setCheckers(list);
      setSelected(new Set(list.map((c) => c.name)));
    });
  }, []);

  const toggle = (name: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  const handleDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const dropped = e.dataTransfer.files[0];
    if (dropped?.name.endsWith(".zip")) setFile(dropped);
    else setError("Only .zip files are accepted");
  };

  const handleSubmit = async () => {
    if (!file) return;
    if (selected.size === 0) {
      setError("Please select at least one scan item");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const { project_id } = await uploadSource(file);
      const { scan_id } = await startScan(project_id, [...selected]);
      onScanStarted(scan_id);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Upload failed";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center p-6">
      <div className="w-full max-w-lg bg-white/95 backdrop-blur rounded-2xl shadow-2xl p-8">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-slate-900 tracking-tight">
            OpenDeepHole
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            C/C++ Source Code Audit Tool
          </p>
        </div>

        {/* Upload zone */}
        <div
          className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
            dragging
              ? "border-blue-500 bg-blue-50"
              : file
                ? "border-green-400 bg-green-50"
                : "border-slate-300 hover:border-slate-400 bg-slate-50"
          }`}
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          onClick={() => inputRef.current?.click()}
        >
          <input
            ref={inputRef}
            type="file"
            accept=".zip"
            className="hidden"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          />
          {file ? (
            <div>
              <div className="text-3xl mb-2">&#128230;</div>
              <p className="text-sm font-medium text-slate-700">{file.name}</p>
              <p className="text-xs text-slate-400 mt-1">
                {(file.size / 1024 / 1024).toFixed(2)} MB
              </p>
            </div>
          ) : (
            <div>
              <div className="text-3xl mb-2 text-slate-400">&#128193;</div>
              <p className="text-sm text-slate-500">
                Drag & drop a <span className="font-semibold">.zip</span> file
                here, or click to browse
              </p>
            </div>
          )}
        </div>

        {/* Scan options (dynamically loaded from API) */}
        <div className="mt-6">
          <h3 className="text-sm font-semibold text-slate-700 uppercase tracking-wider mb-3">
            Scan Items
          </h3>
          {checkers.length === 0 ? (
            <p className="text-sm text-slate-400">Loading checkers...</p>
          ) : (
            <div className="space-y-2">
              {checkers.map((checker) => (
                <label
                  key={checker.name}
                  className={`flex items-center gap-3 p-3 rounded-lg cursor-pointer transition-colors ${
                    selected.has(checker.name)
                      ? "bg-blue-50 border border-blue-200"
                      : "bg-slate-50 border border-transparent hover:bg-slate-100"
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={selected.has(checker.name)}
                    onChange={() => toggle(checker.name)}
                    className="w-4 h-4 rounded text-blue-600 accent-blue-600"
                  />
                  <div>
                    <span className="font-semibold text-sm text-slate-800">
                      {checker.label}
                    </span>
                    <span className="text-sm text-slate-500 ml-2">
                      {checker.description}
                    </span>
                  </div>
                </label>
              ))}
            </div>
          )}
        </div>

        {/* Error */}
        {error && (
          <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
            {error}
          </div>
        )}

        {/* Submit */}
        <button
          onClick={handleSubmit}
          disabled={!file || loading}
          className={`mt-6 w-full py-3 rounded-xl text-sm font-semibold text-white transition-all ${
            !file || loading
              ? "bg-slate-300 cursor-not-allowed"
              : "bg-blue-600 hover:bg-blue-700 active:bg-blue-800 shadow-lg shadow-blue-600/25"
          }`}
        >
          {loading ? (
            <span className="flex items-center justify-center gap-2">
              <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Uploading...
            </span>
          ) : (
            "Start Scan"
          )}
        </button>
      </div>
    </div>
  );
}
