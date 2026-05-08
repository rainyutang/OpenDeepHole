import { useState, useRef, useEffect, type DragEvent } from "react";
import { getCheckers, listFeedback } from "../api/client";
import type { CheckerInfo } from "../types";
import FeedbackManager from "./FeedbackManager";

interface Props {
  onScanStarted?: (scanId: string) => void;
  onBack: () => void;
}

export default function UploadForm({ onBack }: Props) {
  const [checkers, setCheckers] = useState<CheckerInfo[]>([]);
  const [file, setFile] = useState<File | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Two-step: after upload, allow feedback selection before scan
  const [projectId] = useState<string | null>(null);
  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const [selectedFeedbackIds, setSelectedFeedbackIds] = useState<Set<string>>(new Set());
  const [feedbackCount, setFeedbackCount] = useState(0);

  // Fetch available checkers on mount
  useEffect(() => {
    getCheckers().then((list) => {
      setCheckers(list);
      setSelected(new Set(list.map((c) => c.name)));
    });
  }, []);

  // When projectId becomes available, load feedback for selected scan types
  // and auto-select all false_positive entries
  useEffect(() => {
    if (!projectId) return;
    // Load feedback for all selected vuln types
    const loadAll = async () => {
      try {
        const all = await listFeedback();
        const fpIds = all
          .filter((e) => e.verdict === "false_positive" && selected.has(e.vuln_type))
          .map((e) => e.id);
        setSelectedFeedbackIds(new Set(fpIds));
        setFeedbackCount(all.filter((e) => selected.has(e.vuln_type)).length);
      } catch {
        // ignore
      }
    };
    loadAll();
  }, [projectId]);

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

  const handleUpload = async () => {
    if (!file) return;
    if (selected.size === 0) {
      setError("Please select at least one scan item");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      // Legacy upload flow — not used in the new agent-based architecture
      setError("Upload flow is no longer supported. Use 新建扫描 instead.");
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Upload failed";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleStartScan = async () => {
    if (!projectId) return;
    setLoading(true);
    setError(null);
    try {
      // Legacy scan start — not used in the new agent-based architecture
      setError("Direct scan start is no longer supported. Use 新建扫描 instead.");
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Scan failed to start";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async () => {
    if (projectId) {
      await handleStartScan();
    } else {
      await handleUpload();
    }
  };

  // Filter checkers to those selected, for the FeedbackManager tabs
  const selectedTypes = [...selected];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center p-6">
      <div className="w-full max-w-lg bg-white/95 backdrop-blur rounded-2xl shadow-2xl p-8">
        {/* Header */}
        <div className="mb-8">
          <button
            onClick={onBack}
            className="text-sm text-slate-500 hover:text-slate-700 transition-colors flex items-center gap-1 mb-4"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
            返回历史
          </button>
          <div className="text-center">
            <h1 className="text-3xl font-bold text-slate-900 tracking-tight">
              OpenDeepHole
            </h1>
            <p className="text-sm text-slate-500 mt-1">
              C/C++ Source Code Audit Tool
            </p>
          </div>
        </div>

        {/* Upload zone */}
        <div
          className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
            dragging
              ? "border-blue-500 bg-blue-50"
              : file
                ? "border-green-400 bg-green-50"
                : "border-slate-300 hover:border-slate-400 bg-slate-50"
          } ${projectId ? "opacity-60 pointer-events-none" : ""}`}
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          onClick={() => !projectId && inputRef.current?.click()}
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
              {projectId && (
                <p className="text-xs text-green-600 font-medium mt-1">已上传</p>
              )}
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

        {/* Feedback selection (after upload) */}
        {projectId && (
          <div className="mt-4 p-3 bg-slate-50 border border-slate-200 rounded-lg">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-slate-700">经验库</p>
                <p className="text-xs text-slate-500 mt-0.5">
                  共 {feedbackCount} 条经验，已选 {selectedFeedbackIds.size} 条用于 SKILL
                </p>
              </div>
              <button
                onClick={() => setFeedbackOpen(true)}
                className="text-sm px-3 py-1.5 font-medium text-blue-600 bg-blue-50 border border-blue-200 rounded-lg hover:bg-blue-100 transition-colors"
              >
                管理经验
              </button>
            </div>
          </div>
        )}

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
              {projectId ? "Starting..." : "Uploading..."}
            </span>
          ) : projectId ? (
            "Start Scan"
          ) : (
            "Upload & Continue"
          )}
        </button>
      </div>

      {/* Feedback Manager Panel */}
      {feedbackOpen && (
        <FeedbackManager
          checkers={checkers.filter((c) => selected.has(c.name))}
          initialTypes={selectedTypes}
          projectId={projectId || undefined}
          selectedIds={selectedFeedbackIds}
          onSelectionChange={setSelectedFeedbackIds}
          onClose={() => setFeedbackOpen(false)}
        />
      )}
    </div>
  );
}
