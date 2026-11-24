import { useEffect, useId, useMemo, useRef } from "react";
import type { KeyboardEvent } from "react";
import type { StaticFilterOption } from "../model/staticCandidates";

export interface MultiFilterSelectProps {
  label: string;
  values: string[];
  options: StaticFilterOption[];
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onChange: (values: string[]) => void;
}

export function MultiFilterSelect({
  label,
  values,
  options,
  open,
  onOpenChange,
  onChange,
}: MultiFilterSelectProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const listboxId = useId();
  const selectedSet = useMemo(() => new Set(values), [values]);
  const optionLabels = useMemo(
    () => new Map(options.map((option) => [option.value, option.label])),
    [options],
  );
  const selectedLabels = useMemo(
    () => values.map((value) => optionLabels.get(value) ?? value),
    [values, optionLabels],
  );

  useEffect(() => {
    if (!open || typeof document === "undefined") return;
    const handlePointerDown = (event: MouseEvent) => {
      if (!containerRef.current?.contains(event.target as Node)) {
        onOpenChange(false);
      }
    };
    const handleKeyDown = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") {
        onOpenChange(false);
        triggerRef.current?.focus();
      }
    };
    document.addEventListener("mousedown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [open, onOpenChange]);

  const active = values.length > 0;
  const summaryText = values.length === 0
    ? "全部"
    : values.length === 1
      ? selectedLabels[0]
      : `已选 ${values.length} 项`;
  const triggerTitle = active ? `${label}：${selectedLabels.join("、")}` : `${label}：全部`;

  const toggleValue = (optionValue: string) => {
    if (selectedSet.has(optionValue)) {
      onChange(values.filter((value) => value !== optionValue));
    } else {
      onChange([...values, optionValue]);
    }
  };

  const handleContainerKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (open && event.key === "Escape") {
      event.stopPropagation();
      onOpenChange(false);
      triggerRef.current?.focus();
    }
  };

  return (
    <div
      ref={containerRef}
      onKeyDown={handleContainerKeyDown}
      className="relative inline-flex items-center gap-1.5 text-xs text-slate-400"
    >
      <span>{label}</span>
      <button
        ref={triggerRef}
        type="button"
        aria-label={`${label}筛选`}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listboxId : undefined}
        title={triggerTitle}
        onClick={() => onOpenChange(!open)}
        className={`inline-flex max-w-[16rem] items-center gap-1.5 rounded-lg border px-2 py-1.5 text-xs transition-colors focus:border-blue-500 focus:outline-none ${
          active || open
            ? "border-blue-500/60 bg-slate-800 text-slate-100"
            : "border-slate-700 bg-slate-800 text-slate-200 hover:border-slate-600"
        }`}
      >
        <span className="min-w-0 truncate">{summaryText}</span>
        <svg
          className={`h-3.5 w-3.5 shrink-0 text-slate-400 transition-transform ${open ? "rotate-180" : ""}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && (
        <div
          id={listboxId}
          role="listbox"
          aria-label={`${label}选项`}
          aria-multiselectable="true"
          className="absolute left-0 top-full z-40 mt-1.5 w-72 max-w-[calc(100vw-2rem)] overflow-hidden rounded-lg border border-slate-600 bg-slate-900 shadow-xl sm:w-80"
        >
          <button
            type="button"
            role="option"
            aria-selected={!active}
            onClick={() => {
              onChange([]);
              onOpenChange(false);
            }}
            className={`flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-xs transition-colors ${
              !active
                ? "bg-blue-500/15 text-blue-200"
                : "text-slate-300 hover:bg-slate-800"
            }`}
          >
            <span>全部</span>
            <span className={active ? "text-[11px] text-slate-400" : "text-blue-300"}>
              {active ? "清空" : "✓"}
            </span>
          </button>
          <div className="max-h-64 overflow-y-auto border-t border-slate-700/70 py-1">
            {options.length === 0 ? (
              <div className="px-3 py-2 text-center text-xs text-slate-500">暂无可选项</div>
            ) : (
              options.map((option) => {
                const checked = selectedSet.has(option.value);
                return (
                  <button
                    key={option.value}
                    type="button"
                    role="option"
                    aria-selected={checked}
                    title={option.label}
                    onClick={() => toggleValue(option.value)}
                    className={`flex w-full items-center gap-2 px-3 py-2 text-left text-xs transition-colors ${
                      checked
                        ? "bg-blue-500/15 text-blue-200"
                        : "text-slate-300 hover:bg-slate-800"
                    }`}
                  >
                    <span
                      aria-hidden="true"
                      className={`flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded border ${
                        checked
                          ? "border-blue-400 bg-blue-500 text-white"
                          : "border-slate-500 bg-transparent"
                      }`}
                    >
                      {checked && (
                        <svg className="h-2.5 w-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                        </svg>
                      )}
                    </span>
                    <span className="min-w-0 flex-1 truncate">{option.label}</span>
                    {option.count !== undefined && (
                      <span className="shrink-0 tabular-nums text-[11px] text-slate-400">
                        ({option.count})
                      </span>
                    )}
                  </button>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}
