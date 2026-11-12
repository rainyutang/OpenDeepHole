import type { ScanEvent } from "../../../types/scans";
import { MAX_LOG_LINES } from "../model/scan";
import { EventLine } from "./taskUi";

interface Props {
  logOpen: boolean;
  setLogOpen: React.Dispatch<React.SetStateAction<boolean>>;
  logRef: React.RefObject<HTMLDivElement>;
  logEvents: ScanEvent[];
  truncated: boolean;
  allLogEvents: ScanEvent[];
}

export function ScanLogPanel({
  logOpen,
  setLogOpen,
  logRef,
  logEvents,
  truncated,
  allLogEvents,
}: Props) {
  return (
    <>{logOpen && (
      <>
        {/* Backdrop */}
        <div
          className="fixed inset-0 bg-black/30 z-40"
          onClick={() => setLogOpen(false)}
        />
        {/* Panel */}
        <div className="fixed right-0 top-0 bottom-0 w-[32rem] max-w-full bg-slate-900 border-l border-slate-700 z-50 flex flex-col shadow-2xl">
          <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
              处理日志
            </h3>
            <button
              onClick={() => setLogOpen(false)}
              className="text-slate-500 hover:text-slate-300 transition-colors"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <div
            ref={logRef}
            className="flex-1 overflow-y-auto p-3 space-y-1 font-mono text-xs"
          >
            {logEvents.length === 0 ? (
              <p className="text-slate-500">等待事件...</p>
            ) : (
              <>
                {truncated && (
                  <p className="text-slate-600 text-center py-1 border-b border-slate-700/50 mb-1">
                    ... 已省略 {allLogEvents.length - MAX_LOG_LINES} 条早期日志 ...
                  </p>
                )}
                {logEvents.map((event, i) => (
                  <EventLine key={i} event={event} />
                ))}
              </>
            )}
          </div>
        </div>
      </>
    )}</>
  );
}
