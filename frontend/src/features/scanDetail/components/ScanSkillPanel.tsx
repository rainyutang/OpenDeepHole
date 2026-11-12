import type { ScanStatus as ScanStatusType } from "../../../types/scans";

interface Props {
  skillOpen: boolean;
  setSkillOpen: React.Dispatch<React.SetStateAction<boolean>>;
  scan: ScanStatusType;
  loadSkill: (vulnType: string) => Promise<void>;
  skillType: string | null;
  loadFpReviewSkill: () => Promise<void>;
  skillLoading: boolean;
  skillContent: string;
}

export function ScanSkillPanel({
  skillOpen,
  setSkillOpen,
  scan,
  loadSkill,
  skillType,
  loadFpReviewSkill,
  skillLoading,
  skillContent,
}: Props) {
  return (
    <>{skillOpen && (
      <>
        <div
          className="fixed inset-0 bg-black/30 z-40"
          onClick={() => setSkillOpen(false)}
        />
        <div className="fixed right-0 top-0 bottom-0 w-[40rem] max-w-full bg-slate-900 border-l border-slate-700 z-50 flex flex-col shadow-2xl">
          <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
              SKILL 预览
            </h3>
            <button
              onClick={() => setSkillOpen(false)}
              className="text-slate-500 hover:text-slate-300 transition-colors"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          {/* Type tabs */}
          <div className="flex gap-1.5 px-4 py-2.5 border-b border-slate-700/50 overflow-x-auto">
            {scan.scan_items.map((item) => (
              <button
                key={item}
                onClick={() => loadSkill(item)}
                className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap ${skillType === item
                    ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
                    : "text-slate-400 border-slate-700 hover:bg-slate-800"
                  }`}
              >
                {item.toUpperCase()}
              </button>
            ))}
            <button
              onClick={() => loadFpReviewSkill()}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap ${skillType === "__fp_review__"
                  ? "bg-amber-500/20 text-amber-400 border-amber-500/30"
                  : "text-slate-400 border-slate-700 hover:bg-slate-800"
                }`}
            >
              FP REVIEW
            </button>
          </div>
          {/* Content */}
          <div className="flex-1 overflow-y-auto p-4">
            {skillLoading ? (
              <div className="flex items-center gap-2 text-xs text-slate-500">
                <div className="w-3 h-3 border border-slate-600 border-t-blue-400 rounded-full animate-spin" />
                加载中...
              </div>
            ) : (
              <pre className="text-xs text-slate-400 whitespace-pre-wrap leading-relaxed font-mono">
                {skillContent}
              </pre>
            )}
          </div>
        </div>
      </>
    )}</>
  );
}
