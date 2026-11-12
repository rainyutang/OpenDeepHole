import { formatTokenCount } from "../../modelPool/presentation";
import { toneBg, toneBorder, toneText } from "../model/formatting";
import type { TaskTone } from "../model/types";
import { PanelIcon } from "./taskUi";

export function OverviewMetric({
  icon,
  label,
  value,
  detail,
  tone,
  onClick,
}: {
  icon: "target" | "alert" | "history" | "queue";
  label: string;
  value: number;
  detail: string;
  tone: TaskTone;
  onClick?: () => void;
}) {
  const content = (
    <>
      <div className={`flex h-9 w-9 items-center justify-center rounded-lg border ${toneBorder(tone)} ${toneBg(tone)} ${toneText(tone)}`}>
        <PanelIcon name={icon} />
      </div>
      <div className="min-w-0">
        <div className="text-xs text-slate-500">{label}</div>
        <div className="mt-1 flex items-baseline gap-2">
          <span className={`text-2xl font-semibold ${toneText(tone)}`}>{formatTokenCount(value)}</span>
          <span className="truncate text-xs text-slate-500">{detail}</span>
        </div>
      </div>
    </>
  );
  const cls = "flex items-center gap-3 rounded-lg border border-slate-700 bg-slate-900/50 p-4 text-left";
  if (onClick) {
    return <button type="button" onClick={onClick} className={`${cls} transition-colors hover:border-slate-600 hover:bg-slate-800/70`}>{content}</button>;
  }
  return <div className={cls}>{content}</div>;
}
