import type { RefCallback } from "react";
import type { FpReviewResult } from "../../types/fpReview";
import type { Vulnerability, VulnerabilityValidation } from "../../types/issues";
import {
  SEVERITY_STYLES,
  USER_FEEDBACK_DISPLAY,
  displayedVulnerabilityTypeLabel,
  engineId,
  engineLabel,
  severityLabel,
  validationBadgeClass,
  validationStatusLabel,
  versionLabels,
  vulnerabilityFunctionLabel,
  vulnerabilityLocation,
  vulnerabilityTypeLabel,
} from "./model";
import { FpStatusBadge } from "./presentation";

export function VulnListItem({
  vuln,
  fpResult,
  validation,
  problem,
  active,
  isCurrentFpReview,
  fpReviewRunning,
  finalTpOnly,
  staticRuleTypeLabels,
  onClick,
  focusRef,
}: {
  vuln: Vulnerability;
  fpResult?: FpReviewResult | null;
  validation?: VulnerabilityValidation;
  problem: boolean;
  active: boolean;
  isCurrentFpReview: boolean;
  fpReviewRunning?: boolean;
  finalTpOnly: boolean;
  staticRuleTypeLabels?: ReadonlyMap<string, string>;
  onClick: () => void;
  focusRef?: RefCallback<HTMLButtonElement>;
}) {
  const feedback = vuln.user_verdict ? USER_FEEDBACK_DISPLAY[vuln.user_verdict] : null;
  const validationStatus = validation?.status || "";
  const itemClassName = `w-full px-3 py-2.5 text-left transition-colors ${
    active
      ? "bg-blue-500/15"
      : isCurrentFpReview
        ? "bg-amber-500/10 hover:bg-amber-500/15"
        : "hover:bg-slate-800/60"
  }`;
  if (finalTpOnly) {
    const displayedType = displayedVulnerabilityTypeLabel(vuln, staticRuleTypeLabels);
    const rawType = vulnerabilityTypeLabel(vuln);
    return (
      <li>
        <button type="button" ref={focusRef} aria-current={active ? "true" : undefined} onClick={onClick} className={itemClassName}>
          <div className="flex items-center justify-between gap-2">
            <span
              className="min-w-0 truncate rounded bg-slate-700/50 px-1.5 py-0.5 text-[10px] font-semibold text-slate-300"
              title={displayedType !== rawType ? rawType.toUpperCase() : undefined}
            >
              {displayedType}
            </span>
            <span className={`shrink-0 text-[10px] font-semibold ${feedback?.color ?? "text-slate-600"}`}>
              人工：{feedback?.label ?? "未标记"}
            </span>
          </div>
          <div className="mt-1.5 truncate font-mono text-xs text-slate-200" title={vulnerabilityLocation(vuln)}>
            {vulnerabilityLocation(vuln, true)}
          </div>
          <div className="mt-1 truncate font-mono text-[11px] text-slate-500" title={vulnerabilityFunctionLabel(vuln)}>
            {vulnerabilityFunctionLabel(vuln)}
          </div>
        </button>
      </li>
    );
  }
  return (
    <li>
      <button
        type="button"
        onClick={onClick}
        className={itemClassName}
      >
        <div className="flex items-center gap-1.5">
          <span className="truncate font-mono text-xs text-slate-200" title={vulnerabilityLocation(vuln)}>
            {vulnerabilityLocation(vuln, true)}
          </span>
          {!problem && (
            <span className="ml-auto shrink-0 text-[10px] text-slate-500">非问题</span>
          )}
        </div>
        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
          <span className="text-[10px] font-semibold uppercase text-slate-400 bg-slate-700/50 px-1.5 py-0.5 rounded">
            {vulnerabilityTypeLabel(vuln)}
          </span>
          <span
            className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${
              SEVERITY_STYLES[vuln.severity] ?? "bg-slate-700/50 text-slate-400 border-slate-600"
            }`}
          >
            {severityLabel(vuln.severity)}
          </span>
          <span
            className="max-w-full truncate rounded border border-cyan-500/30 bg-cyan-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-cyan-200"
            title={`${engineLabel(vuln)} (${engineId(vuln)})`}
          >
            {engineLabel(vuln)}
          </span>
          {versionLabels(vuln).length > 0 && (
            <span
              className="max-w-full truncate rounded border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-200"
              title={`受影响版本：${versionLabels(vuln).join("、")}`}
            >
              版本：{versionLabels(vuln).join("、")}
            </span>
          )}
          {vuln.provisional && (
            <span className="rounded border border-blue-500/30 bg-blue-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-blue-300">
              临时上报
            </span>
          )}
          <FpStatusBadge fpResult={fpResult} fpReviewRunning={fpReviewRunning} />
          {fpResult?.match_type && (
            <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded border border-purple-500/40 bg-purple-500/15 text-purple-200">
              命中匹配
            </span>
          )}
          {vuln.variant_of && (
            <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded border border-purple-500/40 bg-purple-500/10 text-purple-200">
              变体
            </span>
          )}
          {validation && (
            <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${validationBadgeClass(validationStatus, validation.running)}`}>
              {validationStatusLabel(validationStatus)}
            </span>
          )}
        </div>
        {feedback ? (
          <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
            <span className={`text-[10px] font-semibold ${feedback.color}`}>人工：{feedback.label}</span>
            {vuln.ticket_submitted && (
              <span className="text-[10px] font-semibold text-blue-300 bg-blue-500/10 border border-blue-500/30 px-1.5 py-0.5 rounded">
                {vuln.ticket_id ? `已提单 ${vuln.ticket_id}` : "已提单"}
              </span>
            )}
          </div>
        ) : (
          <div className="mt-1.5 text-[10px] text-slate-600">人工：未标记</div>
        )}
        <div className="mt-1 truncate font-mono text-[11px] text-slate-500" title={vulnerabilityFunctionLabel(vuln)}>
          {vulnerabilityFunctionLabel(vuln)}
        </div>
      </button>
    </li>
  );
}
