import type { IssueDetailProps } from "./types";
import { getVerdict, validationBadgeClass, validationStatusLabel } from "./model";

type ValidationActionProps = Pick<IssueDetailProps,
  "index" | "vuln" | "validation" | "validating" | "stoppingValidation" | "agentOnline"
  | "onTriggerValidation" | "onStopValidation" | "finalTpOnly"
>;

export function IssueValidationActions({
  index, vuln, validation, validating, stoppingValidation, agentOnline,
  onTriggerValidation, onStopValidation, finalTpOnly,
}: ValidationActionProps) {
  const isProblem = getVerdict(vuln) === "confirmed";
  const validationRunning = validating || Boolean(validation?.running);
  const validationStatus = validation?.status || (validationRunning ? "running" : "pending");
  const validationCanStop = Boolean(
    onStopValidation && (stoppingValidation || validationRunning || validationStatus === "queued" || validationStatus === "running"),
  );
  const validationButtonLabel = validationRunning
    ? "验证中..."
    : validation
      ? "重新验证"
      : "启动漏洞验证";
  const validationButtonDisabled = Boolean(vuln.provisional) || !isProblem || validationRunning || !agentOnline || !onTriggerValidation;
  const validationButtonTitle = vuln.provisional
    ? "等待引擎 run() 最终结果对账后才能验证"
    : !isProblem
    ? "仅 AI 确认的问题可启动验证"
    : !agentOnline
      ? "Agent 离线，无法启动本地验证脚本"
      : validation
        ? "重新运行 Agent 本地验证脚本，覆盖当前验证结果"
        : "运行 Agent 本地验证脚本";
  return (
    <>
      {isProblem && !finalTpOnly && (
        <span className={`text-xs font-semibold px-2 py-0.5 rounded border ${validationBadgeClass(validationStatus, validationRunning)}`}>
          {validationStatusLabel(validationStatus)}
        </span>
      )}
      {isProblem && onTriggerValidation && (
        <button
          onClick={() => onTriggerValidation(index)}
          disabled={validationButtonDisabled}
          className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/20 disabled:cursor-not-allowed disabled:opacity-50 transition-colors"
          title={validationButtonTitle}
        >
          {validationButtonLabel}
        </button>
      )}
      {isProblem && validationCanStop && (
        <button
          onClick={() => onStopValidation?.(index)}
          disabled={stoppingValidation}
          className="text-xs px-2 py-0.5 rounded bg-red-500/10 text-red-300 border border-red-500/30 hover:bg-red-500/20 disabled:cursor-not-allowed disabled:opacity-60 transition-colors"
          title="停止当前 Agent 本地验证过程"
        >
          {stoppingValidation ? "停止中..." : "停止验证"}
        </button>
      )}
    </>
  );
}
