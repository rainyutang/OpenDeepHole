import { useEffect, useState } from "react";
import type { IndexedVulnerability, VulnerabilityValidation } from "../../../types/issues";
import type { ScanEvent } from "../../../types/scans";
import { EmptyState, EventList, MiniMetric, StatusPill, TaskPanel } from "../components/taskUi";
import { isAiConfirmed, vulnerabilityFunctionLabel, vulnerabilityLocation, vulnerabilityTypeLabel } from "../model/scan";
import type { TaskTone } from "../model/types";
import {
  isValidationComplete,
  isValidationFailed,
  validationSortRank,
  validationStatusLabel,
  validationTone,
} from "../model/validation";
import { ValidationDetail } from "./ValidationDetail";

export function ValidationPanel({
  vulnerabilities,
  validations,
  stoppingValidationIndices,
  events,
  onStopValidation,
}: {
  vulnerabilities: IndexedVulnerability[];
  validations: VulnerabilityValidation[];
  stoppingValidationIndices?: Set<number>;
  events: ScanEvent[];
  onStopValidation?: (index: number) => void | Promise<void>;
}) {
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  const confirmed = vulnerabilities
    .map((vuln) => ({ vuln, index: vuln.vuln_index }))
    .filter(({ vuln }) => isAiConfirmed(vuln));
  const validationByIndex = new Map(validations.map((item) => [item.vuln_index, item]));
  const items = confirmed
    .map(({ vuln, index }) => ({ vuln, index, validation: validationByIndex.get(index) }))
    .sort((a, b) => {
      const aRank = validationSortRank(a.validation);
      const bRank = validationSortRank(b.validation);
      if (aRank !== bRank) return aRank - bRank;
      return a.index - b.index;
    });
  const itemValidations = items.map((item) => item.validation).filter((item): item is VulnerabilityValidation => Boolean(item));
  const waitingCount = items.filter((item) => !item.validation || item.validation.status === "queued" || item.validation.status === "pending").length;
  const runningCount = itemValidations.filter((item) => item.running || item.status === "running").length;
  const completedCount = itemValidations.filter((item) => isValidationComplete(item.status)).length;
  const failedCount = itemValidations.filter((item) => isValidationFailed(item.status)).length;
  const status = runningCount > 0 ? "验证中" : completedCount > 0 ? "已验证" : confirmed.length > 0 ? "等待" : "无目标";
  const tone: TaskTone = runningCount > 0 ? "blue" : failedCount > 0 ? "red" : completedCount > 0 ? "green" : "slate";
  const selected = selectedIndex === null ? null : items.find((item) => item.index === selectedIndex) ?? null;

  useEffect(() => {
    if (items.length === 0) {
      if (selectedIndex !== null) setSelectedIndex(null);
      return;
    }
    if (selectedIndex === null || !items.some((item) => item.index === selectedIndex)) {
      setSelectedIndex(items[0].index);
    }
  }, [items, selectedIndex]);

  return (
    <TaskPanel
      title="漏洞验证"
      status={status}
      tone={tone}
      summary="对漏洞挖掘阶段确认的问题调用 Agent 本地验证脚本，展示验证过程和脚本返回结果。"
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-5">
        <MiniMetric label="确认问题" value={confirmed.length} tone="red" />
        <MiniMetric label="等待验证" value={waitingCount} />
        <MiniMetric label="验证中" value={runningCount} tone="blue" />
        <MiniMetric label="已完成" value={completedCount} tone="green" />
        <MiniMetric label="异常/超时" value={failedCount} tone="amber" />
      </div>
      {confirmed.length === 0 ? (
        <EmptyState text="当前还没有漏洞挖掘阶段确认的问题。" />
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(18rem,22rem)_1fr]">
          <div className="flex flex-col rounded-xl border border-slate-700 bg-slate-900/40">
            <div className="max-h-[70vh] flex-1 overflow-y-auto">
              <ul className="divide-y divide-slate-800">
                {items.map(({ vuln, index, validation }) => {
                  const active = selectedIndex === index;
                  const statusText = validation?.status || "pending";
                  const itemTone = validationTone(validation);
                  return (
                    <li key={`${index}-${vuln.file}-${vuln.line}`}>
                      <button
                        type="button"
                        onClick={() => setSelectedIndex(index)}
                        className={`w-full px-3 py-2.5 text-left transition-colors ${active ? "bg-blue-500/15" : "hover:bg-slate-800/60"
                          }`}
                      >
                        <div className="flex items-center gap-2">
                          <span className="truncate font-mono text-xs text-slate-200" title={vulnerabilityLocation(vuln)}>
                            {vulnerabilityLocation(vuln, true)}
                          </span>
                          {validation?.running && <span className="ml-auto h-3 w-3 shrink-0 rounded-full border border-blue-500/30 border-t-blue-300 animate-spin" />}
                        </div>
                        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                          <span className="text-[10px] font-semibold uppercase text-slate-400 bg-slate-700/50 px-1.5 py-0.5 rounded">
                            {vulnerabilityTypeLabel(vuln)}
                          </span>
                          <StatusPill label={validationStatusLabel(statusText)} tone={itemTone} />
                        </div>
                        <div className="mt-1 truncate font-mono text-[11px] text-slate-500" title={vulnerabilityFunctionLabel(vuln)}>
                          {vulnerabilityFunctionLabel(vuln)}
                        </div>
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          </div>

          <div className="min-h-[20rem] rounded-xl border border-slate-700 bg-slate-900/40">
            {selected ? (
              <ValidationDetail
                index={selected.index}
                vulnerability={selected.vuln}
                validation={selected.validation}
                stopping={stoppingValidationIndices?.has(selected.index) ?? false}
                onStopValidation={onStopValidation}
              />
            ) : (
              <div className="flex h-full items-center justify-center px-4 py-16 text-sm text-slate-500">
                从左侧选择一个问题查看验证详情
              </div>
            )}
          </div>
        </div>
      )}
      <EventList events={events} empty="暂无验证任务日志" />
    </TaskPanel>
  );
}
