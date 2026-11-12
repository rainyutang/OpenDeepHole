import type { ScanStatus as ScanStatusType } from "../../../types/scans";
import type { ThreatAuditTask, ThreatAuditTaskResult } from "../../../types/audit";
import { formatDateTime } from "../../modelPool/presentation";
import { ThreatAuditResults } from "../../threatAudit/ThreatAuditResults";
import { AuditDetailSection, AuditPromptSection, DetailGrid } from "../components/AuditDetail";
import { MarkdownContent } from "../components/MarkdownContent";
import { MiniMetric, StatusPill } from "../components/taskUi";
import { formatOutputSource, taskTokenUsage } from "../model/scan";
import { scanQueueTaskSessionId } from "../model/taskQueue";
import type { ScanQueueTask } from "../model/types";
import { effectiveThreatAuditTaskStatus, threatAuditStatusLabel, threatAuditStatusTone } from "../model/threatAudit";

export function ThreatAuditTaskDetail({
  scan,
  task,
  patternMode = false,
  runtime,
  result,
  resultLoading,
  resultError,
  onRetryResult,
  onOpenIssue,
}: {
  scan: ScanStatusType;
  task: ThreatAuditTask;
  patternMode?: boolean;
  runtime: ScanQueueTask | null;
  result?: ThreatAuditTaskResult;
  resultLoading: boolean;
  resultError: string;
  onRetryResult: () => void;
  onOpenIssue: (index: number) => void;
}) {
  const sessionId = (runtime ? scanQueueTaskSessionId(runtime.task) : "")
    || scanQueueTaskSessionId({ serve_session_id: task.output_source?.serve_session_id });
  const tokenUsage = runtime ? taskTokenUsage(runtime.task) : null;
  const source = formatOutputSource(task.output_source);
  const codePaths = task.code_paths ?? [];
  const status = effectiveThreatAuditTaskStatus(task, runtime ?? undefined);
  return (
    <div className="max-h-[72vh] space-y-4 overflow-y-auto p-4">
      <div className="border-b border-slate-800 pb-3">
        <div className="flex flex-wrap items-center gap-2">
          <StatusPill label={threatAuditStatusLabel(status)} tone={threatAuditStatusTone(status)} />
          <span className="text-sm font-semibold text-slate-100">{task.method_name || "未命名攻击模式"}</span>
        </div>
        <div className="mt-2 break-all font-mono text-[11px] text-slate-600">{task.task_id}</div>
      </div>
      <AuditDetailSection title="审计结果">
        <ThreatAuditResults
          result={result}
          status={status}
          loading={resultLoading}
          error={resultError}
          onRetry={onRetryResult}
          onOpenIssue={onOpenIssue}
        />
      </AuditDetailSection>
      <AuditDetailSection title="审计目标">
        <DetailGrid items={patternMode ? [
          ["高风险模块", task.surface_name || "—"],
          ["攻击模式", task.method_name || task.method_node_id || "—"],
        ] : [
          ["叶子节点", task.surface_name || task.surface_node_id || "—"],
          ["攻击模式", task.method_name || task.method_node_id || "—"],
          ["攻击目标", task.attack_goal || "—"],
          ["价值资产", task.asset_name || task.asset_id || "—"],
          ["风险", task.risk_name || task.risk_id || "—"],
          ["攻击路径", task.attack_path_id || "—"],
        ]} />
      </AuditDetailSection>
      {(task.description || task.code_path_description) && (
        <AuditDetailSection title="任务说明">
          <MarkdownContent content={task.description || task.code_path_description || ""} />
        </AuditDetailSection>
      )}
      {(task.code_path || codePaths.length > 0) && (
        <AuditDetailSection title="代码路径">
          <div className="space-y-2">
            {(codePaths.length > 0 ? codePaths : [{ path: task.code_path, description: task.code_path_description }]).map((item, index) => (
              <div key={`${item.path}-${index}`} className="rounded border border-slate-800 bg-slate-950/60 px-3 py-2">
                <div className="break-all font-mono text-xs text-cyan-300">{item.path}</div>
                {item.description && <div className="mt-1 text-xs text-slate-400">{item.description}</div>}
              </div>
            ))}
          </div>
        </AuditDetailSection>
      )}
      {task.failure_reason && (
        <AuditDetailSection title="失败原因">
          <div className="whitespace-pre-wrap break-words rounded border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300">
            {task.failure_reason}
          </div>
        </AuditDetailSection>
      )}
      <AuditDetailSection title="执行信息">
        <DetailGrid items={[
          ["模型", runtime?.modelId || task.output_source?.model || task.output_source?.model_id || "—"],
          ["OpenCode Session ID", sessionId || "尚无记录"],
          ["开始时间", task.started_at ? formatDateTime(task.started_at) : "—"],
          ["结束时间", task.finished_at ? formatDateTime(task.finished_at) : "—"],
          ["输出来源", source || "—"],
          ["结果索引", result?.findings.length
            ? result.findings.map((finding) => `#${finding.vuln_index}`).join("、")
            : task.result_vuln_indexes?.length
              ? task.result_vuln_indexes.map((value) => `#${value}`).join("、")
              : "未记录结果索引"],
        ]} />
      </AuditDetailSection>
      {tokenUsage && (
        <AuditDetailSection title="Token 用量">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            {[
              ["输入", tokenUsage.input_tokens],
              ["输出", tokenUsage.output_tokens],
              ["推理", tokenUsage.reasoning_tokens],
              ["缓存读", tokenUsage.cache_read_tokens],
              ["缓存写", tokenUsage.cache_write_tokens],
              ["总计", tokenUsage.total_tokens],
            ].map(([label, value]) => (
              <MiniMetric key={String(label)} label={String(label)} value={Number(value)} />
            ))}
          </div>
        </AuditDetailSection>
      )}
      <AuditPromptSection scan={scan} taskName={task.task_id} runtime={runtime} taskRevision={`${task.updated_at || ""}:${task.status}`} />
    </div>
  );
}
