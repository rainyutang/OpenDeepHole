import type { OpenCodePoolStatus } from "../../types/modelPool";
import { formatDateTime, formatDuration, scanQueueTaskTypeLabel } from "./presentation";

export function ModelPoolDashboard({ pool }: { pool: OpenCodePoolStatus | null; }) {
  const models = pool?.models ?? [];
  const plannedTasks = pool?.planned_tasks ?? [];
  const queuedTasks = pool?.queued_tasks ?? [];
  const completedTasks = pool?.completed_tasks ?? [];
  const failedTasks = completedTasks.filter((task) => {
    const outcome = String(task.outcome || "unknown");
    return outcome !== "success";
  });
  const recentFailedTasks = failedTasks.slice(-10).reverse();
  const unassignedCompletedTasks = completedTasks.filter(
    (task) => !String(task.model_id || task.model || "").trim(),
  );
  const hasEnabledModel = models.length === 0 || models.some((model) => model.enabled);
  const total = models.reduce((sum, item) => sum + item.total, 0) + unassignedCompletedTasks.length;
  const success = models.reduce((sum, item) => sum + item.success, 0)
    + unassignedCompletedTasks.filter((task) => task.outcome === "success").length;
  const failure = models.reduce((sum, item) => sum + item.failure, 0)
    + unassignedCompletedTasks.filter((task) => task.outcome === "failure").length;
  const timeout = models.reduce((sum, item) => sum + item.timeout, 0)
    + unassignedCompletedTasks.filter((task) => task.outcome === "timeout").length;
  const cancelled = models.reduce((sum, item) => sum + item.cancelled, 0)
    + unassignedCompletedTasks.filter((task) => task.outcome === "cancelled").length;

  if (!pool) {
    return (
      <div className="flex-1 overflow-y-auto p-5">
        <div className="rounded-lg border border-slate-800 bg-slate-950 px-4 py-5 text-sm text-slate-500">
          当前扫描尚未收到 OpenCode 模型池状态。
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-y-auto p-5 space-y-4">
      <p className="text-xs text-slate-500">按本扫描累计，含续扫及重试；运行中、排队中和计划中为当前状态。</p>
      {!hasEnabledModel && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm leading-6 text-amber-200">
          当前没有启用的模型，新的 OpenCode 任务会保持阻塞排队，直到启用满足能力要求的模型或用户取消。
        </div>
      )}
      <div className="grid grid-cols-2 md:grid-cols-7 gap-3">
        <MetricBox label="计划中" value={plannedTasks.length} tone="amber" />
        <MetricBox label="运行中" value={pool.global_running} tone="cyan" />
        <MetricBox label="排队中" value={pool.global_queued} tone="amber" />
        <MetricBox label="累计任务" value={total} />
        <MetricBox label="成功" value={success} tone="green" />
        <MetricBox label="失败" value={failure} tone="red" />
        <MetricBox label="超时/取消" value={timeout + cancelled} tone="amber" />
      </div>

      {plannedTasks.length > 0 && (
        <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
          <div className="mb-2 text-xs font-semibold text-slate-400">计划中任务</div>
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
            {plannedTasks.map((task, index) => (
              <div
                key={String(task.planned_task_id || index)}
                className="truncate rounded border border-slate-500/20 bg-slate-800/70 px-2 py-1.5 text-xs text-slate-200"
                title={modelTaskLabel(task)}
              >
                {modelTaskLabel(task)}
              </div>
            ))}
          </div>
        </div>
      )}

      {queuedTasks.length > 0 && (
        <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
          <div className="mb-2 text-xs font-semibold text-slate-400">全局排队任务</div>
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
            {queuedTasks.map((task, index) => (
              <div
                key={String(task.request_id || index)}
                className="truncate rounded border border-amber-500/20 bg-amber-500/10 px-2 py-1.5 text-xs text-amber-100"
                title={modelTaskLabel(task)}
              >
                {modelTaskLabel(task)}
              </div>
            ))}
          </div>
        </div>
      )}

      {failedTasks.length > 0 && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3">
          <div className="mb-2 text-xs font-semibold text-red-200">
            任务失败 {failedTasks.length} 个{failedTasks.length > recentFailedTasks.length ? `（显示最近 ${recentFailedTasks.length} 个）` : ""}
          </div>
          <div className="space-y-2">
            {recentFailedTasks.map((task, index) => {
              const reason = typeof task.failure_reason === "string" && task.failure_reason.trim()
                ? task.failure_reason.trim()
                : "未记录失败原因";
              return (
                <div key={String(task.task_id || index)} className="rounded border border-red-500/20 bg-slate-950/50 px-3 py-2">
                  <div className="text-xs font-medium text-red-100">{modelTaskLabel(task)}</div>
                  <div className="mt-1 whitespace-pre-wrap break-words text-xs leading-relaxed text-red-300">{reason}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {models.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full min-w-[64rem] text-sm">
            <thead className="bg-slate-950">
              <tr>
                <th className={thCls}>模型</th>
                <th className={thCls}>能力</th>
                <th className={thCls}>可用</th>
                <th className={thCls}>配置/有效权重</th>
                <th className={thCls}>运行/上限</th>
                <th className={thCls}>累计</th>
                <th className={thCls}>成功</th>
                <th className={thCls}>失败</th>
                <th className={thCls}>超时</th>
                <th className={thCls}>取消</th>
                <th className={thCls}>平均耗时</th>
                <th className={thCls}>当前任务</th>
                <th className={thCls}>最近状态</th>
              </tr>
            </thead>
            <tbody>
              {models.map((model) => (
                <tr key={model.id} className="border-t border-slate-800/70">
                  <td className={tdCls}>
                    <div className="font-semibold text-slate-100">{model.id}</div>
                    <div className="mt-1 max-w-48 truncate font-mono text-[11px] text-slate-500">
                      {model.use_default_model ? "(CLI 默认模型)" : (model.model || "(模型名为空)")}
                    </div>
                  </td>
                  <td className={tdCls}>{capabilityLabel(model.capability)}</td>
                  <td className={tdCls}>
                    <span className={model.enabled && model.available ? "text-green-300" : "text-slate-500"}>
                      {model.enabled ? (model.available ? "可用" : "时间窗外") : "禁用"}
                    </span>
                  </td>
                  <td className={tdCls}>
                    <div className="font-mono">
                      {model.weight} / {model.effective_weight ?? model.weight}
                    </div>
                    <div className={`mt-1 text-[11px] ${!model.enabled ? "text-slate-500" : (model.health_penalty_level ?? 0) > 0 ? "text-amber-300" : "text-green-400"}`}>
                      {!model.enabled
                        ? "无当前健康状态"
                        : (model.health_penalty_level ?? 0) > 0
                          ? `健康降级 ${model.health_penalty_level} 级`
                          : "健康正常"}
                    </div>
                    {model.enabled && model.last_health_failure_at && (
                      <div
                        className="mt-1 text-[11px] text-slate-600"
                        title={formatDateTime(model.last_health_failure_at)}
                      >
                        最近失败：{model.last_health_failure_kind === "timeout" ? "超时" : "请求失败"}
                      </div>
                    )}
                  </td>
                  <td className={tdCls}>{model.running}/{model.max_concurrency}</td>
                  <td className={tdCls}>{model.total}</td>
                  <td className={`${tdCls} text-green-300`}>{model.success}</td>
                  <td className={`${tdCls} text-red-300`}>{model.failure}</td>
                  <td className={`${tdCls} text-amber-300`}>{model.timeout}</td>
                  <td className={`${tdCls} text-slate-300`}>{model.cancelled}</td>
                  <td className={tdCls}>{formatDuration(model.avg_duration_seconds)}</td>
                  <td className={`${tdCls} max-w-72 text-slate-400`}>
                    <ModelTaskList tasks={model.active_tasks} />
                  </td>
                  <td className={tdCls}>
                    <div className={statusClass(model.last_status)}>
                      {statusLabel(model.last_status)}
                    </div>
                    <div className="mt-1 text-[11px] text-slate-600">
                      {formatDateTime(model.last_finished_at || model.last_started_at)}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export const thCls = "px-3 py-2 text-left text-xs font-semibold text-slate-400";

const tdCls = "px-3 py-3 text-slate-300 align-top";

function MetricBox({
  label,
  value,
  tone = "slate",
}: {
  label: string;
  value: number;
  tone?: "slate" | "cyan" | "amber" | "green" | "red";
}) {
  const color = {
    slate: "text-slate-100",
    cyan: "text-cyan-300",
    amber: "text-amber-300",
    green: "text-green-300",
    red: "text-red-300",
  }[tone];
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-3">
      <div className="text-xs text-slate-500">{label}</div>
      <div className={`mt-1 text-xl font-semibold ${color}`}>{value}</div>
    </div>
  );
}

function capabilityLabel(value: string): string {
  if (value === "high") return "高";
  if (value === "medium") return "中";
  if (value === "low") return "低";
  return value || "-";
}

export function vulnerabilitySeverityLabel(value: string): string {
  if (value === "critical") return "致命";
  if (value === "high") return "严重";
  if (value === "medium") return "一般";
  if (value === "low") return "提示";
  return value || "未知严重性";
}

function statusLabel(value: string): string {
  if (value === "queued") return "排队";
  if (value === "running") return "运行中";
  if (value === "success") return "成功";
  if (value === "failure") return "失败";
  if (value === "timeout") return "超时";
  if (value === "cancelled") return "取消";
  return value || "-";
}

function statusClass(value: string): string {
  const base = "inline-flex rounded border px-2 py-0.5 text-xs";
  if (value === "running") return `${base} border-cyan-500/30 bg-cyan-500/10 text-cyan-300`;
  if (value === "success") return `${base} border-green-500/30 bg-green-500/10 text-green-300`;
  if (value === "failure") return `${base} border-red-500/30 bg-red-500/10 text-red-300`;
  if (value === "timeout" || value === "queued") return `${base} border-amber-500/30 bg-amber-500/10 text-amber-300`;
  return `${base} border-slate-700 bg-slate-800 text-slate-400`;
}

function modelTaskLabel(task: Record<string, unknown> | undefined): string {
  if (!task) return "-";
  const taskType = scanQueueTaskTypeLabel(task);
  const stage = task.stage ? `/${String(task.stage)}` : "";
  const checker = task.checker ? String(task.checker) : "";
  const file = task.file ? String(task.file) : "";
  const line = task.line ? `:${String(task.line)}` : "";
  const target = file ? `${file}${line}` : checker;
  const session = task.serve_session_id ? String(task.serve_session_id) : "";
  const revision = Number(task.revision || 1) > 1 ? `r${String(task.revision)}` : "";
  const blocked = task.blocked_reason ? "阻塞" : "";
  return [revision, taskType + stage, target, session, blocked].filter(Boolean).join(" ");
}

function ModelTaskList({ tasks }: { tasks?: Record<string, unknown>[]; }) {
  const activeTasks = tasks || [];
  if (activeTasks.length === 0) return <>-</>;
  return (
    <div className="space-y-1">
      {activeTasks.map((task, index) => (
        <div key={String(task.task_id || index)} className="truncate">
          {modelTaskLabel(task)}
        </div>
      ))}
    </div>
  );
}
