import { canonicalMiningEngineLabel } from "../../../miningEngines";
import type { MiningEngineRunStatus, MiningEngineSelection } from "../../../types/mining";
import { formatDateTime } from "../../modelPool/presentation";
import { TaskPanel } from "../components/taskUi";
import { toneText } from "../model/formatting";
import { flowStatusLabel, flowStatusTone } from "../model/processFlow";
import { engineFlowStatus } from "../model/scan";
import type { TaskTone } from "../model/types";

export function GenericEnginePanel({
  engine,
  run,
  children,
}: {
  engine: MiningEngineSelection;
  run: MiningEngineRunStatus | null;
  children: React.ReactNode;
}) {
  const status = engineFlowStatus(run);
  const duration = engineRunDuration(run);
  return (
    <TaskPanel
      title={canonicalMiningEngineLabel(engine.engine_id, engine.engine_label)}
      status={flowStatusLabel(status)}
      tone={flowStatusTone(status, "green")}
      summary={`漏洞挖掘引擎 ${engine.engine_id} 的运行状态和输出结果。`}
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <EngineInfoCard label="引擎 ID" value={engine.engine_id} detail="扫描配置快照" tone="cyan" />
        <EngineInfoCard
          label="开始时间"
          value={run?.started_at ? formatDateTime(run.started_at) : "-"}
          detail={run?.started_at ? "引擎已启动" : "尚未启动"}
          tone="blue"
        />
        <EngineInfoCard
          label="运行耗时"
          value={duration || "-"}
          detail={run?.finished_at ? "已结束" : run?.started_at ? "执行中" : "等待运行"}
          tone="purple"
        />
      </div>
      {run?.error_message && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3">
          <div className="text-xs font-semibold text-red-200">引擎错误</div>
          <div className="mt-1 whitespace-pre-wrap break-words text-sm text-red-300">{run.error_message}</div>
        </div>
      )}
      <section>
        <h3 className="mb-3 text-sm font-semibold text-slate-200">该引擎输出的问题</h3>
        {children}
      </section>
    </TaskPanel>
  );
}

function EngineInfoCard({
  label,
  value,
  detail,
  tone,
}: {
  label: string;
  value: string;
  detail: string;
  tone: TaskTone;
}) {
  return (
    <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
      <div className="text-xs text-slate-500">{label}</div>
      <div className={`mt-1 break-all text-sm font-semibold ${toneText(tone)}`}>{value}</div>
      <div className="mt-1 text-xs text-slate-600">{detail}</div>
    </div>
  );
}

function engineRunDuration(run: MiningEngineRunStatus | null): string {
  if (!run?.started_at) return "";
  const started = Date.parse(run.started_at);
  const finished = Date.parse(run.finished_at || new Date().toISOString());
  if (Number.isNaN(started) || Number.isNaN(finished)) return "";
  const seconds = Math.max(0, Math.round((finished - started) / 1000));
  if (seconds < 60) return `${seconds} 秒`;
  const minutes = Math.floor(seconds / 60);
  const remaining = seconds % 60;
  return `${minutes} 分 ${remaining} 秒`;
}
