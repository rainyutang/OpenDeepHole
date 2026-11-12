import type { IndexStatus, ScanEvent } from "../../../types/scans";
import { EventList, MiniMetric, ProgressBlock } from "../components/taskUi";
import { formatIndexProgress } from "../model/scan";

export function CallGraphBuildPanel({
  indexStatus,
  indexProgress,
  events,
}: {
  indexStatus: IndexStatus | null;
  indexProgress: ReturnType<typeof formatIndexProgress>;
  events: ScanEvent[];
}) {
  const stats = indexProgress.stats;
  const files = stats?.files ?? indexProgress.total;
  const functions = stats?.functions ?? 0;
  const structs = stats?.structs ?? 0;
  const globals = stats?.global_variables ?? 0;
  const calls = stats?.function_calls ?? 0;
  const globalRefs = stats?.global_variable_references ?? 0;
  const statusText = indexProgress.failed
    ? (indexStatus?.error || "索引构建失败")
    : indexProgress.skipped
      ? "本次扫描未启用静态分析，无需构建代码索引"
      : indexProgress.done
        ? "索引已完成"
        : indexProgress.running
          ? "索引构建中"
          : "等待索引状态";

  return (
    <>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <MiniMetric label="文件数" value={files} tone="cyan" />
        <MiniMetric label="函数数量" value={functions} tone="blue" />
        <MiniMetric label="调用关系" value={calls} tone="purple" />
        <MiniMetric label="结构体/类/联合体" value={structs} />
        <MiniMetric label="全局变量" value={globals} />
        <MiniMetric label="全局变量引用" value={globalRefs} />
      </div>
      <ProgressBlock label="文件解析" current={indexProgress.current} total={indexProgress.total} fallback="等待索引文件进度" />
      {indexProgress.stage && (
        <ProgressBlock
          label={`索引阶段：${indexProgress.stage}`}
          current={indexProgress.stageCurrent}
          total={indexProgress.stageTotal}
          fallback="等待阶段进度"
        />
      )}
      <div className="rounded-lg border border-slate-700 bg-slate-900/40 px-4 py-3 text-sm text-slate-300">
        {statusText}
      </div>
      <EventList events={events} empty="暂无调用图构建日志" />
    </>
  );
}
