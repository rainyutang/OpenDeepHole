import type { ThreatAnalysisResultTab } from "../../threatAnalysis/analysisModel";
import { THREAT_ANALYSIS_RESULT_TABS } from "../../threatAnalysis/analysisModel";
import { toneBg, toneBorder } from "../model/formatting";
import type { FlowNodeView, ProcessFlowModel } from "../model/processFlow";
import { flowStatusLabel, flowStatusTone } from "../model/processFlow";
import type { FlowNodeId } from "../model/types";
import { StatusPill } from "./taskUi";

export function ProcessFlowNav({
  flow,
  onNodeClick,
  activeThreatResultTab,
  issuesActive,
}: {
  flow: ProcessFlowModel;
  onNodeClick: (node: FlowNodeId) => void;
  activeThreatResultTab: ThreatAnalysisResultTab;
  issuesActive: boolean;
}) {
  const {
    threatAnalysisNode,
    threatResultsReady,
    threatResultCounts,
    allMiningEntries,
    staticAnalysisNode,
    validationNode,
    fpReviewNode,
    indexNode,
    codeGraphMcpEnabled,
    knowledgeBaseEnabled,
  } = flow;
  return (
    <nav className="border-t border-slate-700/60 pt-3" aria-label="扫描执行流程">
      <div className="relative -mx-1">
        <div
          className="pointer-events-none absolute inset-y-1 left-0 z-10 w-8 bg-gradient-to-r from-slate-900/90 to-transparent xl:hidden"
          aria-hidden="true"
        />
        <div
          className="pointer-events-none absolute inset-y-1 right-0 z-10 w-8 bg-gradient-to-l from-slate-900/90 to-transparent xl:hidden"
          aria-hidden="true"
        />
        <div
          className="overflow-x-auto overscroll-x-contain rounded-xl border border-slate-700/50 bg-slate-900/35 px-2 py-3 shadow-inner scroll-smooth snap-x snap-proximity focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400/60 motion-reduce:scroll-auto sm:px-3"
          tabIndex={0}
          aria-label="执行流程图，可横向滚动"
        >
          <div className="mx-auto w-max px-3">
            <div className="grid grid-cols-[18rem_auto] items-stretch gap-3">
              <section
                className="flex min-h-[27rem] flex-col rounded-xl border border-emerald-500/25 bg-emerald-950/10 p-3"
                role="group"
                aria-label="威胁分析"
              >
                <h2 className="text-center text-sm font-semibold text-slate-100">威胁分析</h2>
                <FlowStatusSummary node={threatAnalysisNode} showDetail={!threatResultsReady} />
                <div className="mt-2 grid flex-1 grid-rows-4 gap-2">
                  {THREAT_ANALYSIS_RESULT_TABS.map((item) => (
                    <button
                      key={item.key}
                      type="button"
                      disabled={!threatResultsReady}
                      onClick={() => onNodeClick(`threat_result:${item.key}`)}
                      aria-current={threatAnalysisNode.active && activeThreatResultTab === item.key ? "page" : undefined}
                      className={`flex min-h-0 items-center justify-between gap-3 rounded-lg border px-3 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400/70 disabled:cursor-not-allowed disabled:opacity-45 ${threatAnalysisNode.active && activeThreatResultTab === item.key
                          ? "border-emerald-400/60 bg-emerald-400/15 text-emerald-100"
                          : "border-slate-700 bg-slate-950/45 text-slate-200 hover:border-emerald-400/35 hover:bg-emerald-500/10"
                        }`}
                    >
                      <span>{item.label}</span>
                      <span className="shrink-0 rounded border border-slate-600/70 bg-slate-900/70 px-2 py-0.5 text-xs tabular-nums text-slate-300">
                        {threatResultsReady ? `${threatResultCounts[item.key]} ${item.unit}` : "--"}
                      </span>
                    </button>
                  ))}
                </div>
              </section>

              <section
                role="group"
                aria-label="渗透执行"
                className="flex min-h-[27rem] flex-col rounded-xl border border-cyan-500/25 bg-cyan-950/10 p-3"
              >
                <h2 className="text-center text-sm font-semibold text-slate-100">渗透执行</h2>
                <div className="mt-2 grid flex-1 grid-cols-[10rem_23rem_11rem_11rem_6rem] items-stretch gap-2">
                  <ProcessStageButton
                    title="程序分析"
                    contentLabel="静态分析"
                    node={staticAnalysisNode}
                    onClick={onNodeClick}
                  />

                  <section className="flex min-h-0 flex-col rounded-lg border border-cyan-500/25 bg-slate-950/45 p-2.5" aria-label="多引擎问题识别">
                    <h3 className="text-center text-sm font-semibold text-slate-100">多引擎问题识别</h3>
                    <div className="mt-2 grid flex-1 content-start gap-2">
                      {allMiningEntries.map(({ engine, node, selected }) => (
                        <button
                          key={engine.engine_id}
                          type="button"
                          disabled={!selected}
                          onClick={() => onNodeClick(node.id)}
                          aria-current={node.active ? "page" : undefined}
                          className={`rounded-lg border px-2.5 py-2 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/70 disabled:cursor-not-allowed ${selected
                              ? node.active
                                ? "border-cyan-300/70 bg-cyan-400/20 shadow-sm"
                                : "border-cyan-400/35 bg-cyan-400/10 hover:border-cyan-300/60 hover:bg-cyan-400/15"
                              : "border-slate-800 bg-slate-950/60 opacity-45"
                            }`}
                        >
                          <div className="flex items-start justify-between gap-2">
                            <span className={`min-w-0 break-words text-xs font-medium ${selected ? "text-slate-100" : "text-slate-500"}`}>
                              {node.label}
                            </span>
                            <StatusPill
                              label={selected ? flowStatusLabel(node.status) : "未选择"}
                              tone={selected ? flowStatusTone(node.status, node.tone) : "slate"}
                            />
                          </div>
                          <div className="mt-1 line-clamp-2 text-[11px] leading-4 text-slate-500">{node.detail}</div>
                        </button>
                      ))}
                    </div>
                  </section>

                  <ProcessStageButton
                    title="问题复核"
                    contentLabel={fpReviewNode.label}
                    node={fpReviewNode}
                    onClick={onNodeClick}
                  />
                  <ProcessStageButton
                    title={validationNode.label}
                    node={validationNode}
                    onClick={onNodeClick}
                  />
                  <button
                    type="button"
                    onClick={() => onNodeClick("issues")}
                    aria-current={issuesActive ? "page" : undefined}
                    className={`flex h-full min-h-0 w-full items-center justify-center rounded-lg border px-2 text-center text-sm font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-400/70 ${issuesActive
                        ? "border-red-300/70 bg-red-400/20 text-red-100"
                        : "border-red-500/40 bg-red-500/10 text-red-200 hover:border-red-300/70 hover:bg-red-500/20"
                      }`}
                  >
                    疑似问题
                  </button>
                </div>
              </section>
            </div>

            <section
              className="mt-3 rounded-xl border border-blue-500/25 bg-blue-950/10 p-3"
              role="group"
              aria-label="基础能力"
            >
              <h2 className="text-center text-sm font-semibold text-slate-100">基础能力</h2>
              <div className="mt-2 grid grid-cols-2 gap-3">
                <CapabilityStatusCard
                  label="代码图谱"
                  enabled={codeGraphMcpEnabled}
                  node={indexNode}
                  onClick={onNodeClick}
                />
                <CapabilityStatusCard label="知识库" enabled={knowledgeBaseEnabled} />
              </div>
            </section>
          </div>
        </div>
      </div>
    </nav>
  );
}

function FlowStatusSummary({
  node,
  showDetail = true,
}: {
  node: FlowNodeView;
  showDetail?: boolean;
}) {
  return (
    <div className="mt-2 rounded-lg border border-slate-700 bg-slate-950/45 px-3 py-2.5" role="status">
      <div className="flex items-start justify-between gap-2">
        <span className="min-w-0 break-words text-sm font-medium text-slate-100">{node.label}</span>
        <StatusPill label={flowStatusLabel(node.status)} tone={flowStatusTone(node.status, node.tone)} />
      </div>
      {showDetail && node.detail && (
        <div className="mt-1 line-clamp-2 text-xs leading-5 text-slate-400">{node.detail}</div>
      )}
    </div>
  );
}

function ProcessStageButton({
  title,
  contentLabel,
  node,
  onClick,
}: {
  title: string;
  contentLabel?: string;
  node: FlowNodeView;
  onClick: (node: FlowNodeId) => void;
}) {
  return (
    <button
      type="button"
      onClick={() => onClick(node.id)}
      aria-current={node.active ? "page" : undefined}
      className={`flex h-full min-h-0 flex-col rounded-lg border p-3 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400/70 ${node.active
          ? `${toneBorder(node.tone)} ${toneBg(node.tone)}`
          : "border-slate-700 bg-slate-950/45 hover:border-slate-500 hover:bg-slate-900/80"
        }`}
    >
      <h3 className="text-center text-sm font-semibold text-slate-100">{title}</h3>
      <div className="mt-4 flex flex-1 flex-col justify-center">
        {contentLabel && <div className="mb-2 text-xs font-medium text-slate-300">{contentLabel}</div>}
        <div><StatusPill label={flowStatusLabel(node.status)} tone={flowStatusTone(node.status, node.tone)} /></div>
        <div className="mt-2 line-clamp-3 text-xs leading-5 text-slate-400">{node.detail}</div>
      </div>
    </button>
  );
}

function CapabilityStatusCard({
  label,
  enabled,
  node,
  onClick,
}: {
  label: string;
  enabled: boolean;
  node?: FlowNodeView;
  onClick?: (node: FlowNodeId) => void;
}) {
  const content = (
    <>
      <div className="flex items-start justify-between gap-3">
        <span className="text-sm font-semibold text-slate-100">{label}</span>
        <StatusPill label={enabled ? "已启用" : "未启用"} tone={enabled ? "green" : "slate"} />
      </div>
    </>
  );
  const className = `min-h-[5.5rem] rounded-lg border p-3 text-left ${enabled ? "border-blue-400/35 bg-blue-400/10" : "border-slate-700 bg-slate-950/45"
    }`;
  if (node && onClick) {
    return (
      <button
        type="button"
        onClick={() => onClick(node.id)}
        aria-current={node.active ? "page" : undefined}
        className={`${className} transition-colors hover:border-blue-300/60 hover:bg-blue-400/15 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400/70`}
      >
        {content}
      </button>
    );
  }
  return <div className={className}>{content}</div>;
}
