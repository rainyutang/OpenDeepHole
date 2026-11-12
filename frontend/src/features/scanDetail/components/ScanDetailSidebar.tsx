import { toneBg, toneBorder, toneText } from "../model/formatting";
import type { ProcessFlowModel } from "../model/processFlow";
import { flowStatusLabel, sidebarStatusDotClass } from "../model/processFlow";
import type { FlowNodeId, FlowNodeStatus, MainTab, TaskTone } from "../model/types";

type ScanSidebarTool = "info" | "feedback" | "skill" | "models" | "reports" | "logs";

export function ScanBrandButton({ onClick }: { onClick: () => void; }) {
  return <button type="button" onClick={onClick} aria-label="DeepHole 2.0，返回扫描列表"
    className="shrink-0 rounded-md text-lg font-bold text-white transition-colors hover:text-blue-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400/70">
    DeepHole 2.0
  </button>;
}

interface ScanDetailSidebarProps {
  mobileOpen: boolean;
  onScanList: () => void;
  flow: ProcessFlowModel;
  activeTab: MainTab;
  issueCount: number;
  confirmedIssueCount: number;
  feedbackCount: number;
  modelRunningCount: number;
  hasReportModeSkill: boolean;
  reportCount: number;
  unseenLogCount: number;
  openTool: ScanSidebarTool | null;
  onClose: () => void;
  onHome: () => void;
  onIssues: () => void;
  onNodeClick: (node: FlowNodeId) => void;
  onOpenScanInfo: () => void;
  onReviewNotes?: () => void;
  onOpenFeedback?: () => void;
  onOpenSkill: () => void;
  onOpenModels: () => void;
  onOpenReports: () => void;
  onOpenLogs: () => void;
}

export function ScanDetailSidebar(props: ScanDetailSidebarProps) {
  const { mobileOpen, ...contentProps } = props;
  return (
    <>
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 border-r border-slate-700/80 bg-slate-950/80 backdrop-blur lg:block">
        <ScanSidebarContent {...contentProps} showClose={false} />
      </aside>
      {mobileOpen && (
        <div className="fixed inset-0 z-[60] lg:hidden">
          <button
            type="button"
            className="absolute inset-0 bg-black/55"
            aria-label="关闭扫描导航"
            onClick={props.onClose}
          />
          <aside
            role="dialog"
            aria-modal="true"
            aria-label="扫描导航"
            className="relative h-full w-72 max-w-[85vw] border-r border-slate-700 bg-slate-950 shadow-2xl"
          >
            <ScanSidebarContent {...contentProps} showClose />
          </aside>
        </div>
      )}
    </>
  );
}

function ScanSidebarContent({
  onScanList,
  flow,
  activeTab,
  issueCount,
  confirmedIssueCount,
  feedbackCount,
  modelRunningCount,
  hasReportModeSkill,
  reportCount,
  unseenLogCount,
  openTool,
  onClose,
  onHome,
  onIssues,
  onNodeClick,
  onOpenScanInfo,
  onReviewNotes,
  onOpenFeedback,
  onOpenSkill,
  onOpenModels,
  onOpenReports,
  onOpenLogs,
  showClose,
}: Omit<ScanDetailSidebarProps, "mobileOpen"> & { showClose: boolean; }) {
  const select = (action: () => void) => {
    action();
    onClose();
  };
  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between gap-3 border-b border-slate-800 px-4 py-4">
        <ScanBrandButton onClick={onScanList} />
        {showClose && (
          <button
            type="button"
            autoFocus
            onClick={onClose}
            aria-label="关闭扫描导航"
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-slate-400 transition-colors hover:bg-slate-800 hover:text-slate-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400/70"
          >
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18 18 6M6 6l12 12" />
            </svg>
          </button>
        )}
      </div>

      <nav className="min-h-0 flex-1 space-y-5 overflow-y-auto px-3 py-4" aria-label="扫描详情导航">
        <SidebarSection title="扫描概览">
          <SidebarNavigationButton
            label="首页"
            detail="扫描概览与任务队列"
            current={activeTab === "overview"}
            onClick={() => select(onHome)}
          />
          <SidebarNavigationButton
            label="疑似问题"
            detail={`问题总数：${issueCount}，确认问题：${confirmedIssueCount}`}
            current={activeTab === "issues"}
            tone="red"
            badge={issueCount}
            onClick={() => select(onIssues)}
          />
        </SidebarSection>

        <SidebarSection title="执行流程">
          <SidebarNavigationButton
            label="威胁分析"
            detail={flow.threatAnalysisNode.detail === "等待生成攻击树" ? undefined : flow.threatAnalysisNode.detail}
            current={flow.threatAnalysisNode.active}
            status={flow.threatAnalysisNode.status}
            tone={flow.threatAnalysisNode.tone}
            onClick={() => select(() => onNodeClick(flow.threatAnalysisNode.id))}
          />

          <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-2">
            <div className="mb-2 px-1 text-xs font-semibold text-cyan-100">程序分析</div>
            <SidebarNavigationButton
              label={flow.staticAnalysisNode.label}
              detail={flow.staticAnalysisNode.detail}
              current={flow.staticAnalysisNode.active}
              status={flow.staticAnalysisNode.status}
              tone={flow.staticAnalysisNode.tone}
              compact
              onClick={() => select(() => onNodeClick(flow.staticAnalysisNode.id))}
            />
          </div>

          <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-2">
            <div className="mb-2 flex items-center justify-between gap-2 px-1 text-xs font-semibold text-cyan-100">
              <span>多引擎问题识别</span>
              <span className="text-[10px] font-medium text-cyan-300/80">{flow.miningEntries.length} 个引擎</span>
            </div>
            {flow.miningEntries.length > 0 ? (
              <div className="space-y-2">
                {flow.miningEntries.map(({ engine, node }) => (
                  <SidebarNavigationButton
                    key={engine.engine_id}
                    label={node.label}
                    detail={node.detail}
                    current={node.active}
                    status={node.status}
                    tone={node.tone}
                    compact
                    onClick={() => select(() => onNodeClick(node.id))}
                  />
                ))}
              </div>
            ) : (
              <div className="rounded-lg border border-dashed border-slate-700 px-2 py-3 text-center text-xs text-slate-500">
                本次扫描未选择漏洞挖掘引擎
              </div>
            )}
          </div>

          <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-2">
            <div className="mb-2 px-1 text-xs font-semibold text-amber-100">问题复核</div>
            <SidebarNavigationButton
              label={flow.fpReviewNode.label}
              detail={flow.fpReviewNode.detail}
              current={flow.fpReviewNode.active}
              status={flow.fpReviewNode.status}
              tone={flow.fpReviewNode.tone}
              compact
              onClick={() => select(() => onNodeClick(flow.fpReviewNode.id))}
            />
          </div>

          <SidebarNavigationButton
            label={flow.validationNode.label}
            detail={flow.validationNode.detail}
            current={flow.validationNode.active}
            status={flow.validationNode.status}
            tone={flow.validationNode.tone}
            onClick={() => select(() => onNodeClick(flow.validationNode.id))}
          />
        </SidebarSection>

        <SidebarSection title="其它信息">
          {onReviewNotes && <SidebarNavigationButton
            label="问题判定依据"
            detail="管理本次扫描参考的判断条件"
            current={activeTab === "review_notes"}
            onClick={() => select(onReviewNotes)}
          />}
          <SidebarNavigationButton
            label="扫描信息"
            detail="查看创建扫描时的范围与流程配置"
            expanded={openTool === "info"}
            tone="cyan"
            onClick={() => select(onOpenScanInfo)}
          />
          <SidebarNavigationButton
            label="SKILL 预览"
            detail="查看本次扫描使用的 SKILL"
            expanded={openTool === "skill"}
            onClick={() => select(onOpenSkill)}
          />
          <SidebarNavigationButton
            label="模型看板"
            detail="查看 OpenCode 模型池与任务状态"
            expanded={openTool === "models"}
            tone="cyan"
            badge={modelRunningCount}
            onClick={() => select(onOpenModels)}
          />
          {onOpenFeedback && <SidebarNavigationButton
            label="误报屏蔽规则"
            detail="管理本次扫描使用的反馈规则"
            expanded={openTool === "feedback"}
            badge={feedbackCount}
            onClick={() => select(onOpenFeedback)}
          />}
          {hasReportModeSkill && (
            <SidebarNavigationButton
              label="SKILL 报告"
              detail="查看报告型 SKILL 的 Markdown 输出"
              expanded={openTool === "reports"}
              tone="purple"
              badge={reportCount}
              onClick={() => select(onOpenReports)}
            />
          )}
          <SidebarNavigationButton
            label="日志"
            detail="查看扫描过程事件"
            expanded={openTool === "logs"}
            badge={unseenLogCount}
            onClick={() => select(onOpenLogs)}
          />
        </SidebarSection>
      </nav>
    </div>
  );
}

function SidebarSection({ title, children }: { title: string; children: React.ReactNode; }) {
  return (
    <section>
      <h2 className="mb-2 px-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">{title}</h2>
      <div className="space-y-1.5">{children}</div>
    </section>
  );
}

function SidebarNavigationButton({
  label,
  detail,
  current = false,
  expanded = false,
  status,
  tone = "blue",
  badge = 0,
  compact = false,
  onClick,
}: {
  label: string;
  detail?: string;
  current?: boolean;
  expanded?: boolean;
  status?: FlowNodeStatus;
  tone?: TaskTone;
  badge?: number;
  compact?: boolean;
  onClick: () => void;
}) {
  const active = current || expanded;
  return (
    <div>
      <button
        type="button"
        onClick={onClick}
        aria-current={current ? "page" : undefined}
        aria-expanded={expanded || undefined}
        title={detail ? `${label} · ${detail}` : label}
        className={`w-full rounded-lg border text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400/70 motion-reduce:transition-none ${compact ? "px-2.5 py-2" : "px-3 py-2.5"} ${active
            ? `${toneBorder(tone)} ${toneBg(tone)}`
            : "border-transparent bg-slate-900/35 hover:border-slate-700 hover:bg-slate-800/80"
          }`}
      >
        <span className="flex items-start justify-between gap-2">
          <span className={`min-w-0 break-words text-sm font-medium ${active ? toneText(tone) : "text-slate-200"}`}>
            {label}
          </span>
          {status ? (
            <span className="mt-0.5 inline-flex shrink-0 items-center gap-1 text-[10px] text-slate-400">
              <span className={`h-1.5 w-1.5 rounded-full ${sidebarStatusDotClass(status)}`} aria-hidden="true" />
              {flowStatusLabel(status)}
            </span>
          ) : badge > 0 ? (
            <span className={`shrink-0 rounded-full px-1.5 py-0.5 text-[10px] font-semibold ${active ? `${toneBg(tone)} ${toneText(tone)}` : "bg-slate-700 text-slate-200"}`}>
              {badge > 99 ? "99+" : badge}
            </span>
          ) : null}
        </span>
        {detail && (
          <span className={`mt-1 block text-xs leading-4 text-slate-500 ${compact ? "line-clamp-1" : "line-clamp-2"}`}>
            {detail}
          </span>
        )}
      </button>
    </div>
  );
}
