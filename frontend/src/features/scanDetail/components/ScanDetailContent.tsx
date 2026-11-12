import { isPublicScan } from "../../../api/accessPolicy";
import type { ListFocusRequest } from "../../../auditNavigation";
import { ReviewNotesManager } from "../../../components/ReviewNotes";
import RuntimeErrorBoundary from "../../../components/RuntimeErrorBoundary";
import StaticAnalysisFailures from "../../../components/StaticAnalysisFailures";
import VulnerabilityList from "../../issues/VulnerabilityList";
import {
  isPatternAuditEngine,
  STATIC_CANDIDATE_ENGINE_ID as STATIC_ENGINE_ID,
  THREAT_AUDIT_ENGINE_ID as THREAT_ENGINE_ID,
} from "../../../miningEngines";
import type { FpReviewMethodSelection, FpReviewStageConfig } from "../../../types/fpReview";
import type { IndexedVulnerability } from "../../../types/issues";
import type { MiningEngineSelection } from "../../../types/mining";
import type { ScanEvent, ScanStatus as ScanStatusType } from "../../../types/scans";
import { isThreatAnalysisResultReady } from "../../threatAnalysis/analysisModel";
import { ThreatAnalysisPanel } from "../../threatAnalysis/ThreatAnalysisPanel";
import { CoverageViewport, ThreatCoverageView } from "../../threatAnalysis/ThreatCoveragePanel";
import { useCoverageIssues, useThreatCoverage } from "../../threatAnalysis/useThreatCoverage";
import type { useDetailPagination } from "../hooks/useDetailPagination";
import type { DetailResources } from "../hooks/useDetailResources";
import type { useScanActions } from "../hooks/useScanActions";
import type { useScanArtifacts } from "../hooks/useScanArtifacts";
import type { useScanEvents } from "../hooks/useScanEvents";
import { useScanNavigation } from "../hooks/useScanNavigation";
import type { ScanSnapshotState } from "../hooks/useScanSnapshotState";
import { detailCursor } from "../model/detailPages";
import {
  currentStageLabel,
  filterEvents,
  formatIndexProgress,
  fpReviewMethodLabel,
  isThreatAnalysisSelected,
  miningEngineRun,
  taskStateLabel,
  threatAnalysisMethodLabel,
} from "../model/scan";
import type { DetailResource } from "../model/types";
import { AuditTaskPanel } from "../panels/AuditTaskPanel";
import { CallGraphBuildPanel } from "../panels/CallGraphBuildPanel";
import { GenericEnginePanel } from "../panels/EnginePanels";
import { FpReviewPanel } from "../panels/FpReviewPanel";
import { ScanOverview } from "../panels/ScanOverview";
import { StaticTaskPanel } from "../panels/StaticTaskPanel";
import { ThreatAuditPanel } from "../panels/ThreatAuditPanel";
import { ValidationPanel } from "../panels/ValidationPanel";
import { TaskPanel } from "./taskUi";

interface Props {
  scanId: string;
  scan: ScanStatusType;
  sharedView: boolean;
  issuesView: React.ReactNode;
  snapshot: Pick<ScanSnapshotState, "gitHistory" | "isRunning" | "isDone" | "fpReview" | "indexStatus" | "threatResultRevision" | "coverageRevision" | "patternTaskRevision" | "launchingValidations" | "stoppingValidations" | "fpReviewHydrated">;
  navigation: Pick<ReturnType<typeof useScanNavigation>, "activeTab" | "activeEngineId" | "auditNavigation" | "setActiveTab" | "threatAnalysisResultTab" | "setThreatAnalysisResultTab">;
  resources: Pick<DetailResources, "detailFailedResources" | "loadDetailResource" | "detailLoadingResources">;
  pagination: Pick<ReturnType<typeof useDetailPagination>, "fpReviewPageFailed" | "setFpReviewPageRetry" | "fpReviewPageLoading">;
  events: Pick<ReturnType<typeof useScanEvents>, "overviewFailed" | "refreshOverview" | "refreshFailures" | "refreshDetails">;
  actions: Pick<ReturnType<typeof useScanActions>, "handleTriggerValidation" | "handleStopValidation" | "fpReviewLoading" | "fpReviewStopping" | "handleFpReview" | "handleStopFpReview">;
  artifacts: Pick<ReturnType<typeof useScanArtifacts>, "addSelectedFeedbackIds" | "removeSelectedFeedbackIds">;
  presentation: {
    threatAnalysisFailed: boolean;
    threatAnalysisLoading: boolean;
    refreshThreatAnalysis: (force?: boolean) => void;
    activeDetailLoading: boolean;
    activeDetailFailed: boolean;
    showsFpResults: boolean;
    automaticListResources: DetailResource[];
    manualDetailResources: DetailResource[];
    issueCount: number;
    continuableCount: number;
    variantIssueCount: number;
    showGitHistoryStages: boolean;
    pct: number;
    isFpReviewing: boolean;
    currentFpReviewTargets: IndexedVulnerability[];
    confirmedIssueCount: number;
    activateCoverage: () => void;
    coverageState: ReturnType<typeof useThreatCoverage>;
    coverageIssues: ReturnType<typeof useCoverageIssues>;
    indexProgress: ReturnType<typeof formatIndexProgress>;
    threatAnalysisEvents: ScanEvent[];
    activeEngine: MiningEngineSelection | null;
    miningEvents: ScanEvent[];
    threatAuditEvents: ScanEvent[];
    currentFpReviewIndices: Set<number>;
    selectedEngines: MiningEngineSelection[];
    validationEvents: ScanEvent[];
    selectedFpReviewMethod: string;
    selectedFpReviewSelection: FpReviewMethodSelection | null;
    selectedFpReviewStages: FpReviewStageConfig[];
  };
}

export function ScanDetailContent({
  scanId,
  scan,
  sharedView,
  issuesView,
  snapshot,
  navigation,
  resources,
  pagination,
  events,
  actions,
  artifacts,
  presentation,
}: Props) {
  const {
    gitHistory,
    isRunning,
    isDone,
    fpReview,
    indexStatus,
    threatResultRevision,
    coverageRevision,
    patternTaskRevision,
    launchingValidations,
    stoppingValidations,
    fpReviewHydrated,
  } = snapshot;
  const { activeTab, activeEngineId, auditNavigation, setActiveTab, threatAnalysisResultTab, setThreatAnalysisResultTab } = navigation;
  const { detailFailedResources, loadDetailResource, detailLoadingResources } = resources;
  const { fpReviewPageFailed, setFpReviewPageRetry, fpReviewPageLoading } = pagination;
  const { overviewFailed, refreshOverview, refreshFailures, refreshDetails } = events;
  const { handleTriggerValidation, handleStopValidation, fpReviewLoading, fpReviewStopping, handleFpReview, handleStopFpReview } = actions;
  const { addSelectedFeedbackIds, removeSelectedFeedbackIds } = artifacts;
  const {
    threatAnalysisFailed,
    threatAnalysisLoading,
    refreshThreatAnalysis,
    activeDetailLoading,
    activeDetailFailed,
    showsFpResults,
    automaticListResources,
    manualDetailResources,
    issueCount,
    continuableCount,
    variantIssueCount,
    showGitHistoryStages,
    pct,
    isFpReviewing,
    currentFpReviewTargets,
    confirmedIssueCount,
    activateCoverage,
    coverageState,
    coverageIssues,
    indexProgress,
    threatAnalysisEvents,
    activeEngine,
    miningEvents,
    threatAuditEvents,
    currentFpReviewIndices,
    selectedEngines,
    validationEvents,
    selectedFpReviewMethod,
    selectedFpReviewSelection,
    selectedFpReviewStages,
  } = presentation;

  return (
    <div className="flex-1 overflow-auto px-4 py-4 sm:px-6">
      <RuntimeErrorBoundary
        name={`scan-panel:${activeTab}`}
        resetKey={[
          scanId,
          activeTab,
          activeEngineId,
          scan.status,
          scan.progress,
          scan.vulnerabilities.length,
          scan.validations?.length ?? 0,
          scan.events.length,
          scan.events[scan.events.length - 1]?.timestamp ?? "",
          scan.opencode_pool?.updated_at ?? "",
        ].join(":")}
      >
        <>
          <StaticAnalysisFailures scan={scan} />
          {overviewFailed && <div role="alert" className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">
            扫描状态更新失败，已保留当前内容。
            <button type="button" className="ml-3 underline" onClick={refreshOverview}>重试更新扫描状态</button>
          </div>}
          {threatAnalysisFailed && <div role="alert" className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">
            威胁分析结果获取失败，已保留当前内容。
            <button type="button" disabled={threatAnalysisLoading} className="ml-3 underline disabled:opacity-50" onClick={() => refreshThreatAnalysis(true)}>{threatAnalysisLoading ? "正在重试…" : "重试获取威胁分析结果"}</button>
          </div>}
          {refreshFailures.size > 0 && (
            <div role="status" className="fixed bottom-4 right-4 z-30 rounded-lg border border-amber-500/30 bg-slate-900 px-4 py-3 text-sm text-amber-100 shadow-lg">
              详情更新失败，已保留当前内容。
              <button type="button" className="ml-3 underline" onClick={() => refreshDetails([...refreshFailures])}>重试刷新详情</button>
            </div>
          )}
          {(auditNavigation.loading || auditNavigation.error) && (
            <div role={auditNavigation.error ? "alert" : "status"} className="mb-4 rounded-lg border border-blue-500/30 bg-blue-500/10 px-4 py-3 text-sm text-slate-200">
              {auditNavigation.loading ? "正在定位目标记录…" : auditNavigation.error}
              {auditNavigation.error && <button type="button" onClick={auditNavigation.retry} className="ml-3 text-blue-300 underline">重试</button>}
              <button type="button" onClick={auditNavigation.cancel} className="ml-3 text-slate-400 underline">{auditNavigation.loading ? "取消" : "关闭"}</button>
            </div>
          )}
          {(activeDetailLoading || activeDetailFailed) && (
            <div
              role="status"
              className={`mb-4 rounded-lg border px-4 py-3 text-sm ${activeDetailFailed
                  ? "border-amber-500/30 bg-amber-500/10 text-amber-100"
                  : "border-blue-500/30 bg-blue-500/10 text-blue-100"
                }`}
            >
              {activeDetailFailed
                ? "部分详情加载失败，可点击下方按钮重试。"
                : activeTab === "issues" ? "正在加载全部问题…"
                  : activeTab === "fp_review" ? "正在加载全部复核记录…" : "正在加载下一页详情…"}
              {showsFpResults && activeDetailFailed && (
                <button type="button" className="ml-3 text-blue-300 underline" onClick={() => {
                  for (const resource of automaticListResources) {
                    if (detailFailedResources.has(resource)) void loadDetailResource(resource);
                  }
                  if (fpReviewPageFailed) setFpReviewPageRetry((value) => value + 1);
                }}>{activeTab === "fp_review" ? "重试加载复核记录" : "重试加载问题"}</button>
              )}
            </div>
          )}
          {manualDetailResources.length > 0 && (
            <div className="mb-4 flex flex-wrap items-center gap-2 text-xs text-slate-400">
              <span>已加载当前部分记录</span>
              {manualDetailResources.map((resource) => (
                <button key={resource} type="button" disabled={detailLoadingResources.has(resource)}
                  onClick={() => void loadDetailResource(resource)}
                  className="rounded border border-slate-700 px-3 py-2 hover:bg-slate-800 disabled:opacity-40">
                  加载更多{({ candidates: "候选点", vulnerabilities: "漏洞", events: "日志", threat_tasks: "审计任务", pattern_tasks: "审计任务", validations: "验证记录" })[resource]}
                </button>
              ))}
            </div>
          )}
          {activeTab === "overview" && (
            <ScanOverview
              scan={scan}
              issueCount={issueCount}
              continuableCount={continuableCount}
              variantIssueCount={variantIssueCount}
              gitHistoryCount={gitHistory.length}
              showGitHistoryStages={showGitHistoryStages}
              currentStage={currentStageLabel(scan, scan.events)}
              pct={pct}
              isRunning={!!isRunning}
              isDone={!!isDone}
              fpReview={fpReview}
              isFpReviewing={isFpReviewing}
              currentFpReviewTargets={currentFpReviewTargets}
              confirmedIssueCount={confirmedIssueCount}
              onNavigate={setActiveTab}
              coverage={<CoverageViewport key={`coverage:${scanId}`} onVisible={activateCoverage}>
                <ThreatCoverageView {...coverageState} issuesState={coverageIssues}
                  analysisStatus={scan.threat_analysis_run?.status} onOpenIssue={auditNavigation.openIssue} />
              </CoverageViewport>}
            />
          )}
          {activeTab === "index" && (
            <TaskPanel
              title="代码图谱构建"
              status={indexProgress.skipped ? "已跳过" : taskStateLabel(indexProgress.done, indexProgress.running, indexProgress.failed)}
              tone={indexProgress.failed ? "red" : indexProgress.done ? "green" : indexProgress.running ? "blue" : "slate"}
              summary="作为静态分析的底层能力，提供扫描路径内的函数、结构体与调用关系。"
            >
              <CallGraphBuildPanel
                indexStatus={indexStatus}
                indexProgress={indexProgress}
                events={filterEvents(scan.events, ["init", "code_graph_build"])}
              />
            </TaskPanel>
          )}
          {activeTab === "static" && (
            <StaticTaskPanel
              scan={scan}
              indexProgress={indexProgress}
              candidates={scan.candidates ?? []}
              vulnerabilities={scan.vulnerabilities}
              events={filterEvents(scan.events, ["static_analysis"])}
              fpReview={fpReview}
              resultRevision={threatResultRevision}
              focusRequest={auditNavigation.focus?.kind === "static_candidate" ? auditNavigation.focus : undefined}
              onOpenIssue={auditNavigation.openIssue}
            />
          )}
          {activeTab === "threat" && isThreatAnalysisSelected(scan) && (
            <ThreatAnalysisPanel
              key={scanId}
              scanId={scanId}
              coverageRevision={coverageRevision}
              coverageState={coverageState}
              analysisStatus={scan.threat_analysis_run?.status}
              analysis={scan.threat_analysis ?? null}
              events={threatAnalysisEvents}
              loading={(threatAnalysisLoading || scan.threat_analysis_run?.status === "running") && !isThreatAnalysisResultReady(scan.threat_analysis)}
              isDone={!!isDone}
              methodLabel={threatAnalysisMethodLabel(scan)}
              resultTab={threatAnalysisResultTab}
              onResultTabChange={setThreatAnalysisResultTab}
              errorMessage={!isThreatAnalysisResultReady(scan.threat_analysis) && scan.threat_analysis_run?.status === "error"
                ? scan.threat_analysis_run.error_message
                : ""}
            />
          )}
          {activeTab === "threat" && !isThreatAnalysisSelected(scan) && (
            <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-6 text-sm text-slate-400">
              本次扫描未选择威胁分析。
            </div>
          )}
          {activeTab === "mining" && activeEngine?.engine_id === STATIC_ENGINE_ID && (
            <AuditTaskPanel
              scan={scan}
              pct={pct}
              currentCandidate={scan.current_candidate}
              events={filterEvents(miningEvents, ["auditing", "opencode_output"])}
              pool={scan.opencode_pool ?? null}
              onOpenStaticAnalysis={() => setActiveTab("static")}
            />
          )}
          {activeTab === "mining" && activeEngine && (activeEngine.engine_id === THREAT_ENGINE_ID || isPatternAuditEngine(activeEngine.engine_id)) && (
            <ThreatAuditPanel
              key={activeEngine.engine_id}
              patternMode={isPatternAuditEngine(activeEngine.engine_id)}
              engineId={activeEngine.engine_id}
              taskRevision={patternTaskRevision}
              scan={scan}
              events={isPatternAuditEngine(activeEngine.engine_id) ? filterEvents(scan.events, [activeEngine.engine_id]) : threatAuditEvents}
              fpReview={fpReview}
              resultRevision={threatResultRevision}
              focusRequest={auditNavigation.focus?.kind === (isPatternAuditEngine(activeEngine.engine_id) ? "threat_pattern_audit" : activeEngine.engine_id) ? auditNavigation.focus as ListFocusRequest<string> : undefined}
              onOpenIssue={auditNavigation.openIssue}
            />
          )}
          {activeTab === "mining" && activeEngine && ![STATIC_ENGINE_ID, THREAT_ENGINE_ID].includes(activeEngine.engine_id) && !isPatternAuditEngine(activeEngine.engine_id) && (
            <GenericEnginePanel
              engine={activeEngine}
              run={miningEngineRun(scan, activeEngine.engine_id)}
            >
              <VulnerabilityList
                scanId={scanId}
                vulnerabilities={scan.vulnerabilities}
                events={scan.events}
                isScanning={!!isRunning}
                totalCandidates={scan.total_candidates}
                processedCandidates={scan.processed_candidates}
                fpReview={fpReview}
                currentFpReviewIndices={currentFpReviewIndices}
                fpReviewRunning={isFpReviewing}
                validations={scan.validations ?? []}
                validatingIndices={launchingValidations}
                stoppingValidationIndices={stoppingValidations}
                agentOnline={!!scan.agent_online}
                fixedEngineId={activeEngine.engine_id}
                onTriggerValidation={!sharedView && scan.vulnerability_validation_enabled ? handleTriggerValidation : undefined}
                onStopValidation={sharedView ? undefined : handleStopValidation}
                onFeedbackCreated={sharedView ? undefined : addSelectedFeedbackIds}
                onFeedbackRemoved={removeSelectedFeedbackIds}
              />
            </GenericEnginePanel>
          )}
          {activeTab === "mining" && !activeEngine && (
            <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-6 text-sm text-slate-400">
              {selectedEngines.length > 0 ? "请从流程图中选择一个漏洞挖掘引擎。" : "本次扫描未选择漏洞挖掘引擎。"}
            </div>
          )}
          {activeTab === "validation" && (
            <ValidationPanel
              vulnerabilities={scan.vulnerabilities}
              validations={scan.validations ?? []}
              stoppingValidationIndices={stoppingValidations}
              events={validationEvents}
              onStopValidation={sharedView ? undefined : handleStopValidation}
            />
          )}
          {activeTab === "fp_review" && (
            <FpReviewPanel
              canControl={!sharedView}
              vulnerabilities={scan.vulnerabilities}
              scanId={scanId}
              reviewDataLoaded={fpReviewHydrated && !fpReviewPageLoading && !fpReviewPageFailed
                && fpReview?.next_cursor == null && detailCursor(scan, "vulnerabilities") == null
                && !detailFailedResources.has("vulnerabilities")}
              focusRequest={auditNavigation.focus?.kind === "fp_review" ? auditNavigation.focus : undefined}
              onOpenIssue={auditNavigation.openIssue}
              fpReview={fpReview}
              methodLabel={fpReviewMethodLabel(selectedFpReviewMethod, selectedFpReviewSelection)}
              methodDescription={selectedFpReviewSelection?.description ?? "按漏洞粒度逐条执行去误报复核。"}
              stages={selectedFpReviewStages}
              isFpReviewing={isFpReviewing}
              loading={fpReviewLoading}
              stopping={fpReviewStopping}
              events={filterEvents(miningEvents, ["fp_review", "opencode_output"])}
              onTrigger={handleFpReview}
              onStop={handleStopFpReview}
            />
          )}
          {activeTab === "issues" && issuesView}
          {activeTab === "review_notes" && !sharedView && !isPublicScan(scanId) && <ReviewNotesManager scanId={scanId} />}
        </>
      </RuntimeErrorBoundary>
    </div>
  );
}
