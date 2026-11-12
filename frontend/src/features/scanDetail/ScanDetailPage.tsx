import { useCallback, useEffect, useRef, useState } from "react";
import { getFpReviewSkill } from "../../api/fpReview";
import { getSkillContent } from "../../api/checkers";
import { isPublicScan, isSharedScan } from "../../api/accessPolicy";
import EditScanMetadataDialog from "../../components/EditScanMetadataDialog";
import FeedbackManager from "../../components/FeedbackManager";
import { ThemeToggle } from "../../components/ThemeToggle";
import VulnerabilityList from "../issues/VulnerabilityList";
import { canonicalMiningEngineLabel, isPatternAuditEngine } from "../../miningEngines";
import type { ScanNavigation } from "../../routing";
import { findIndexedVulnerability } from "../../scanRuntime/issues";
import { mergeScanCodeGraph, mergeScanMetadata } from "../../scanRuntime/scanSnapshots";
import type { IndexedVulnerability } from "../../types/issues";
import type { ScanMetadata } from "../../types/scans";
import { ModelPoolDashboard } from "../modelPool/ModelPoolDashboard";
import { formatDateTime } from "../modelPool/presentation";
import { useThreatAnalysisResult } from "../threatAnalysis/useThreatAnalysisResult";
import { useCoverageIssues, useThreatCoverage } from "../threatAnalysis/useThreatCoverage";
import { ScanDetailContent } from "./components/ScanDetailContent";
import { ScanDetailHeader } from "./components/ScanDetailHeader";
import { ScanDetailSidebar } from "./components/ScanDetailSidebar";
import { ScanInformationPanel } from "./components/ScanInformationPanel";
import { ScanLogPanel } from "./components/ScanLogPanel";
import { ScanReportsPanel } from "./components/ScanReportsPanel";
import { ScanSkillPanel } from "./components/ScanSkillPanel";
import { useDetailPagination } from "./hooks/useDetailPagination";
import { useDetailResources } from "./hooks/useDetailResources";
import { useScanActions } from "./hooks/useScanActions";
import { useScanArtifacts } from "./hooks/useScanArtifacts";
import { useScanCatalog } from "./hooks/useScanCatalog";
import { useScanEvents } from "./hooks/useScanEvents";
import { useScanHydration } from "./hooks/useScanHydration";
import { useScanNavigation } from "./hooks/useScanNavigation";
import { useScanSnapshotState } from "./hooks/useScanSnapshotState";
import { DETAIL_REFRESH_RESOURCE, detailCursor, ISSUE_DETAIL_RESOURCES } from "./model/detailPages";
import { buildProcessFlowModel } from "./model/processFlow";
import {
  effectiveMiningEngines,
  filterEvents,
  finalReviewedIssueCount,
  formatIndexProgress,
  hasEvent,
  humanConfirmedIssueCount,
  isAgentDisconnectError,
  isThreatAnalysisSelected,
  MAX_LOG_LINES,
} from "./model/scan";
import type { DetailResource } from "./model/types";

interface Props {
  scanId: string;
  onHome: () => void;
  onCopyScan?: (scanId: string) => void;
  sharedView?: boolean;
  navigation?: ScanNavigation;
}

export default function ScanStatus({ scanId, onHome, onCopyScan, sharedView = isSharedScan(scanId), navigation }: Props) {
  const scanSnapshotState = useScanSnapshotState();
  const {
    scan,
    setScan,
    scanLoadFailed,
    setScanLoadAttempt,
    fpReview,
    setThreatResultRevision,
    coverageRevision,
    coverageIssuesRevision,
    fpReviewHydrated,
    launchingValidations,
    stoppingValidations,
    indexStatus,
    gitHistory,
    isRunning,
    isDone,
  } = scanSnapshotState;
  const navigationState = useScanNavigation(scanId, scanSnapshotState, navigation);
  const {
    handleFlowNodeClick,
    activeTab,
    activeEngineId,
    threatAnalysisResultTab,
    setActiveTab,
    sidebarOpen,
    setSidebarOpen,
    scanInfoOpen,
    setScanInfoOpen,
    auditNavigation,
  } = navigationState;

  const [editingScan, setEditingScan] = useState<Pick<ScanMetadata, "scan_id" | "scan_name" | "product"> | null>(null);

  const [exportMenuOpen, setExportMenuOpen] = useState(false);

  const [logOpen, setLogOpen] = useState(false);

  const [modelPoolOpen, setModelPoolOpen] = useState(false);
  const detailResources = useDetailResources(scanId, scanSnapshotState);
  const { detailLoadingResources, detailFailedResources, scheduleOverviewSummaryRefresh } = detailResources;

  const [lastSeenEvents, setLastSeenEvents] = useState(0);

  const logRef = useRef<HTMLDivElement>(null);

  const exportMenuRef = useRef<HTMLDivElement>(null);
  const artifacts = useScanArtifacts(scanId, sharedView, scanSnapshotState);
  const {
    feedbackOpen,
    setFeedbackOpen,
    selectedFeedbackIds,
    setSelectedFeedbackIds,
    skillOpen,
    setSkillOpen,
    skillType,
    skillContent,
    setSkillContent,
    skillLoading,
    reportsOpen,
    setReportsOpen,
    reports,
    reportsLoading,
    activeReportIndex,
    setActiveReportIndex,
    handleFeedbackChange,
    addSelectedFeedbackIds,
    removeSelectedFeedbackIds,
    loadSkill,
    loadFpReviewSkill,
    loadSkillReports,
  } = artifacts;

  const scanCatalog = useScanCatalog(scanId);
  const { checkers, miningEngineCatalog, staticRuleTypeLabels } = scanCatalog;

  const [coverageRequestedScan, setCoverageRequestedScan] = useState("");

  const activateCoverage = useCallback(() => setCoverageRequestedScan(scanId), [scanId]);

  const coverageVisible = activeTab === "overview" && coverageRequestedScan === scanId;

  const coverageState = useThreatCoverage(scanId, coverageRevision,
    scan?.scan_id === scanId && (coverageVisible || activeTab === "threat"), scan ? isThreatAnalysisSelected(scan) : true);

  const coverageIssues = useCoverageIssues(scanId, `${coverageRevision}:${coverageIssuesRevision}`,
    coverageState.data?.inventory?.snapshot_id, coverageVisible && !!coverageState.data?.inventory?.entries.length,
    !!fpReview && ["pending", "running"].includes(fpReview.status));

  const {
    loading: threatAnalysisLoading,
    error: threatAnalysisFailed,
    refresh: refreshThreatAnalysis,
    acceptAnalysis: acceptThreatAnalysis,
  } = useThreatAnalysisResult(scanId, scan, setScan);

  useEffect(() => setExportMenuOpen(false), [scanId]);

  useEffect(() => {
    if (!exportMenuOpen) return;

    const handlePointerDown = (event: MouseEvent) => {
      if (!exportMenuRef.current?.contains(event.target as Node)) {
        setExportMenuOpen(false);
      }
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setExportMenuOpen(false);
    };

    document.addEventListener("mousedown", handlePointerDown);
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [exportMenuOpen]);

  useScanHydration(scanId, scanSnapshotState, { setSelectedFeedbackIds, setEditingScan });
  const events = useScanEvents(scanId, scanSnapshotState, detailResources, { refresh: refreshThreatAnalysis, acceptAnalysis: acceptThreatAnalysis });
  const { refreshFailures, refreshDetails } = events;

  const pagination = useDetailPagination(scanId, scanSnapshotState, detailResources, { activeTab, activeEngineId, logOpen, refreshFailures });
  const { fpReviewPageLoading, fpReviewPageFailed, fpReviewRefreshFailed, requiredDetailResources } = pagination;

  const actions = useScanActions(scanId, scanSnapshotState, refreshDetails, setExportMenuOpen);
  const {
    stopping,
    continuing,
    exportingReport,
    handleTriggerValidation,
    handleStopValidation,
    handleStop,
    handleContinue,
    handleExportReport,
  } = actions;

  // Compute log event count for scroll/unseen tracking
  const logEventCount = scan?.events.length ?? 0;

  // Auto-scroll log
  useEffect(() => {
    if (logRef.current && logOpen) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logEventCount, logOpen]);

  // Track unseen events
  useEffect(() => {
    if (logOpen) {
      setLastSeenEvents(logEventCount);
    }
  }, [logOpen, logEventCount]);

  if (!scan) {
    return (
      <div className="relative min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
        <div className="absolute right-4 top-4">
          <ThemeToggle />
        </div>
        {scanLoadFailed ? <div role="alert" className="text-center text-sm text-slate-300">
          <p>扫描详情加载失败，请重试。</p>
          <button type="button" className="mt-3 text-blue-300 underline" onClick={() => setScanLoadAttempt((value) => value + 1)}>重试加载扫描</button>
        </div> : <div role="status" aria-label="加载扫描详情" className="page-spinner w-5 h-5 border-2 rounded-full animate-spin" />}
      </div>
    );
  }

  const pct = Math.round(scan.progress * 100);

  const allLogEvents = scan.events;

  const truncated = allLogEvents.length > MAX_LOG_LINES;

  const logEvents = truncated ? allLogEvents.slice(-MAX_LOG_LINES) : allLogEvents;

  const unseenCount = allLogEvents.length - lastSeenEvents;

  const feedbackCount = selectedFeedbackIds?.size ?? scan.feedback_ids?.length ?? 0;

  const agentDisconnectError = isAgentDisconnectError(scan.error_message);

  const staleAgentDisconnectError = scan.status === "cancelled" && agentDisconnectError && !!scan.agent_online;

  const visibleErrorMessage = staleAgentDisconnectError ? null : scan.error_message;

  const isFpReviewing = fpReview?.status === "running" || fpReview?.status === "pending";

  const fpIndicesSource = !isFpReviewing
    ? []
    : fpReview?.current_vuln_indices?.length
      ? fpReview.current_vuln_indices
      : fpReview?.current_vuln_index != null
        ? [fpReview.current_vuln_index]
        : [];

  const currentFpReviewIndices = new Set(fpIndicesSource.filter((i) => i >= 0));

  const currentFpReviewTargets = [...currentFpReviewIndices]
    .sort((a, b) => a - b)
    .map((i) => findIndexedVulnerability(scan.vulnerabilities, i))
    .filter((vulnerability): vulnerability is IndexedVulnerability => Boolean(vulnerability));

  const reportCheckers = checkers.filter(
    (checker) => scan.scan_items.includes(checker.name) && checker.result_mode === "markdown_reports",
  );

  const hasReportModeSkill = reportCheckers.length > 0 || (scan.skill_reports?.length ?? 0) > 0;

  const displayedReports = reports.length > 0 ? reports : (scan.skill_reports ?? []);

  const activeReport = displayedReports[activeReportIndex] ?? displayedReports[0];

  const continuableCount = scan.continuable_task_count || 0;

  const issueCount = finalReviewedIssueCount(fpReview);

  const confirmedIssueCount = humanConfirmedIssueCount(scan, fpReview);

  const variantIssueCount = scan.vulnerabilities.filter((v) => Boolean(v?.variant_of)).length;

  const showGitHistoryStages = gitHistory.length > 0
    || variantIssueCount > 0
    || hasEvent(scan.events, ["git_history", "variant_hunt"]);

  const indexProgress = formatIndexProgress(indexStatus, scan);

  const selectedEngines = effectiveMiningEngines(scan);

  const activeEngine = selectedEngines.find((item) => item.engine_id === activeEngineId)
    ?? (["threat_audit", "threat_pattern_audit"].includes(auditNavigation.focus?.kind ?? "")
      && (activeEngineId === auditNavigation.focus?.kind || (auditNavigation.focus?.kind === "threat_pattern_audit" && isPatternAuditEngine(activeEngineId)))
      ? { engine_id: activeEngineId, engine_label: canonicalMiningEngineLabel(activeEngineId), enabled: true }
      : null);

  const threatAnalysisEvents = filterEvents(scan.events, ["threat_analysis"]);

  const threatAuditEvents = filterEvents(scan.events, ["threat_audit"]);

  const miningEvents = filterEvents(scan.events, ["auditing", "fp_review", "opencode_output"]);

  const selectedFpReviewMethod = fpReview?.method ?? scan.fp_review_method ?? "adversarial";

  const selectedFpReviewSelection = scan.fp_review_method_selection?.method_id === selectedFpReviewMethod
    ? scan.fp_review_method_selection
    : null;

  const selectedFpReviewStages = selectedFpReviewSelection?.stages ?? [];

  const validationEvents = filterEvents(scan.events, ["validation"]);

  const flowModel = buildProcessFlowModel({
    scan,
    indexProgress,
    fpReview,
    activeTab,
    activeEngineId,
    engineCatalog: miningEngineCatalog,
    threatAnalysisLoading,
    isDone: !!isDone,
    isFpReviewing,
  });

  const showsFpResults = activeTab === "issues" || activeTab === "fp_review";

  const automaticListResources: DetailResource[] = activeTab === "issues" ? ISSUE_DETAIL_RESOURCES
    : activeTab === "fp_review" ? ["vulnerabilities"] : [];

  const activeDetailLoading = requiredDetailResources.some((resource) => detailLoadingResources.has(resource))
    || (showsFpResults && (!fpReviewHydrated || fpReviewPageLoading
      || (!fpReviewPageFailed && !fpReviewRefreshFailed && fpReview?.next_cursor != null)
      || automaticListResources.some((resource) => detailCursor(scan, resource) != null
        && !detailFailedResources.has(resource) && !refreshFailures.has(DETAIL_REFRESH_RESOURCE[resource]))));

  const activeDetailFailed = requiredDetailResources.some((resource) => detailFailedResources.has(resource))
    || (showsFpResults && fpReviewPageFailed);

  const manualDetailResources = requiredDetailResources.filter((resource) => detailCursor(scan, resource) != null
    && !automaticListResources.includes(resource));

  const issuesView = (
    <VulnerabilityList
      scanId={scanId}
      vulnerabilities={scan.vulnerabilities}
      events={scan.events}
      isScanning={!!isRunning}
      totalCandidates={scan.total_candidates}
      processedCandidates={scan.processed_candidates}
      fpReview={fpReview}
      fpReviewStages={selectedFpReviewStages}
      currentFpReviewIndices={currentFpReviewIndices}
      fpReviewRunning={isFpReviewing}
      viewMode="final_tp"
      focusRequest={auditNavigation.focus?.kind === "issue" ? auditNavigation.focus : undefined}
      onOpenAuditSource={auditNavigation.openSource}
      onOpenFpReview={auditNavigation.openFpReview}
      staticRuleTypeLabels={staticRuleTypeLabels}
      validations={scan.validations ?? []}
      validatingIndices={launchingValidations}
      stoppingValidationIndices={stoppingValidations}
      agentOnline={!!scan.agent_online}
      onTriggerValidation={!sharedView && scan.vulnerability_validation_enabled ? handleTriggerValidation : undefined}
      onStopValidation={sharedView ? undefined : handleStopValidation}
      onFeedbackCreated={sharedView ? undefined : addSelectedFeedbackIds}
      onFeedbackRemoved={removeSelectedFeedbackIds}
      onVulnMarked={() => {
        setThreatResultRevision((value) => value + 1);
        scheduleOverviewSummaryRefresh(0);
        if (skillOpen && skillType) {
          if (skillType === "__fp_review__") {
            getFpReviewSkill(scanId).then(setSkillContent).catch(() => { });
          } else {
            getSkillContent(scanId, skillType).then(setSkillContent).catch(() => { });
          }
        }
      }}
    />
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 lg:flex">
      <ScanDetailSidebar
        mobileOpen={sidebarOpen}
        onScanList={onHome}
        flow={flowModel}
        activeTab={activeTab}
        issueCount={issueCount}
        confirmedIssueCount={confirmedIssueCount}
        feedbackCount={feedbackCount}
        modelRunningCount={scan.opencode_pool?.global_running ?? 0}
        hasReportModeSkill={hasReportModeSkill}
        reportCount={scan.skill_reports?.length ?? 0}
        unseenLogCount={unseenCount}
        openTool={scanInfoOpen
          ? "info"
          : feedbackOpen
            ? "feedback"
            : skillOpen
              ? "skill"
              : modelPoolOpen
                ? "models"
                : reportsOpen
                  ? "reports"
                  : logOpen
                    ? "logs"
                    : null}
        onClose={() => setSidebarOpen(false)}
        onHome={() => { auditNavigation.cancel(); setActiveTab("overview"); }}
        onIssues={() => { auditNavigation.cancel(); setActiveTab("issues"); }}
        onNodeClick={handleFlowNodeClick}
        onOpenScanInfo={() => setScanInfoOpen(true)}
        onReviewNotes={!sharedView && !isPublicScan(scanId) ? () => { auditNavigation.cancel(); setActiveTab("review_notes"); } : undefined}
        onOpenFeedback={sharedView ? undefined : () => setFeedbackOpen(true)}
        onOpenSkill={() => {
          setSkillOpen(true);
          if (!skillType && scan.scan_items.length > 0) {
            void loadSkill(scan.scan_items[0]);
          }
        }}
        onOpenModels={() => setModelPoolOpen(true)}
        onOpenReports={() => { void loadSkillReports(); }}
        onOpenLogs={() => {
          setLogOpen(true);
          setLastSeenEvents(logEvents.length);
        }}
      />

      <div className="flex min-h-screen min-w-0 flex-1 flex-col">
        {/* Top bar */}
        <ScanDetailHeader
          onHome={onHome}
          setSidebarOpen={setSidebarOpen}
          sidebarOpen={sidebarOpen}
          scan={scan}
          agentDisconnectError={agentDisconnectError}
          isRunning={isRunning}
          isDone={isDone}
          sharedView={sharedView}
          scanId={scanId}
          handleContinue={handleContinue}
          continuing={continuing}
          continuableCount={continuableCount}
          exportMenuRef={exportMenuRef}
          setExportMenuOpen={setExportMenuOpen}
          exportingReport={exportingReport}
          exportMenuOpen={exportMenuOpen}
          handleExportReport={handleExportReport}
          handleStop={handleStop}
          stopping={stopping}
          activeTab={activeTab}
          flowModel={flowModel}
          handleFlowNodeClick={handleFlowNodeClick}
          threatAnalysisResultTab={threatAnalysisResultTab}
          visibleErrorMessage={visibleErrorMessage}
        />

        {/* Main content */}
        <ScanDetailContent
          scanId={scanId}
          scan={scan}
          sharedView={sharedView}
          issuesView={issuesView}
          snapshot={scanSnapshotState}
          navigation={navigationState}
          resources={detailResources}
          pagination={pagination}
          events={events}
          actions={actions}
          artifacts={artifacts}
          presentation={{
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
          }}
        />
      </div>

      {scanInfoOpen && (
        <ScanInformationPanel
          key={scan.scan_id}
          scan={scan}
          onClose={() => setScanInfoOpen(false)}
          onEdit={!sharedView && !isPublicScan(scanId) ? () => setEditingScan({
            scan_id: scan.scan_id,
            scan_name: scan.scan_name || scan.project_id,
            product: scan.product,
          }) : undefined}
          onCopy={!sharedView && !isPublicScan(scanId) && scan.can_copy_scan === true && onCopyScan
            ? () => onCopyScan(scan.scan_id) : undefined}
          onCodeGraphSaved={!sharedView && !isPublicScan(scanId) ? (state) => setScan((previous) => previous?.scan_id === state.scan_id
            ? mergeScanCodeGraph(previous, { ...previous, ...state }) : previous) : undefined}
        />
      )}
      {editingScan && (
        <EditScanMetadataDialog
          scan={editingScan}
          onSaved={(metadata) => setScan((previous) => previous?.scan_id === metadata.scan_id
            ? mergeScanMetadata(previous, { ...previous, ...metadata }) : previous)}
          onClose={() => setEditingScan(null)}
        />
      )}

      {/* Log slide-over panel */}
      <ScanLogPanel
        logOpen={logOpen}
        setLogOpen={setLogOpen}
        logRef={logRef}
        logEvents={logEvents}
        truncated={truncated}
        allLogEvents={allLogEvents}
      />

      {/* Feedback Manager Panel */}
      {feedbackOpen && !sharedView && scan.project_id && (
        <FeedbackManager
          checkers={checkers.filter((c) => scan.scan_items.includes(c.name))}
          initialTypes={scan.scan_items}
          scanId={scanId}
          projectId={scan.project_id}
          selectedIds={selectedFeedbackIds ?? new Set(scan.feedback_ids)}
          onSelectionChange={handleFeedbackChange}
          onFeedbackCreated={addSelectedFeedbackIds}
          onClose={() => setFeedbackOpen(false)}
        />
      )}

      {/* OpenCode model pool dashboard */}
      {modelPoolOpen && (
        <>
          <div
            className="fixed inset-0 bg-black/30 z-40"
            onClick={() => setModelPoolOpen(false)}
          />
          <div className="fixed right-0 top-0 bottom-0 w-[60rem] max-w-full bg-slate-900 border-l border-slate-700 z-50 flex flex-col shadow-2xl">
            <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
              <div>
                <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
                  OpenCode 模型看板
                </h3>
                <p className="text-xs text-slate-500 mt-1">
                  {scan.opencode_pool?.updated_at
                    ? `最后更新：${formatDateTime(scan.opencode_pool.updated_at)}`
                    : "当前扫描尚未产生 OpenCode 模型池统计"}
                </p>
              </div>
              <button
                onClick={() => setModelPoolOpen(false)}
                className="text-slate-500 hover:text-slate-300 transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <ModelPoolDashboard pool={scan.opencode_pool ?? null} />
          </div>
        </>
      )}

      {/* SKILL Preview Panel */}
      <ScanSkillPanel
        skillOpen={skillOpen}
        setSkillOpen={setSkillOpen}
        scan={scan}
        loadSkill={loadSkill}
        skillType={skillType}
        loadFpReviewSkill={loadFpReviewSkill}
        skillLoading={skillLoading}
        skillContent={skillContent}
      />

      {/* Markdown report panel */}
      <ScanReportsPanel
        reportsOpen={reportsOpen}
        setReportsOpen={setReportsOpen}
        isRunning={isRunning}
        displayedReports={displayedReports}
        reportsLoading={reportsLoading}
        setActiveReportIndex={setActiveReportIndex}
        activeReportIndex={activeReportIndex}
        activeReport={activeReport}
      />
    </div>
  );
}
