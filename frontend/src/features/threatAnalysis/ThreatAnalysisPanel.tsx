import { useMemo } from "react";
import type { KeyboardEvent } from "react";
import type { NativeThreatHighRiskModule, NativeThreatModulePatternBaseline, NativeThreatValueAsset, ThreatAnalysis } from "../../types/threatAnalysis";
import type { ScanEvent } from "../../types/scans";

import { useThreatCoverage } from "./useThreatCoverage";

import "./ThreatAnalysisPanel.css";
import {
  ThreatAnalysisResultTab,
  THREAT_ANALYSIS_RESULT_TABS,
  getThreatAnalysisResultCounts,
  artifactContent,
  artifactArray,
  attackTreesFromAnalysis,
  collectInternalNodes,
  isRecord,
  recordItems,
} from './analysisModel';
import { AttackTrees } from './AttackTrees';
import { ValueAssetsTable, HighRiskModulesTable, InternalNodesTable } from './AnalysisTables';
import { ThreatAnalysisError, PanelHeading, ArtifactPaths, ThreatEventList, EmptyState } from './AnalysisSupportingViews';

interface ThreatAnalysisPanelProps {
  scanId: string;
  coverageRevision: number;
  coverageState?: ReturnType<typeof useThreatCoverage>;
  analysisStatus?: string;
  analysis: ThreatAnalysis | null;
  events: ScanEvent[];
  loading: boolean;
  isDone: boolean;
  methodLabel: string;
  resultTab: ThreatAnalysisResultTab;
  onResultTabChange: (tab: ThreatAnalysisResultTab) => void;
  errorMessage?: string;
}

export function ThreatAnalysisPanel({
  scanId,
  coverageRevision,
  coverageState: sharedCoverage,
  analysis,
  events,
  loading,
  isDone,
  methodLabel,
  resultTab,
  onResultTabChange,
  errorMessage = "",
}: ThreatAnalysisPanelProps) {
  const localCoverage = useThreatCoverage(scanId, coverageRevision, !sharedCoverage);
  const coverageState = sharedCoverage ?? localCoverage;
  const assets = artifactArray<NativeThreatValueAsset>(
    analysis,
    "value_asset_path",
  );
  const modules = artifactArray<NativeThreatHighRiskModule>(
    analysis,
    "high_risk_modules_path",
  );
  const trees = attackTreesFromAnalysis(analysis);
  const attackTreeArtifact = artifactContent(analysis, "attack_tree_path");
  const unassignedBaselines = isRecord(attackTreeArtifact)
    ? recordItems<NativeThreatModulePatternBaseline>(attackTreeArtifact.unassigned_module_pattern_baselines)
    : [];
  const internalNodes = useMemo(() => collectInternalNodes(trees), [trees]);

  if (!analysis) {
    return (
      <div className="space-y-4">
        {errorMessage && (
          <ThreatAnalysisError methodLabel={methodLabel} message={errorMessage} />
        )}
        <EmptyState
          text={
            loading
              ? "威胁分析运行中，完成后会展示原生产物。"
              : isDone
                ? "当前扫描未生成威胁分析产物。"
                : "等待威胁分析结果。"
          }
        />
        <ThreatEventList events={events} />
      </div>
    );
  }

  if (
    !analysis.entrypoint_result
    || analysis.entrypoint_result.result !== true
    || !analysis.artifacts
  ) {
    return (
      <div className="space-y-4">
        {errorMessage && (
          <ThreatAnalysisError methodLabel={methodLabel} message={errorMessage} />
        )}
        <EmptyState text="该扫描使用旧版威胁分析格式，当前版本不再提供兼容展示。" />
        <ThreatEventList events={events} />
      </div>
    );
  }

  const counts = getThreatAnalysisResultCounts(analysis);

  const handleTabKeyDown = (
    event: KeyboardEvent<HTMLButtonElement>,
    current: ThreatAnalysisResultTab,
  ) => {
    const currentIndex = THREAT_ANALYSIS_RESULT_TABS.findIndex((item) => item.key === current);
    let nextIndex: number | null = null;
    if (event.key === "ArrowRight") nextIndex = (currentIndex + 1) % THREAT_ANALYSIS_RESULT_TABS.length;
    if (event.key === "ArrowLeft") nextIndex = (currentIndex - 1 + THREAT_ANALYSIS_RESULT_TABS.length) % THREAT_ANALYSIS_RESULT_TABS.length;
    if (event.key === "Home") nextIndex = 0;
    if (event.key === "End") nextIndex = THREAT_ANALYSIS_RESULT_TABS.length - 1;
    if (nextIndex === null) return;
    event.preventDefault();
    const nextTab = THREAT_ANALYSIS_RESULT_TABS[nextIndex].key;
    onResultTabChange(nextTab);
    document.getElementById(`threat-analysis-tab-${nextTab}`)?.focus();
  };

  return (
    <div className="space-y-4">
      {errorMessage && (
        <ThreatAnalysisError methodLabel={methodLabel} message={errorMessage} />
      )}
      <section className="threat-analysis-viewer">
        <header className="threat-analysis-viewer__header">
          <h2 className="threat-analysis-viewer__title">威胁分析结果</h2>
          <p className="threat-analysis-viewer__summary">
            方法：{methodLabel} · {assets.length} 个价值资产 / {modules.length} 个高风险模块 /{" "}
            {internalNodes.length} 个内部节点 / {trees.length} 棵攻击树
          </p>
        </header>

        <nav
          className="threat-analysis-viewer__tabs"
          aria-label="威胁分析结果页签"
          role="tablist"
        >
          {THREAT_ANALYSIS_RESULT_TABS.map((item) => (
            <button

              key={item.key}

              id={`threat-analysis-tab-${item.key}`}

              type="button"

              role="tab"

              aria-controls={`threat-analysis-panel-${item.key}`}

              aria-selected={resultTab === item.key}

              tabIndex={resultTab === item.key ? 0 : -1}

              onKeyDown={(event) => handleTabKeyDown(event, item.key)}

              onClick={() => onResultTabChange(item.key)}

              className={`threat-analysis-viewer__tab ${resultTab === item.key ? "is-active" : ""
                }`}
            >
              {item.label}
            </button>
          ))}
        </nav>

        <section

          id={`threat-analysis-panel-${resultTab}`}

          role="tabpanel"

          aria-labelledby={`threat-analysis-tab-${resultTab}`}

          className="threat-analysis-viewer__panel"
        >
          <PanelHeading

            title={THREAT_ANALYSIS_RESULT_TABS.find((item) => item.key === resultTab)?.label ?? ""}

            count={counts[resultTab]}

            unit={THREAT_ANALYSIS_RESULT_TABS.find((item) => item.key === resultTab)?.unit ?? "项"}
          />
          {resultTab === "valueAssets" && <ValueAssetsTable assets={assets} />}
          {resultTab === "highRiskModules" && <HighRiskModulesTable modules={modules} coverage={coverageState.data} pathError={coverageState.error} />}
          {resultTab === "internalNodes" && <InternalNodesTable nodes={internalNodes} />}
          {resultTab === "attackTrees" && <AttackTrees trees={trees} unassignedBaselines={unassignedBaselines} />}
        </section>
      </section>

      <ArtifactPaths analysis={analysis} />
      <ThreatEventList events={events} />
    </div>
  );
}

export { THREAT_ANALYSIS_RESULT_TABS, getThreatAnalysisResultCounts, isThreatAnalysisResultReady } from './analysisModel';
export type { ThreatAnalysisResultTab, ThreatAnalysisResultCounts } from './analysisModel';
