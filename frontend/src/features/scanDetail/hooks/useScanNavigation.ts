import { useCallback, useEffect, useRef, useState } from "react";
import type { AuditTarget } from "../../../auditNavigation";
import { useAuditNavigation } from "../../../auditNavigation";
import {
  THREAT_AUDIT_ENGINE_ID as THREAT_ENGINE_ID,
  THREAT_PATTERN_AUDIT_ENGINE_ID as THREAT_PATTERN_ENGINE_ID,
} from "../../../miningEngines";
import type { ScanNavigation, ScanRouteState } from "../../../routing";
import { DEFAULT_SCAN_ROUTE } from "../../../routing";
import type { ThreatAnalysisResultTab } from "../../threatAnalysis/analysisModel";
import type { FlowNodeId, MainTab } from "../model/types";
import type { ScanSnapshotState } from "./useScanSnapshotState";

export function useScanNavigation(scanId: string, state: ScanSnapshotState, navigation?: ScanNavigation) {
  const { scanRef, setScan, fpReview, setFpReview } = state;

  const [localRoute, setLocalRoute] = useState(DEFAULT_SCAN_ROUTE);

  const route = navigation?.state ?? localRoute;

  const { tab: activeTab, engineId: activeEngineId, threatResult: threatAnalysisResultTab } = route;

  const routeRef = useRef(route);

  const navigationRef = useRef(navigation);

  routeRef.current = route;

  navigationRef.current = navigation;

  const changeRoute = useCallback((patch: Partial<ScanRouteState>) => {
    const next = { ...routeRef.current, ...patch };
    if (navigationRef.current) navigationRef.current.onNavigate(next);
    else setLocalRoute(next);
  }, []);

  const setActiveTab = useCallback((tab: MainTab) => changeRoute({ tab }), [changeRoute]);

  const setThreatAnalysisResultTab = useCallback((threatResult: ThreatAnalysisResultTab) => changeRoute({ threatResult }), [changeRoute]);

  const [sidebarOpen, setSidebarOpen] = useState(false);

  const [scanInfoOpen, setScanInfoOpen] = useState(false);

  const navigateToAuditTarget = useCallback((kind: AuditTarget["kind"], engineId?: string) => {
    setSidebarOpen(false);
    if (kind === "issue") setActiveTab("issues");
    else if (kind === "static_candidate") setActiveTab("static");
    else if (kind === "fp_review") setActiveTab("fp_review");
    else {
      changeRoute({ tab: "mining", engineId: kind === "threat_pattern_audit" ? engineId || THREAT_PATTERN_ENGINE_ID : THREAT_ENGINE_ID });
    }
  }, [setActiveTab, changeRoute]);

  const auditNavigation = useAuditNavigation(scanId, scanRef, setScan, navigateToAuditTarget, fpReview, setFpReview);

  useEffect(() => {
    if (navigation?.action === "POP") auditNavigation.cancel();
  }, [navigation?.locationKey, navigation?.action, auditNavigation.cancel]);

  useEffect(() => {
    if (!sidebarOpen) return;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setSidebarOpen(false);
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [sidebarOpen]);

  const handleFlowNodeClick = (node: FlowNodeId) => {
    auditNavigation.cancel();
    if (node === "issues") {
      setActiveTab("issues");
      return;
    }
    if (node.startsWith("threat_result:")) {
      changeRoute({ tab: "threat", threatResult: node.slice("threat_result:".length) as ThreatAnalysisResultTab });
      return;
    }
    if (node === "index") {
      setActiveTab("index");
      return;
    }
    if (node === "static") {
      setActiveTab("static");
      return;
    }
    if (node === "threat") {
      setActiveTab("threat");
      return;
    }
    if (node === "validation") {
      setActiveTab("validation");
      return;
    }
    if (node === "fp_review") {
      setActiveTab("fp_review");
      return;
    }
    const engineId = node.slice("engine:".length);
    changeRoute({ tab: "mining", engineId });
  };
  useEffect(() => {
    if (!navigationRef.current) setLocalRoute((previous) => previous.threatResult === "valueAssets"
      ? previous : { ...previous, threatResult: "valueAssets" });
    setSidebarOpen(false);
    setScanInfoOpen(false);
  }, [scanId]);

  return {
    handleFlowNodeClick,
    activeTab,
    activeEngineId,
    threatAnalysisResultTab,
    setActiveTab,
    setThreatAnalysisResultTab,
    changeRoute,
    sidebarOpen,
    setSidebarOpen,
    scanInfoOpen,
    setScanInfoOpen,
    auditNavigation,
  };
}
