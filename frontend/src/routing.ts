import type { PublicScanAccess } from "./api/client";
import type { ThreatAnalysisResultTab } from "./features/threatAnalysis";

export type ScanTab = "overview" | "index" | "static" | "threat" | "mining" | "validation" | "fp_review" | "issues";
export interface ScanRouteState {
  tab: ScanTab;
  engineId: string;
  threatResult: ThreatAnalysisResultTab;
}
export interface ScanNavigation {
  state: ScanRouteState;
  onNavigate: (state: ScanRouteState) => void;
  locationKey: string;
  action: "POP" | "PUSH" | "REPLACE";
}

export const DEFAULT_SCAN_ROUTE: ScanRouteState = { tab: "overview", engineId: "", threatResult: "valueAssets" };
const sections: Record<ScanTab, string> = {
  overview: "overview", index: "index", static: "static", threat: "threat", mining: "mining",
  validation: "validation", fp_review: "fp-review", issues: "issues",
};
const threatResults: ThreatAnalysisResultTab[] = ["valueAssets", "highRiskModules", "internalNodes", "attackTrees"];

export function parseScanRoute(section: string | undefined, search = ""): ScanRouteState | null {
  const tab = section === undefined ? "overview"
    : (Object.keys(sections) as ScanTab[]).find((key) => sections[key] === section);
  if (!tab) return null;
  const params = new URLSearchParams(search);
  const view = params.get("view") as ThreatAnalysisResultTab;
  return { tab, engineId: params.get("engine") || "", threatResult: threatResults.includes(view) ? view : "valueAssets" };
}

export function scanPath(scanId: string, state = DEFAULT_SCAN_ROUTE, access?: PublicScanAccess | null): string {
  const prefix = access ? (access.kind === "shared" ? "shared-scan" : "public-scan") : "scans";
  const params = new URLSearchParams();
  if (access?.token) params.set("token", access.token);
  if (state.tab === "mining" && state.engineId) params.set("engine", state.engineId);
  if (state.tab === "threat" && state.threatResult !== "valueAssets") params.set("view", state.threatResult);
  const search = params.toString();
  return `/${prefix}/${encodeURIComponent(scanId)}/${sections[state.tab]}${search ? `?${search}` : ""}`;
}

/** Accept historical hash links as well as the current pathname + query. */
export function parsePublicScanAccess(address = window.location.pathname + window.location.search): PublicScanAccess | null {
  const match = address.match(/^#?\/(public|shared)-scan\/([^/?]*)(?:\/[^?]*)?(?:\?(.*))?$/);
  if (!match) return null;
  const kind = match[1] === "shared" ? "shared" : "integration";
  let scanId = "";
  try {
    scanId = decodeURIComponent(match[2] || "");
  } catch {
    return kind === "shared" ? { scanId: "", token: "", kind } : null;
  }
  const token = new URLSearchParams(match[3] || "").get("token") || "";
  if ((!scanId || !token) && kind !== "shared") return null;
  return { scanId, token, kind };
}

export function legacyRoute(pathname: string, hash: string): string | null {
  if (pathname !== "/") return null;
  if (hash === "#/" || hash === "#/history") return "/";
  return /^#\/(?:public|shared)-scan\//.test(hash) ? hash.slice(1) : null;
}

export function loginDestination(state: unknown): string {
  const target = (state as { returnTo?: unknown } | null)?.returnTo;
  return typeof target === "string" && target.startsWith("/") && !target.startsWith("//")
    && !/^\/(?:login|register)(?:[/?#]|$)/.test(target) ? target : "/";
}
