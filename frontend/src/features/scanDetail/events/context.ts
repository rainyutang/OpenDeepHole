import type { useThreatAnalysisResult } from "../../threatAnalysis/useThreatAnalysisResult";
import type { DetailResources } from "../hooks/useDetailResources";
import type { ScanSnapshotState } from "../hooks/useScanSnapshotState";

/** Stable setters and refs shared by a single scan subscription. */
export interface ScanEventContext {
  scanId: string;
  state: ScanSnapshotState;
  resources: DetailResources;
  analysis: Pick<ReturnType<typeof useThreatAnalysisResult>, "refresh" | "acceptAnalysis">;
}
