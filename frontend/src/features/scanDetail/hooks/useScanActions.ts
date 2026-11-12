import { useState } from "react";
import { downloadScanReport, downloadScanReportZip } from "../../../api/reports";
import { getScanOverviewRequest } from "../../../api/scanSnapshots";
import { resumeScan, stopScan } from "../../../api/scans";
import { stopFpReview, triggerFpReview } from "../../../api/fpReview";
import { stopVulnerabilityValidation, triggerVulnerabilityValidation } from "../../../api/issues";
import type { ScanDetailResource } from "../../../scanResourceRefresh";
import { mergeScanOverview } from "../../../scanRuntime/scanSnapshots";
import type { ReportExportFormat } from "../model/types";
import { downloadBlob } from "../resources/downloadBlob";
import type { ScanSnapshotState } from "./useScanSnapshotState";

export function useScanActions(
  scanId: string,
  state: ScanSnapshotState,
  refreshDetails: (resources?: readonly ScanDetailResource[]) => void,
  setExportMenuOpen: React.Dispatch<React.SetStateAction<boolean>>,
) {
  const { scan, scanRef, setScan, setFpReview, setLaunchingValidations, setStoppingValidations } = state;

  const [stopping, setStopping] = useState(false);

  const [continuing, setContinuing] = useState(false);

  const [exportingReport, setExportingReport] = useState<ReportExportFormat | null>(null);

  const [fpReviewLoading, setFpReviewLoading] = useState(false);

  const [fpReviewStopping, setFpReviewStopping] = useState(false);

  const handleFpReview = async () => {
    setFpReviewLoading(true);
    try {
      const started = await triggerFpReview(scanId);
      setFpReview((prev) => ({
        review_id: started.review_id,
        scan_id: scanId,
        method: started.method ?? prev?.method ?? scan?.fp_review_method ?? "adversarial",
        status: started.status ?? "running",
        total: started.total ?? 0,
        processed: started.processed ?? 0,
        current_vuln_index: null,
        current_vuln_indices: [],
        results: prev?.results ?? [],
        error_message: null,
        created_at: prev?.created_at ?? new Date().toISOString(),
      }));
    } catch (err: unknown) {
      const msg = err && typeof err === "object" && "response" in err
        ? (err as { response: { data: { detail: string; }; }; }).response?.data?.detail
        : "触发失败";
      alert(`AI去误报失败：${msg || "未知错误"}`);
    } finally {
      setFpReviewLoading(false);
    }
  };

  const handleTriggerValidation = async (index: number) => {
    if (!scan?.vulnerability_validation_enabled) {
      alert("本次扫描未启用漏洞验证，不能在扫描结束后临时套用新的全局配置");
      return;
    }
    setLaunchingValidations((prev) => new Set(prev).add(index));
    try {
      await triggerVulnerabilityValidation(scanId, index);
    } catch (err: unknown) {
      const response = (err as { response?: { data?: { detail?: string; }; }; }).response;
      const msg = response?.data?.detail || (err instanceof Error ? err.message : "未知错误");
      alert(`启动漏洞验证失败：${msg}`);
      setLaunchingValidations((prev) => {
        const next = new Set(prev);
        next.delete(index);
        return next;
      });
    }
  };

  const handleStopValidation = async (index: number) => {
    setStoppingValidations((prev) => new Set(prev).add(index));
    try {
      await stopVulnerabilityValidation(scanId, index);
    } catch (err: unknown) {
      const response = (err as { response?: { data?: { detail?: string; }; }; }).response;
      const msg = response?.data?.detail || (err instanceof Error ? err.message : "未知错误");
      alert(`停止漏洞验证失败：${msg}`);
      setStoppingValidations((prev) => {
        const next = new Set(prev);
        next.delete(index);
        return next;
      });
    }
  };

  const handleStopFpReview = async () => {
    setFpReviewStopping(true);
    try {
      await stopFpReview(scanId);
      refreshDetails(["fp-review"]);
    } catch (err: unknown) {
      const msg = err && typeof err === "object" && "response" in err
        ? (err as { response: { data: { detail: string; }; }; }).response?.data?.detail
        : "停止失败";
      alert(`停止AI复核失败：${msg || "未知错误"}`);
    } finally {
      setFpReviewStopping(false);
    }
  };

  const handleStop = async () => {
    setStopping(true);
    try {
      const result = await stopScan(scanId);
      if (result.agent_stop_state === "pending") {
        alert("已记录停止请求，但 Agent 暂未确认；重连后将继续停止。");
      }
      const request = getScanOverviewRequest(scanId, scanRef.current);
      const next = await request.promise;
      setScan((previous) => previous?.scan_id === scanId ? mergeScanOverview(previous, next, request.requestedFrom) : previous);
      refreshDetails();
    } catch {
      // The next poll can still reconcile an Agent-side stop.
    } finally {
      setStopping(false);
    }
  };

  const handleContinue = async () => {
    setContinuing(true);
    try {
      await resumeScan(scanId);
      const request = getScanOverviewRequest(scanId, scanRef.current);
      const next = await request.promise;
      setScan((previous) => previous?.scan_id === scanId ? mergeScanOverview(previous, next, request.requestedFrom) : previous);
      refreshDetails();
    } catch (err: unknown) {
      const msg = err && typeof err === "object" && "response" in err
        ? (err as { response: { data: { detail: string; }; }; }).response?.data?.detail
        : "续扫失败";
      alert(`续扫失败：${msg || "未知错误"}`);
    } finally {
      setContinuing(false);
    }
  };

  const handleExportReport = async (format: ReportExportFormat) => {
    if (!scan || exportingReport) return;
    const currentScanId = scan.scan_id;
    setExportMenuOpen(false);
    setExportingReport(format);
    try {
      const blob = format === "zip"
        ? await downloadScanReportZip(currentScanId)
        : await downloadScanReport(currentScanId);
      downloadBlob(
        blob,
        format === "zip"
          ? `scan-${currentScanId}-report.zip`
          : `report-${currentScanId}.csv`,
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "未知错误";
      alert(`${format === "zip" ? "导出压缩包" : "导出 CSV"}失败：${msg}`);
    } finally {
      setExportingReport(null);
    }
  };
  return {
    stopping,
    continuing,
    exportingReport,
    fpReviewLoading,
    fpReviewStopping,
    handleFpReview,
    handleTriggerValidation,
    handleStopValidation,
    handleStopFpReview,
    handleStop,
    handleContinue,
    handleExportReport,
  };
}
