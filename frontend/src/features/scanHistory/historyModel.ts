import type { ScanSummary, ScanItemStatus } from "../../types/scans";
import type { User } from "../../types/auth";

export interface ScanHistoryProps {
  onViewScan: (scanId: string) => void;
  onDownloadAgent: () => void;
  onAgentConfig: () => void;
  onNewScan: () => void;
  user: User;
  onLogout: () => void;
  onManageUsers: () => void;
  onCheckerDashboard: () => void;
  onCheckerCatalog: () => void;
  onReviewNotes?: () => void;
}

export const STATUS_STYLES: Record<ScanItemStatus, { label: string; cls: string }> = {
  pending: { label: "等待中", cls: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
  analyzing: { label: "分析中", cls: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
  auditing: { label: "审计中", cls: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
  complete: { label: "已完成", cls: "bg-green-500/20 text-green-400 border-green-500/30" },
  error: { label: "错误", cls: "bg-red-500/20 text-red-400 border-red-500/30" },
  cancelled: { label: "已取消", cls: "bg-amber-500/20 text-amber-400 border-amber-500/30" },
};

export function isRunning(status: ScanItemStatus) {
  return status === "pending" || status === "analyzing" || status === "auditing";
}

export const ALL_FILTER = "__all__";

export const UNCONFIGURED_PRODUCT_FILTER = "__unconfigured__";

export function projectName(scan: Pick<ScanSummary, "scan_name" | "project_id" | "scan_id">) {
  return scan.scan_name || scan.project_id || scan.scan_id.slice(0, 8);
}

export function productFilterValue(scan: Pick<ScanSummary, "product">) {
  return scan.product || UNCONFIGURED_PRODUCT_FILTER;
}

export function productFilterLabel(value: string) {
  return value === UNCONFIGURED_PRODUCT_FILTER ? "未配置" : value;
}

export function uniqueOptions(values: string[]) {
  return Array.from(new Set(values)).sort((a, b) => a.localeCompare(b));
}

export interface HeaderFilterOption {
  value: string;
  label: string;
}

export function formatTime(iso: string) {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}
