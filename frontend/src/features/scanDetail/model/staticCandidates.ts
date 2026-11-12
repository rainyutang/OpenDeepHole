import type { StaticAuditStatus } from "../../../staticAudit";
import { STATIC_AUDIT_STATUS_ORDER, staticAuditStatusLabel } from "../../../staticAudit";
import type { ScanCandidate } from "../../../types/audit";
import type { Vulnerability } from "../../../types/issues";
import type { TaskTone } from "./types";

export const ALL_STATIC_FILTER = "__all__";

export interface StaticFilterOption {
  value: string;
  label: string;
  count?: number;
}

export interface StaticCandidateItem {
  candidate: ScanCandidate;
  vulnerability?: Vulnerability;
  vulnerabilityIndex?: number;
  auditStatus: StaticAuditStatus;
}

export function valueOptions(
  values: string[],
  formatLabel: (value: string) => string = (value) => value,
): StaticFilterOption[] {
  const counts = new Map<string, number>();
  values.forEach((value) => counts.set(value, (counts.get(value) ?? 0) + 1));
  return Array.from(counts.entries())
    .sort(([a], [b]) => formatLabel(a).localeCompare(formatLabel(b)))
    .map(([value, count]) => ({ value, label: formatLabel(value), count }));
}

export function countStaticAuditOptions(values: StaticAuditStatus[], ended = false): StaticFilterOption[] {
  const counts = new Map<string, number>();
  values.forEach((value) => counts.set(value, (counts.get(value) ?? 0) + 1));
  return STATIC_AUDIT_STATUS_ORDER.filter((value) => !ended || !["queued", "running"].includes(value)).map((value) => ({
    value,
    label: staticAuditStatusLabel(value, ended),
    count: counts.get(value) ?? 0,
  }));
}

export function staticAuditTone(status: StaticAuditStatus): TaskTone {
  if (status === "success") return "green";
  if (status === "failed") return "red";
  if (status === "running") return "blue";
  if (status === "queued") return "amber";
  return "slate";
}
