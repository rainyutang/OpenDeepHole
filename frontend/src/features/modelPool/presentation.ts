import {
  canonicalMiningEngineLabel,
  STATIC_CANDIDATE_ENGINE_LABEL,
  THREAT_AUDIT_ENGINE_LABEL,
  THREAT_PATTERN_AUDIT_ENGINE_LABEL,
  THREAT_PATTERN_ITERATIVE_ENGINE_ID,
} from "../../miningEngines";

export function formatTokenCount(value: number): string {
  return new Intl.NumberFormat("zh-CN").format(value || 0);
}

export function poolTaskType(task: Record<string, unknown>): string {
  const direct = String(task.task_type || "").trim();
  if (direct) return direct.toLowerCase();
  const context = task.context;
  if (context && typeof context === "object") {
    return String((context as Record<string, unknown>).task_type || "").trim().toLowerCase();
  }
  return "";
}

export function poolTaskName(task: Record<string, unknown>): string {
  const direct = String(task.task_name || "").trim();
  if (direct) return direct.toLowerCase();
  const context = task.context;
  if (context && typeof context === "object") {
    return String((context as Record<string, unknown>).task_name || "").trim().toLowerCase();
  }
  return "";
}

export const SCAN_QUEUE_TASK_KINDS = {
  candidate_audit: "候选点审计",
  project_audit: "项目级审计",
  sensitive_clear: "敏感信息清理审计",
  report_audit: "报告审计",
  threat_analysis: "威胁分析",
  threat_audit: "威胁审计",
  threat_pattern_audit: "攻击模式审计",
  threat_pattern_iterative_audit: "迭代审计",
  fp_review: "去误报复核",
  vulnerability_validation: "漏洞验证",
  vulnerability_dedup: "漏洞去重",
  vulnerability_mining: "其他漏洞挖掘",
  other: "其他任务",
} as const;

export type ScanQueueTaskKind = keyof typeof SCAN_QUEUE_TASK_KINDS;

// Keep these business kinds aligned with backend/task_kinds.py. Raw mining
// tasks share a type; their stable name prefixes identify the actual work.
export function scanQueueTaskKind(task: Record<string, unknown>): ScanQueueTaskKind {
  const type = poolTaskType(task);
  const taskName = poolTaskName(task);
  if (type === "vulnerability_mining") {
    if (taskName.startsWith("vulnerability-dedup-")) return "vulnerability_dedup";
    if (taskName.startsWith("candidate-audit-")) return "candidate_audit";
    if (taskName.startsWith("project-audit-")) return "project_audit";
    if (taskName.startsWith("threat-audit-")) return "threat_audit";
    if (taskName.startsWith("threat-pattern-iterative-audit-")) return "threat_pattern_iterative_audit";
    if (taskName.startsWith("threat-pattern-audit-")) return "threat_pattern_audit";
    return "vulnerability_mining";
  }
  if (!type) return "vulnerability_mining";
  if (type === "audit") return "candidate_audit";
  if (type === "validation") return "vulnerability_validation";
  return Object.prototype.hasOwnProperty.call(SCAN_QUEUE_TASK_KINDS, type) ? type as ScanQueueTaskKind : "other";
}

export function scanQueueTaskTypeLabel(task: Record<string, unknown>): string {
  const kind = scanQueueTaskKind(task);
  if (["candidate_audit", "project_audit", "sensitive_clear", "report_audit"].includes(kind)) {
    return `${STATIC_CANDIDATE_ENGINE_LABEL} / ${SCAN_QUEUE_TASK_KINDS[kind]}`;
  }
  if (kind === "threat_audit") return `${THREAT_AUDIT_ENGINE_LABEL} / 威胁审计`;
  if (kind === "threat_pattern_audit") return `${THREAT_PATTERN_AUDIT_ENGINE_LABEL} / 攻击模式审计`;
  if (kind === "threat_pattern_iterative_audit") return `${canonicalMiningEngineLabel(THREAT_PATTERN_ITERATIVE_ENGINE_ID)} / 迭代审计`;
  if (kind === "vulnerability_mining") return "漏洞挖掘";
  if (kind === "other") return poolTaskType(task) || "其他任务";
  return SCAN_QUEUE_TASK_KINDS[kind];
}

export function formatDuration(seconds: number): string {
  if (!seconds || seconds <= 0) return "-";
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds % 60);
  return `${minutes}m ${rest}s`;
}

export function formatDateTime(value: string): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}
