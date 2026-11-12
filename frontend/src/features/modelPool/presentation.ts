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

export function scanQueueTaskTypeLabel(task: Record<string, unknown>): string {
  const type = poolTaskType(task);
  const taskName = poolTaskName(task);
  if (type === "vulnerability_mining") {
    if (taskName.startsWith("vulnerability-dedup-")) return "漏洞去重";
    if (taskName.startsWith("candidate-audit-")) return `${STATIC_CANDIDATE_ENGINE_LABEL} / 候选点审计`;
    if (taskName.startsWith("project-audit-")) return `${STATIC_CANDIDATE_ENGINE_LABEL} / 项目级审计`;
    if (taskName.startsWith("threat-audit-")) return `${THREAT_AUDIT_ENGINE_LABEL} / 威胁审计`;
    if (taskName.startsWith("threat-pattern-iterative-audit-")) return `${canonicalMiningEngineLabel(THREAT_PATTERN_ITERATIVE_ENGINE_ID)} / 迭代审计`;
    if (taskName.startsWith("threat-pattern-audit-")) return `${THREAT_PATTERN_AUDIT_ENGINE_LABEL} / 攻击模式审计`;
    return "漏洞挖掘";
  }
  if (type === "audit") return `${STATIC_CANDIDATE_ENGINE_LABEL} / 候选点审计`;
  if (type === "project_audit") return `${STATIC_CANDIDATE_ENGINE_LABEL} / 项目级审计`;
  if (type === "sensitive_clear") return `${STATIC_CANDIDATE_ENGINE_LABEL} / 敏感信息清理审计`;
  if (type === "report_audit") return `${STATIC_CANDIDATE_ENGINE_LABEL} / 报告审计`;
  if (type === "fp_review") return "去误报复核";
  if (type === "threat_analysis") return "威胁分析";
  if (type === "threat_audit") return `${THREAT_AUDIT_ENGINE_LABEL} / 威胁审计`;
  if (type === "validation" || type === "vulnerability_validation") return "漏洞验证";
  return type || "漏洞挖掘";
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
