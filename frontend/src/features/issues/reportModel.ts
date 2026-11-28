import type { FpReviewResult } from "../../types/fpReview";
import type { OutputSource, Vulnerability } from "../../types/issues";
import { isRedlineAuditEngine } from "../../miningEngines";
import { compactVulnerabilityReport } from "../../vulnerabilityReport";
import {
  engineId,
  isFinalFpProblem,
  severityLabel,
  vulnerabilityFunctionLabel,
  vulnerabilityTypeLabel,
} from "./model";

const COMPACT_TYPE_RE = /^\*\*漏洞类型\*\*：(.+)$/m;
const COMPACT_LOCATION_RE = /^\*\*漏洞位置\*\*：`([^`\n]+):([^`\n]+)`$/m;
const COMPACT_FUNCTION_RE = /^\*\*漏洞函数\*\*：`([^`\n]+)`$/m;

export function isCompactVulnerabilityReport(report?: string | null): boolean {
  return Boolean(report && report.trim().startsWith("**漏洞类型**："));
}

function hasSourceMetadata(source?: OutputSource | null): boolean {
  return Boolean(
    source && (
      source.agent_name || source.agent_id || source.tool || source.backend
      || source.model || source.model_id || source.use_default_model
    ),
  );
}

export function hasRegeneratedFpReport(
  fpReviewResult?: FpReviewResult | null,
): fpReviewResult is FpReviewResult {
  return Boolean(
    fpReviewResult
    && isFinalFpProblem(fpReviewResult)
    && isCompactVulnerabilityReport(fpReviewResult.vulnerability_report),
  );
}

export function parseCompactReportHeader(report: string): Partial<Pick<Vulnerability, "vuln_type" | "file" | "line" | "function">> {
  const text = report.trim();
  if (!isCompactVulnerabilityReport(text)) return {};
  const updates: Partial<Pick<Vulnerability, "vuln_type" | "file" | "line" | "function">> = {};
  const typeMatch = COMPACT_TYPE_RE.exec(text);
  const vulnType = typeMatch?.[1]?.trim();
  if (vulnType && vulnType !== "未知类型") {
    updates.vuln_type = vulnType;
  }
  const locationMatch = COMPACT_LOCATION_RE.exec(text);
  if (locationMatch) {
    const file = locationMatch[1]?.trim();
    const rawLine = locationMatch[2]?.trim();
    if (file && file !== "未知文件") updates.file = file;
    if (rawLine && /^\d+$/.test(rawLine) && Number(rawLine) > 0) {
      updates.line = Number(rawLine);
    }
  }
  const fnMatch = COMPACT_FUNCTION_RE.exec(text);
  const fnName = fnMatch?.[1]?.trim();
  if (fnName && fnName !== "未知函数") {
    updates.function = fnName;
  }
  return updates;
}

export function resolvedIssueDisplayVuln(
  vuln: Vulnerability,
  fpReviewResult?: FpReviewResult | null,
): Vulnerability {
  if (isRedlineAuditEngine(engineId(vuln))) return vuln;
  if (!hasRegeneratedFpReport(fpReviewResult)) return vuln;
  const regenerated = fpReviewResult.vulnerability_report.trim();
  const headerUpdates = parseCompactReportHeader(regenerated);
  return {
    ...vuln,
    ...headerUpdates,
    vulnerability_report: regenerated,
  };
}

export function vulnerabilityReportSource(
  vuln: Vulnerability,
  fpReviewResult?: FpReviewResult | null,
): OutputSource | undefined {
  if (isRedlineAuditEngine(engineId(vuln))) return vuln.output_source;
  if (hasRegeneratedFpReport(fpReviewResult) && hasSourceMetadata(fpReviewResult.output_source)) {
    return fpReviewResult.output_source;
  }
  return vuln.output_source;
}

export function vulnerabilityReportContent(
  vuln: Vulnerability,
  locationOnly = false,
  fpReviewResult?: FpReviewResult | null,
): string {
  if (!isRedlineAuditEngine(engineId(vuln)) && hasRegeneratedFpReport(fpReviewResult)) {
    return `${fpReviewResult.vulnerability_report.trim()}\n`;
  }
  const existing = vuln.vulnerability_report?.trim();
  if (existing) return existing;
  const compact = compactVulnerabilityReport(vuln);
  if (compact) return compact;

  const line = vuln.line > 0 ? String(vuln.line) : "未知";
  const lines = locationOnly ? [
    "# 漏洞报告",
    "",
    "| 字段 | 内容 |",
    "| --- | --- |",
    `| 文件 | ${vuln.file?.trim() || "未知文件"} |`,
    `| 行号 | ${line} |`,
    `| 函数 | ${vulnerabilityFunctionLabel(vuln)} |`,
  ] : [
    "# 漏洞报告",
    "",
    "| 字段 | 内容 |",
    "| --- | --- |",
    `| 是否是问题 | ${vuln.confirmed ? "是" : "否"} |`,
    `| 漏洞类型 | ${vulnerabilityTypeLabel(vuln)} |`,
    `| 文件 | ${vuln.file?.trim() || "未知文件"} |`,
    `| 函数 | ${vulnerabilityFunctionLabel(vuln)} |`,
    `| 行号 | ${line} |`,
    `| 严重程度 | ${severityLabel(vuln.severity)} |`,
  ];
  const sections: Array<[string, string | undefined]> = [
    ["漏洞描述", vuln.description],
    ["攻击入口", vuln.attack_entry],
    ["触发条件", vuln.trigger_conditions],
    ["漏洞代码", vuln.vulnerable_code],
    ["漏洞根因", vuln.root_cause],
    ["漏洞调用链", vuln.call_chain],
    ["漏洞影响", vuln.impact],
  ];
  let sectionCount = 0;
  sections.forEach(([title, rawContent]) => {
    const content = rawContent?.trim();
    if (!content) return;
    lines.push("", `## ${title}`, "", content);
    sectionCount += 1;
  });
  if (vuln.ai_analysis?.trim()) {
    lines.push("", "## 补充分析", "", vuln.ai_analysis.trim());
    sectionCount += 1;
  }
  if (sectionCount === 0) {
    lines.push("", "## 审计结论", "", "引擎未提供更多结构化信息。");
  }
  return `${lines.join("\n")}\n`;
}
