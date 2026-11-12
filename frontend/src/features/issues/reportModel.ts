import type { FpReviewResult, FpReviewStageConfig } from "../../types/fpReview";
import type { OutputSource, Vulnerability } from "../../types/issues";
import { compactVulnerabilityReport } from "../../vulnerabilityReport";
import { severityLabel, vulnerabilityFunctionLabel, vulnerabilityTypeLabel } from "./model";

export function vulnerabilityReportContent(vuln: Vulnerability, locationOnly = false): string {
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

export function finalFpReviewPresentation(
  result: FpReviewResult,
  stages: FpReviewStageConfig[],
): { content: string; source?: OutputSource | null } {
  const outputs = result.stage_outputs ?? {};
  const sources = result.stage_output_sources ?? {};
  const finalJudge = outputs.final_judge?.trim();
  if (finalJudge) {
    return {
      content: finalJudge,
      source: sources.final_judge ?? result.output_source,
    };
  }

  const declaredKeys = stages.map((stage) => stage.key);
  const orderedKeys = [
    ...declaredKeys,
    ...Object.keys(outputs).filter((key) => !declaredKeys.includes(key)),
  ];
  const finalStage = [...orderedKeys].reverse().find((key) => (
    key !== "history_match" && Boolean(outputs[key]?.trim())
  ));
  if (finalStage) {
    return {
      content: outputs[finalStage].trim(),
      source: sources[finalStage] ?? result.output_source,
    };
  }
  return {
    content: result.reason?.trim() || result.vulnerability_report?.trim() || "暂无最终裁定内容。",
    source: result.output_source,
  };
}
