import type { FpReviewResult, FpReviewStageConfig } from "./types";

const FP_REVIEW_NO_RESULT_REASON = "Review incomplete";

/** Waiting placeholders returned by pagination are not stored review history. */
export function hasFpReviewRecord(result?: FpReviewResult | null): result is FpReviewResult {
  return !!result && Boolean(result.review_id || result.created_at || result.reason || result.vulnerability_report
    || Object.values(result.stage_outputs ?? {}).some(Boolean)
    || Object.values(result.pending_stage_outputs ?? {}).some(Boolean));
}

export function isEffectiveFpReviewResult(
  result?: FpReviewResult | null,
): result is FpReviewResult {
  if (!result || !["tp", "fp"].includes(result.verdict)) return false;
  if (!result.reason && !result.vulnerability_report) return false;
  return !String(result.reason || "").startsWith(FP_REVIEW_NO_RESULT_REASON);
}

export function isFpReviewNonProblem(
  result?: FpReviewResult | null,
): boolean {
  return isEffectiveFpReviewResult(result) && result.verdict === "fp";
}

interface StageVerdict {
  label: "是问题" | "非问题";
  tone: "red" | "green";
}

interface StageReport {
  sections: { label?: string; markdown: string }[];
  verdict?: StageVerdict;
}

const ADVERSARIAL_STAGE_LABELS = new Map([
  ["prove_bug", "正方子Agent"],
  ["prove_fp", "反方子Agent"],
  ["final_judge", "最终裁决"],
]);

// Both the field-style and heading-style templates are used by saved reports.
const STAGE_FIELD_LABELS = new Map([
  ["verdict", "判定说明"],
  ["final verdict", "判定说明"],
  ["candidate", "候选问题"],
  ["bug type", "问题类型"],
  ["external trigger", "外部可触发性"],
  ["external source", "外部输入源"],
  ["trigger path", "触发路径"],
  ["controllable variables", "可控变量"],
  ["sink", "危险操作"],
  ["guard analysis", "校验分析"],
  ["exploit story", "触发方式"],
  ["evidence", "关键证据"],
  ["confidence", "置信度"],
  ["missing context", "缺失上下文"],
  ["code chain", "代码调用链"],
  ["key code evidence", "关键代码证据"],
  ["analysis", "分析说明"],
  ["residual uncertainty", "剩余不确定性"],
  ["original claim review", "原始主张核对"],
  ["rebuttal code chain", "反证调用链"],
  ["primary fp reason", "主要误报依据"],
  ["external trigger rebuttal", "外部触发反证"],
  ["reachability rebuttal", "可达性反证"],
  ["controllability rebuttal", "可控性反证"],
  ["guard evidence", "校验证据"],
  ["sink safety evidence", "危险操作安全性证据"],
  ["counterexample", "反例"],
  ["residual risk", "残余风险"],
  ["severity", "严重性"],
  ["decision summary", "裁决摘要"],
  ["evidence compared", "证据比较"],
  ["why prove-bug is accepted or rejected", "正方证据评价"],
  ["why prove-fp is accepted or rejected", "反方证据评价"],
  ["final analysis", "裁决分析"],
  ["final reason", "裁决理由"],
]);

const STAGE_REPORT_TITLES = new Set([
  "prove bug", "prove false positive", "final judge",
  "正方子agent", "反方子agent", "最终裁决",
]);

const UNCERTAIN_VERDICTS = new Map([
  ["uncertain", "尚未确定是否为问题。"],
  ["not_proven", "尚未证实问题成立。"],
  ["insufficient_evidence", "证据不足，尚未确定是否为问题。"],
  ["likely_real_bug", "倾向认为是问题，尚未确认。"],
  ["likely_false_positive", "倾向认为非问题，尚未确认。"],
]);

const STAGE_VALUE_LABELS = new Map<string, Map<string, string>>([
  ["severity", new Map([["high", "高"], ["medium", "中"], ["low", "低"]])],
  ["confidence", new Map([["high", "高"], ["medium", "中"], ["low", "低"]])],
  ["external trigger", new Map([["yes", "是"], ["likely", "可能"], ["unknown", "未知"], ["no", "否"]])],
  ["primary fp reason", new Map([
    ["not_externally_triggerable", "不可被外部触发"],
    ["unreachable", "调用路径不可达"],
    ["not_controllable", "关键变量不可控"],
    ["sufficient_guard", "已有充分校验"],
    ["safe_object_size", "对象容量安全"],
    ["safe_memfunc_usage", "内存函数使用安全"],
    ["safe_loop_bound", "循环边界安全"],
    ["error_path_blocks", "错误路径阻断危险操作"],
    ["other", "其他依据"],
  ])],
]);

function stageVerdict(label: string): StageVerdict | undefined {
  const value = label.toLowerCase();
  if (["tp", "true_positive", "real_bug", "not_false_positive", "是问题"].includes(value)) {
    return { label: "是问题", tone: "red" };
  }
  if (["fp", "false_positive", "非问题"].includes(value)) return { label: "非问题", tone: "green" };
  return undefined;
}

function unwrapMarkdown(value: string): string {
  let text = value.trim();
  for (const marker of ["**", "__", "*", "_", "`"]) {
    const inner = text.slice(marker.length, -marker.length);
    if (text.startsWith(marker) && text.endsWith(marker) && inner && !inner.includes(marker)) {
      text = inner.trim();
    }
  }
  return text;
}

function reportText(line: string): string {
  return unwrapMarkdown(line.trim()
    .replace(/^[-*+]\s+/, "")
    .replace(/^#{1,6}\s+/, "")
    .replace(/\s+#+\s*$/, ""));
}

interface StageField {
  index: number;
  key: string;
  label: string;
  value: string;
}

function stageField(line: string, index: number): StageField | undefined {
  const text = reportText(line).replace(/^(\*\*|__|\*|_|`)(.+?)\1/, "$2");
  const match = text.match(/^([^:：=]+?)(?:[ \t]*[:：=][ \t]*(.*))?$/);
  if (!match) return undefined;
  const key = match[1].trim().toLowerCase();
  const label = STAGE_FIELD_LABELS.get(key);
  // A bare word in prose is not a field header (the historical Verdict is an exception).
  if (!label || (match[2] === undefined && !/^(?:#{1,6}\s|\*|_|`)/.test(line.trim())
    && !["verdict", "final verdict"].includes(key))) return undefined;
  return { index, key, label, value: match[2] ?? "" };
}

function reportLineEligibility(lines: string[]): boolean[] {
  let fence = "";
  let quoted = false;
  return lines.map((line) => {
    if (fence) {
      const closing = line.match(/^[ \t]*(`{3,}|~{3,})[ \t]*\r?$/);
      if (closing && closing[1][0] === fence[0] && closing[1].length >= fence.length) fence = "";
      return false;
    }
    if (/^ {0,3}>/.test(line)) {
      quoted = true;
      return false;
    }
    // Markdown permits quoted paragraphs to continue without a leading '>'.
    if (!line.trim() || /^ {0,3}(?:#{1,6}\s|[-*+]\s|\d+[.)]\s|`{3,}|~{3,})/.test(line)) quoted = false;
    if (quoted || /^(?: {4}|[ \t]*\t)/.test(line)) return false;
    const marker = line.match(/^ {0,3}(?:(?:[-*+]|\d+[.)])[ \t]+)?(`{3,}|~{3,})(.*)$/);
    if (marker) {
      fence = marker[1];
      return false;
    }
    return true;
  });
}

/** Parse only standalone template fields; code, quotations and unrecognized prose remain Markdown. */
export function parseFpReviewStageOutput(markdown: string): StageReport {
  const lines = markdown.split("\n");
  const eligible = reportLineEligibility(lines);
  const fields = new Map<number, StageField>();
  const removed = new Set<number>();
  for (const [index, line] of lines.entries()) {
    if (!eligible[index]) continue;
    const text = reportText(line);
    if (/^\[(?:PROVE-BUG|PROVE-FP|FINAL-JUDGE)-RESULT\]$/.test(text)
      || (/^ {0,3}#{1,6}\s+/.test(line) && STAGE_REPORT_TITLES.has(text.toLowerCase()))) {
      removed.add(index);
      continue;
    }
    const field = stageField(line, index);
    if (field) fields.set(index, field);
  }

  const verdictFields = [...fields.values()].filter(({ key }) => ["verdict", "final verdict"].includes(key));
  const replacements = new Map<number, string>();
  let verdict: StageVerdict | undefined;
  for (const field of fields.values()) {
    let valueIndex = field.index;
    if (!field.value.trim()) {
      do { valueIndex++; } while (valueIndex < lines.length && !lines[valueIndex].trim());
      if (!eligible[valueIndex] || fields.has(valueIndex) || removed.has(valueIndex)) continue;
    }
    const value = unwrapMarkdown(valueIndex === field.index ? field.value : lines[valueIndex]).toLowerCase();
    let replacement: string | undefined;
    if (verdictFields.includes(field)) {
      const conclusion = stageVerdict(value);
      if (verdictFields.length === 1 && conclusion) {
        verdict = conclusion;
        replacement = "";
      } else {
        replacement = conclusion?.label ?? UNCERTAIN_VERDICTS.get(value);
      }
    } else {
      replacement = STAGE_VALUE_LABELS.get(field.key)?.get(value);
    }
    if (replacement !== undefined) replacements.set(valueIndex, replacement);
  }

  const sections: StageReport["sections"] = [];
  let label: string | undefined;
  let content: string[] = [];
  function flush() {
    // Trim blank padding, never code indentation or whitespace within evidence.
    while (content.length && !content[0].trim()) content.shift();
    while (content.length && !content[content.length - 1].trim()) content.pop();
    if (content.length) sections.push({ ...(label ? { label } : {}), markdown: content.join("\n") });
    content = [];
  }
  for (const [index, line] of lines.entries()) {
    if (removed.has(index)) continue;
    const field = fields.get(index);
    if (field) {
      flush();
      label = field.label;
      content.push(replacements.get(index) ?? field.value);
    } else {
      if (label && eligible[index] && /^ {0,3}#{1,6}\s+/.test(line)) {
        flush();
        label = undefined;
      }
      content.push(replacements.get(index) ?? line);
    }
  }
  flush();
  return { sections, ...(verdict ? { verdict } : {}) };
}

export function getFpReviewStageDisplays(
  result: FpReviewResult | null | undefined,
  stages: FpReviewStageConfig[],
): (StageReport & { key: string; label: string })[] {
  const outputs = new Map(Object.entries(result?.stage_outputs ?? {}));
  for (const [key, content] of Object.entries(result?.pending_stage_outputs ?? {})) {
    if (content.trim()) outputs.set(key, content);
  }
  const orderedKeys = [...new Set([...stages.map((stage) => stage.key), ...ADVERSARIAL_STAGE_LABELS.keys()])];
  const order = new Map(orderedKeys.map((key, index) => [key, index]));
  const labels = new Map(stages.map((stage) => [stage.key, stage.label]));
  return [...outputs]
    .filter(([, content]) => content.trim())
    .sort(([a], [b]) => (order.get(a) ?? order.size) - (order.get(b) ?? order.size))
    .map(([key, content]) => ({
      key,
      label: ADVERSARIAL_STAGE_LABELS.get(key) ?? labels.get(key) ?? key,
      ...parseFpReviewStageOutput(content),
    }));
}
