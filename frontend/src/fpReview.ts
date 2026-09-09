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
  label: string;
  tone: "red" | "green" | "amber" | "slate";
}

interface StageReport {
  markdown: string;
  verdict?: StageVerdict;
}

function stageVerdict(label: string): StageVerdict {
  const value = label.toLowerCase();
  const tone = ["tp", "true_positive", "real_bug", "not_false_positive"].includes(value) ? "red"
    : ["fp", "false_positive"].includes(value) ? "green"
      : ["uncertain", "likely_real_bug", "likely_false_positive", "not_proven", "insufficient_evidence"].includes(value)
        ? "amber" : "slate";
  return { label, tone };
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

/** Extract only an unambiguous standalone field; code and report prose stay intact. */
export function parseFpReviewStageOutput(markdown: string): StageReport {
  const lines = markdown.split("\n");
  let fence = "";
  const eligible = lines.map((line) => {
    const marker = line.match(/^ {0,3}(`{3,}|~{3,})(.*)$/);
    if (fence) {
      if (marker && marker[1][0] === fence[0] && marker[1].length >= fence.length && !marker[2].trim()) fence = "";
      return false;
    }
    if (marker) {
      fence = marker[1];
      return false;
    }
    return !/^(?: {4}|[ \t]*\t| {0,3}>)/.test(line);
  });
  const fields: { start: number; end: number; value: string }[] = [];
  for (let index = 0; index < lines.length; index++) {
    if (!eligible[index]) continue;
    const field = unwrapMarkdown(lines[index].trim()
      .replace(/^[-*+]\s+/, "")
      .replace(/^#{1,6}\s+/, "")
      .replace(/\s+#+\s*$/, ""))
      .replace(/^(\*\*|__|\*|_|`)verdict([ \t]*[:：=]?)\1/i, "Verdict$2")
      .match(/^verdict(?:[ \t]*[:：=][ \t]*(.*)|[ \t]*)$/i);
    if (!field) continue;
    let end = index;
    let value = field[1]?.trim() ?? "";
    if (!value) {
      do { end++; } while (end < lines.length && !lines[end].trim());
      if (!eligible[end]) continue;
      value = lines[end];
    }
    value = unwrapMarkdown(value);
    if (/^[a-z][a-z0-9_-]*$/i.test(value)) fields.push({ start: index, end, value });
  }
  if (fields.length !== 1) return { markdown };
  const { start, end, value } = fields[0];
  return {
    markdown: lines.filter((_, index) => index < start || index > end).join("\n"),
    verdict: stageVerdict(value),
  };
}

export function getFpReviewStageDisplays(
  result: FpReviewResult | null | undefined,
  stages: FpReviewStageConfig[],
): (StageReport & { key: string; label: string })[] {
  const outputs = new Map(Object.entries(result?.stage_outputs ?? {}));
  for (const [key, content] of Object.entries(result?.pending_stage_outputs ?? {})) {
    if (content.trim()) outputs.set(key, content);
  }
  const order = new Map(stages.map((stage, index) => [stage.key, index]));
  const labels = new Map(stages.map((stage) => [stage.key, stage.label]));
  return [...outputs]
    .filter(([, content]) => content.trim())
    .sort(([a], [b]) => (order.get(a) ?? stages.length) - (order.get(b) ?? stages.length))
    .map(([key, content]) => ({ key, label: labels.get(key) ?? key, ...parseFpReviewStageOutput(content) }));
}
