import assert from "node:assert/strict";
import test, { after } from "node:test";
import { createServer } from "vite";

const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
const { parseFpReviewStageOutput: parse, getFpReviewStageDisplays: displays } = await server.ssrLoadModule("/src/fpReview.ts");
after(async () => { await server.close(); });

test("recognizes stage verdict fields in plain, heading, bold and inline-code forms", () => {
  for (const field of [
    "Verdict: REAL_BUG",
    "Verdict:\nREAL_BUG",
    "Verdict:\n\nREAL_BUG",
    "## Verdict\n\nREAL_BUG",
    "### Verdict: REAL_BUG ###",
    "**Verdict:** REAL_BUG",
    "**Verdict**: **REAL_BUG**",
    "**Verdict: REAL_BUG**",
    "### **Verdict**\n\n`REAL_BUG`",
    "__Verdict:__\n__REAL_BUG__",
    "*Verdict:* REAL_BUG",
    "- **Verdict:** `REAL_BUG`",
    "`verdict` = `REAL_BUG`",
    "verdict：REAL_BUG",
  ]) {
    const report = `[PROVE-BUG-RESULT]\n\n${field}\n\nEvidence:\nsrc/parse.c:17`;
    const parsed = parse(report);
    assert.deepEqual(parsed.verdict, { label: "REAL_BUG", tone: "red" }, field);
    assert.equal(parsed.markdown, "[PROVE-BUG-RESULT]\n\n\nEvidence:\nsrc/parse.c:17", field);
  }
});

test("keeps original stage verdicts and distinguishes tentative conclusions from TP or FP", () => {
  const groups = {
    red: ["true_positive", "REAL_BUG", "NOT_FALSE_POSITIVE", "tp"],
    green: ["false_positive", "FALSE_POSITIVE", "fp"],
    amber: ["LIKELY_REAL_BUG", "LIKELY_FALSE_POSITIVE", "NOT_PROVEN", "INSUFFICIENT_EVIDENCE", "uncertain"],
    slate: ["CUSTOM_RESULT"],
  };
  for (const [tone, values] of Object.entries(groups)) {
    for (const label of values) assert.deepEqual(parse(`Verdict:\n${label}`).verdict, { label, tone });
  }
});

test("leaves fenced, indented and quoted examples intact when extracting the actual verdict", () => {
  const examples = [
    "```text\nVerdict: false_positive\n```",
    "~~~markdown\n## Verdict\nFALSE_POSITIVE\n~~~",
    "````text\n```\nVerdict: false_positive\n```\n````",
    "    Verdict: false_positive",
    "\tVerdict: false_positive",
    "> Verdict: false_positive",
  ].join("\n\n");
  const report = `${examples}\n\nVerdict: true_positive\n\nEvidence: confirmed`;
  const parsed = parse(report);
  assert.deepEqual(parsed.verdict, { label: "true_positive", tone: "red" });
  assert.equal(parsed.markdown, `${examples}\n\n\nEvidence: confirmed`);
});

test("preserves historical prose and missing, ambiguous or unsupported verdict fields", () => {
  for (const markdown of [
    "", "# Historical report\n\nNo structured verdict was saved.",
    "The earlier Verdict: false_positive was rejected after checking the code.",
    "Verdict: true_positive / false_positive",
    "Verdict: REAL_BUG because the copy exceeds the buffer",
    "Verdict:\n\nEvidence:\nThe input is reachable.",
    "Verdict:\n\n", "Verdict: true_positive\n\nVerdict: false_positive",
    "```text\nVerdict: true_positive\n```",
    "~~~text\nVerdict: true_positive", "    Verdict: true_positive",
    "Verdict:\n\n```text\ntrue_positive\n```",
  ]) assert.deepEqual(parse(markdown), { markdown });
});

test("preserves CRLF and code indentation outside the removed field", () => {
  const markdown = "# Stage\r\n\r\n**Verdict:**\r\ntrue_positive\r\n\r\n    memcpy(dst, src, length);\r\n";
  const parsed = parse(markdown);
  assert.equal(parsed.markdown, "# Stage\r\n\r\n\r\n    memcpy(dst, src, length);\r\n");
  assert.deepEqual(parsed.verdict, { label: "true_positive", tone: "red" });
});

test("shows each stage once in method order with nonblank pending output taking precedence", () => {
  const result = {
    verdict: "tp", reason: "Previous final conclusion",
    stage_outputs: { final_judge: "Previous final report", prove_fp: "Previous rebuttal", prove_bug: "Previous proof", custom: "Other method output" },
    pending_stage_outputs: { prove_bug: "Verdict: false_positive\n\nNew proof", prove_fp: " \n\t", empty: " " },
  };
  const before = structuredClone(result);
  const stages = [
    { key: "prove_bug", label: "确认漏洞" }, { key: "prove_fp", label: "证明误报" }, { key: "final_judge", label: "最终裁定" },
  ];
  const reports = displays(result, stages);
  assert.deepEqual(reports.map(({ key, label }) => [key, label]), [
    ["prove_bug", "确认漏洞"], ["prove_fp", "证明误报"], ["final_judge", "最终裁定"], ["custom", "custom"],
  ]);
  assert.equal(reports[0].markdown, "\nNew proof");
  assert.deepEqual(reports[0].verdict, { label: "false_positive", tone: "green" });
  assert.equal(reports[1].markdown, "Previous rebuttal");
  assert.equal(reports[2].markdown, "Previous final report");
  assert.deepEqual(result, before);
  assert.deepEqual(displays(undefined, stages), []);
  assert.equal(displays({ pending_stage_outputs: { prove_bug: "First report" } }, stages)[0].markdown, "First report");
});
