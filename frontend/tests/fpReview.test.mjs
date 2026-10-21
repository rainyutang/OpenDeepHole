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
    "## Final Verdict\nREAL_BUG",
    "**Final Verdict:** REAL_BUG",
  ]) {
    const report = `[PROVE-BUG-RESULT]\n\n${field}\n\nEvidence:\nsrc/parse.c:17`;
    const parsed = parse(report);
    assert.deepEqual(parsed.verdict, { label: "是问题", tone: "red" }, field);
    assert.deepEqual(parsed.sections, [{ label: "关键证据", markdown: "src/parse.c:17" }], field);
  }
});

test("only definite stage conclusions receive a Chinese binary badge", () => {
  const groups = {
    red: ["true_positive", "REAL_BUG", "NOT_FALSE_POSITIVE", "tp", "是问题"],
    green: ["false_positive", "FALSE_POSITIVE", "fp", "非问题"],
  };
  for (const [tone, values] of Object.entries(groups)) {
    for (const value of values) assert.deepEqual(parse(`Verdict:\n${value}`), {
      sections: [], verdict: { label: tone === "red" ? "是问题" : "非问题", tone },
    });
  }
  for (const value of ["LIKELY_REAL_BUG", "LIKELY_FALSE_POSITIVE", "NOT_PROVEN", "INSUFFICIENT_EVIDENCE", "uncertain"]) {
    const report = parse(`Verdict: ${value}\n\n证据说明。`);
    assert.equal(report.verdict, undefined, value);
    assert.equal(report.sections[0].label, "判定说明");
    assert.match(report.sections[0].markdown, /尚未/);
    assert.match(report.sections[0].markdown, /证据说明。/);
    assert.ok(!report.sections[0].markdown.includes(value));
  }
});

test("leaves fenced, indented and quoted examples intact when extracting the actual verdict", () => {
  const examples = [
    "```text\n[PROVE-BUG-RESULT]\nVerdict: false_positive\nEvidence: example\n```",
    "~~~markdown\n## Verdict\nFALSE_POSITIVE\n~~~",
    "````text\n```\nVerdict: false_positive\n```\n````",
    "    Verdict: false_positive",
    "\tVerdict: false_positive",
    "> # Prove Bug\n> Verdict: false_positive\n> Evidence: quoted",
  ].join("\n\n");
  const report = `${examples}\n\nVerdict: true_positive\n\nEvidence: confirmed`;
  const parsed = parse(report);
  assert.deepEqual(parsed.verdict, { label: "是问题", tone: "red" });
  assert.deepEqual(parsed.sections, [{ markdown: examples }, { label: "关键证据", markdown: "confirmed" }]);
});

test("does not extract fields from list code fences or lazy quote continuations", () => {
  for (const example of [
    "- ```text\n  [PROVE-BUG-RESULT]\n  Verdict: false_positive\n  Evidence: example\n  ```",
    "10. ```text\n    [PROVE-BUG-RESULT]\n    Verdict: false_positive\n    Evidence: example\n    ```",
    "> 下面是引用中的结论：\nVerdict: false_positive\nEvidence: quoted",
  ]) {
    const parsed = parse(`${example}\n\nVerdict: true_positive\n\nEvidence: actual`);
    assert.deepEqual(parsed, {
      verdict: { label: "是问题", tone: "red" },
      sections: [{ markdown: example }, { label: "关键证据", markdown: "actual" }],
    });
  }
});

test("preserves historical prose and quoted or incomplete examples", () => {
  assert.deepEqual(parse(""), { sections: [] });
  for (const markdown of [
    "# Historical report\n\nNo structured verdict was saved.",
    "The earlier Verdict: false_positive was rejected after checking the code.",
    "```text\nVerdict: true_positive\n```",
    "~~~text\nVerdict: true_positive", "    Verdict: true_positive",
    "The [PROVE-BUG-RESULT] marker is part of this explanation.",
    "[PROVE-BUG-RESULT](https://example.invalid/evidence)",
  ]) assert.deepEqual(parse(markdown), { sections: [{ markdown }] });
});

test("missing, conflicting and unsupported conclusions never produce a badge or lose their evidence", () => {
  for (const value of ["CUSTOM_RESULT", "true_positive / false_positive", "REAL_BUG because the copy exceeds the buffer"]) {
    assert.deepEqual(parse(`Verdict: ${value}`), { sections: [{ label: "判定说明", markdown: value }] });
  }
  assert.deepEqual(parse("Verdict:\n\nEvidence:\nThe input is reachable."), {
    sections: [{ label: "关键证据", markdown: "The input is reachable." }],
  });
  assert.deepEqual(parse("Verdict:\n\n"), { sections: [] });
  assert.deepEqual(parse("Verdict: true_positive\n\n## Final Verdict\nfalse_positive"), {
    sections: [{ label: "判定说明", markdown: "是问题" }, { label: "判定说明", markdown: "非问题" }],
  });
  assert.deepEqual(parse("Verdict:\n\n```text\ntrue_positive\n```"), {
    sections: [{ label: "判定说明", markdown: "```text\ntrue_positive\n```" }],
  });
  assert.equal(parse("Verdict: true_positive\n\n## Final Verdict\nUnknown conclusion").verdict, undefined);
});

test("preserves CRLF and code indentation outside the removed field", () => {
  const markdown = "# Stage\r\n\r\n**Verdict:**\r\ntrue_positive\r\n\r\n    memcpy(dst, src, length);\r\n";
  const parsed = parse(markdown);
  assert.deepEqual(parsed.sections, [
    { markdown: "# Stage\r" },
    { label: "判定说明", markdown: "    memcpy(dst, src, length);\r" },
  ]);
  assert.deepEqual(parsed.verdict, { label: "是问题", tone: "red" });
});

test("structures the field-style proof template without rewriting code or paths", () => {
  const report = parse(`# Prove Bug
[PROVE-BUG-RESULT]

Verdict:
NOT_PROVEN

Bug Type:
OOB Write

External Trigger: UNKNOWN

External Source:
网络输入。

Trigger Path:
decode -> copy

Controllable Variables:
\`length\` 来自输入。

Sink:
src/parse.c:17

Guard Analysis:
需要核对上界。

Exploit Story:
尚未建立触发方式。

Evidence:

    memcpy(dst, src, length);

Confidence: Low

Missing Context:
缺少调用方。`);
  assert.equal(report.verdict, undefined);
  assert.deepEqual(report.sections.map(({ label }) => label), [
    "判定说明", "问题类型", "外部可触发性", "外部输入源", "触发路径", "可控变量", "危险操作",
    "校验分析", "触发方式", "关键证据", "置信度", "缺失上下文",
  ]);
  assert.equal(report.sections[0].markdown, "尚未证实问题成立。");
  assert.equal(report.sections[2].markdown, "未知");
  assert.equal(report.sections[5].markdown, "`length` 来自输入。");
  assert.equal(report.sections[6].markdown, "src/parse.c:17");
  assert.equal(report.sections[9].markdown, "    memcpy(dst, src, length);");
  assert.equal(report.sections[10].markdown, "低");
});

test("structures rebuttal and final-judge templates with independent conclusions", () => {
  const rebuttal = parse(`**[PROVE-FP-RESULT]**
# Prove False Positive
## Verdict
FALSE_POSITIVE
## Original Claim Review
原始主张遗漏了校验。
**Primary FP Reason:** SUFFICIENT_GUARD
External Trigger Rebuttal: 外部输入被拒绝。
Reachability Rebuttal: 危险路径不可达。
Controllability Rebuttal: 长度被限制。
Guard Evidence: src/input.c:20
Sink Safety Evidence: 容量足够。
Counterexample: 超长输入提前返回。
## Rebuttal Code Chain
input -> validate -> return
## Key Code Evidence
src/input.c:21
## Analysis
校验覆盖调用。
## Residual Risk
未覆盖其他构建配置。`);
  assert.deepEqual(rebuttal.verdict, { label: "非问题", tone: "green" });
  assert.deepEqual(rebuttal.sections.map(({ label }) => label), [
    "原始主张核对", "主要误报依据", "外部触发反证", "可达性反证", "可控性反证", "校验证据",
    "危险操作安全性证据", "反例", "反证调用链", "关键代码证据", "分析说明", "残余风险",
  ]);
  assert.equal(rebuttal.sections[1].markdown, "已有充分校验");

  const final = parse(`# Final Judge
[FINAL-JUDGE-RESULT]
## Final Verdict
true_positive
Severity: medium
Decision Summary: 仍然存在内部可触发的缺陷。
## Evidence Compared
两方证据比较。
Code Chain: caller -> copy
Key Code Evidence: src/copy.c:42
Why Prove-Bug Is Accepted Or Rejected: 正方成立。
Why Prove-FP Is Accepted Or Rejected: 反方未覆盖内部调用。
## Final Analysis
验证缺陷。
Final Reason: 缺陷成立。
Residual Risk: 外部可达性未确认。`);
  assert.deepEqual(final.verdict, { label: "是问题", tone: "red" });
  assert.deepEqual(final.sections.map(({ label }) => label), [
    "严重性", "裁决摘要", "证据比较", "代码调用链", "关键代码证据", "正方证据评价", "反方证据评价",
    "裁决分析", "裁决理由", "残余风险",
  ]);
  assert.equal(final.sections[0].markdown, "中");
});

test("preserves unrecognized sections, tables, lists, emphasis and links in report order", () => {
  const evidence = "| field | value |\n| --- | --- |\n| Verdict | false_positive |\n\n- [src/input.c:20](https://example.invalid/src)\n- **required guard**";
  const parsed = parse(`## Candidate\nCandidate text\n\n## Custom Context\nUnknown field: keep this\n\n## Evidence\n${evidence}\n\n## Residual Risk\n未验证部分。`);
  assert.equal(parsed.verdict, undefined);
  assert.deepEqual(parsed.sections, [
    { label: "候选问题", markdown: "Candidate text" },
    { markdown: "## Custom Context\nUnknown field: keep this" },
    { label: "关键证据", markdown: evidence },
    { label: "残余风险", markdown: "未验证部分。" },
  ]);
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
    ["prove_bug", "正方子Agent"], ["prove_fp", "反方子Agent"], ["final_judge", "最终裁决"], ["custom", "custom"],
  ]);
  assert.deepEqual(reports[0].sections, [{ label: "判定说明", markdown: "New proof" }]);
  assert.deepEqual(reports[0].verdict, { label: "非问题", tone: "green" });
  assert.deepEqual(reports[1].sections, [{ markdown: "Previous rebuttal" }]);
  assert.deepEqual(reports[2].sections, [{ markdown: "Previous final report" }]);
  assert.deepEqual(result, before);
  assert.deepEqual(displays(undefined, stages), []);
  assert.deepEqual(displays({ pending_stage_outputs: { prove_bug: "First report" } }, stages)[0].sections, [{ markdown: "First report" }]);
});

test("uses built-in role names for old scans without stage config and retains other method names and order", () => {
  const old = displays({ stage_outputs: { final_judge: "final", prove_fp: "rebuttal", prove_bug: "proof" } }, []);
  assert.deepEqual(old.map(({ key, label }) => [key, label]), [
    ["prove_bug", "正方子Agent"], ["prove_fp", "反方子Agent"], ["final_judge", "最终裁决"],
  ]);
  const custom = displays({ stage_outputs: { gate_review: "gates", claim_context: "claim", extra: "extra" } }, [
    { key: "claim_context", label: "主张与上下文" }, { key: "gate_review", label: "六道门复核" },
  ]);
  assert.deepEqual(custom.map(({ key, label }) => [key, label]), [
    ["claim_context", "主张与上下文"], ["gate_review", "六道门复核"], ["extra", "extra"],
  ]);
});
