import assert from "node:assert/strict";
import test, { after } from "node:test";
import { createServer } from "vite";

const server = await createServer({
  appType: "custom",
  logLevel: "silent",
  server: { middlewareMode: true },
});
const audit = await server.ssrLoadModule("/src/staticAudit.ts");

after(async () => {
  await server.close();
});

function vulnerability(overrides = {}) {
  return {
    ai_verdict: "not_confirmed",
    confirmed: false,
    severity: "low",
    description: "有效 Guard 阻止攻击者输入到达危险状态",
    failure_reason: "",
    ai_analysis: "",
    ...overrides,
  };
}

test("keeps the requested status labels and order", () => {
  assert.deepEqual(audit.STATIC_AUDIT_STATUS_ORDER, [
    "success",
    "failed",
    "pending",
    "running",
  ]);
  assert.deepEqual(audit.STATIC_AUDIT_STATUS_LABELS, {
    success: "审计成功",
    failed: "审计失败",
    pending: "待审计",
    running: "审计中",
  });
});

test("classifies the four static audit states", () => {
  assert.equal(audit.staticAuditStatus(vulnerability({
    ai_verdict: "confirmed",
    confirmed: true,
  })), "success");
  assert.equal(audit.staticAuditStatus(vulnerability()), "success");
  assert.equal(audit.staticAuditStatus(vulnerability({
    ai_verdict: "filtered_same_pattern",
  })), "success");

  for (const verdict of ["failed", "timeout", "no_result"]) {
    assert.equal(audit.staticAuditStatus(vulnerability({ ai_verdict: verdict })), "failed");
  }

  assert.equal(audit.staticAuditStatus(undefined), "pending");
  assert.equal(audit.staticAuditStatus(vulnerability({ ai_verdict: "failed" }), true), "running");
});

test("keeps historical audit records compatible", () => {
  assert.equal(audit.staticAuditStatus(vulnerability({
    ai_verdict: "",
    severity: "unknown",
  })), "failed");
  assert.equal(audit.staticAuditStatus(vulnerability({
    ai_verdict: "",
    severity: "low",
  })), "success");
  assert.equal(audit.staticAuditStatus(vulnerability({
    ai_verdict: "",
    confirmed: true,
    severity: "unknown",
  })), "success");
});

test("shows descriptions for successful vulnerability and non-problem conclusions", () => {
  assert.equal(audit.staticAuditConclusion(vulnerability({
    ai_verdict: "confirmed",
    confirmed: true,
    description: "攻击者可触发越界写入",
  })), "攻击者可触发越界写入");
  assert.equal(audit.staticAuditConclusion(vulnerability()), "有效 Guard 阻止攻击者输入到达危险状态");
});

test("shows the fixed candidate dedup conclusion for same-pattern results", () => {
  assert.equal(audit.staticAuditConclusion(vulnerability({
    ai_verdict: "filtered_same_pattern",
    description: "原候选描述",
    failure_reason: "Filtered by a previously rejected same-pattern candidate",
  })), audit.SAME_PATTERN_AUDIT_CONCLUSION);
  assert.equal(
    audit.SAME_PATTERN_AUDIT_CONCLUSION,
    "候选点去重：同模式代表点已被 AI 审计为非问题，本候选未再次调用模型。",
  );
});

test("prefers failure_reason and falls back to legacy ai_analysis", () => {
  assert.equal(audit.staticAuditConclusion(vulnerability({
    ai_verdict: "failed",
    failure_reason: "模型服务不可用",
    ai_analysis: "旧错误文本",
  })), "模型服务不可用");
  assert.equal(audit.staticAuditConclusion(vulnerability({
    ai_verdict: "timeout",
    failure_reason: "",
    ai_analysis: "模型调用超时",
  })), "模型调用超时");
  assert.equal(audit.staticAuditConclusion(vulnerability({
    ai_verdict: "no_result",
    failure_reason: "",
    ai_analysis: "",
  })), "审计失败，但未记录错误信息");
});

test("never falls back to the old no-analysis placeholder", () => {
  assert.equal(audit.staticAuditConclusion(vulnerability({
    description: "",
    ai_analysis: "历史成功结论",
  })), "历史成功结论");
  assert.equal(audit.staticAuditConclusion(vulnerability({
    description: "",
    ai_analysis: "",
  })), "审计成功，但未记录审计结论");
});
