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

test("static failures support legacy snapshots and preserve each version", () => {
  assert.deepEqual(audit.staticAnalysisFailures({}), []);
  assert.deepEqual(audit.staticAnalysisFailures({ mining_engine_runs: [{ engine_id: "static_candidate" }] }), []);
  const errors = ["v1", "v2"].map((version_name) => ({
    checker_name: "loop_var_misuse", error: "native crash", version_name,
  }));
  assert.deepEqual(audit.staticAnalysisFailures({ mining_engine_runs: [{
    engine_id: "multi_version", status: "success", static_analysis_errors: errors,
  }] }), errors.map((error) => ({ ...error, engine_id: "multi_version" })));
});

test("candidate variables use the same subject and fallback order as the audit prompt", () => {
  const candidate = { description: "变量 old_description 不应参与取值" };
  assert.equal(audit.staticCandidateRelatedVariable({ ...candidate,
    metadata: { subject: " data->buffer ", focus_variable: "length", target_variable: "destination" },
  }), "data->buffer");
  assert.equal(audit.staticCandidateRelatedVariable({ ...candidate,
    metadata: { subject: " ", focus_variable: " length ", target_variable: "destination" },
  }), "length、destination");
  assert.equal(audit.staticCandidateRelatedVariable({ ...candidate,
    metadata: { focus_variable: " length ", target_variable: "length" },
  }), "length");
  for (const metadata of [undefined, null, {}, [], "length", { subject: " ", target_variable: "" }]) {
    assert.equal(audit.staticCandidateRelatedVariable({ ...candidate, metadata }), "未指定");
  }
});

test("keeps the requested status labels and order", () => {
  assert.deepEqual(audit.STATIC_AUDIT_STATUS_ORDER, [
    "success",
    "failed",
    "pending",
    "queued",
    "running",
  ]);
  assert.deepEqual(audit.STATIC_AUDIT_STATUS_LABELS, {
    success: "审计成功",
    failed: "审计失败",
    pending: "待审计",
    queued: "排队中",
    running: "审计中",
  });
});

test("classifies static audit outcomes", () => {
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

test("candidate flow uses aggregate unfinished counts even when detail pages are absent", () => {
  const run = { status: "success" };
  const scan = {
    status: "complete", static_analysis_done: true, total_candidates: 125, processed_candidates: 123,
    candidates: [], detail_counts: { candidates: 125, candidate_audit_success: 123,
      candidate_audit_failed: 0, candidate_audit_pending: 0, candidate_audit_queued: 2, candidate_audit_running: 0 },
  };
  for (const status of ["complete", "cancelled", "error"]) {
    assert.equal(audit.staticCandidateAuditFlowStatus({ ...scan, status }, run), "incomplete");
  }
  assert.equal(audit.staticCandidateAuditFlowStatus({ ...scan, status: "auditing" }, { status: "pending" }), "queued");
  for (const status of ["success", "error"]) {
    assert.equal(audit.staticCandidateAuditFlowStatus({ ...scan, status: "auditing" }, { status }), "incomplete");
  }
  const resumed = { ...scan, status: "auditing", detail_counts: {
    ...scan.detail_counts, candidate_audit_queued: 1, candidate_audit_running: 1,
  } };
  assert.equal(audit.staticCandidateAuditFlowStatus(resumed, { status: "running" }), "running");
  const finished = { ...scan, processed_candidates: 125, detail_counts: {
    ...scan.detail_counts, candidate_audit_failed: 2, candidate_audit_queued: 0,
  } };
  assert.equal(audit.staticCandidateAuditFlowStatus(finished, run), "warning");
  assert.equal(audit.staticCandidateAuditFlowStatus(finished, { status: "error" }), "error");
  assert.equal(audit.staticCandidateAuditFlowStatus({ ...finished, detail_counts: {
    ...finished.detail_counts, candidate_audit_success: 125, candidate_audit_failed: 0,
  } }, run), "done");
});

test("legacy incomplete progress cannot become done and terminal waiting states become resumable", () => {
  const legacyScan = {
    status: "complete", static_analysis_done: true, total_candidates: 125, processed_candidates: 123,
  };
  assert.equal(audit.staticCandidateAuditFlowStatus(legacyScan, { status: "success" }), "incomplete");
  assert.equal(audit.staticCandidateAuditFlowStatus({
    ...legacyScan, detail_counts: { candidates: 0 },
  }, { status: "success" }), "incomplete");
  for (const status of ["pending", "queued", "running"]) {
    const displayed = audit.staticAuditDisplayStatus(status, true);
    assert.equal(displayed, "pending");
    assert.equal(audit.staticAuditStatusLabel(displayed, true), "待续扫");
    assert.equal(audit.staticAuditDisplayStatus(status, false), status);
  }
  for (const status of ["success", "failed"]) {
    assert.equal(audit.staticAuditDisplayStatus(status, true), status);
  }
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
