import assert from "node:assert/strict";
import test, { after } from "node:test";
import { createServer } from "vite";

const server = await createServer({
  appType: "custom",
  logLevel: "silent",
  server: { middlewareMode: true },
});
const runtime = await server.ssrLoadModule("/src/scanRuntime.ts");
const miningEngines = await server.ssrLoadModule("/src/miningEngines.ts");

after(async () => {
  await server.close();
});

function vulnerability(file, variantOf = "") {
  return {
    file,
    line: 1,
    function: "target",
    vuln_type: "npd",
    severity: "high",
    description: "description",
    ai_analysis: "analysis",
    confirmed: true,
    variant_of: variantOf,
  };
}

function pool(updatedAt, overrides = {}) {
  return runtime.normalizeOpenCodePool({
    scope_id: "scan-1",
    execution_revision: 1,
    global_running: 0,
    global_queued: 0,
    total_tasks: 0,
    completed_task_count: 0,
    planned_tasks: [],
    queued_tasks: [],
    completed_tasks: [],
    models: [],
    updated_at: updatedAt,
    ...overrides,
  });
}

test("normalizes legacy arrays without materializing invalid entries", () => {
  const normalized = runtime.normalizeIndexedVulnerabilities([
    null,
    vulnerability("kept.c"),
  ]);

  assert.deepEqual(normalized.map((item) => item.vuln_index), [1]);
  assert.equal(normalized[0].file, "kept.c");
});

test("merges non-contiguous backend indexes into a dense collection", () => {
  const first = runtime.mergeIndexedVulnerabilities([], [
    { index: 1, vulnerability: vulnerability("one.c") },
  ]);
  const merged = runtime.mergeIndexedVulnerabilities(first, [
    { index: 3, vulnerability: vulnerability("three.c", "history") },
    { index: 1, vulnerability: vulnerability("one-updated.c") },
  ]);

  assert.deepEqual(merged.map((item) => item.vuln_index), [1, 3]);
  assert.equal(merged[0].file, "one-updated.c");
  assert.equal(merged.filter((item) => item.variant_of).length, 1);
  assert.ok(merged.every(Boolean));
});

test("finds vulnerabilities by stable index instead of array position", () => {
  const merged = runtime.mergeIndexedVulnerabilities([], [
    { index: 4, vulnerability: vulnerability("four.c") },
    { index: 9, vulnerability: vulnerability("nine.c") },
  ]);

  assert.equal(runtime.findIndexedVulnerability(merged, 9)?.file, "nine.c");
  assert.equal(runtime.findIndexedVulnerability(merged, 1), undefined);
});

test("normalizes candidate-owned audit state by stable idx", () => {
  const candidate = runtime.normalizeScanCandidate({
    idx: 7,
    file: "same.c",
    line: 9,
    function: "same",
    description: "candidate",
    vuln_type: "npd",
    audit_state: "success",
    audit_result: vulnerability("same.c"),
    vulnerability_idx: 12,
    dedup_decision: { method: "semantic" },
  });

  assert.equal(candidate.idx, 7);
  assert.equal(candidate.audit_state, "success");
  assert.equal(candidate.audit_result.file, "same.c");
  assert.equal(candidate.vulnerability_idx, 12);
  assert.deepEqual(candidate.dedup_decision, { method: "semantic" });
});

test("normalizes optional mining engine progress without inventing legacy counts", () => {
  const current = runtime.normalizeScanStatus({
    scan_id: "scan-current",
    status: "auditing",
    mining_engine_runs: [{
      engine_id: "threat_pattern_audit",
      engine_label: "Pattern audit",
      status: "running",
      processed_candidates: 3,
      total_candidates: 8,
    }],
  });
  const legacy = runtime.normalizeScanStatus({
    scan_id: "scan-legacy",
    status: "complete",
    mining_engine_runs: [{
      engine_id: "threat_pattern_audit",
      engine_label: "Pattern audit",
      status: "success",
    }],
  });

  assert.equal(current.mining_engine_runs[0].processed_candidates, 3);
  assert.equal(current.mining_engine_runs[0].total_candidates, 8);
  assert.equal(legacy.mining_engine_runs[0].processed_candidates, null);
  assert.equal(legacy.mining_engine_runs[0].total_candidates, null);
});

test("formats bounded attack-pattern audit progress", () => {
  assert.equal(
    miningEngines.formatMiningEngineAuditProgress({
      processed_candidates: 3,
      total_candidates: 8,
    }),
    "3/8 已审计",
  );
  assert.equal(
    miningEngines.formatMiningEngineAuditProgress({
      processed_candidates: 9,
      total_candidates: 4,
    }),
    "4/4 已审计",
  );
  assert.equal(
    miningEngines.formatMiningEngineAuditProgress({
      processed_candidates: 0,
      total_candidates: 0,
    }),
    "0/0 已审计",
  );
  assert.equal(
    miningEngines.formatMiningEngineAuditProgress({}),
    null,
  );
  assert.equal(
    miningEngines.threatPatternAuditFlowDetail({
      status: "running",
      started_at: "2026-09-04T00:00:00Z",
    }, true),
    "正在统计审计任务",
  );
  assert.equal(
    miningEngines.threatPatternAuditFlowDetail({ status: "success" }, true),
    "历史扫描无进度数据",
  );
  assert.equal(
    miningEngines.threatPatternAuditFlowDetail({
      status: "error",
      error_message: "one task failed",
      processed_candidates: 8,
      total_candidates: 8,
    }, true),
    "8/8 已审计",
  );
  assert.equal(
    miningEngines.threatPatternAuditFlowDetail({
      status: "error",
      error_message: "artifact invalid",
    }, true),
    "artifact invalid",
  );
  assert.equal(
    miningEngines.threatPatternAuditFlowDetail({ status: "pending" }, false),
    "等待威胁分析完成",
  );
});

test("preserves completed task session traces during pool normalization", () => {
  const sessionEvents = [
    {
      sequence: 1,
      phase: "business",
      session_id: "ses_timeout",
      session_attempt: 1,
      outcome: "timeout",
      failure_kind: "timeout",
    },
    {
      sequence: 2,
      phase: "business",
      session_id: "ses_success",
      session_attempt: 2,
      outcome: "success",
    },
  ];

  const pool = runtime.normalizeOpenCodePool({
    scope_id: "scan-1",
    global_running: 0,
    global_queued: 0,
    total_tasks: 1,
    completed_task_count: 1,
    queued_tasks: [],
    completed_tasks: [{
      task_id: "logical-task",
      outcome: "success",
      serve_session_id: "ses_success",
      session_events: sessionEvents,
    }],
    models: [],
    updated_at: "2026-09-02T00:00:00Z",
  });

  assert.ok(pool);
  assert.deepEqual(pool.completed_tasks[0].session_events, sessionEvents);
  assert.equal(pool.completed_tasks.length, 1);
});

test("keeps a newer SSE pool snapshot when an older GET resolves later", () => {
  const live = pool("2026-09-03T00:00:02Z", {
    global_running: 1,
    total_tasks: 1,
    planned_tasks: [{ task_id: "threat" }],
  });
  const staleGet = pool("2026-09-03T00:00:01Z");

  const selected = runtime.selectOpenCodePoolSnapshot(live, staleGet);

  assert.equal(selected.global_running, 1);
  assert.equal(selected.planned_tasks[0].task_id, "threat");
});

test("prefers a higher execution revision even when its timestamp is older", () => {
  const previous = pool("2026-09-03T00:01:00Z", { execution_revision: 2 });
  const replacement = pool("2026-09-03T00:00:00Z", {
    execution_revision: 3,
    global_queued: 1,
  });

  const selected = runtime.selectOpenCodePoolSnapshot(previous, replacement);

  assert.equal(selected.execution_revision, 3);
  assert.equal(selected.global_queued, 1);
});

test("merges incremental completed-task history without accepting stale live state", () => {
  const live = pool("2026-09-03T00:00:03Z", {
    global_running: 1,
    total_tasks: 2,
    completed_task_count: 1,
    completed_tasks: [{ task_id: "first", revision: 1, outcome: "success" }],
  });
  const stale = pool("2026-09-03T00:00:02Z", {
    global_running: 0,
    total_tasks: 2,
    completed_task_count: 2,
    completed_tasks: [{ task_id: "second", revision: 1, outcome: "success" }],
  });

  const selected = runtime.selectOpenCodePoolSnapshot(live, stale);

  assert.equal(selected.global_running, 1);
  assert.equal(selected.completed_task_count, 2);
  assert.deepEqual(
    selected.completed_tasks.map((task) => task.task_id).sort(),
    ["first", "second"],
  );
});

test("only clears a pool snapshot when the caller marks null as authoritative", () => {
  const live = pool("2026-09-03T00:00:03Z", { global_running: 1 });

  assert.equal(runtime.selectOpenCodePoolSnapshot(live, null), live);
  assert.equal(
    runtime.selectOpenCodePoolSnapshot(live, null, { allowClear: true }),
    null,
  );
});
