import assert from "node:assert/strict";
import test, { after } from "node:test";
import { createServer } from "vite";

const server = await createServer({
  appType: "custom",
  logLevel: "silent",
  server: { middlewareMode: true },
});
const runtime = await server.ssrLoadModule("/src/scanRuntime.ts");

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
