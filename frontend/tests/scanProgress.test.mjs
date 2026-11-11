import assert from "node:assert/strict";
import test, { after } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
const progress = await server.ssrLoadModule("/src/scanProgress.ts");
const runtime = await server.ssrLoadModule("/src/scanRuntime.ts");
const { ScanProgressPanel } = await server.ssrLoadModule("/src/components/ScanProgressPanel.tsx");
after(() => server.close());

function estimate(overrides = {}) {
  return { progress: 0.35, remaining_seconds: 4800, state: "ready", calculated_at: "2026-11-09T01:00:00Z",
    execution_revision: 2, active: true, ...overrides };
}
function scan(overrides = {}) {
  return runtime.normalizeScanStatus({ scan_id: "s", status: "auditing", execution_revision: 2,
    progress: 0.9, total_candidates: 10, processed_candidates: 9, ...overrides });
}
function text(node) {
  if (typeof node === "string") return node;
  return (Array.isArray(node) ? node : node?.children ?? []).map(text).join("");
}
function render(value, active = progress.hasActiveScanProgress(value)) {
  const root = TestRenderer.create(createElement(ScanProgressPanel, { scan: value, active }));
  const result = { text: text(root.toJSON()), bar: root.root.findByProps({ role: "progressbar" }).props };
  root.unmount();
  return result;
}

test("overall progress and remaining time use the server summary without task history or candidate progress", () => {
  const result = render(scan({ progress_estimate: estimate() }));
  assert.equal(result.text, "整体进度35%预计剩余时间 约 1 小时 20 分钟");
  assert.equal(result.bar["aria-valuenow"], 35);
  assert.doesNotMatch(result.text, /90%|任务数|预计完成|动态|已知/);
});

test("legacy scans, unknown averages and unavailable estimates do not invent a remaining time", () => {
  const legacy = render(scan());
  assert.equal(legacy.bar["aria-valuenow"], undefined);
  assert.match(legacy.text, /估算中/);
  assert.match(render(scan({ progress_estimate: estimate({ state: "estimating", remaining_seconds: null }) })).text, /预计剩余时间 估算中/);
  for (const extra of [{ state: "unavailable", remaining_seconds: null }, {}]) {
    assert.match(render(scan({ agent_online: false, progress_estimate: estimate(extra) })).text, /暂无法估算/);
  }
  for (const status of ["error", "cancelled"]) {
    const result = render(scan({ status }));
    assert.match(result.text, /暂无法估算/);
    assert.doesNotMatch(result.text, /100%|已完成/);
    const cached = render(scan({ status, progress_estimate: estimate() }));
    assert.match(cached.text, /暂无法估算/, "terminal state overrides a cached active estimate immediately");
    assert.doesNotMatch(cached.text, /约 1 小时/);
  }
});

test("a newer forecast may lower overall progress and extend the remaining duration", () => {
  const previous = scan({ progress_estimate: estimate({ progress: 0.6, remaining_seconds: 600 }) });
  const larger = scan({ progress_estimate: estimate({ progress: 0.45, remaining_seconds: 1800,
    calculated_at: "2026-11-09T01:01:00Z" }) });
  const merged = runtime.mergeScanOverview(previous, larger, previous);
  assert.equal(render(merged).bar["aria-valuenow"], 45);
  assert.match(render(merged).text, /预计剩余时间 约 30 分钟/);
});

test("completion and continuing independent work have distinct progress states", () => {
  assert.equal(render(scan({ status: "complete" })).text, "整体进度100%预计剩余时间 0 分钟");
  const done = estimate({ progress: 1, remaining_seconds: 0, state: "complete", active: false });
  assert.equal(render(scan({ status: "complete", progress_estimate: done })).bar["aria-valuenow"], 100);
  assert.equal(render(scan({ status: "complete", progress_estimate: estimate({ progress: 0.999 }) })).bar["aria-valuenow"], 99);
  assert.match(render(scan({ status: "complete" }), true).text, /估算中/);
});

test("remaining duration rounds conservatively without displaying a seconds countdown", () => {
  assert.equal(progress.formatRemainingTime(0), "约 1 分钟内");
  assert.equal(progress.formatRemainingTime(59), "约 1 分钟内");
  assert.equal(progress.formatRemainingTime(61), "约 2 分钟");
  assert.equal(progress.formatRemainingTime(3600), "约 1 小时");
});

test("normalization ignores malformed or absent summaries and clamps the progress", () => {
  for (const value of [null, undefined, {}, estimate({ remaining_seconds: -1 }), estimate({ progress: NaN }),
    estimate({ calculated_at: "bad" }), estimate({ state: "invalid" })]) {
    assert.equal(progress.normalizeScanProgressEstimate(value), undefined);
  }
  assert.equal(progress.normalizeScanProgressEstimate(estimate({ progress: 1.2 })).progress, 1);
});

test("late GET cannot overwrite newer same-execution estimates and new executions clear missing estimates", () => {
  const first = scan({ progress_estimate: estimate() });
  const current = scan({ progress_estimate: estimate({ progress: 0.6, calculated_at: "2026-11-09T01:02:00Z" }) });
  const merged = runtime.mergeScanOverview(current, first, first);
  assert.equal(merged.progress_estimate.progress, 0.6);
  assert.equal(merged.progress, 0.9, "candidate progress keeps its independent meaning");
  assert.equal(runtime.mergeScanOverview(current, scan()).progress_estimate.progress, 0.6);
  assert.equal(runtime.mergeScanOverview(current, scan({ execution_revision: 3 })).progress_estimate, undefined);
  const next = scan({ execution_revision: 3, progress_estimate: estimate({ execution_revision: 3,
    calculated_at: "2026-11-09T00:00:00Z", progress: 0.2 }) });
  assert.equal(runtime.mergeScanOverview(current, next).progress_estimate.progress, 0.2);
  assert.equal(runtime.mergeScanOverview(next, current), next);
});

test("overview refresh remains enabled for known work after the main scan ends", () => {
  const ended = scan({ status: "complete" });
  assert.equal(progress.hasActiveScanProgress(ended), false);
  assert.equal(progress.hasActiveScanProgress(ended, { status: "running" }), true);
  assert.equal(progress.hasActiveScanProgress({ ...ended, progress_estimate: estimate() }), true);
  assert.equal(progress.hasActiveScanProgress({ ...ended, validations: [{ status: "queued" }] }), true);
  const pool = { models: [], global_running: 0, global_queued: 0, planned_tasks: [{ planned_task_id: "p" }] };
  assert.equal(progress.hasActiveScanProgress({ ...ended, opencode_pool: pool }), true);
});
