import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement, useState } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true, hmr: false } });
const client = await server.ssrLoadModule("/src/api/client.ts");
const { useScanSSE } = await server.ssrLoadModule("/src/hooks/useScanSSE.ts");
const { normalizeScanStatus } = await server.ssrLoadModule("/src/scanRuntime.ts");
const originalAdapter = client.api.defaults.adapter;
const streams = [], roots = [];
globalThis.localStorage = { getItem: () => null };
globalThis.window = { setTimeout, clearTimeout, location: { origin: "http://localhost" } };
globalThis.document = Object.assign(new EventTarget(), { hidden: false });
globalThis.EventSource = class extends EventTarget {
  constructor() { super(); streams.push(this); }
  close() { this.closed = true; }
  emit(type, data) { this.dispatchEvent(new MessageEvent(type, { data: JSON.stringify(data) })); }
};
afterEach(async () => {
  await act(async () => roots.splice(0).forEach((root) => root.unmount()));
  streams.length = 0;
  document.hidden = false;
  client.api.defaults.adapter = originalAdapter;
  client.setPublicScanAccess(null);
});
after(async () => {
  for (const key of ["window", "document", "localStorage", "EventSource"]) delete globalThis[key];
  await server.close();
});

const wait = (ms = 200) => new Promise((resolve) => setTimeout(resolve, ms));
const deferred = () => { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; };
const finding = (index) => ({ vuln_index: index, file: "src/a.c", line: index + 1, function: "parse", description: "finding " + index,
  vuln_type: "oob", severity: "high", ai_analysis: "report", confirmed: true });
function fixture(scanId = "s") {
  const vulnerabilities = Array.from({ length: 120 }, (_, index) => finding(index));
  const scan = normalizeScanStatus({ scan_id: scanId, status: "auditing", execution_revision: 1,
    processed_candidates: 1, total_candidates: 120, progress: 1 / 120,
    vulnerabilities, candidates: [], events: [], validations: [], threat_audit_tasks: [], threat_pattern_audit_tasks: [],
    detail_counts: { vulnerabilities: 120 },
    detail_pages: { vulnerabilities_next_cursor: null, candidates_next_cursor: null, events_next_cursor: null,
      validations_next_cursor: null, threat_tasks_next_cursor: null, pattern_tasks_next_cursor: null },
  });
  const review = { scan_id: scanId, review_id: "review-" + scanId, status: "running", total: 120, processed: 1,
    results: vulnerabilities.map(({ vuln_index }) => ({ vuln_index, verdict: "tp", reason: "review" })), next_cursor: null };
  return { scan, review, index: { status: "complete" } };
}
function installApi(value, intercept = async () => undefined) {
  const calls = [];
  client.api.defaults.adapter = async (config) => {
    calls.push(config);
    let data = await intercept(config);
    if (data === undefined) {
      const after = config.params?.after ?? -1;
      const page = (items) => {
        const rows = items.filter((item) => item.vuln_index > after).slice(0, 50);
        const cursor = rows.at(-1)?.vuln_index;
        const more = items.some((item) => item.vuln_index > cursor);
        return { items: rows, next_cursor: more ? cursor : null, has_more: more };
      };
      if (config.url.endsWith("/fp-review/overview")) data = { ...value.review, results: [] };
      else if (config.url.endsWith("/overview")) data = { ...value.scan, vulnerabilities: [], candidates: [], validations: [] };
      else if (config.url.endsWith("/index-status")) data = value.index;
      else if (config.url.endsWith("/vulnerabilities")) {
        const result = page(value.scan.vulnerabilities);
        data = { ...result, items: result.items.map((item) => ({ index: item.vuln_index, vulnerability: item })) };
      } else if (config.url.endsWith("/fp-review/results")) data = { ...page(value.review.results), vulnerabilities: [] };
      else if (config.url.includes("/details/vulnerabilities/")) data = value.scan.vulnerabilities[Number(config.url.split("/").at(-1))];
      else if (config.url.includes("/details/fp-review/")) data = value.review.results[Number(config.url.split("/").at(-1))];
      else if (/\/(candidates|validations|threat-audit-tasks|threat-pattern-audit-tasks|events)$/.test(config.url)) data = { items: [], next_cursor: null };
      else assert.fail("Unexpected request: " + config.url);
    }
    return { config, data, status: 200, statusText: "OK", headers: {} };
  };
  return calls;
}
async function mount(value, handlers = {}) {
  const observed = { resultRefreshes: 0 };
  function Harness({ scanId = value.scan.scan_id }) {
    const [scan, setScan] = useState(value.scan);
    const [review, setReview] = useState(value.review);
    const [index, setIndex] = useState(value.index);
    const state = useScanSSE(scanId, {
      onStateRefresh: () => { observed.resultRefreshes += 1; },
      onScanVulnerability: ({ index, vulnerability }) => setScan((previous) => ({ ...previous,
        vulnerabilities: previous.vulnerabilities.map((item) => item.vuln_index === index ? { ...vulnerability, vuln_index: index } : item) })),
      ...handlers,
    }, { getScan: () => scan, getFpReview: () => review, setScan, setFpReview: setReview, setIndexStatus: setIndex });
    Object.assign(observed, { scan, review, index, ...state });
    return null;
  }
  let root;
  await act(async () => { root = create(createElement(Harness)); });
  roots.push(root);
  return { observed, root, Harness };
}
async function notify(...events) {
  await act(async () => {
    events.forEach(([type, data]) => streams.at(-1).emit(type, data));
    await wait();
  });
}
const count = (calls, suffix) => calls.filter((call) => call.url.endsWith(suffix)).length;

function patternFixture() {
  const value = fixture();
  value.scan.threat_pattern_audit_tasks = Array.from({ length: 150 }, (_, index) => ({
    task_id: String(index).padStart(4, "0"), scan_id: "s", status: "cancelled", created_at: "2026-11-16T00:00:00Z",
  }));
  return value;
}
function patternPages(value, config) {
  if (!config.url.endsWith("/threat-pattern-audit-tasks")) return undefined;
  const offset = Number(config.params?.cursor ?? 0);
  const end = offset + 50;
  return { items: value.scan.threat_pattern_audit_tasks.slice(offset, end), next_cursor: end < 150 ? String(end) : null };
}

test("a resumed execution ignores late engine terminal reports, including pending status batches", async () => {
  const value = fixture();
  installApi(value);
  const runs = [];
  await mount(value, { onMiningEngineRun: (event) => runs.push(event.run.status) });
  const report = (execution_revision, status) => ["mining_engine_run", {
    execution_revision, run: { engine_id: "threat_pattern_audit", status }, runs: [],
  }];
  await notify(["scan_status", { status: "auditing", execution_revision: 2 }], report(1, "cancelled"));
  assert.deepEqual(runs, []);
  await notify(report(2, "running"));
  assert.deepEqual(runs, ["running"]);
});

test("spaced task cancellations share one refresh per second without rereading result bodies", async () => {
  const value = patternFixture(), calls = installApi(value, (config) => patternPages(value, config));
  const { observed } = await mount(value);
  for (let index = 0; index < 6; index += 1) {
    await notify(["resource_changed", { resource: "threat-pattern-audit-tasks", change: "task_status", execution_revision: 1 }]);
  }
  await act(async () => { await wait(250); });
  assert.equal(count(calls, "/threat-pattern-audit-tasks"), 6);
  assert.equal(count(calls, "/overview"), 2);
  assert.equal(observed.resultRefreshes, 0);
  assert.equal(calls.length, 8);
});

test("a thousand task notifications form one batch and delegated iterative pages avoid generic reads", async () => {
  const value = patternFixture(), calls = installApi(value, (config) => patternPages(value, config));
  let taskRefreshes = 0;
  await mount(value, { ownsPatternTaskPages: () => true,
    onDetailRefreshState: (resources, refreshing) => { if (refreshing && resources.includes("threat-pattern-audit-tasks")) taskRefreshes += 1; } });
  await notify(...Array.from({ length: 1000 }, () => ["resource_changed", {
    resource: "threat-pattern-audit-tasks", change: "task_status",
  }]));
  assert.equal(taskRefreshes, 1);
  assert.equal(count(calls, "/threat-pattern-audit-tasks"), 0);
  assert.equal(count(calls, "/overview"), 1);
});

test("inactive task caches stay dirty until visited while summaries settle normally", async () => {
  const value = patternFixture(), calls = installApi(value, (config) => patternPages(value, config));
  let active = [];
  const { observed } = await mount(value, { activeTaskCollections: () => active });
  const cached = observed.scan.threat_pattern_audit_tasks;
  value.scan = { ...value.scan, threat_pattern_audit_tasks: value.scan.threat_pattern_audit_tasks.map((task) => ({ ...task, status: "completed" })) };
  await notify(["resource_changed", { resource: "threat-pattern-audit-tasks", change: "task_status", execution_revision: 1 }]);
  await act(async () => { await wait(1050); });
  assert.equal(count(calls, "/threat-pattern-audit-tasks"), 0);
  assert.equal(count(calls, "/overview"), 1);
  assert.equal(observed.scan.threat_pattern_audit_tasks, cached);
  active = ["threat-pattern-audit-tasks"];
  await act(async () => { observed.refreshDetails([]); await wait(); });
  assert.equal(count(calls, "/threat-pattern-audit-tasks"), 3);
  assert.equal(observed.scan.threat_pattern_audit_tasks[0].status, "completed");
  active = [];
  await act(async () => { observed.refreshDetails([]); await wait(); });
  active = ["threat-pattern-audit-tasks"];
  await act(async () => { observed.refreshDetails([]); await wait(); });
  assert.equal(count(calls, "/threat-pattern-audit-tasks"), 3, "a clean cache does not refresh on every visit");
  assert.equal(observed.resultRefreshes, 0);
});

test("iterative notices do not mark the shared pattern cache clean or refresh it on unrelated pages", async () => {
  const value = patternFixture(), calls = installApi(value, (config) => patternPages(value, config));
  let active = ["threat-pattern-audit-tasks"], delegated = true, taskRefreshes = 0;
  const { observed } = await mount(value, {
    activeTaskCollections: () => active, ownsPatternTaskPages: () => delegated,
    onDetailRefreshState: (resources, refreshing) => {
      if (refreshing && resources.includes("threat-pattern-audit-tasks")) taskRefreshes += 1;
    },
  });
  await notify(["resource_changed", { resource: "threat-pattern-audit-tasks", change: "task_status" }]);
  await act(async () => { await wait(1050); });
  assert.equal(taskRefreshes, 1, "delegated dirtiness must not schedule repeatedly");
  assert.equal(count(calls, "/threat-pattern-audit-tasks"), 0);
  active = []; delegated = false;
  await act(async () => { observed.refreshDetails([]); await wait(); });
  assert.equal(count(calls, "/threat-pattern-audit-tasks"), 0);
  active = ["threat-pattern-audit-tasks"];
  await act(async () => { observed.refreshDetails([]); await wait(); });
  assert.equal(count(calls, "/threat-pattern-audit-tasks"), 3);
  assert.equal(taskRefreshes, 2);
});

test("hidden resync and a new execution retain deferred task refreshes and reject old notices", async () => {
  const value = patternFixture(), calls = installApi(value, (config) => patternPages(value, config));
  let active = [];
  const { observed } = await mount(value, { activeTaskCollections: () => active });
  document.hidden = true;
  await notify(["resync_required", {}]);
  assert.equal(calls.length, 0);
  value.scan = { ...value.scan, execution_revision: 2, status: "auditing" };
  await act(async () => { document.hidden = false; document.dispatchEvent(new Event("visibilitychange")); await wait(400); });
  assert.equal(observed.scan.execution_revision, 2);
  assert.equal(count(calls, "/threat-pattern-audit-tasks"), 0);
  await notify(["scan_finish", { status: "cancelled", execution_revision: 2 }]);
  await act(async () => { await wait(800); });
  active = ["threat-pattern-audit-tasks"];
  await act(async () => { observed.refreshDetails([]); await wait(); });
  assert.equal(count(calls, "/threat-pattern-audit-tasks"), 3, "new executions refresh the loaded task span on entry");
  const before = calls.length;
  await notify(["resource_changed", { resource: "threat-pattern-audit-tasks", change: "task_status", execution_revision: 1 }]);
  assert.equal(calls.length, before);
});

test("late task invalidation gets a trailing refresh while light progress remains independent", async () => {
  const value = patternFixture(), pending = deferred();
  let block = true;
  const calls = installApi(value, async (config) => {
    if (block && config.url.endsWith("/threat-pattern-audit-tasks")) { block = false; await pending.promise; }
    return patternPages(value, config);
  });
  const { observed } = await mount(value);
  await notify(["resource_changed", { resource: "threat-pattern-audit-tasks", change: "task_status" }]);
  value.scan = { ...value.scan, processed_candidates: 12 };
  await notify(["resource_changed", { resource: "threat-pattern-audit-tasks", change: "task_status" }],
    ["resource_changed", { resource: "overview" }]);
  assert.equal(observed.scan.processed_candidates, 12);
  assert.equal(count(calls, "/threat-pattern-audit-tasks"), 1);
  await act(async () => { pending.resolve(); await wait(1000); });
  assert.equal(count(calls, "/threat-pattern-audit-tasks"), 6);
  assert.equal(observed.scan.threat_pattern_audit_tasks.length, 150);
});

test("stop reconciliation and duplicate final events do not trigger full detail reloads", async () => {
  const value = fixture(), calls = installApi(value);
  const { observed } = await mount(value);
  await act(async () => { observed.refreshStopped(); await wait(); });
  assert.deepEqual(calls.map((call) => call.url), ["/api/v2/scans/s/overview"]);
  calls.length = 0;
  await notify(["scan_finish", { status: "cancelled", error_message: null, execution_revision: 1 }],
    ["scan_finish", { status: "cancelled", error_message: null, execution_revision: 1 }]);
  assert.equal(count(calls, "/overview"), 1);
  await notify(["scan_finish", { status: "cancelled", error_message: null, execution_revision: 1 }]);
  assert.equal(count(calls, "/overview"), 1);
  assert.equal(calls.length, 1);
  await notify(["resource_changed", { resource: "threat-pattern-audit-tasks", change: "task_status", execution_revision: 0 }]);
  assert.equal(calls.length, 1, "old execution notices cannot revive old task work");
});

test("old resource notices are discarded before a newer batched status has rendered", async () => {
  const value = fixture(), calls = installApi(value);
  await mount(value);
  await notify(["scan_status", { execution_revision: 2, status: "auditing" }],
    ["resource_changed", { resource: "threat-pattern-audit-tasks", change: "task_status", execution_revision: 1 }]);
  assert.equal(calls.length, 0);
});

for (const kind of ["authenticated", "integration", "shared"]) {
  test(`overview invalidations read only one overview and preserve loaded details (${kind})`, async () => {
    if (kind !== "authenticated") client.setPublicScanAccess({ scanId: "s", token: "access-token", kind });
    const value = fixture(), calls = installApi(value);
    const { observed } = await mount(value);
    const findings = observed.scan.vulnerabilities, review = observed.review;
    value.scan = { ...value.scan, processed_candidates: 35, progress: 35 / 120,
      progress_estimate: { active: true, execution_revision: 1, state: "ready", progress: 0.4,
        remaining_seconds: 600, calculated_at: "2026-11-11T01:00:00Z" } };
    await notify(...Array.from({ length: 20 }, () => ["resource_changed", { resource: "overview" }]));
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, `/api/${kind === "authenticated" ? "v2" : kind === "shared" ? "shared" : "public"}/scans/s/overview`);
    if (kind !== "authenticated") assert.equal(calls[0].params.token, "access-token");
    assert.equal(observed.scan.processed_candidates, 35);
    assert.deepEqual(observed.scan.progress_estimate, value.scan.progress_estimate);
    assert.equal(observed.scan.vulnerabilities, findings);
    assert.equal(observed.review, review);
    assert.equal(observed.resultRefreshes, 0, "pool overview changes must not invalidate audit results");
  });
}

test("connection, resync and fallback share one state batch and one FP overview", async () => {
  const value = fixture(), calls = installApi(value);
  const { observed } = await mount(value);
  await act(async () => {
    streams[0].onopen();
    streams[0].emit("resync_required", { reason: "connected" });
    observed.refreshOverview();
    await wait(400);
  });
  assert.equal(count(calls, "/scans/s/overview"), 1);
  assert.equal(count(calls, "/index-status"), 1);
  assert.equal(count(calls, "/fp-review/overview"), 1);
  assert.equal(count(calls, "/vulnerabilities"), 3);
  assert.equal(count(calls, "/fp-review/results"), 3);
  assert.equal(observed.scan.vulnerabilities.length, 120);
  assert.equal(observed.review.results.length, 120);
});

test("healthy visibility recovery reads light state and only the changed hidden detail", async () => {
  const value = fixture(), calls = installApi(value);
  const { observed } = await mount(value);
  document.hidden = true;
  value.scan = { ...value.scan, vulnerabilities: value.scan.vulnerabilities.map((item) => item.vuln_index === 7
    ? { ...item, description: "edited while hidden" } : item) };
  await notify(["resource_changed", { resource: "vulnerabilities", index: 7 }]);
  assert.equal(calls.length, 0);
  await act(async () => {
    document.hidden = false;
    document.dispatchEvent(new Event("visibilitychange"));
    await wait();
  });
  assert.equal(count(calls, "/vulnerabilities"), 0);
  assert.equal(count(calls, "/fp-review/results"), 0);
  assert.equal(count(calls, "/details/vulnerabilities/7"), 1);
  assert.equal(count(calls, "/scans/s/overview"), 1);
  assert.equal(observed.scan.vulnerabilities[7].description, "edited while hidden");
});

for (const reason of ["disconnect", "explicit resync"]) {
  test(`${reason} while hidden still restores all details`, async () => {
    const value = fixture(), calls = installApi(value);
    await mount(value);
    document.hidden = true;
    if (reason === "disconnect") streams[0].onerror();
    else streams[0].emit("resync_required", { reason: "subscriber_overflow" });
    await act(async () => {
      if (reason === "disconnect") streams[0].onopen();
      document.hidden = false;
      document.dispatchEvent(new Event("visibilitychange"));
      await wait();
    });
    assert.equal(count(calls, "/vulnerabilities"), 3);
    assert.equal(count(calls, "/fp-review/overview"), 1);
    assert.equal(count(calls, "/scans/s/overview"), 1);
  });
}

test("slow finding pagination cannot block candidate and FP stage progress", async () => {
  const value = fixture(), pending = deferred();
  let hold = true;
  const calls = installApi(value, (config) => hold && config.url.endsWith("/vulnerabilities") ? pending.promise : undefined);
  const { observed } = await mount(value);
  await notify(["resource_changed", { resource: "vulnerabilities" }]);
  value.scan = { ...value.scan, processed_candidates: 55 };
  value.review = { ...value.review, processed: 45 };
  await notify(["resource_changed", { resource: "overview" }], ["resource_changed", { resource: "fp-review", index: 7, change: "stage_output" }]);
  assert.equal(observed.scan.processed_candidates, 55);
  assert.equal(observed.review.processed, 45);
  assert.equal(count(calls, "/fp-review/overview"), 1);
  hold = false;
  await act(async () => { pending.resolve({ items: [], next_cursor: null }); await wait(); });
  assert.equal(count(calls, "/details/fp-review/7"), 1, "detail notices received during pagination are retained");
});

test("an overview invalidated during a read gets one follow-up with the newer progress", async () => {
  const value = fixture(), pending = deferred();
  let hold = true;
  const calls = installApi(value, (config) => hold && config.url.endsWith("/scans/s/overview") ? pending.promise : undefined);
  const { observed } = await mount(value);
  await notify(["resource_changed", { resource: "overview" }]);
  await notify(["resource_changed", { resource: "overview" }], ["resource_changed", { resource: "overview" }]);
  assert.equal(calls.length, 1);
  const old = value.scan;
  value.scan = { ...value.scan, processed_candidates: 85 };
  hold = false;
  await act(async () => { pending.resolve(old); await wait(); });
  assert.equal(calls.length, 2);
  assert.equal(observed.scan.processed_candidates, 85);
});

test("scan changes abort owned FP and index reads without cancelling another overview consumer", async () => {
  const value = fixture(), pending = deferred();
  const calls = installApi(value, () => pending.promise);
  const { root, Harness, observed } = await mount(value);
  await act(async () => { observed.refreshOverview(); await wait(); });
  const shared = client.getScanOverviewRequest("s", value.scan);
  await act(async () => root.update(createElement(Harness, { scanId: "next" })));
  assert.ok(calls.filter((call) => !call.url.endsWith("/scans/s/overview")).every((call) => call.signal.aborted));
  assert.equal(calls.find((call) => call.url.endsWith("/scans/s/overview")).signal, undefined);
  await act(async () => pending.resolve({ ...value.scan, processed_candidates: 99 }));
  assert.equal((await shared.promise).processed_candidates, 99);
  assert.equal(observed.scan.processed_candidates, 1, "a disposed hook must not apply its old response");
});

for (const newerExecution of [true, false]) {
  test(`late FP-only overview preserves ${newerExecution ? "a new review execution" : "same-execution live progress"}`, async () => {
    const { refreshFullState } = await server.ssrLoadModule("/src/hooks/scanSSE/refreshState.ts");
    const { createFpReviewHandlers } = await server.ssrLoadModule("/src/features/scanDetail/events/createFpReviewHandlers.ts");
    const initial = { ...fixture().review, execution_revision: 1, status: newerExecution ? "error" : "running" };
    let current = initial;
    const setFpReview = (update) => { current = typeof update === "function" ? update(current) : update; };
    const setters = { getScan: () => fixture().scan, getFpReview: () => current, setFpReview, setScan() {}, setIndexStatus() {} };
    const handlers = createFpReviewHandlers({ scanId: "s", state: { setFpReview }, resources: { scheduleOverviewSummaryRefresh() {} } });
    const pending = deferred();
    const refresh = refreshFullState("s", setters, () => true, new Set(["fp-review"]), new AbortController().signal, pending.promise);
    const revision = newerExecution ? 2 : 1;
    if (newerExecution) handlers.onFpReviewStarted({ review_id: initial.review_id, execution_revision: 2, status: "running", total: 120, processed: 1 });
    handlers.onFpReviewProgress({ review_id: initial.review_id, execution_revision: revision, total: 120, processed: 2, vuln_index: 2 });
    if (newerExecution) {
      handlers.onFpReviewStarted({ review_id: initial.review_id, execution_revision: 1, status: "running", total: 120, processed: 0 });
      handlers.onFpReviewFinish({ review_id: initial.review_id, execution_revision: 1, status: "error", error_message: "old failure" });
      handlers.onFpReviewProgress({ review_id: initial.review_id, execution_revision: 1, total: 120, processed: 0, vuln_index: 0 });
    }
    pending.resolve({ ...initial, results: [] });
    await refresh;
    assert.equal(current.execution_revision, revision);
    assert.equal(current.status, "running");
    assert.equal(current.processed, 2);
    assert.equal(current.results, initial.results, "overview must retain loaded results");
    handlers.onFpReviewFinish({ review_id: initial.review_id, execution_revision: revision, status: "complete", error_message: null });
    assert.equal(current.status, "complete");
    assert.equal(current.execution_revision, revision);
  });
}
