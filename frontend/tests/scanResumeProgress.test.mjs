import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
const client = await server.ssrLoadModule("/src/api/client.ts");
const { default: ScanStatus } = await server.ssrLoadModule("/src/components/ScanStatus.tsx");
const { ThemeProvider } = await server.ssrLoadModule("/src/theme/ThemeProvider.tsx");
const originalAdapter = client.api.defaults.adapter;
const originalSetInterval = globalThis.setInterval;
const originalClearInterval = globalThis.clearInterval;
const timers = new Map();
const roots = [];
const streams = [];
globalThis.setInterval = (callback, delay) => {
  const id = Symbol("poll");
  timers.set(id, { callback, delay });
  return id;
};
globalThis.clearInterval = (id) => timers.delete(id);
globalThis.localStorage = { getItem: () => null, setItem() {} };
globalThis.window = Object.assign(new EventTarget(), {
  localStorage, setTimeout, clearTimeout, setInterval, clearInterval,
  location: { origin: "http://localhost" },
});
globalThis.document = Object.assign(new EventTarget(), {
  hidden: false, documentElement: { dataset: {}, style: {} },
});
globalThis.EventSource = class extends EventTarget {
  constructor() { super(); streams.push(this); }
  close() {}
  emit(type, data) { this.dispatchEvent(new MessageEvent(type, { data: JSON.stringify(data) })); }
};

afterEach(async () => {
  await act(async () => roots.splice(0).forEach((root) => root.unmount()));
  assert.equal(timers.size, 0);
  streams.length = 0;
  client.api.defaults.adapter = originalAdapter;
});
after(async () => {
  globalThis.setInterval = originalSetInterval;
  globalThis.clearInterval = originalClearInterval;
  delete globalThis.window;
  delete globalThis.document;
  delete globalThis.localStorage;
  delete globalThis.EventSource;
  await server.close();
});

function text(node) {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(text).join("");
  return text(node?.children ?? node?.props?.children ?? "");
}
function assertProgress(root, completed) {
  const expected = `${completed}/100 候选点已审计`;
  const nodes = root.root.findAllByType("button").filter((node) => text(node).includes(expected));
  assert.ok(nodes.length >= 2, "Sidebar and home diagram must both show " + expected + ": " + text(root.toJSON()));
}
function overview(completed = 100, revision = 1) {
  const complete = revision === 1;
  return {
    scan_id: "s", execution_revision: revision, status: complete ? "complete" : "auditing",
    progress: completed / 100, total_candidates: 100, processed_candidates: completed,
    static_analysis_done: true, scan_items: ["npd"], auto_fp_review: false,
    agent_online: true, can_continue: complete, continuable_task_count: 20,
    mining_engines: [{ engine_id: "static_candidate", engine_label: "static", enabled: true }],
    mining_engine_runs: [{ engine_id: "static_candidate", engine_label: "static", status: complete ? "success" : "running" }],
    detail_counts: { candidates: 100, candidate_audit_success: Math.min(completed, 80),
      candidate_audit_failed: complete ? 20 : 0, candidate_audit_pending: 100 - completed },
    opencode_pool: null,
  };
}
function installApi(initial = overview()) {
  const state = { overview: initial, intercept: null };
  client.api.defaults.adapter = async (config) => {
    let data;
    if (config.url === "/api/mining-engines") data = { engines: [] };
    else if (config.url.includes("checkers")) data = [];
    else if (config.url.endsWith("/fp-review/overview")) data = { review_id: "r", scan_id: "s", status: "complete", total: 0, processed: 0, results: [] };
    else if (config.url.endsWith("/overview")) data = state.intercept ? await state.intercept() : structuredClone(state.overview);
    else if (config.url.endsWith("/resume")) { state.overview = overview(80, 2); data = { scan_id: "s" }; }
    else if (config.url.endsWith("/index-status")) data = { status: "skipped" };
    else if (config.url.endsWith("/git_history")) data = [];
    else if (/\/(events|event-history|candidates|vulnerabilities|threat-audit-tasks|validations|results|tasks)$/.test(config.url)) {
      data = { items: [], vulnerabilities: [], next_cursor: null, has_more: false };
    } else assert.fail("Unexpected request: " + config.url);
    return { config, data, status: 200, statusText: "OK", headers: {} };
  };
  return state;
}
async function mount() {
  let root;
  await act(async () => {
    root = create(createElement(ThemeProvider, null, createElement(ScanStatus, { scanId: "s", onBack() {} })));
  });
  roots.push(root);
  return root;
}
async function notify(...events) {
  await act(async () => {
    for (const [type, data] of events) streams.at(-1).emit(type, data);
    await new Promise((resolve) => setTimeout(resolve, 110));
  });
}
async function poll(delay) {
  await act(async () => {
    const callbacks = [...timers.values()].filter((timer) => timer.delay === delay);
    assert.ok(callbacks.length, "Missing poll: " + delay);
    callbacks.forEach(({ callback }) => callback());
  });
}

test("completed scan resumes and both flow views advance despite pool and old execution events", async () => {
  const state = installApi();
  const root = await mount();
  assertProgress(root, 100);
  const resume = root.root.findAllByType("button").find((node) => text(node).includes("续扫"));
  assert.ok(resume);
  await act(async () => resume.props.onClick());
  assertProgress(root, 80);
  await notify(["scan_status", { execution_revision: 2, status: "auditing", processed_candidates: 81, total_candidates: 100 }]);
  assertProgress(root, 81);
  await notify(
    ["scan_status", { execution_revision: 2, opencode_pool: { execution_revision: 2, global_running: 1, completed_task_count: 120 } }],
    ["scan_status", { execution_revision: 1, status: "complete", processed_candidates: 100, total_candidates: 100 }],
    ["scan_finish", { execution_revision: 1, status: "complete", error_message: null }],
  );
  assertProgress(root, 81);
  state.overview = overview(82, 2);
  await notify(["scan_status", { execution_revision: 2, processed_candidates: 82, total_candidates: 100 }]);
  assertProgress(root, 82);
});

test("late overview from the current execution cannot roll back a newer SSE count", async () => {
  const state = installApi(overview(80, 2));
  const root = await mount();
  let resolve;
  state.intercept = () => new Promise((done) => { resolve = done; });
  await poll(30_000);
  await notify(["scan_status", { execution_revision: 2, processed_candidates: 81, total_candidates: 100 }]);
  assertProgress(root, 81);
  await act(async () => resolve(overview(80, 2)));
  assertProgress(root, 81);
  state.intercept = null;
  state.overview = overview(82, 2);
  await poll(30_000);
  assertProgress(root, 82);
});

test("overview polling advances both views when SSE is lost and details are not loaded", async () => {
  const state = installApi(overview(80, 2));
  const root = await mount();
  state.overview = overview(81, 2);
  await poll(10_000);
  assertProgress(root, 81);
  state.overview = overview(82, 2);
  await poll(30_000);
  assertProgress(root, 82);
});

test("batched SSE never mixes old completion fields into a new execution", async () => {
  installApi();
  const root = await mount();
  await notify(
    ["scan_status", { execution_revision: 1, status: "complete", progress: 1, processed_candidates: 100, total_candidates: 100 }],
    ["scan_status", { execution_revision: 2, opencode_pool: { execution_revision: 2, global_running: 1 } }],
    ["scan_status", { execution_revision: 2, status: "auditing", processed_candidates: 80, total_candidates: 100 }],
  );
  assertProgress(root, 80);
});

test("partial static failures survive SSE completion and a fresh overview", async () => {
  const state = installApi(overview(80, 2));
  const root = await mount();
  const failure = {
    checker_name: "loop_var_misuse", checker_label: "循环变量误用",
    error: "worker stopped: 0xC0000005 ACCESS_VIOLATION\ncrash detail", exit_code: 3221225477,
  };
  const run = { ...state.overview.mining_engine_runs[0], static_analysis_errors: [failure] };
  await notify(["mining_engine_run", { execution_revision: 2, run, runs: [run] }]);
  const assertWarning = (view) => {
    const alert = view.root.findAllByProps({ role: "alert" }).find((node) => text(node).includes("循环变量误用"));
    assert.ok(alert, text(view.toJSON()));
    assert.match(alert.props.className, /amber/);
    assert.match(text(alert), /完成（部分规则失败）/);
    assert.match(text(alert), /3221225477/);
    assert.match(text(alert), /0xC0000005 ACCESS_VIOLATION/);
    assert.match(text(alert), /crash detail/);
    const staticNodes = view.root.findAllByType("button").filter((node) =>
      text(node).includes("静态分析") && text(node).includes("1 条规则失败"));
    assert.ok(staticNodes.length >= 2, "Sidebar and home must both retain the warning");
    assert.ok(staticNodes.every((node) => text(node).includes("完成但有失败")));
  };
  assertWarning(root);
  assertProgress(root, 80);
  state.overview = { ...overview(100, 2), status: "complete", mining_engine_runs: [{ ...run, status: "success" }] };
  await notify(
    ["mining_engine_run", { execution_revision: 2, run: state.overview.mining_engine_runs[0], runs: state.overview.mining_engine_runs }],
    ["scan_status", { execution_revision: 2, status: "complete", processed_candidates: 100, total_candidates: 100 }],
    ["scan_finish", { execution_revision: 2, status: "complete", error_message: null }],
  );
  assertWarning(root);
  assertProgress(root, 100);
  const reloaded = await mount();
  assertWarning(reloaded);
  assertProgress(reloaded, 100);
});

test("all failed static rules stay failed when the overall scan completes", async () => {
  const value = overview(0);
  value.static_analysis_done = false;
  value.total_candidates = 0;
  value.detail_counts = { candidates: 0 };
  value.mining_engine_runs[0] = {
    ...value.mining_engine_runs[0], status: "error",
    static_analysis_errors: [{ checker_name: "loop_var_misuse", error: "native crash" }],
  };
  installApi(value);
  const root = await mount();
  const staticNodes = root.root.findAllByType("button").filter((node) =>
    text(node).includes("静态分析") && text(node).includes("1 条规则失败"));
  assert.ok(staticNodes.length >= 2);
  assert.ok(staticNodes.every((node) => text(node).includes("执行失败")));
  await act(async () => staticNodes[0].props.onClick());
  assert.doesNotMatch(text(root.toJSON()), /完成（部分规则失败）/);
  assert.match(text(root.toJSON()), /存在失败的静态规则/);
  assert.match(text(root.toJSON()), /异常/);
});
