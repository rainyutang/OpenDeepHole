import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
const client = await server.ssrLoadModule("/src/api/client.ts");
const runtime = await server.ssrLoadModule("/src/scanRuntime.ts");
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
    detail_counts: { candidates: 100, candidate_audit_success: complete ? Math.max(0, completed - 20) : completed,
      candidate_audit_failed: complete ? Math.min(20, completed) : 0, candidate_audit_pending: 100 - completed },
    opencode_pool: null,
  };
}
function installApi(initial = overview()) {
  const state = {
    overview: initial, intercept: null, overviewRequestCount: 0,
    fpReview: { review_id: "r", scan_id: "s", status: "complete", total: 0, processed: 0, results: [] },
    indexStatus: { status: "skipped" },
  };
  client.api.defaults.adapter = async (config) => {
    let data;
    if (config.url === "/api/mining-engines") data = { engines: [] };
    else if (config.url.includes("checkers")) data = [];
    else if (config.url.endsWith("/fp-review/overview")) data = structuredClone(state.fpReview);
    else if (config.url.endsWith("/overview")) {
      state.overviewRequestCount += 1;
      data = state.intercept ? await state.intercept() : structuredClone(state.overview);
    }
    else if (config.url.endsWith("/resume")) { state.overview = overview(80, 2); data = { scan_id: "s" }; }
    else if (config.url.endsWith("/index-status")) data = structuredClone(state.indexStatus);
    else if (config.url.endsWith("/git_history")) data = [];
    else if (/\/(events|event-history|candidates|vulnerabilities|threat-audit-tasks|threat-pattern-audit-tasks|validations|results|tasks)$/.test(config.url)) {
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

function summaryRow(root, label) {
  const row = root.root.findAll((node) => typeof node.type === "function"
    && node.type.name === "TaskSummaryRow" && node.props.label === label)[0];
  assert.ok(row, "Missing task progress row: " + label);
  return row;
}

function assertReviewProgress(root, processed, total) {
  const row = summaryRow(root, "对抗式复核");
  assert.ok(text(row).includes(`${processed}/${total} 已复核`), text(row));
  const fill = row.findAllByType("div").find((node) => node.props.style?.width !== undefined);
  assert.ok(fill, "Review progress must include a progress bar even at zero");
  assert.equal(fill.props.style.width, `${total > 0 ? Math.round(processed / total * 100) : 0}%`);
}

for (const enabled of [false, true]) {
  for (const staticSelected of [false, true]) {
    test(`codegraph capability agrees with task progress (enabled=${enabled}, static=${staticSelected})`, async () => {
      const value = { ...overview(), code_graph_mcp_enabled: enabled };
      if (!staticSelected) Object.assign(value, { mining_engines: [], mining_engine_runs: [], scan_items: [] });
      const state = installApi(value);
      if (staticSelected) state.indexStatus = { status: "done", parsed_files: 12, total_files: 12 };
      const root = await mount();
      const expected = enabled ? "已启用" : "未启用";
      const card = root.root.findAllByType("button").find((node) => text(node).startsWith("代码图谱"));
      assert.ok(card);
      assert.equal(text(card), `代码图谱${expected}`);
      const row = summaryRow(root, "代码图谱构建（底层能力）");
      assert.ok(text(row).includes(expected), text(row));
      assert.doesNotMatch(text(row), /已跳过|静态分析引擎|文件/);
      assert.equal(row.findAllByType("div").some((node) => node.props.style?.width !== undefined), false);
      await act(async () => card.props.onClick());
      assert.ok(root.root.findAllByType("h2").some((node) => text(node) === "代码图谱构建"));
    });
  }
}

test("review task progress follows live completion counts and survives reload", async () => {
  const value = {
    ...overview(), auto_fp_review: true,
    fp_review_method_selection: { method_id: "adversarial", method_label: "对抗式复核", stages: [] },
  };
  const state = installApi(value);
  state.fpReview.status = "pending";
  const root = await mount();
  assertReviewProgress(root, 0, 0);
  await notify(["fp_review_started", { review_id: "r", status: "running", total: 10, processed: 0 }]);
  assertReviewProgress(root, 0, 10);
  await notify(["fp_review_progress", { review_id: "r", vuln_index: 4, total: 10, processed: 4, active_indices: [4] }]);
  assertReviewProgress(root, 4, 10);
  state.fpReview = { ...state.fpReview, status: "running", total: 10, processed: 4 };
  const reloaded = await mount();
  assertReviewProgress(reloaded, 4, 10);
  await notify(
    ["fp_review_progress", { review_id: "r", vuln_index: 9, total: 10, processed: 10, active_indices: [] }],
    ["fp_review_finish", { review_id: "r", status: "complete", error_message: null }],
  );
  assertReviewProgress(reloaded, 10, 10);
});

for (const status of ["error", "cancelled"]) {
  test(`review task progress retains partial completion after ${status}`, async () => {
    const state = installApi({
      ...overview(), auto_fp_review: true,
      fp_review_method_selection: { method_id: "adversarial", method_label: "对抗式复核", stages: [] },
    });
    Object.assign(state.fpReview, { status: "running", total: 10, processed: 4 });
    const root = await mount();
    await notify(["fp_review_finish", { review_id: "r", status, error_message: null }]);
    assertReviewProgress(root, 4, 10);
  });
}

test("report export is removed from task progress while the export menu remains available", async () => {
  installApi();
  const root = await mount();
  assert.doesNotMatch(text(root.toJSON()), /报告导出|可使用顶部导出按钮/);
  const exportButton = root.root.findAllByType("button").find((node) => text(node) === "导出报告");
  assert.ok(exportButton);
  await act(async () => exportButton.props.onClick());
  assert.deepEqual(root.root.findAllByProps({ role: "menuitem" }).map(text), ["ZIP", "CSV"]);
});

test("completed scan resumes and both flow views advance despite pool and old execution events", async () => {
  const state = installApi();
  const root = await mount();
  assertProgress(root, 100);
  const resume = root.root.findAllByType("button").find((node) => text(node).includes("续扫"));
  assert.ok(resume);
  await act(async () => resume.props.onClick());
  assertProgress(root, 80);
  state.overview = overview(81, 2);
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

test("coalesced overview consumers keep the physical request baseline after newer SSE progress", async () => {
  const state = installApi(overview(80, 2));
  const root = await mount();
  const initialRequests = state.overviewRequestCount;
  let resolve;
  state.intercept = () => new Promise((done) => { resolve = done; });
  await poll(10_000);
  state.overview = overview(81, 2);
  await notify(["scan_status", { execution_revision: 2, processed_candidates: 81, total_candidates: 100 }]);
  assertProgress(root, 81);
  await act(async () => streams.at(-1).onopen());
  assert.equal(state.overviewRequestCount, initialRequests + 1, "reconnect joins the pending summary GET");
  await act(async () => resolve(overview(80, 2)));
  assertProgress(root, 81);
  state.intercept = null;
  state.overview = overview(82, 2);
  await poll(30_000);
  assert.equal(state.overviewRequestCount, initialRequests + 2, "settled requests leave the cache for the next GET");
  assertProgress(root, 82);
});

test("overview descriptors share the first snapshot and release their cache after success", async () => {
  const state = installApi(overview(80, 2));
  const firstSnapshot = runtime.normalizeScanStatus(overview(80, 2));
  const laterSnapshot = runtime.normalizeScanStatus(overview(81, 2));
  let resolve;
  state.intercept = () => new Promise((done) => { resolve = done; });
  const first = client.getScanOverviewRequest("s", firstSnapshot);
  const joined = client.getScanOverviewRequest("s", laterSnapshot);
  assert.equal(joined, first);
  assert.equal(joined.requestedFrom, firstSnapshot);
  assert.equal(client.getScanOverview("s"), first.promise);
  await act(async () => {});
  assert.equal(state.overviewRequestCount, 1);
  await act(async () => resolve(overview(80, 2)));
  await first.promise;
  state.intercept = null;
  state.overview = overview(82, 2);
  const fresh = client.getScanOverviewRequest("s", laterSnapshot);
  assert.notEqual(fresh, first);
  assert.equal(fresh.requestedFrom, laterSnapshot);
  assert.equal((await fresh.promise).processed_candidates, 82);
  assert.equal(state.overviewRequestCount, 2);
});

test("unknown overview origins remain explicit when a later caller joins", async () => {
  const state = installApi(overview(80, 2));
  const current = runtime.normalizeScanStatus(overview(81, 2));
  let resolve;
  state.intercept = () => new Promise((done) => { resolve = done; });
  const legacy = client.getScanOverview("s");
  const joined = client.getScanOverviewRequest("s", current);
  assert.equal(joined.promise, legacy);
  assert.equal(joined.requestedFrom, null);
  await act(async () => {});
  await act(async () => resolve(overview(80, 2)));
  const incoming = await joined.promise;
  const protectedScan = runtime.mergeScanOverview(current, incoming, joined.requestedFrom);
  assert.equal(protectedScan.processed_candidates, 81);
  assert.equal(state.overviewRequestCount, 1);
});

test("full hydration keeps the baseline of an earlier coalesced overview request", async () => {
  const state = installApi(overview(80, 2));
  const firstSnapshot = runtime.normalizeScanStatus(overview(80, 2));
  const current = runtime.normalizeScanStatus(overview(81, 2));
  let resolve;
  state.intercept = () => new Promise((done) => { resolve = done; });
  const first = client.getScanOverviewRequest("s", firstSnapshot);
  const hydration = client.getScanStatusRequest("s", current);
  assert.equal(hydration.requestedFrom, first.requestedFrom);
  await act(async () => {});
  assert.equal(state.overviewRequestCount, 1);
  await act(async () => resolve(overview(80, 2)));
  const hydrated = await hydration.promise;
  const merged = runtime.mergeScanSnapshot(current, hydrated, hydration.requestedFrom);
  assert.equal(merged.processed_candidates, 81);
  assert.deepEqual(hydrated.candidates, []);
});

test("a rejected overview leaves the cache so the next refresh can retry", async () => {
  const state = installApi(overview(80, 2));
  const snapshot = runtime.normalizeScanStatus(overview(80, 2));
  state.intercept = () => { throw new Error("temporary network failure"); };
  const failed = client.getScanOverviewRequest("s", snapshot);
  assert.equal(client.getScanOverviewRequest("s", snapshot), failed);
  await assert.rejects(failed.promise, /temporary network failure/);
  state.intercept = null;
  const retry = client.getScanOverviewRequest("s", snapshot);
  assert.notEqual(retry, failed);
  assert.equal((await retry.promise).processed_candidates, 80);
  assert.equal(state.overviewRequestCount, 2);
});

test("fresh authoritative overviews can lower progress within the same execution", async () => {
  const state = installApi(overview(81, 2));
  const root = await mount();
  assertProgress(root, 81);
  state.overview = overview(80, 2);
  await poll(10_000);
  assertProgress(root, 80);
});

test("a pool-only new revision permits the resumed overview to reset old counters", async () => {
  const state = installApi();
  const root = await mount();
  assertProgress(root, 100);
  await notify(["scan_status", { execution_revision: 2, opencode_pool: { execution_revision: 2, global_running: 1 } }]);
  state.overview = overview(80, 2);
  await poll(30_000);
  assertProgress(root, 80);
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

test("attack-pattern engine shows live tasks and navigates to the linked report and back", async () => {
  const engine = { engine_id: "threat_pattern_audit", enabled: true,
    engine_label: "DeepHole基于攻击模式的漏洞挖掘引擎" };
  installApi({ ...overview(0, 2), mining_engines: [engine],
    mining_engine_runs: [{ ...engine, status: "running", total_candidates: 1 }],
    detail_counts: undefined });
  const fallback = client.api.defaults.adapter;
  let task = { task_id: "threat-pattern-audit-1", scan_id: "s", module_name: "认证模块",
    pattern_id: "AUTH-1", pattern_name: "会话伪造", status: "pending",
    code_paths: [{ path: "src/auth" }], updated_at: "2026-10-16T00:00:00Z" };
  const finding = { file: "src/auth/session.c", line: 17, function: "restore", vuln_type: "auth",
    severity: "high", description: "身份未绑定", user_verdict: "confirmed", confirmed: true,
    engine_id: engine.engine_id, analysis_source: engine.engine_id, source_task_id: task.task_id,
    vulnerability_report: "# 攻击模式审计报告 207" };
  client.api.defaults.adapter = async (config) => {
    let data;
    if (config.url.endsWith("/threat-pattern-audit-tasks")) data = { items: [task], next_cursor: null };
    else if (config.url.endsWith("/threat-pattern-audit-results")) data = [{ task_id: task.task_id,
      findings: task.status === "completed" ? [{ ...finding, vuln_index: 207, verdict: "confirmed", verdict_source: "human" }] : [],
      confirmed_issue_count: task.status === "completed" ? 1 : 0, association_complete: true }];
    else if (config.url.endsWith("/vulnerabilities") && config.params?.after === 206) {
      data = { items: [{ index: 207, vulnerability: finding }], next_cursor: null };
    } else return fallback(config);
    return { config, data, status: 200, statusText: "OK", headers: {} };
  };
  const root = await mount();
  const click = async (label, exact = true) => {
    const button = root.root.findAllByType("button").find((node) => exact ? text(node) === label : text(node).includes(label));
    assert.ok(button, "Missing button: " + label);
    await act(async () => button.props.onClick());
  };
  await click(engine.engine_label, false);
  assert.match(text(root.toJSON()), /高风险模块认证模块/);
  assert.doesNotMatch(text(root.toJSON()), /该引擎输出的问题/);
  task = { ...task, status: "running", updated_at: "2026-10-16T00:00:01Z" };
  await notify(["threat_pattern_audit_task", { task }]);
  assert.match(text(root.toJSON()), /运行中.*会话伪造/);
  task = { ...task, status: "completed", result_vuln_indexes: [207], updated_at: "2026-10-16T00:00:02Z" };
  await notify(["threat_pattern_audit_task", { task }]);
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 350)); });
  await click("查看问题报告");
  assert.match(text(root.toJSON()), /当前定位：结果 #207/);
  assert.match(text(root.toJSON()), /攻击模式审计报告 207/);
  await click("详情 ▸");
  await click("查看攻击模式审计任务");
  assert.match(text(root.toJSON()), /高风险模块认证模块/);
  assert.match(text(root.toJSON()), /threat-pattern-audit-1/);
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
