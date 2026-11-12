import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement, useRef, useState } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true, hmr: false } });
const client = await server.ssrLoadModule("/src/api/client.ts");
const runtime = await server.ssrLoadModule("/src/scanRuntime.ts");
const engines = await server.ssrLoadModule("/src/miningEngines.ts");
const navigation = await server.ssrLoadModule("/src/auditNavigation.ts");
const { ThreatAuditPanel } = await server.ssrLoadModule("/src/components/ScanStatus.tsx");
const engineId = engines.THREAT_PATTERN_ITERATIVE_ENGINE_ID;
const originalAdapter = client.api.defaults.adapter;
const originalNavigator = globalThis.navigator;
const roots = [];
const copied = [];
globalThis.localStorage = { getItem: () => null };
Object.defineProperty(globalThis, "navigator", { configurable: true, value: { clipboard: { writeText: async (value) => copied.push(value) } } });

afterEach(async () => {
  await act(async () => roots.splice(0).forEach((root) => root.unmount()));
  client.api.defaults.adapter = originalAdapter;
  client.setPublicScanAccess(null);
  copied.length = 0;
});
after(async () => {
  delete globalThis.localStorage;
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: originalNavigator });
  await server.close();
});

const text = (node) => typeof node === "string" || typeof node === "number" ? String(node)
  : Array.isArray(node) ? node.map(text).join("") : text(node?.children ?? "");
const rowButtons = (root) => root.root.findAllByType("button").filter((item) => item.parent?.type === "li");
const response = (config, data) => ({ config, data, status: 200, statusText: "OK", headers: {} });
const counts = (total) => ({ tasks: total, current: total, pending: 0, queued: 0, running: 0,
  completed: Math.max(0, total - 2), failed: 1, cancelled: 1, superseded: 0 });
function task(round, overrides = {}) {
  return runtime.normalizePatternTask({ task_id: `iterative-${round}`, scan_id: "s", engine_id: engineId, iteration: round,
    status: ["completed", "failed", "cancelled"][round - 1] || "completed", parent_task_id: round > 1 ? `iterative-${round - 1}` : "",
    module_name: "非常长的认证模块名称".repeat(12), pattern_id: "pattern", pattern_name: "边界检查攻击模式".repeat(12),
    code_paths: [{ path: "src/auth" }], created_at: `2026-11-12T00:00:0${round}Z`, updated_at: `2026-11-12T00:00:1${round}Z`,
    has_more_findings: round < 3, followup_clues: round < 3 ? `第 ${round} 轮的后续线索\n保留换行` : "", ...overrides });
}
function scan(tasks, overrides = {}) {
  return runtime.normalizeScanStatus({ scan_id: "s", status: "complete", project_id: "project", scan_items: [],
    vulnerabilities: [], candidates: [], events: [], threat_pattern_audit_tasks: tasks,
    detail_counts: { threat_pattern_audit_tasks: 104, threat_pattern_audit_current: 104,
      threat_pattern_audit_by_engine: { [engineId]: counts(3), threat_pattern_audit: counts(101) } },
    mining_engine_runs: [{ engine_id: engineId, status: "success", total_candidates: 3 }], ...overrides });
}
function props(value, overrides = {}) {
  return { scan: value, patternMode: true, engineId, events: [], fpReview: null, resultRevision: 0,
    onOpenIssue() {}, ...overrides };
}
async function mount(value, overrides) {
  let root;
  await act(async () => { root = create(createElement(ThreatAuditPanel, props(value, overrides))); });
  roots.push(root);
  return root;
}
async function expandPrompt(root, expanded = true) {
  const section = root.root.findAllByType("details").find((item) => text(item.findByType("summary")) === "完整 Prompt");
  await act(async () => section.props.onToggle({ currentTarget: { open: expanded } }));
}
function fixture(allTasks, { firstPage = allTasks, nextCursor = null } = {}) {
  const requests = [];
  client.api.defaults.adapter = async (config) => {
    requests.push(config);
    if (config.url.endsWith("/threat-pattern-audit-tasks")) {
      assert.equal(config.params.engine_id, engineId);
      assert.equal(config.params.summary, true);
      return response(config, { items: (config.params.cursor ? allTasks.slice(firstPage.length) : firstPage)
        .map((item) => ({ ...item, followup_clues: "" })), next_cursor: config.params.cursor ? null : nextCursor, has_more: !!nextCursor });
    }
    if (config.url.includes("/threat-pattern-audit-tasks/")) {
      const item = allTasks.find((entry) => config.url.endsWith(`/${entry.task_id}`));
      assert.ok(item, config.url);
      return response(config, { ...item, next_task_id: allTasks.find((entry) => entry.parent_task_id === item.task_id)?.task_id || "" });
    }
    if (config.url.endsWith("/threat-pattern-audit-results")) {
      return response(config, config.params.getAll("task_ids").map((id) => ({ task_id: id,
        findings: id === "iterative-1" ? [{ vuln_index: 19, vuln_type: "边界检查", severity: "high", file: "src/auth.c",
          line: 9, description: "第一轮找到的问题", verdict: "confirmed", verdict_source: "fp_review" }] : [],
        confirmed_issue_count: id === "iterative-1" ? 1 : 0, association_complete: true })));
    }
    if (config.url.endsWith("/tasks")) return response(config, { items: [{ task_id: `runtime-${config.params.task_name}`,
      task_name: config.params.task_name, scope_id: "s", revision: 3, record_id: `record-${config.params.task_name}`,
      model_id: "model-each-round", serve_session_id: `ses-${config.params.task_name}` }], next_cursor: null });
    if (config.url.includes("/tasks/runtime-")) {
      assert.equal(config.params.revision, 3);
      assert.ok(config.params.record_id.startsWith("record-iterative-"));
      return response(config, { prompt: `实际保存的 Prompt\n${config.params.record_id}\n审计时参考线索：原始内容`,
        token_usage: { input_tokens: 70, output_tokens: 29, total_tokens: 99 } });
    }
    assert.fail(`Unexpected request ${config.url}`);
  };
  return requests;
}

test("iterative engine is opt-in, depends on threat analysis, and legacy task defaults stay compatible", () => {
  assert.equal(engines.miningEngineSelectedByDefault(engineId), false);
  assert.equal(engines.miningEngineSelectedByDefault("threat_pattern_audit"), true);
  assert.equal(engines.miningEngineRequiresThreatAnalysis(engineId), true);
  assert.equal(engines.canonicalMiningEngineLabel(engineId), "DeepHole基于攻击模式的迭代漏洞挖掘引擎");
  assert.equal(runtime.normalizePatternTask({ task_id: "legacy" }).engine_id, "threat_pattern_audit");
  assert.equal(runtime.normalizePatternTask({ task_id: "legacy" }).iteration, 1);
});

test("every round has a non-truncating list badge, isolated counts, Session, clues and lazy exact Prompt", async () => {
  const tasks = [1, 2, 3].map((round) => task(round));
  const requests = fixture(tasks);
  const value = scan([...tasks, task(1, { task_id: "legacy", engine_id: "threat_pattern_audit" })]);
  const opened = [];
  const root = await mount(value, { onOpenIssue: (index) => opened.push(index) });
  const rows = rowButtons(root);
  assert.equal(rows.length, 3);
  assert.match(text(root.toJSON()), /任务总数3待执行0排队中0运行中0已完成1未成功1已取消1/);
  for (let index = 0; index < rows.length; index += 1) {
    const badge = rows[index].findAllByType("span").find((item) => text(item) === `第 ${index + 1} 轮`);
    assert.ok(badge, `round ${index + 1} has its own badge`);
    assert.match(badge.props.className, /shrink-0/);
    assert.match(badge.props.className, /whitespace-nowrap/);
    for (let ancestor = badge; ancestor !== rows[index]; ancestor = ancestor.parent) {
      assert.doesNotMatch(ancestor.props.className || "", /truncate|hidden/);
    }
  }
  assert.match(text(root.toJSON()), /ses-iterative-1/);
  assert.match(text(root.toJSON()), /model-each-round/);
  assert.match(text(root.toJSON()), /第 1 轮的后续线索\n保留换行/);
  assert.equal(requests.filter((request) => request.url.includes("/tasks/runtime-")).length, 0);
  assert.ok(root.root.findAllByType("details").every((item) => !item.props.open));
  await act(async () => root.root.findAllByType("button").find((item) => text(item) === "查看问题报告").props.onClick());
  assert.deepEqual(opened, [19]);
  await expandPrompt(root);
  assert.equal(root.root.findByType("pre").children.join(""), "实际保存的 Prompt\nrecord-iterative-1\n审计时参考线索：原始内容");
  await act(async () => root.root.findByProps({ "aria-label": "复制完整 Prompt" }).props.onClick());
  await act(async () => root.root.findByProps({ "aria-label": "复制 Session ID" }).props.onClick());
  assert.deepEqual(copied, ["实际保存的 Prompt\nrecord-iterative-1\n审计时参考线索：原始内容", "ses-iterative-1"]);
  const requestCount = requests.length;
  await act(async () => root.update(createElement(ThreatAuditPanel, props({ ...value, completed_task_count: 800 }))));
  await expandPrompt(root, false);
  await expandPrompt(root);
  assert.equal(requests.length, requestCount, "other tasks completing and collapse/reopen do not refetch this round");
  await act(async () => rowButtons(root)[1].props.onClick());
  assert.match(text(root.toJSON()), /ses-iterative-2/);
  assert.match(text(root.toJSON()), /审计时参考线索第 1 轮的后续线索/);
  assert.match(text(root.toJSON()), /后续线索第 2 轮的后续线索/);
  assert.equal(root.root.findAllByType("pre").length, 0);
  await expandPrompt(root);
  assert.match(root.root.findByType("pre").children.join(""), /record-iterative-2/);
  await act(async () => rowButtons(root)[0].props.onClick());
  await expandPrompt(root);
  assert.equal(requests.filter((request) => request.url.endsWith("/tasks/runtime-iterative-1")).length, 1);
});

test("adjacent rounds are navigable by ID when outside the loaded summary page", async () => {
  const tasks = [1, 2, 3].map((round) => task(round));
  const requests = fixture(tasks, { firstPage: [tasks[1]], nextCursor: "page-2" });
  const root = await mount(scan([]));
  assert.equal(rowButtons(root).length, 1);
  assert.match(text(root.toJSON()), /ses-iterative-2/);
  await act(async () => root.root.findAllByType("button").find((item) => text(item) === "下一轮 · 第 3 轮").props.onClick());
  assert.match(text(root.toJSON()), /ses-iterative-3/);
  assert.equal(rowButtons(root).length, 2);
  await act(async () => root.root.findAllByType("button").find((item) => text(item) === "上一轮 · 第 2 轮").props.onClick());
  await act(async () => root.root.findAllByType("button").find((item) => text(item) === "上一轮 · 第 1 轮").props.onClick());
  assert.match(text(root.toJSON()), /ses-iterative-1/);
  assert.equal(requests.filter((request) => request.url.endsWith("/threat-pattern-audit-tasks")).length, 1,
    "adjacent navigation does not crawl all pages");
});

test("execution details lazily load historical Token usage and share the Prompt record cache", async () => {
  const tasks = [task(1)];
  const requests = fixture(tasks);
  const root = await mount(scan(tasks));
  assert.equal(requests.filter((request) => request.url.includes("/tasks/runtime-")).length, 0);
  const execution = root.root.findAllByType("details").find((item) => text(item.findByType("summary")) === "执行信息与 Token");
  await act(async () => execution.props.onToggle({ currentTarget: { open: true } }));
  assert.match(text(root.toJSON()), /总计 99/);
  assert.equal(root.root.findAllByType("pre").length, 0);
  await expandPrompt(root);
  assert.equal(requests.filter((request) => request.url.includes("/tasks/runtime-")).length, 1);
});

test("fetching an adjacent round on another list page moves both selection and list page", async () => {
  const unrelated = Array.from({ length: 19 }, (_, index) => task(1, { task_id: `unrelated-${index}`,
    created_at: `2026-11-11T00:00:${String(index).padStart(2, "0")}Z`, has_more_findings: false, followup_clues: "" }));
  const second = task(2, { parent_task_id: "" });
  const third = task(3);
  fixture([...unrelated, second, third], { firstPage: [...unrelated, second], nextCursor: "page-2" });
  const root = await mount(scan([second]), { focusRequest: { key: second.task_id, revision: 1 } });
  await act(async () => root.root.findAllByType("button").find((item) => text(item) === "下一轮 · 第 3 轮").props.onClick());
  assert.match(text(root.toJSON()), /第 2\/2 页 · 共 21 条/);
  assert.equal(rowButtons(root).length, 1);
  assert.equal(rowButtons(root)[0].props["aria-current"], "true");
  assert.match(text(rowButtons(root)[0]), /第 3 轮/);
});

test("reopening a completed parent discovers a child created after the cached detail", async () => {
  const tasks = [task(1), task(1, { task_id: "unrelated", has_more_findings: false, followup_clues: "" })];
  const requests = fixture(tasks);
  const root = await mount(scan([]));
  assert.equal(root.root.findAllByType("button").some((item) => text(item) === "下一轮 · 第 2 轮"), false);
  tasks.push(task(2));
  await act(async () => rowButtons(root)[1].props.onClick());
  await act(async () => rowButtons(root)[0].props.onClick());
  assert.ok(root.root.findAllByType("button").some((item) => text(item) === "下一轮 · 第 2 轮"));
  assert.equal(requests.filter((request) => request.url.endsWith("/threat-pattern-audit-tasks/iterative-1")).length, 2);
});

test("SSE resync refreshes every loaded iterative page even when the global first page contains only the old engine", async () => {
  const tasks = Array.from({ length: 25 }, (_, index) => task(1, { task_id: `iterative-${index + 1}`,
    status: "running", created_at: `2026-11-12T00:00:${String(index).padStart(2, "0")}Z`,
    has_more_findings: null, followup_clues: "" }));
  const requests = fixture(tasks, { firstPage: tasks.slice(0, 20), nextCursor: "page-2" });
  const oldTasks = Array.from({ length: 50 }, (_, index) => task(1, { task_id: `legacy-${index}`, engine_id: "threat_pattern_audit" }));
  const value = scan(oldTasks);
  const root = await mount(value);
  await act(async () => root.root.findAllByType("button").find((item) => text(item) === "加载更多审计任务").props.onClick());
  await act(async () => root.root.findAllByType("button").find((item) => text(item) === "下一页").props.onClick());
  assert.equal(rowButtons(root).length, 5);
  assert.ok(rowButtons(root).every((item) => text(item).includes("运行中")));
  Object.assign(tasks[24], { status: "completed", updated_at: "2026-11-12T01:00:00Z" });
  const before = requests.filter((request) => request.url.endsWith("/threat-pattern-audit-tasks")).length;
  await act(async () => root.update(createElement(ThreatAuditPanel, props(value, { taskRevision: 1 }))));
  assert.match(text(rowButtons(root)[4]), /已完成/);
  const refreshed = requests.filter((request) => request.url.endsWith("/threat-pattern-audit-tasks")).slice(before);
  assert.deepEqual(refreshed.map((request) => request.params.cursor ?? null), [null, "page-2"]);
  assert.ok(refreshed.every((request) => request.params.engine_id === engineId));
  const count = requests.length;
  await act(async () => root.update(createElement(ThreatAuditPanel, props({ ...value, completed_task_count: 700 }, { taskRevision: 1 }))));
  assert.equal(requests.length, count, "unrelated completions do not restart page refresh");
});

for (const round of [1, 2, 3]) test(`round ${round} keeps history after refresh, including failed and cancelled rounds`, async () => {
  const tasks = [1, 2, 3].map((number) => task(number));
  fixture(tasks);
  const value = scan(tasks.map((item) => ({ ...item, followup_clues: "" })));
  const root = await mount(value, { focusRequest: { key: `iterative-${round}`, revision: 1 } });
  assert.match(text(root.toJSON()), new RegExp(`ses-iterative-${round}`));
  await expandPrompt(root);
  assert.match(text(root.toJSON()), new RegExp(`record-iterative-${round}`));
  await act(async () => root.unmount());
  const refreshed = await mount(value, { focusRequest: { key: `iterative-${round}`, revision: 1 } });
  assert.match(text(refreshed.toJSON()), new RegExp(`ses-iterative-${round}`));
  assert.equal(refreshed.root.findAllByType("pre").length, 0);
  await expandPrompt(refreshed);
  assert.match(text(refreshed.toJSON()), new RegExp(`record-iterative-${round}`));
});

test("source navigation preserves the iterative engine and exact round", async () => {
  let state;
  const navigated = [];
  const sourceTask = task(3);
  const value = scan([sourceTask], { vulnerabilities: [{ file: "src/auth.c", line: 9, vuln_index: 19,
    engine_id: engineId, analysis_source: engineId, source_task_id: sourceTask.task_id }] });
  function Harness() {
    const [current, setCurrent] = useState(value);
    const ref = useRef(current); ref.current = current;
    state = navigation.useAuditNavigation("s", ref, setCurrent, (...args) => navigated.push(args));
    return null;
  }
  let root;
  await act(async () => { root = create(createElement(Harness)); }); roots.push(root);
  await act(async () => state.openSource(19));
  assert.deepEqual(navigated, [["threat_pattern_audit", engineId]]);
  assert.equal(state.focus.key, "iterative-3");
});

for (const kind of ["integration", "shared"]) test(`filtered summaries and full round detail use ${kind} access`, async () => {
  client.setPublicScanAccess({ scanId: "s", token: "view-token", kind });
  const requests = fixture([task(1)]);
  const page = await client.getScanPatternTasksPage("s", null, undefined, engineId);
  const detail = await client.getScanPatternTaskDetail("s", page.items[0].task_id);
  assert.equal(detail.followup_clues, "第 1 轮的后续线索\n保留换行");
  for (const request of requests) {
    assert.ok(request.url.startsWith(`/api/${kind === "shared" ? "shared" : "public"}/scans/s/`));
    assert.equal(request.params.token, "view-token");
  }
});
