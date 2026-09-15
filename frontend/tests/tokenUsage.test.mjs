import assert from "node:assert/strict";
import test, { after } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
const { ScanTokenUsagePanel } = await server.ssrLoadModule("/src/components/ScanTokenUsagePanel.tsx");
const runtime = await server.ssrLoadModule("/src/scanRuntime.ts");
after(async () => { await server.close(); });

function usage(input, overrides = {}) {
  return { input_tokens: input, output_tokens: 0, reasoning_tokens: 0, cache_read_tokens: 0,
    cache_write_tokens: 0, total_tokens: input, complete: true, by_model: [], ...overrides };
}
function pool(value) {
  return runtime.normalizeOpenCodePool({ scope_id: "s", queued_tasks: [], models: [], ...value });
}
function text(value) {
  if (typeof value === "string") return value;
  return Array.isArray(value) ? value.map(text).join("") : value?.children ? text(value.children) : "";
}
function render(value, inspect) {
  const root = TestRenderer.create(createElement(ScanTokenUsagePanel, { usage: value }));
  try { inspect(root); } finally { root.unmount(); }
}

test("category table shows sorted totals, all counters, percentages and completeness", () => {
  render(usage(100, { by_category: [
    { ...usage(20), category: "threat_analysis", label: "威胁分析" },
    { ...usage(50), category: "fp_review", label: "去误报", complete: false },
  ] }), (root) => {
    const rows = root.root.findAllByType("tr").slice(1);
    assert.deepEqual(rows.map((row) => text(row.findAllByType("td")[0])), ["去误报统计可能不完整", "威胁分析", "未分类"]);
    assert.deepEqual(rows.map((row) => text(row.findAllByType("td")[2])), ["50.0%", "20.0%", "30.0%"]);
    assert.equal(rows[0].findAllByType("td").length, 8);
    assert.match(text(root.toJSON()), /部分用量缺少可确认的任务分类/);
  });
});

test("old responses retain their full unclassified balance and missing statistics are distinct from zero", () => {
  render(usage(1234), (root) => {
    assert.match(text(root.toJSON()), /未分类1,234100.0%/);
    assert.doesNotMatch(text(root.toJSON()), /威胁分析/);
  });
  render(null, (root) => assert.match(text(root.toJSON()), /暂无已采集/));
  render(usage(0, { by_category: [{ ...usage(0), category: "fp_review", label: "去误报" }] }), (root) => {
    assert.match(text(root.toJSON()), /去误报00.0%/);
    assert.doesNotMatch(text(root.toJSON()), /NaN|Infinity/);
  });
});

test("category counters survive normalization, refresh and stale execution protection", () => {
  const tokens = usage(25, { by_category: [{ ...usage(25), category: "static_candidate", label: "基于候选点的审计" }] });
  const current = pool({ execution_revision: 5, updated_at: "2026-09-15T01:00:00Z", token_usage: tokens });
  const { by_model, ...category } = tokens.by_category[0];
  assert.deepEqual(current.token_usage.by_category[0], category);
  const scan = { scan_id: "s", status: "auditing", execution_revision: 5, opencode_pool: current };
  const stale = { ...scan, execution_revision: 4, opencode_pool: pool({ execution_revision: 4, token_usage: usage(1) }) };
  assert.deepEqual(runtime.mergeScanSnapshot(scan, stale).opencode_pool.token_usage, current.token_usage);
  const refreshed = runtime.mergeScanSnapshot(scan, { ...scan, opencode_pool: current });
  assert.equal(refreshed.opencode_pool.token_usage.by_category[0].total_tokens, 25);
  assert.deepEqual(pool({ token_usage: usage(1) }).token_usage.by_category, []);
});
