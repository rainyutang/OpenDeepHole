import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
const client = await server.ssrLoadModule("/src/api/client.ts");
const { ScanTaskQueuePanel } = await server.ssrLoadModule("/src/components/ScanStatus.tsx");
const { compareTaskHistory } = await server.ssrLoadModule("/src/taskOrder.ts");
const originalAdapter = client.api.defaults.adapter;
const roots = [];
globalThis.localStorage = { getItem: () => null };
globalThis.document = { hidden: false };

afterEach(async () => {
  await act(async () => { roots.splice(0).forEach((root) => root.unmount()); });
  client.api.defaults.adapter = originalAdapter;
  client.setPublicScanAccess(null);
});
after(async () => { delete globalThis.localStorage; delete globalThis.document; await server.close(); });

function response(config, data) { return { config, data, status: 200, statusText: "OK", headers: {} }; }
function text(node) {
  if (typeof node === "string") return node;
  if (Array.isArray(node)) return node.map(text).join("");
  return node?.children ? text(node.children) : "";
}
function task(id, finishedAt, overrides = {}) {
  return { task_id: id, model_id: id, revision: 1, record_id: `record-${id}`, outcome: "success", finished_at: finishedAt, ...overrides };
}
function pool(overrides = {}) {
  return { scope_id: "s", global_running: 0, global_queued: 0, completed_task_count: 107, total_tasks: 107,
    models: [], planned_tasks: [], queued_tasks: [], completed_tasks: [], updated_at: "", ...overrides };
}
function rows(root) { return root.root.findAllByType("tr").filter((row) => row.props["aria-expanded"] !== undefined); }
function ids(root) { return rows(root).map((row) => text(row.findAllByType("td")[3])); }
function button(root, label) {
  const result = root.root.findAllByType("button").find((item) => text(item).includes(label));
  assert.ok(result, `Missing button: ${label}`);
  return result;
}
async function mount(value = pool()) {
  let root;
  await act(async () => { root = create(createElement(ScanTaskQueuePanel, { scanId: "s", pool: value })); });
  roots.push(root);
  return root;
}

test("history uses real UTC time, microseconds and stable ID ties, with invalid times last", () => {
  const values = [
    task("no-date", "now"),
    task("old", "2026-09-08T08:00:00+08:00", { outcome: "failure" }),
    task("z-earlier-microsecond", "2026-09-08T00:00:00.000001Z"),
    task("a-later-microsecond", "2026-09-08T00:00:00.000002Z", { outcome: "timeout" }),
    task("tie-a", "2026-09-08T00:00:01Z"),
    task("tie-z", "2026-09-08T08:00:01+08:00", { outcome: "cancelled" }),
    task("start-fallback", "2026-02-30T00:00:00Z", { started_at: "2026-09-08T00:00:02" }),
  ];
  assert.deepEqual(values.sort(compareTaskHistory).map((item) => item.task_id), [
    "start-fallback", "tie-z", "tie-a", "a-later-microsecond", "z-earlier-microsecond", "old", "no-date"]);
});

for (const publicAccess of [false, true]) {
  test(`queue keeps active states first, loads 50 at a time and preserves history on refresh (${publicAccess ? "public" : "authenticated"})`, async () => {
    if (publicAccess) client.setPublicScanAccess({ scanId: "s", token: "public-token" });
    const prefix = publicAccess ? "/api/public/scans/s" : "/api/v2/scans/s";
    const values = Array.from({ length: 107 }, (_, index) => task(`task-${index}`,
      new Date(Date.UTC(2026, 8, 8, 0, 0, 107 - index)).toISOString(), { outcome: index % 2 ? "failure" : "success" }));
    let refreshed = false;
    const calls = [];
    client.api.defaults.adapter = async (config) => {
      assert.ok(config.url.startsWith(prefix));
      if (publicAccess) assert.equal(config.params.token, "public-token");
      calls.push(config);
      if (config.url === `${prefix}/tasks/task-0`) return response(config, { ...values[0], prompt: "完整任务 Prompt" });
      assert.equal(config.params.limit, 50);
      const offset = Number(config.params.cursor || 0);
      const items = offset ? values.slice(offset, offset + 50)
        : refreshed ? [task("latest", "2026-09-08T00:03:00Z", { outcome: "failure" }), ...values.slice(0, 49)] : values.slice(0, 50);
      return response(config, { items, next_cursor: offset + 50 < values.length ? String(offset + 50) : null });
    };
    const value = pool({ models: [{ id: "running", active_tasks: [{ task_id: "run", started_at: "2026-09-07T00:00:00Z" }] }],
      queued_tasks: [{ request_id: "queued", queued_at: "2026-09-07T00:00:01Z" }],
      planned_tasks: [{ planned_task_id: "planned", planned_at: "2026-09-07T00:00:02Z" }] });
    const root = await mount(value);
    assert.deepEqual(rows(root).slice(0, 3).map((row) => text(row.findAllByType("td")[0])), ["运行中", "排队中", "计划中"]);
    assert.deepEqual(ids(root).slice(3), values.slice(0, 9).map((item) => item.task_id));
    assert.equal(rows(root).length, 12);
    assert.match(text(root.toJSON()), /已加载 50 条/);
    await act(async () => rows(root)[3].props.onClick());
    assert.match(text(root.toJSON()), /完整任务 Prompt/);
    await act(async () => button(root, "加载更多历史任务").props.onClick());
    assert.match(text(root.toJSON()), /已加载 100 条/);
    refreshed = true;
    await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "s", pool: { ...value, updated_at: "new" } })));
    assert.equal(ids(root)[3], "latest");
    assert.match(text(root.toJSON()), /已加载 101 条/);
    assert.match(text(root.toJSON()), /完整任务 Prompt/);
    await act(async () => button(root, "加载更多历史任务").props.onClick());
    assert.deepEqual(calls.filter((call) => call.params.cursor).map((call) => call.params.cursor), ["50", "100"]);
    const loadedIds = ids(root);
    for (let page = 1; page < 10; page += 1) {
      await act(async () => button(root, "下一页").props.onClick());
      loadedIds.push(...ids(root));
    }
    assert.deepEqual(loadedIds.slice(3), ["latest", ...values.map((item) => item.task_id)]);
    assert.equal(calls.filter((call) => call.url.includes("/tasks/task-")).length, 1);
  });
}

test("older page responses cannot replace a newer execution already refreshed", async () => {
  let resolvePage;
  let refreshed = false;
  client.api.defaults.adapter = async (config) => {
    if (config.params.cursor) return new Promise((resolve) => { resolvePage = (items) => resolve(response(config, { items, next_cursor: null })); });
    return response(config, { items: [task("same", refreshed ? "2026-09-08T02:00:00Z" : "2026-09-08T01:00:00Z",
      { revision: refreshed ? 2 : 1, outcome: refreshed ? "success" : "failure" })], next_cursor: "older" });
  };
  const root = await mount();
  let loading;
  act(() => { loading = button(root, "加载更多历史任务").props.onClick(); });
  refreshed = true;
  await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "s", pool: pool({ updated_at: "new" }) })));
  await act(async () => { resolvePage([task("same", "2026-09-08T01:00:00Z", { outcome: "failure" })]); await loading; });
  assert.deepEqual(ids(root), ["same"]);
  assert.equal(text(rows(root)[0].findAllByType("td")[0]), "成功");
});

test("more than 50 new completions are paged without skipping the interval before loaded history", async () => {
  let newest = 107;
  const cursors = [];
  client.api.defaults.adapter = async (config) => {
    const cursor = config.params.cursor;
    if (cursor) cursors.push(cursor);
    const start = Math.min(newest, cursor ? Number(cursor) - 1 : newest);
    const numbers = Array.from({ length: Math.max(0, start) }, (_, i) => start - i).slice(0, 50);
    return response(config, { items: numbers.map((i) => task(String(i), new Date(Date.UTC(2026, 8, 8, 0, 0, i)).toISOString())),
      next_cursor: start > 50 ? String(numbers.at(-1)) : null });
  };
  const root = await mount();
  await act(async () => button(root, "加载更多历史任务").props.onClick());
  newest = 237;
  await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "s", pool: pool({ completed_task_count: newest }) })));
  for (let i = 0; i < 3; i += 1) await act(async () => button(root, "加载更多历史任务").props.onClick());
  assert.deepEqual(cursors, ["58", "188", "138", "8"]);
  const loaded = ids(root);
  for (let page = 1; page < Math.ceil(newest / 12); page += 1) {
    await act(async () => button(root, "下一页").props.onClick());
    loaded.push(...ids(root));
  }
  assert.deepEqual(loaded, Array.from({ length: newest }, (_, i) => String(newest - i)));
});

test("an obsolete cursor resets to the newest page once and ordinary errors remain retryable", async () => {
  let firstPageCalls = 0;
  let failed = false;
  client.api.defaults.adapter = async (config) => {
    if (config.params.cursor === "old-id-cursor") throw { isAxiosError: true, response: { status: 400, data: { detail: "Invalid cursor" } } };
    if (config.params.cursor === "new-cursor") {
      if (!failed) { failed = true; throw new Error("temporary failure"); }
      return response(config, { items: [task("older", "2026-09-08T01:00:00Z")], next_cursor: null });
    }
    firstPageCalls += 1;
    return response(config, firstPageCalls === 1
      ? { items: [task("obsolete", "2026-09-07T01:00:00Z")], next_cursor: "old-id-cursor" }
      : { items: [task("newest", "2026-09-08T02:00:00Z")], next_cursor: "new-cursor" });
  };
  const root = await mount();
  await act(async () => button(root, "加载更多历史任务").props.onClick());
  assert.equal(firstPageCalls, 2);
  assert.deepEqual(ids(root), ["newest"]);
  await act(async () => button(root, "加载更多历史任务").props.onClick());
  assert.match(text(root.toJSON()), /历史任务加载失败/);
  await act(async () => button(root, "重试加载历史任务").props.onClick());
  assert.equal(firstPageCalls, 2);
  assert.deepEqual(ids(root), ["newest", "older"]);
});
