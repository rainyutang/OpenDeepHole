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
function ids(root) { return rows(root).map((row) => text(row.findAllByType("td")[2])); }
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
  test(`review-only queue shows planned, waiting and running work (${publicAccess ? "public" : "authenticated"})`, async () => {
    if (publicAccess) client.setPublicScanAccess({ scanId: "s", token: "public-token" });
    client.api.defaults.adapter = async (config) => response(config, { items: [], next_cursor: null });
    const owner = { task_type: "fp_review", execution_kind: "fp_review", execution_id: "review", execution_revision: 2 };
    const value = pool({ completed_task_count: 0, total_tasks: 3, global_running: 1, global_queued: 1,
      models: [{ id: "m", model: "p/m", active_tasks: [{ ...owner, task_id: "run" }] }],
      queued_tasks: [{ ...owner, request_id: "wait" }],
      planned_tasks: [{ ...owner, planned_task_id: "next" }] });
    const root = await mount(value);
    assert.deepEqual(rows(root).map((row) => text(row.findAllByType("td")[0])), ["运行中", "排队中", "计划中"]);
    assert.equal((text(root.toJSON()).match(/去误报/g) || []).length, 3);
    const next = { ...value, global_queued: 0, planned_tasks: [], queued_tasks: [],
      models: [{ id: "m", model: "p/m", active_tasks: [{ ...owner, task_id: "next-run" }] }], updated_at: "next" };
    await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "s", pool: next })));
    assert.equal(rows(root).length, 1);
    assert.equal(text(rows(root)[0].findAllByType("td")[0]), "运行中");
  });

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

test("repeated cursor errors retain history and the retry boundary through refresh and recovery", async () => {
  const values = Array.from({ length: 105 }, (_, index) => task(`task-${index}`,
    new Date(Date.UTC(2026, 8, 9, 0, 0, 105 - index)).toISOString()));
  let firstPageCalls = 0;
  let rejectPages = true;
  const cursors = [];
  client.api.defaults.adapter = async (config) => {
    const cursor = config.params.cursor;
    if (!cursor) {
      firstPageCalls += 1;
      return response(config, { items: values.slice(0, 50),
        next_cursor: firstPageCalls === 1 ? "obsolete" : firstPageCalls === 2 ? "50" : "refresh-boundary" });
    }
    cursors.push(cursor);
    if (cursor === "obsolete" || rejectPages) {
      throw { isAxiosError: true, response: { status: 400, data: { detail: "Invalid cursor" } } };
    }
    const offset = Number(cursor);
    return response(config, { items: values.slice(offset, offset + 50), next_cursor: offset === 50 ? "100" : null });
  };
  const root = await mount(pool({ completed_task_count: 105 }));
  await act(async () => button(root, "加载更多历史任务").props.onClick());
  assert.equal(firstPageCalls, 2);
  assert.match(text(root.toJSON()), /已加载 50 条/);
  await act(async () => button(root, "加载更多历史任务").props.onClick());
  assert.equal(firstPageCalls, 2);
  assert.match(text(root.toJSON()), /历史任务加载失败/);
  assert.match(text(root.toJSON()), /共 50 条/);

  await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "s", pool: pool({ updated_at: "refresh" }) })));
  assert.match(text(root.toJSON()), /历史任务加载失败/);
  await act(async () => button(root, "重试加载历史任务").props.onClick());
  assert.equal(firstPageCalls, 3);
  assert.equal(cursors.at(-1), "50");
  rejectPages = false;
  await act(async () => button(root, "重试加载历史任务").props.onClick());
  assert.match(text(root.toJSON()), /已加载 100 条/);
  assert.doesNotMatch(text(root.toJSON()), /历史任务加载失败/);

  // A successful page must not grant another automatic reset in this scan.
  rejectPages = true;
  await act(async () => button(root, "加载更多历史任务").props.onClick());
  assert.equal(firstPageCalls, 3);
  assert.match(text(root.toJSON()), /历史任务加载失败/);
  assert.match(text(root.toJSON()), /共 100 条/);
  rejectPages = false;
  await act(async () => button(root, "重试加载历史任务").props.onClick());
  assert.equal(cursors.at(-1), "100");
  assert.match(text(root.toJSON()), /共 105 条/);
  assert.doesNotMatch(text(root.toJSON()), /加载更多历史任务|重试加载历史任务|历史任务加载失败/);
  const loadedIds = ids(root);
  for (let page = 1; page < Math.ceil(values.length / 12); page += 1) {
    await act(async () => button(root, "下一页").props.onClick());
    loadedIds.push(...ids(root));
  }
  assert.deepEqual(loadedIds, values.map((value) => value.task_id));
});

test("changing scans renews cursor recovery and ignores an old scan's pending error", async () => {
  const firstPageCalls = { s: 0, other: 0 };
  let rejectOldPage;
  client.api.defaults.adapter = async (config) => {
    const scanId = config.url.includes("/other/") ? "other" : "s";
    if (config.params.cursor === "pending") return new Promise((_, reject) => { rejectOldPage = reject; });
    if (config.params.cursor) throw { isAxiosError: true, response: { status: 400, data: { detail: "Invalid cursor" } } };
    firstPageCalls[scanId] += 1;
    return response(config, { items: [task(scanId, "2026-09-09T00:00:00Z")],
      next_cursor: scanId === "s" && firstPageCalls.s === 2 ? "pending" : "obsolete" });
  };
  const root = await mount();
  await act(async () => button(root, "加载更多历史任务").props.onClick());
  assert.equal(firstPageCalls.s, 2);
  await act(async () => button(root, "加载更多历史任务").props.onClick());
  assert.equal(button(root, "加载中").props.disabled, true);
  await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "other", pool: pool() })));
  assert.equal(button(root, "加载更多历史任务").props.disabled, false);
  await act(async () => rejectOldPage({ isAxiosError: true, response: { status: 400, data: { detail: "Invalid cursor" } } }));
  assert.doesNotMatch(text(root.toJSON()), /历史任务加载失败/);
  await act(async () => button(root, "加载更多历史任务").props.onClick());
  assert.equal(firstPageCalls.other, 2);
  assert.deepEqual(ids(root), ["other"]);
});

for (const access of ["authenticated", "public", "shared"]) {
  test(`live queue reads prompts after SSE strips bodies and retains them on refresh (${access})`, async () => {
    if (access !== "authenticated") client.setPublicScanAccess({ scanId: "s", token: "token", kind: access === "shared" ? "shared" : "integration" });
    const prefix = access === "authenticated" ? "/api/v2/scans/s" : `/api/${access}/scans/s`;
    const calls = [];
    const pending = new Map();
    const running = { task_id: "running", revision: 2, prompt: "运行任务完整 Prompt" };
    const queued = { task_id: "queued", request_id: "queued", revision: 2, prompt: "排队任务完整 Prompt" };
    client.api.defaults.adapter = async (config) => {
      assert.ok(config.url.startsWith(prefix));
      if (access !== "authenticated") assert.equal(config.params.token, "token");
      if (config.url === `${prefix}/tasks`) return response(config, { items: [], next_cursor: null });
      calls.push(config);
      return new Promise((resolve) => pending.set(config.url, (value) => resolve(response(config, value))));
    };
    const initial = pool({ completed_task_count: 0, total_tasks: 3,
      models: [{ id: "m", active_tasks: [running] }], queued_tasks: [queued],
      planned_tasks: [{ planned_task_id: "planned" }] });
    const root = await mount(initial);
    await act(async () => rows(root)[0].props.onClick());
    assert.match(text(root.toJSON()), /运行任务完整 Prompt/);
    assert.equal(calls.length, 0);

    // Older SSE summaries keep task_id but can omit request_id as well as the body.
    const summary = { ...initial, updated_at: "sse",
      models: [{ id: "m", active_tasks: [{ task_id: "running", revision: 2, prompt_length: running.prompt.length }] }],
      queued_tasks: [{ task_id: "queued", revision: 2, prompt_length: queued.prompt.length }] };
    await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "s", pool: summary })));
    assert.match(text(root.toJSON()), /正在读取完整 Prompt/);
    assert.doesNotMatch(text(root.toJSON()), /尚未生成|未保存完整 Prompt/);
    assert.equal(calls[0].params.revision, 2);
    await act(async () => pending.get(`${prefix}/tasks/running`)({ ...running, serve_session_id: "loaded-session" }));
    assert.match(text(root.toJSON()), /运行任务完整 Prompt/);
    assert.match(text(root.toJSON()), /loaded-session/);
    await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "s", pool: { ...summary, updated_at: "heartbeat" } })));
    assert.match(text(root.toJSON()), /运行任务完整 Prompt/);
    assert.equal(calls.length, 1);

    await act(async () => rows(root)[1].props.onClick());
    assert.match(text(root.toJSON()), /正在读取完整 Prompt/);
    assert.doesNotMatch(text(root.toJSON()), /尚未生成|运行任务完整 Prompt/);
    await act(async () => pending.get(`${prefix}/tasks/queued`)(queued));
    assert.match(text(root.toJSON()), /排队任务完整 Prompt/);
    await act(async () => rows(root)[2].props.onClick());
    assert.match(text(root.toJSON()), /尚未生成，进入排队或运行后显示/);
    assert.equal(calls.length, 2);
    await act(async () => rows(root)[0].props.onClick());
    assert.match(text(root.toJSON()), /运行任务完整 Prompt/);
    assert.equal(calls.length, 2);
  });
}

function poolWithLiveTask(task, status = "running", overrides = {}) {
  return pool({ completed_task_count: 0, total_tasks: 1,
    ...(status === "queued" ? { queued_tasks: [task] } : { models: [{ id: "m", active_tasks: [task] }] }),
    ...overrides });
}

for (const status of ["queued", "running"]) {
  test(`${status} task distinguishes request failure from an unsynced prompt and allows retry`, async () => {
    const task = { task_id: "live", revision: 1, prompt_length: 42 };
    let calls = 0;
    client.api.defaults.adapter = async (config) => {
      if (config.url.endsWith("/tasks")) return response(config, { items: [], next_cursor: null });
      calls += 1;
      if (calls === 1) throw new Error("Network error");
      return response(config, calls === 2 ? task : { ...task, prompt: "补读成功的 Prompt" });
    };
    const value = poolWithLiveTask(task, status, { details_truncated: true });
    const root = await mount(value);
    await act(async () => rows(root)[0].props.onClick());
    assert.match(text(root.toJSON()), /完整 Prompt 加载失败/);
    assert.doesNotMatch(text(root.toJSON()), /尚未生成|暂未同步/);
    await act(async () => button(root, "完整任务加载失败，点击重试").props.onClick());
    assert.match(text(root.toJSON()), /完整 Prompt 暂未同步，已记录长度 42 chars/);
    assert.doesNotMatch(text(root.toJSON()), /加载失败|尚未生成/);
    await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "s", pool: { ...value, updated_at: "heartbeat" } })));
    assert.equal(calls, 2);
    await act(async () => button(root, "重新读取完整 Prompt").props.onClick());
    assert.match(text(root.toJSON()), /补读成功的 Prompt/);
    assert.equal(calls, 3);
  });
}

test("live detail requests follow revisions, executions and sessions while ignoring superseded responses", async () => {
  const pending = [];
  client.api.defaults.adapter = async (config) => {
    if (config.url.endsWith("/tasks")) return response(config, { items: [], next_cursor: null });
    return new Promise((resolve) => pending.push({ config, resolve: (prompt) => resolve(response(config, { prompt })) }));
  };
  let current = { task_id: "same", revision: 1, execution_revision: 3, agent_session_id: "agent-a" };
  const root = await mount(poolWithLiveTask(current));
  await act(async () => rows(root)[0].props.onClick());
  current = { ...current, revision: 2 };
  await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "s", pool: poolWithLiveTask(current) })));
  assert.equal(pending.length, 2);
  assert.equal(pending[0].config.signal.aborted, true);
  assert.equal(pending[1].config.params.revision, 2);
  await act(async () => pending[1].resolve("第二次执行正文"));
  await act(async () => pending[0].resolve("旧任务正文"));
  assert.match(text(root.toJSON()), /第二次执行正文/);
  assert.doesNotMatch(text(root.toJSON()), /旧任务正文/);

  for (const change of [{ execution_revision: 4 }, { agent_session_id: "agent-b" }, { serve_session_id: "new-session" }]) {
    current = { ...current, ...change };
    const count = pending.length;
    await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "s", pool: poolWithLiveTask(current) })));
    assert.equal(pending.length, count + 1);
    assert.doesNotMatch(text(root.toJSON()), /第二次执行正文/);
    await act(async () => pending.at(-1).resolve("当前执行正文"));
    assert.match(text(root.toJSON()), /当前执行正文/);
  }
});

test("changing tasks or scans cancels pending details and keeps cache scoped to the scan", async () => {
  const pending = [];
  client.api.defaults.adapter = async (config) => {
    if (config.url.endsWith("/tasks")) return response(config, { items: [], next_cursor: null });
    return new Promise((resolve) => pending.push({ config, resolve: (prompt) => resolve(response(config, { prompt })) }));
  };
  const value = poolWithLiveTask({ task_id: "same", revision: 1 }, "running", {
    queued_tasks: [{ task_id: "queued", revision: 1 }],
  });
  const root = await mount(value);
  await act(async () => rows(root)[0].props.onClick());
  await act(async () => rows(root)[1].props.onClick());
  assert.equal(pending[0].config.signal.aborted, true);
  await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "other", pool: value })));
  assert.equal(pending[1].config.signal.aborted, true);
  assert.equal(pending.length, 2);
  await act(async () => rows(root)[0].props.onClick());
  assert.equal(pending[2].config.url, "/api/v2/scans/other/tasks/same");
  await act(async () => pending[2].resolve("新扫描正文"));
  await act(async () => { pending[0].resolve("旧扫描运行正文"); pending[1].resolve("旧扫描排队正文"); });
  assert.match(text(root.toJSON()), /新扫描正文/);
  assert.doesNotMatch(text(root.toJSON()), /旧扫描|加载失败|尚未生成/);
  await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "s", pool: value })));
  await act(async () => rows(root)[0].props.onClick());
  assert.equal(pending.length, 4);
  assert.doesNotMatch(text(root.toJSON()), /新扫描正文|旧扫描/);
  await act(async () => pending[3].resolve("重新读取正文"));
  assert.match(text(root.toJSON()), /重新读取正文/);
});

test("queued task details do not become stale running or historical details", async () => {
  let calls = 0;
  const current = { task_id: "transition", revision: 1 };
  let terminal = false;
  client.api.defaults.adapter = async (config) => {
    if (config.url.endsWith("/tasks")) return response(config, { items: terminal ? [task("transition", "2026-10-15T00:00:00Z")] : [], next_cursor: null });
    calls += 1;
    return response(config, { ...current, prompt: `${calls} 阶段正文` });
  };
  const root = await mount(poolWithLiveTask(current, "queued"));
  await act(async () => rows(root)[0].props.onClick());
  assert.match(text(root.toJSON()), /1 阶段正文/);
  await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "s", pool: poolWithLiveTask(current) })));
  await act(async () => rows(root)[0].props.onClick());
  assert.match(text(root.toJSON()), /2 阶段正文/);
  terminal = true;
  await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "s", pool: pool() })));
  await act(async () => rows(root)[0].props.onClick());
  assert.match(text(root.toJSON()), /3 阶段正文/);
  assert.equal(calls, 3);
});
