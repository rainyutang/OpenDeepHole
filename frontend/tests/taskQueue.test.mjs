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
function typeFilter(root) { return root.root.findByProps({ "aria-label": "任务类型" }); }
async function selectType(root, value) {
  await act(async () => typeFilter(root).props.onChange({ target: { value } }));
}
function hasHistoryButton(root) {
  return root.root.findAllByType("button").some((item) => /加载更多历史任务|重试加载历史任务/.test(text(item)));
}
async function mount(value = pool()) {
  let root;
  await act(async () => { root = create(createElement(ScanTaskQueuePanel, { scanId: "s", pool: value })); });
  roots.push(root);
  return root;
}

test("planned-only work is hidden until it enters the queue, while shared runtime collection retains it", async () => {
  const { collectScanQueueTasks } = await server.ssrLoadModule("/src/features/scanDetail/model/taskQueue.ts");
  client.api.defaults.adapter = async (config) => response(config, { items: [], next_cursor: null });
  const candidate = { task_type: "vulnerability_mining", task_name: "candidate-audit-s-1", planned_task_id: "candidate" };
  const review = { task_type: "fp_review", planned_task_id: "review" };
  const value = pool({ total_tasks: 2, completed_task_count: 0, planned_tasks: [candidate, review] });
  assert.equal(collectScanQueueTasks(value).filter((item) => item.status === "planned").length, 2);
  const root = await mount(value);
  assert.equal(rows(root).length, 0);
  assert.doesNotMatch(text(root.toJSON()), /计划中/);
  await selectType(root, "candidate_audit");
  assert.equal(rows(root).length, 0);
  const queued = { ...candidate, task_id: "candidate", queued_at: "2026-11-13T01:00:00Z" };
  const next = { ...value, global_queued: 1, queued_tasks: [queued], planned_tasks: [review] };
  await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "s", pool: next })));
  assert.equal(rows(root).length, 1);
  assert.equal(text(rows(root)[0].findAllByType("td")[0]), "排队中");
  await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "s", pool: {
    ...next, global_queued: 0, global_running: 1, queued_tasks: [],
    models: [{ id: "candidate-model", active_tasks: [{ ...queued, started_at: "2026-11-13T01:01:00Z" }] }],
  } })));
  assert.deepEqual(ids(root), ["candidate-model"]);
  assert.equal(text(rows(root)[0].findAllByType("td")[0]), "运行中");
});

test("task filters classify new and legacy types, context fallbacks, and unknown task labels consistently", async () => {
  client.api.defaults.adapter = async (config) => response(config, { items: [], next_cursor: null });
  const samples = [
    ["candidate-new", "candidate_audit", { task_type: "vulnerability_mining", task_name: "candidate-audit-s-0" }],
    ["candidate-old", "candidate_audit", { task_type: "audit" }],
    ["candidate-direct", "candidate_audit", { task_type: "candidate_audit" }],
    ["candidate-nested", "candidate_audit", { task_type: " ", task_name: "", context: { task_type: " VULNERABILITY_MINING ", task_name: " CANDIDATE-AUDIT-S-1 " } }],
    ["project-new", "project_audit", { task_type: "vulnerability_mining", task_name: "project-audit-s-0" }],
    ["project-old", "project_audit", { task_type: "project_audit" }],
    ["project-name-priority", "project_audit", { task_type: " VULNERABILITY_MINING ", task_name: " PROJECT-AUDIT-S-2 ", context: { task_name: "candidate-audit-s-2" } }],
    ["sensitive", "sensitive_clear", { task_type: "sensitive_clear" }],
    ["report", "report_audit", { task_type: "report_audit" }],
    ["analysis", "threat_analysis", { task_type: "threat_analysis" }],
    ["threat", "threat_audit", { task_type: "vulnerability_mining", task_name: "threat-audit-s-0" }],
    ["pattern", "threat_pattern_audit", { task_type: "vulnerability_mining", task_name: "threat-pattern-audit-s-0" }],
    ["iterative", "threat_pattern_iterative_audit", { task_type: "vulnerability_mining", task_name: "threat-pattern-iterative-audit-s-0" }],
    ["review", "fp_review", { task_type: "fp_review", context: { task_type: "audit" } }],
    ["validation-old", "vulnerability_validation", { task_type: "validation" }],
    ["validation-new", "vulnerability_validation", { task_type: "vulnerability_validation" }],
    ["dedup", "vulnerability_dedup", { task_type: "vulnerability_mining", task_name: "vulnerability-dedup-s-0" }],
    ["generic", "vulnerability_mining", { task_type: "vulnerability_mining", task_name: "custom-work" }],
    ["legacy-empty", "vulnerability_mining", {}],
    ["legacy-name-only", "vulnerability_mining", { task_name: "threat-audit-s-1" }],
    ["unknown", "other", { task_type: "custom-task-kind" }],
  ];
  const values = samples.map(([id, , fields]) => task(id, "2026-11-13T01:00:00Z", fields));
  const root = await mount(pool({ completed_tasks: values, completed_task_count: values.length }));
  assert.equal(typeFilter(root).props.value, "");
  const expectedKinds = [...new Set(samples.map(([, kind]) => kind))];
  assert.deepEqual(new Set(typeFilter(root).findAllByType("option").map((option) => option.props.value)), new Set(["", ...expectedKinds]));
  for (const kind of expectedKinds) {
    await selectType(root, kind);
    assert.deepEqual([...ids(root)].sort(), samples.filter(([, expected]) => expected === kind).map(([id]) => id).sort());
  }
  assert.match(text(rows(root)[0]), /custom-task-kind/);
});

test("direct business types retain their filter keys independently of task names", async () => {
  const { scanQueueTaskKind, scanQueueTaskTypeLabel } = await server.ssrLoadModule("/src/features/modelPool/presentation.ts");
  const directKinds = ["candidate_audit", "project_audit", "sensitive_clear", "report_audit", "threat_analysis",
    "threat_audit", "threat_pattern_audit", "threat_pattern_iterative_audit", "fp_review", "vulnerability_validation", "vulnerability_dedup"];
  for (const kind of directKinds) {
    const value = { task_type: ` ${kind.toUpperCase()} `, task_name: "candidate-audit-unrelated-name", context: { task_type: "validation" } };
    assert.equal(scanQueueTaskKind(value), kind);
    assert.notEqual(scanQueueTaskTypeLabel(value), kind);
  }
  assert.equal(scanQueueTaskKind({ task_type: " AUDIT " }), "candidate_audit");
  assert.equal(scanQueueTaskKind({ task_type: " VALIDATION " }), "vulnerability_validation");
  assert.equal(scanQueueTaskKind({ task_type: "custom-type" }), "other");
  assert.equal(scanQueueTaskTypeLabel({ task_type: "custom-type" }), "custom-type");
  assert.equal(scanQueueTaskKind({}), "vulnerability_mining");
});

for (const access of ["authenticated", "public", "shared"]) {
  test(`type filtering reaches older history before pagination and keeps global counts (${access})`, async () => {
    if (access !== "authenticated") client.setPublicScanAccess({ scanId: "s", token: "token", kind: access === "shared" ? "shared" : "integration" });
    const prefix = access === "authenticated" ? "/api/v2/scans/s" : `/api/${access}/scans/s`;
    const values = Array.from({ length: 126 }, (_, index) => task(`history-${index}`,
      new Date(Date.UTC(2026, 10, 13, 0, 0, 126 - index)).toISOString(), index < 65
        ? { task_type: "fp_review" }
        : { task_type: "vulnerability_mining", task_name: `candidate-audit-s-${index}` }));
    const calls = [];
    client.api.defaults.adapter = async (config) => {
      assert.ok(config.url.startsWith(prefix));
      if (access !== "authenticated") assert.equal(config.params.token, "token");
      if (config.url !== `${prefix}/tasks`) {
        const item = values.find((candidate) => config.url.endsWith(`/${candidate.task_id}`));
        assert.ok(item);
        return response(config, { ...item, prompt: "筛选任务完整 Prompt" });
      }
      calls.push({ kind: config.params.task_kind || "", cursor: config.params.cursor });
      assert.equal(config.params.limit, 50);
      const filtered = config.params.task_kind === "candidate_audit" ? values.slice(65)
        : config.params.task_kind === "fp_review" ? values.slice(0, 65)
        : config.params.task_kind ? [] : values;
      const offset = Number(config.params.cursor || 0);
      return response(config, { items: filtered.slice(offset, offset + 50), next_cursor: offset + 50 < filtered.length ? String(offset + 50) : null });
    };
    const value = pool({ completed_task_count: values.length, global_running: 2, global_queued: 2,
      models: [
        { id: "candidate-running", active_tasks: [{ task_id: "run-candidate", task_type: "audit" }] },
        { id: "review-running", active_tasks: [{ task_id: "run-review", task_type: "fp_review" }] },
      ],
      queued_tasks: [{ task_id: "wait-candidate", task_type: "audit" }, { task_id: "wait-review", task_type: "fp_review" }],
      completed_tasks: [task("snapshot-analysis", "2026-11-13T03:00:00Z", { task_type: "threat_analysis" })],
      planned_tasks: [{ planned_task_id: "planned-candidate", task_type: "audit" }],
    });
    const root = await mount(value);
    assert.ok(!ids(root).includes("history-65"));
    await act(async () => button(root, "下一页").props.onClick());
    await selectType(root, "candidate_audit");
    assert.match(text(root.toJSON()), /第 1\//);
    assert.deepEqual(ids(root).slice(0, 3), ["candidate-running", "-", "history-65"]);
    assert.doesNotMatch(text(root.toJSON()), /计划中/);
    assert.match(text(root.toJSON()), /运行中 2/);
    assert.match(text(root.toJSON()), /排队中 2/);
    assert.match(text(root.toJSON()), /已执行 126/);
    await act(async () => rows(root)[2].props.onClick());
    assert.match(text(root.toJSON()), /筛选任务完整 Prompt/);
    await act(async () => button(root, "加载更多历史任务").props.onClick());
    assert.equal(hasHistoryButton(root), false);
    const loaded = ids(root);
    for (let page = 1; page < Math.ceil(63 / 12); page += 1) {
      await act(async () => button(root, "下一页").props.onClick());
      loaded.push(...ids(root));
    }
    assert.deepEqual(loaded, ["candidate-running", "-", ...values.slice(65).map((item) => item.task_id)]);
    await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "s", pool: { ...value, updated_at: "heartbeat" } })));
    assert.equal(hasHistoryButton(root), false, "an unrelated global count must not reopen exhausted filtered history");
    assert.deepEqual(calls.filter((call) => call.cursor), [{ kind: "candidate_audit", cursor: "50" }]);
    await selectType(root, "fp_review");
    assert.match(text(root.toJSON()), /第 1\//);
    assert.deepEqual(ids(root).slice(0, 3), ["review-running", "-", "history-0"]);
    assert.doesNotMatch(text(root.toJSON()), /筛选任务完整 Prompt/);
    await selectType(root, "vulnerability_validation");
    assert.equal(rows(root).length, 0);
    assert.match(text(root.toJSON()), /当前.*类型.*(?:暂无|没有)|没有.*匹配|暂无.*匹配/);
    assert.equal(hasHistoryButton(root), false);
    await selectType(root, "");
    assert.equal(calls.at(-1).kind, "");
    assert.ok(ids(root).includes("snapshot-analysis"));
  });
}

for (const kind of ["", "candidate_audit"]) {
  test(`late historical completions reopen exhausted pages once per count increase (${kind || "all"})`, async () => {
    const values = Array.from({ length: 60 }, (_, index) => task(`original-${index}`,
      new Date(Date.UTC(2026, 10, 13, 0, 0, 60 - index)).toISOString(), { task_type: "audit" }));
    const firstPageIds = values.slice(0, 50).map((item) => item.task_id);
    const calls = [];
    client.api.defaults.adapter = async (config) => {
      const ordered = [...values].sort(compareTaskHistory);
      const offset = Number(config.params.cursor || 0);
      const items = ordered.slice(offset, offset + 50);
      calls.push({ kind: config.params.task_kind || "", cursor: config.params.cursor, ids: items.map((item) => item.task_id) });
      return response(config, { items, next_cursor: offset + 50 < ordered.length ? String(offset + 50) : null });
    };
    // Filtered history can stay much smaller than the scan-wide total.
    let completedCount = kind ? 160 : 60;
    const root = await mount(pool({ completed_task_count: completedCount }));
    if (kind) await selectType(root, kind);
    await act(async () => button(root, "加载更多历史任务").props.onClick());
    assert.equal(hasHistoryButton(root), false);
    for (let arrival = 1; arrival <= 2; arrival += 1) {
      values.push(task(`late-${arrival}`, `2026-11-13T00:00:${String(11 - arrival).padStart(2, "0")}.500Z`, { task_type: "audit" }));
      completedCount += 1;
      await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "s", pool: pool({
        completed_task_count: completedCount, updated_at: `arrival-${arrival}`,
      }) })));
      assert.deepEqual(calls.at(-1).ids, firstPageIds, "late completions do not alter the newest history page");
      assert.equal(calls.at(-1).kind, kind);
      assert.equal(hasHistoryButton(root), true, "a new scan completion can be an older report outside the first page");
      assert.equal(calls.filter((call) => call.cursor).length, arrival, "refresh must not fetch all older history automatically");
      await act(async () => button(root, "加载更多历史任务").props.onClick());
      assert.equal(hasHistoryButton(root), false);
      while (!button(root, "上一页").props.disabled) await act(async () => button(root, "上一页").props.onClick());
      const loaded = [...ids(root)];
      while (!button(root, "下一页").props.disabled) {
        await act(async () => button(root, "下一页").props.onClick());
        loaded.push(...ids(root));
      }
      assert.deepEqual(loaded, [...values].sort(compareTaskHistory).map((item) => item.task_id));
      for (let heartbeat = 0; heartbeat < 2; heartbeat += 1) {
        await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "s", pool: pool({
          completed_task_count: completedCount, updated_at: `heartbeat-${arrival}-${heartbeat}`,
        }) })));
        assert.equal(hasHistoryButton(root), false, "the same completion count must not repeatedly reopen exhausted history");
      }
    }
    assert.deepEqual(calls.filter((call) => call.cursor).map(({ kind: selected, cursor }) => ({ kind: selected, cursor })), [
      { kind, cursor: "50" }, { kind, cursor: "50" }, { kind, cursor: "50" },
    ]);
  });
}

for (const outcome of ["success", "error"]) {
  test(`changing task types ignores an old filter's pending page ${outcome}`, async () => {
    let finishOld;
    client.api.defaults.adapter = async (config) => {
      if (config.params.cursor === "candidate-older") {
        return new Promise((resolve, reject) => { finishOld = () => outcome === "success"
          ? resolve(response(config, { items: [task("old-candidate", "2026-11-12T00:00:00Z", { task_type: "audit" })], next_cursor: "stale" }))
          : reject(new Error("old filter failed")); });
      }
      const kind = config.params.task_kind || "";
      return response(config, { items: kind ? [task(kind, "2026-11-13T00:00:00Z", { task_type: kind === "candidate_audit" ? "audit" : kind })] : [],
        next_cursor: kind === "candidate_audit" ? "candidate-older" : null });
    };
    const root = await mount();
    await selectType(root, "candidate_audit");
    await act(async () => button(root, "加载更多历史任务").props.onClick());
    assert.equal(button(root, "加载中").props.disabled, true);
    await selectType(root, "fp_review");
    assert.deepEqual(ids(root), ["fp_review"]);
    await act(async () => finishOld());
    assert.deepEqual(ids(root), ["fp_review"]);
    assert.doesNotMatch(text(root.toJSON()), /历史任务加载失败|加载中/);
    assert.equal(hasHistoryButton(root), false);
  });
}

test("changing scans restores all task types and discards an old filter's pending first page", async () => {
  let finishOld;
  const calls = [];
  client.api.defaults.adapter = async (config) => {
    calls.push({ url: config.url, kind: config.params.task_kind || "" });
    if (config.url.includes("/s/") && config.params.task_kind === "candidate_audit") {
      return new Promise((resolve) => { finishOld = () => resolve(response(config, {
        items: [task("old-scan", "2026-11-13T00:00:00Z", { task_type: "audit" })], next_cursor: "old-cursor",
      })); });
    }
    return response(config, { items: [task(config.url.includes("/other/") ? "other-scan" : "s", "2026-11-13T00:00:00Z")], next_cursor: null });
  };
  const root = await mount();
  await selectType(root, "candidate_audit");
  await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "other", pool: pool({ scope_id: "other" }) })));
  assert.equal(typeFilter(root).props.value, "");
  assert.deepEqual(ids(root), ["other-scan"]);
  await act(async () => finishOld());
  assert.deepEqual(ids(root), ["other-scan"]);
  assert.equal(hasHistoryButton(root), false);
  assert.ok(calls.filter((call) => call.url.includes("/other/")).every((call) => call.kind === ""));
});

test("a failed filtered history page retries the same filter and cursor after a refresh", async () => {
  const calls = [];
  let failed = false;
  client.api.defaults.adapter = async (config) => {
    const kind = config.params.task_kind || "";
    calls.push({ kind, cursor: config.params.cursor });
    if (config.params.cursor === "older") {
      assert.equal(kind, "candidate_audit");
      if (!failed) { failed = true; throw new Error("temporary failure"); }
      return response(config, { items: [task("older", "2026-11-12T00:00:00Z", { task_type: "audit" })], next_cursor: null });
    }
    return response(config, { items: kind ? [task("current", "2026-11-13T00:00:00Z", { task_type: "audit" })] : [],
      next_cursor: kind ? "older" : null });
  };
  const root = await mount();
  await selectType(root, "candidate_audit");
  await act(async () => button(root, "加载更多历史任务").props.onClick());
  assert.match(text(root.toJSON()), /历史任务加载失败/);
  await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "s", pool: pool({ updated_at: "heartbeat" }) })));
  assert.match(text(root.toJSON()), /历史任务加载失败/);
  await act(async () => button(root, "重试加载历史任务").props.onClick());
  assert.deepEqual(ids(root), ["current", "older"]);
  assert.deepEqual(calls.filter((call) => call.cursor), [
    { kind: "candidate_audit", cursor: "older" }, { kind: "candidate_audit", cursor: "older" },
  ]);
  assert.equal(hasHistoryButton(root), false);
});

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
  test(`review-only queue hides planned work and keeps waiting and running work (${publicAccess ? "public" : "authenticated"})`, async () => {
    if (publicAccess) client.setPublicScanAccess({ scanId: "s", token: "public-token" });
    client.api.defaults.adapter = async (config) => response(config, { items: [], next_cursor: null });
    const owner = { task_type: "fp_review", execution_kind: "fp_review", execution_id: "review", execution_revision: 2 };
    const value = pool({ completed_task_count: 0, total_tasks: 3, global_running: 1, global_queued: 1,
      models: [{ id: "m", model: "p/m", active_tasks: [{ ...owner, task_id: "run" }] }],
      queued_tasks: [{ ...owner, request_id: "wait" }],
      planned_tasks: [{ ...owner, planned_task_id: "next" }] });
    const root = await mount(value);
    assert.deepEqual(rows(root).map((row) => text(row.findAllByType("td")[0])), ["运行中", "排队中"]);
    assert.equal(rows(root).filter((row) => text(row).includes("去误报")).length, 2);
    assert.doesNotMatch(text(root.toJSON()), /计划中/);
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
    assert.deepEqual(rows(root).slice(0, 2).map((row) => text(row.findAllByType("td")[0])), ["运行中", "排队中"]);
    assert.deepEqual(ids(root).slice(2), values.slice(0, 10).map((item) => item.task_id));
    assert.equal(rows(root).length, 12);
    assert.match(text(root.toJSON()), /已加载 50 条/);
    await act(async () => rows(root)[2].props.onClick());
    assert.match(text(root.toJSON()), /完整任务 Prompt/);
    await act(async () => button(root, "加载更多历史任务").props.onClick());
    assert.match(text(root.toJSON()), /已加载 100 条/);
    refreshed = true;
    await act(async () => root.update(createElement(ScanTaskQueuePanel, { scanId: "s", pool: { ...value, updated_at: "new" } })));
    assert.equal(ids(root)[2], "latest");
    assert.match(text(root.toJSON()), /已加载 101 条/);
    assert.match(text(root.toJSON()), /完整任务 Prompt/);
    await act(async () => button(root, "加载更多历史任务").props.onClick());
    assert.deepEqual(calls.filter((call) => call.params.cursor).map((call) => call.params.cursor), ["50", "100"]);
    const loadedIds = ids(root);
    for (let page = 1; page < 10; page += 1) {
      await act(async () => button(root, "下一页").props.onClick());
      loadedIds.push(...ids(root));
    }
    assert.deepEqual(loadedIds.slice(2), ["latest", ...values.map((item) => item.task_id)]);
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
  assert.match(text(root.toJSON()), /已加载 50 条/);

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
  assert.match(text(root.toJSON()), /已加载 100 条/);
  rejectPages = false;
  await act(async () => button(root, "重试加载历史任务").props.onClick());
  assert.equal(cursors.at(-1), "100");
  assert.match(text(root.toJSON()), /已加载 105 条/);
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
  test(`missing Session IDs stay unknown per attempt after reload (${access})`, async () => {
    if (access !== "authenticated") client.setPublicScanAccess({ scanId: "s", token: "token", kind: access === "shared" ? "shared" : "integration" });
    const prefix = access === "authenticated" ? "/api/v2/scans/s" : `/api/${access}/scans/s`;
    const reason = "OpenCode call timed out during scan_mcp_wait (session total timeout)";
    const event = (sequence, sessionId) => ({ sequence, phase: "business", session_id: sessionId,
      session_attempt: sequence, outcome: "timeout", failure_kind: "timeout", failure_reason: reason });
    const history = [
      task("missing", "2026-11-13T04:00:00Z", { outcome: "timeout", session_events: [event(1, "")] }),
      task("retry", "2026-11-13T04:00:00Z", { outcome: "timeout", serve_session_id: "ses_previous",
        session_events: [event(1, "ses_previous"), event(2, "")] }),
      task("no-trace", "2026-11-13T04:00:00Z", { outcome: "timeout" }),
      task("legacy", "2026-11-13T04:00:00Z", { outcome: "timeout", serve_session_id: "ses_legacy" }),
    ];
    client.api.defaults.adapter = async (config) => {
      assert.ok(config.url.startsWith(prefix));
      if (access !== "authenticated") assert.equal(config.params.token, "token");
      if (config.url === `${prefix}/tasks`) return response(config, {
        items: history.map(({ session_events, ...metadata }) => metadata), next_cursor: null,
      });
      const detail = history.find((item) => config.url === `${prefix}/tasks/${item.task_id}`);
      assert.ok(detail);
      return response(config, { ...detail, prompt: "原始任务" });
    };
    for (let reload = 0; reload < 2; reload += 1) {
      const root = await mount(pool({ completed_task_count: history.length, total_tasks: history.length }));
      for (const item of history) {
        const row = rows(root).find((candidate) => text(candidate.findAllByType("td")[2]) === item.task_id);
        assert.ok(row);
        await act(async () => row.props.onClick());
        const rendered = text(root.toJSON());
        assert.doesNotMatch(rendered, /Session 未创建|Session 尚未创建|Session 创建前结束/);
        if (item.task_id === "no-trace") {
          assert.match(rendered, /该任务未记录 Session ID，无法确认是否已创建 Session。/);
        } else if (item.task_id === "legacy") {
          assert.equal((rendered.match(/ses_legacy/g) || []).length, 1);
          assert.doesNotMatch(rendered, /未记录 Session ID/);
        } else {
          assert.equal((rendered.match(/未记录 Session ID/g) || []).length, 1);
          assert.ok(rendered.includes(reason));
          if (item.task_id === "retry") assert.equal((rendered.match(/ses_previous/g) || []).length, 1);
        }
      }
      await act(async () => root.unmount());
      roots.splice(roots.indexOf(root), 1);
    }
  });

  test(`live tasks wait for Session ID reporting without inferring creation state (${access})`, async () => {
    if (access !== "authenticated") client.setPublicScanAccess({ scanId: "s", token: "token", kind: access === "shared" ? "shared" : "integration" });
    const prefix = access === "authenticated" ? "/api/v2/scans/s" : `/api/${access}/scans/s`;
    const liveTasks = [{ task_id: "run", revision: 1 }, { task_id: "wait", revision: 1 }];
    client.api.defaults.adapter = async (config) => {
      assert.ok(config.url.startsWith(prefix));
      if (access !== "authenticated") assert.equal(config.params.token, "token");
      if (config.url === `${prefix}/tasks`) return response(config, { items: [], next_cursor: null });
      const detail = liveTasks.find((item) => config.url === `${prefix}/tasks/${item.task_id}`);
      assert.ok(detail);
      return response(config, { ...detail, prompt: "原始任务" });
    };
    const root = await mount(pool({ completed_task_count: 0, total_tasks: 3,
      models: [{ id: "m", active_tasks: [liveTasks[0]] }], queued_tasks: [liveTasks[1]],
      planned_tasks: [{ planned_task_id: "next" }] }));
    for (const row of rows(root)) {
      await act(async () => row.props.onClick());
      const rendered = text(root.toJSON());
      assert.match(rendered, /等待 Session ID 上报。/);
      assert.doesNotMatch(rendered, /Session 未创建|Session 尚未创建/);
    }
  });

  test(`missing model reminder is retained in task history after reload (${access})`, async () => {
    if (access !== "authenticated") client.setPublicScanAccess({ scanId: "s", token: "token", kind: access === "shared" ? "shared" : "integration" });
    const prefix = access === "authenticated" ? "/api/v2/scans/s" : `/api/${access}/scans/s`;
    const reason = "配置的模型不存在：provider/missing-model。请在 Agent 的“模型配置”中重新导入或选择有效模型，保存后重试。";
    const history = ["full", "kind-only"].map((id) => task(id, "2026-10-21T04:00:00Z", {
      outcome: "failure", model: "provider/missing-model", serve_session_id: `ses_${id}`,
      failure_kind: "model_not_found", failure_reason: id === "full" ? reason : "",
      session_events: [{ sequence: 1, phase: "business", session_id: `ses_${id}`,
        session_attempt: 1, outcome: "failure", failure_kind: "model_not_found",
        failure_reason: id === "full" ? reason : "" }],
    }));
    client.api.defaults.adapter = async (config) => {
      assert.ok(config.url.startsWith(prefix));
      if (access !== "authenticated") assert.equal(config.params.token, "token");
      if (config.url === `${prefix}/tasks`) return response(config, { items: history, next_cursor: null });
      const detail = history.find((item) => config.url === `${prefix}/tasks/${item.task_id}`);
      assert.ok(detail);
      return response(config, { ...detail, prompt: "原始任务" });
    };
    for (let reload = 0; reload < 2; reload += 1) {
      const root = await mount(pool({ completed_task_count: 2, total_tasks: 2 }));
      for (const row of rows(root)) await act(async () => row.props.onClick());
      const rendered = text(root.toJSON());
      assert.ok(rendered.includes(reason));
      assert.ok((rendered.match(/配置的模型不存在/g) || []).length >= 2);
      assert.doesNotMatch(rendered, /model_not_found/);
      await act(async () => root.unmount());
      roots.splice(roots.indexOf(root), 1);
    }
  });

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
    assert.equal(rows(root).length, 2);
    assert.doesNotMatch(text(root.toJSON()), /计划中|尚未生成，进入排队或运行后显示/);
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
