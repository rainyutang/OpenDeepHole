import assert from "node:assert/strict";
import test, { after } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
const { ModelPoolDashboard } = await server.ssrLoadModule("/src/components/ScanStatus.tsx");
const runtime = await server.ssrLoadModule("/src/scanRuntime.ts");
after(async () => { await server.close(); });

function pool(overrides = {}) {
  return runtime.normalizeOpenCodePool({
    scope_id: "scan", agent_session_id: "first", execution_revision: 1,
    updated_at: "2026-10-14T00:00:00.000Z", queued_tasks: [],
    models: [{ id: "m", total: 5, success: 4, failure: 1, avg_duration_seconds: 12 }],
    ...overrides,
  });
}
function text(node) {
  if (typeof node === "string") return node;
  if (Array.isArray(node)) return node.map(text).join("");
  return node?.children ? text(node.children) : "";
}

test("resume, restart, repeated SSE and page reload display the backend lifetime counters", () => {
  let current = pool();
  const root = TestRenderer.create(createElement(ModelPoolDashboard, { pool: current }));
  try {
    const resumed = pool({ execution_revision: 2, agent_session_id: "second",
      updated_at: "2026-10-14T00:00:01.001Z" });
    current = runtime.selectOpenCodePoolSnapshot(current, resumed);
    root.update(createElement(ModelPoolDashboard, { pool: current }));
    assert.match(text(root.toJSON()), /累计任务5成功4失败1/);
    const increment = pool({ execution_revision: 2, agent_session_id: "second",
      updated_at: "2026-10-14T00:00:01.002Z",
      models: [{ id: "m", total: 7, success: 5, failure: 1, timeout: 1, avg_duration_seconds: 100 / 7 }] });
    for (const event of [increment, increment, resumed]) {
      current = runtime.selectOpenCodePoolSnapshot(current, event);
      root.update(createElement(ModelPoolDashboard, { pool: current }));
      assert.match(text(root.toJSON()), /累计任务7成功5失败1超时\/取消1/);
      const cells = root.root.findAllByType("tr")[1].findAllByType("td");
      assert.equal(text(cells[5]), "7");
      assert.equal(text(cells[10]), "14.3s");
    }
    assert.match(text(root.toJSON()), /按本扫描累计，含续扫及重试/);
    const reloaded = runtime.normalizeOpenCodePool(JSON.parse(JSON.stringify(increment)));
    assert.deepEqual(runtime.selectOpenCodePoolSnapshot(null, reloaded).models, current.models);
  } finally {
    root.unmount();
  }
});

test("execution identity changes remain observable even when counters and timestamps match", () => {
  const current = pool();
  const resumed = pool({ execution_revision: 2, agent_session_id: "second" });
  assert.equal(runtime.sameOpenCodePoolSnapshot(current, resumed), false);
  assert.equal(runtime.sameOpenCodePoolSnapshot(current, pool({ agent_session_id: "second" })), false);
  assert.equal(runtime.selectOpenCodePoolSnapshot(current, resumed), resumed);
  const restarted = pool({ agent_session_id: "second", updated_at: "2026-10-14T00:00:00.001Z" });
  assert.equal(runtime.selectOpenCodePoolSnapshot(current, restarted).agent_session_id, "second");
});

test("historical models contribute counters while live rows and a new scan remain independent", () => {
  const value = pool({ global_running: 1, models: [
    { id: "removed", total: 5, success: 4, failure: 1, enabled: false, running: 0, max_concurrency: 1, active_tasks: [] },
    { id: "new", total: 2, success: 1, running: 1, max_concurrency: 3, active_tasks: [{ task_id: "active" }] },
  ] });
  const root = TestRenderer.create(createElement(ModelPoolDashboard, { pool: value }));
  try {
    assert.match(text(root.toJSON()), /运行中1排队中0累计任务7/);
    const rows = root.root.findAllByType("tr").slice(1);
    assert.equal(text(rows[0].findAllByType("td")[2]), "禁用");
    assert.equal(text(rows[0].findAllByType("td")[4]), "0/1");
    assert.equal(text(rows[1].findAllByType("td")[4]), "1/3");
    root.update(createElement(ModelPoolDashboard, { pool: pool({ scope_id: "other", models: [] }) }));
    assert.match(text(root.toJSON()), /累计任务0成功0失败0/);
  } finally {
    root.unmount();
  }
});

test("planned tasks are hidden from model pool dashboard while queued and running tasks remain visible", () => {
  const value = pool({
    global_running: 1,
    global_queued: 1,
    planned_tasks: [
      {
        planned_task_id: "planned-1",
        task_type: "vulnerability_mining",
        task_name: "candidate-audit-1",
        file: "src/planned.c",
        line: 42,
      },
    ],
    queued_tasks: [
      {
        request_id: "queued-1",
        task_type: "vulnerability_mining",
        task_name: "candidate-audit-2",
        file: "src/queued.c",
        line: 88,
      },
    ],
    models: [
      { id: "m", total: 5, success: 4, failure: 1, running: 1, max_concurrency: 2, active_tasks: [{ task_id: "active-1", file: "src/running.c", line: 12 }] },
    ],
  });
  const root = TestRenderer.create(createElement(ModelPoolDashboard, { pool: value }));
  try {
    const rendered = text(root.toJSON());
    assert.doesNotMatch(rendered, /计划中/);
    assert.doesNotMatch(rendered, /src\/planned\.c:42/);
    assert.match(rendered, /运行中和排队中为当前状态。/);
    assert.match(rendered, /运行中1排队中1累计任务5/);
    assert.match(rendered, /全局排队任务/);
    assert.match(rendered, /src\/queued\.c:88/);
    assert.match(rendered, /src\/running\.c:12/);
  } finally {
    root.unmount();
  }
});

test("model pool dashboard surfaces circuit cooldown, half-open probe, cross-scan global running and queue waiting hints", () => {
  const value = pool({
    global_running: 1,
    global_queued: 1,
    queued_tasks: [
      {
        request_id: "queued-avoid",
        task_type: "vulnerability_mining",
        file: "src/retry.c",
        line: 19,
        waiting_hint: "前序尝试未通过，正在等待其他未尝试模型释放并发额度。",
      },
    ],
    models: [
      {
        id: "m-quota",
        model: "p/quota",
        enabled: true,
        available: true,
        circuit_state: "quota_open",
        cooldown_remaining_seconds: 45,
        last_health_failure_at: "2026-11-19T02:00:00Z",
        last_health_failure_kind: "quota",
        running: 0,
        global_running: 0,
        max_concurrency: 4,
      },
      {
        id: "m-probe",
        model: "p/probe",
        enabled: true,
        available: true,
        circuit_state: "quota_half_open",
        running: 1,
        global_running: 3,
        max_concurrency: 4,
      },
      {
        id: "m-access",
        model: "p/access",
        enabled: true,
        available: true,
        circuit_state: "access_open",
        cooldown_remaining_seconds: 120,
        last_health_failure_at: "2026-11-19T02:01:00Z",
        last_health_failure_kind: "access_denied",
        running: 0,
        global_running: 0,
        max_concurrency: 2,
      },
    ],
  });
  const root = TestRenderer.create(createElement(ModelPoolDashboard, { pool: value }));
  try {
    const rendered = text(root.toJSON());
    assert.match(rendered, /前序尝试未通过，正在等待其他未尝试模型释放并发额度。/);
    const rows = root.root.findAllByType("tr").slice(1);
    assert.match(text(rows[0].findAllByType("td")[2]), /配额冷却中/);
    assert.match(text(rows[0].findAllByType("td")[3]), /配额限流/);
    assert.equal(text(rows[1].findAllByType("td")[2]), "恢复探测中 (限 1 并发)");
    assert.match(text(rows[1].findAllByType("td")[4]), /1\/4全局 3\/4/);
    assert.match(text(rows[2].findAllByType("td")[2]), /权限隔离中/);
    assert.match(text(rows[2].findAllByType("td")[3]), /权限拒绝/);
  } finally {
    root.unmount();
  }
});
