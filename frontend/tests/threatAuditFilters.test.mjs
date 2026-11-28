import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "./helpers/reactTestEnv.mjs";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true, hmr: false } });
const client = await server.ssrLoadModule("/src/api/client.ts");
const runtime = await server.ssrLoadModule("/src/scanRuntime.ts");
const engines = await server.ssrLoadModule("/src/miningEngines.ts");
const threatAuditModel = await server.ssrLoadModule("/src/features/scanDetail/model/threatAudit.ts");
const { ThreatAuditPanel } = await server.ssrLoadModule("/src/components/ScanStatus.tsx");

const originalAdapter = client.api.defaults.adapter;
const roots = [];
globalThis.localStorage = { getItem: () => null };

afterEach(async () => {
  await act(async () => roots.splice(0).forEach((root) => root.unmount()));
  client.api.defaults.adapter = originalAdapter;
  client.setPublicScanAccess(null);
});

after(async () => {
  delete globalThis.localStorage;
  await server.close();
});

const text = (node) => {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(text).join("");
  return text(node?.children ?? node?.props?.children ?? "");
};
const rowButtons = (root) => root.root.findAllByType("button").filter((item) => item.parent?.type === "li");
const response = (config, data) => ({ config, data, status: 200, statusText: "OK", headers: {} });

function patternTask(id, overrides = {}) {
  return runtime.normalizePatternTask({
    task_id: id,
    scan_id: "scan-1",
    engine_id: engines.THREAT_PATTERN_AUDIT_ENGINE_ID,
    status: "completed",
    module_name: "认证模块",
    pattern_id: "ODH-NATIVE-01",
    pattern_name: "越界写入破坏内存状态",
    code_paths: [{ path: "src/auth" }],
    created_at: `2026-11-24T00:00:00Z`,
    ...overrides,
  });
}

function threatTask(id, overrides = {}) {
  return runtime.normalizeThreatTask({
    task_id: id,
    scan_id: "scan-1",
    status: "completed",
    surface_name: "请求解析入口",
    method_node_id: "ODH-PROTO-01",
    method_name: "协议长度计数与帧边界失配",
    code_path: "src/proto.c",
    created_at: `2026-11-24T00:00:00Z`,
    ...overrides,
  });
}

function makeScan(overrides = {}) {
  return runtime.normalizeScanStatus({
    scan_id: "scan-1",
    project_id: "proj-1",
    status: "complete",
    scan_items: [],
    vulnerabilities: [],
    candidates: [],
    events: [],
    threat_audit_tasks: [],
    threat_pattern_audit_tasks: [],
    ...overrides,
  });
}

function installEmptyResultsApi(extra = async () => undefined) {
  client.api.defaults.adapter = async (config) => {
    const custom = await extra(config);
    if (custom !== undefined) return response(config, custom);
    if (config.url.endsWith("-results")) {
      return response(
        config,
        config.params.getAll("task_ids").map((id) => ({
          task_id: id,
          findings: [],
          confirmed_issue_count: 0,
          association_complete: true,
        })),
      );
    }
    if (config.url.endsWith("/tasks")) {
      return response(config, { items: [], next_cursor: null });
    }
    return response(config, {});
  };
}

async function mountPanel(props) {
  let root;
  await act(async () => {
    root = create(createElement(ThreatAuditPanel, {
      events: [],
      fpReview: null,
      resultRevision: 0,
      onOpenIssue() {},
      ...props,
    }));
  });
  roots.push(root);
  return root;
}

function filterTrigger(root, label) {
  return root.root.findByProps({ "aria-label": `${label}筛选` });
}

function filterOption(root, labelText) {
  const found = root.root.findAllByProps({ role: "option" }).find((item) => text(item).includes(labelText));
  assert.ok(found, `Missing option containing: ${labelText}`);
  return found;
}

test("pure model aggregates, normalizes, deduplicates, sorts and filters modules and attack patterns", () => {
  const tasks = [
    { task_id: "t1", status: "completed", surface_name: "模块10", method_node_id: "ODH-NATIVE-10", method_name: "竞态条件与检查使用时差", code_path: "" },
    { task_id: "t2", status: "pending", surface_name: "模块2", method_node_id: "ODH-NATIVE-02", method_name: "越界读取泄露或干扰处理", code_path: "" },
    { task_id: "t3", status: "failed", surface_name: " 模块2 ", method_node_id: "ODH-NATIVE-02", method_name: "ODH-NATIVE-02 越界读取泄露或干扰处理", code_path: "" },
    { task_id: "t4", status: "completed", surface_name: "认证模块", method_node_id: "ODH-CRYPTO-01", method_name: "ODH-CRYPTO-01", code_path: "" },
    { task_id: "t5", status: "completed", surface_name: "", method_node_id: "", method_name: "", code_path: "" },
  ];

  const moduleOpts = threatAuditModel.threatAuditModuleOptions(tasks, true);
  assert.deepEqual(
    moduleOpts.map((item) => [item.value, item.label, item.count]),
    [
      ["模块2", "模块2", 2],
      ["模块10", "模块10", 1],
      ["认证模块", "认证模块", 1],
      [threatAuditModel.UNNAMED_THREAT_FILTER_VALUE, "未命名模块", 1],
    ],
  );
  assert.equal(
    threatAuditModel.threatAuditModuleOptions(tasks, false).at(-1).label,
    "未命名叶子节点",
  );

  const typeOpts = threatAuditModel.threatAuditTypeOptions(tasks);
  assert.deepEqual(
    typeOpts.map((item) => [item.value, item.label, item.count]),
    [
      ["ODH-CRYPTO-01", "ODH-CRYPTO-01", 1],
      ["ODH-NATIVE-02 越界读取泄露或干扰处理", "ODH-NATIVE-02 越界读取泄露或干扰处理", 2],
      ["ODH-NATIVE-10 竞态条件与检查使用时差", "ODH-NATIVE-10 竞态条件与检查使用时差", 1],
      [threatAuditModel.UNNAMED_THREAT_FILTER_VALUE, "未命名攻击模式", 1],
    ],
  );

  const runtimeByTaskId = new Map([
    ["t2", { id: "run-2", status: "running", modelId: "m", task: { task_name: "t2" } }],
  ]);
  // Multi-module OR + live runtime status AND.
  const matched = threatAuditModel.filterThreatAuditTasks(tasks, runtimeByTaskId, {
    status: "running",
    modules: ["模块2", "模块10"],
    types: ["ODH-NATIVE-02 越界读取泄露或干扰处理", "ODH-NATIVE-10 竞态条件与检查使用时差"],
  });
  assert.deepEqual(matched.map((item) => item.task_id), ["t2"]);

  // Multi-type OR across modules.
  const multiType = threatAuditModel.filterThreatAuditTasks(tasks, runtimeByTaskId, {
    status: "__all__",
    modules: [],
    types: ["ODH-CRYPTO-01", threatAuditModel.UNNAMED_THREAT_FILTER_VALUE],
  });
  assert.deepEqual(multiType.map((item) => item.task_id), ["t4", "t5"]);
});

test("ThreatAuditPanel supports multi-select module and attack-pattern filters with AND/OR semantics and reset", async () => {
  installEmptyResultsApi();
  const tasks = [
    patternTask("p1", { status: "completed", module_name: "认证模块", pattern_id: "ODH-NATIVE-01", pattern_name: "越界写入破坏内存状态" }),
    patternTask("p2", { status: "failed", module_name: "认证模块", pattern_id: "ODH-SYS-08", pattern_name: "日志错误与崩溃产物泄露敏感信息" }),
    patternTask("p3", { status: "completed", module_name: "协议解析模块", pattern_id: "ODH-NATIVE-01", pattern_name: "越界写入破坏内存状态" }),
    patternTask("p4", { status: "completed", module_name: "协议解析模块", pattern_id: "ODH-PROTO-01", pattern_name: "协议长度计数与帧边界失配" }),
    patternTask("p5", { status: "failed", module_name: "存储模块", pattern_id: "ODH-SYS-08", pattern_name: "日志错误与崩溃产物泄露敏感信息" }),
  ];
  const root = await mountPanel({
    scan: makeScan({ threat_pattern_audit_tasks: tasks }),
    patternMode: true,
  });

  // Initial state: all 5 rows, filters default to 全部, no search input, no reset button.
  assert.equal(rowButtons(root).length, 5);
  assert.equal(text(filterTrigger(root, "模块")), "全部");
  assert.equal(text(filterTrigger(root, "类型")), "全部");
  assert.equal(root.root.findAllByType("input").length, 0);
  assert.equal(root.root.findAllByType("button").some((item) => text(item) === "重置筛选"), false);

  // Open 模块 dropdown: no search input, rowButtons unaffected while dropdown is open.
  await act(async () => filterTrigger(root, "模块").props.onClick());
  assert.equal(root.root.findAllByType("input").length, 0);
  assert.equal(rowButtons(root).length, 5);

  // Select 认证模块 -> dropdown stays open, summary shows 认证模块, 2 tasks match.
  await act(async () => filterOption(root, "认证模块").props.onClick());
  assert.equal(filterTrigger(root, "模块").props["aria-expanded"], true);
  assert.equal(text(filterTrigger(root, "模块")), "认证模块");
  assert.equal(rowButtons(root).length, 2);
  assert.match(text(root.toJSON()), /匹配 2 \/ 5 条/);

  // Also select 存储模块 -> dropdown stays open, summary shows 已选 2 项, 3 tasks match.
  await act(async () => filterOption(root, "存储模块").props.onClick());
  assert.equal(filterTrigger(root, "模块").props["aria-expanded"], true);
  assert.equal(text(filterTrigger(root, "模块")), "已选 2 项");
  assert.equal(filterTrigger(root, "模块").props.title, "模块：认证模块、存储模块");
  assert.equal(rowButtons(root).length, 3);

  // Open 类型 dropdown -> automatically closes 模块 dropdown.
  await act(async () => filterTrigger(root, "类型").props.onClick());
  assert.equal(filterTrigger(root, "模块").props["aria-expanded"], false);
  assert.equal(filterTrigger(root, "类型").props["aria-expanded"], true);

  // Select ODH-SYS-08 -> intersects with {认证模块, 存储模块} => p2 & p5 (2 tasks).
  await act(async () => filterOption(root, "ODH-SYS-08 日志错误与崩溃产物泄露敏感信息").props.onClick());
  assert.equal(rowButtons(root).length, 2);
  assert.equal(text(filterTrigger(root, "类型")), "ODH-SYS-08 日志错误与崩溃产物泄露敏感信息");

  // Also select ODH-NATIVE-01 -> union within 类型 => p1, p2, p5 (3 tasks).
  await act(async () => filterOption(root, "ODH-NATIVE-01 越界写入破坏内存状态").props.onClick());
  assert.equal(rowButtons(root).length, 3);
  assert.equal(text(filterTrigger(root, "类型")), "已选 2 项");

  // Escape closes the open 类型 dropdown.
  await act(async () => filterTrigger(root, "类型").parent.props.onKeyDown({ key: "Escape", stopPropagation() {} }));
  assert.equal(filterTrigger(root, "类型").props["aria-expanded"], false);

  // Combine with 状态 = completed => only p1 matches.
  const statusSelect = root.root.findByType("select");
  await act(async () => statusSelect.props.onChange({ target: { value: "completed" } }));
  assert.equal(rowButtons(root).length, 1);
  assert.match(text(rowButtons(root)[0]), /越界写入破坏内存状态.*认证模块/);

  // Clear 类型 via 全部 inside dropdown => matches completed tasks in {认证模块, 存储模块} = p1.
  await act(async () => filterTrigger(root, "类型").props.onClick());
  await act(async () => filterOption(root, "全部").props.onClick());
  assert.equal(filterTrigger(root, "类型").props["aria-expanded"], false);
  assert.equal(text(filterTrigger(root, "类型")), "全部");

  // Filter to an empty intersection (failed + 协议解析模块) -> shows empty state.
  await act(async () => statusSelect.props.onChange({ target: { value: "failed" } }));
  await act(async () => filterTrigger(root, "模块").props.onClick());
  await act(async () => filterOption(root, "全部").props.onClick());
  await act(async () => filterTrigger(root, "模块").props.onClick());
  await act(async () => filterOption(root, "协议解析模块").props.onClick());
  assert.equal(rowButtons(root).length, 0);
  assert.match(text(root.toJSON()), /当前筛选条件下无任务/);
  assert.match(text(root.toJSON()), /从左侧选择一个审计任务查看详情/);

  // Reset all filters restores full list and hides reset button.
  const resetBtn = root.root.findAllByType("button").find((item) => text(item) === "重置筛选");
  assert.ok(resetBtn);
  await act(async () => resetBtn.props.onClick());
  assert.equal(rowButtons(root).length, 5);
  assert.equal(text(filterTrigger(root, "模块")), "全部");
  assert.equal(text(filterTrigger(root, "类型")), "全部");
  assert.equal(root.root.findAllByType("button").some((item) => text(item) === "重置筛选"), false);
});

test("filtering resets pagination, focusRequest clears active filters, and threat_audit mode works", async () => {
  installEmptyResultsApi();
  const tasks = [
    ...Array.from({ length: 24 }, (_, index) => patternTask(`p-${index}`, {
      module_name: index < 21 ? "模块A" : "模块B",
      pattern_id: index === 23 ? "ODH-SYS-01" : "ODH-NATIVE-01",
      pattern_name: index === 23 ? "外部数据进入命令或解释器" : "越界写入破坏内存状态",
      created_at: `2026-11-24T00:00:${String(index).padStart(2, "0")}Z`,
    })),
  ];
  const value = makeScan({ threat_pattern_audit_tasks: tasks });
  const root = await mountPanel({ scan: value, patternMode: true });

  // Go to page 2 first.
  const nextPage = root.root.findAllByType("button").find((item) => text(item) === "下一页");
  await act(async () => nextPage.props.onClick());
  assert.match(text(root.toJSON()), /第 2\/2 页 · 共 24 条/);

  // Selecting 模块B resets pagination back to page 1 showing only the 3 tasks in 模块B.
  await act(async () => filterTrigger(root, "模块").props.onClick());
  await act(async () => filterOption(root, "模块B").props.onClick());
  assert.equal(rowButtons(root).length, 3);
  assert.match(text(root.toJSON()), /匹配 3 \/ 24 条/);

  // Incoming focusRequest for p-0 (in 模块A) resets filters and focuses p-0.
  await act(async () => root.update(createElement(ThreatAuditPanel, {
    scan: value,
    patternMode: true,
    events: [],
    fpReview: null,
    resultRevision: 0,
    focusRequest: { key: "p-0", revision: 1 },
    onOpenIssue() {},
  })));
  assert.equal(text(filterTrigger(root, "模块")), "全部");
  assert.equal(rowButtons(root).length, 20);
  assert.equal(rowButtons(root)[0].props["aria-current"], "true");

  // Non-pattern threat_audit mode supports module & type multi-select with leaf fallback.
  const legacyScan = makeScan({
    threat_audit_tasks: [
      threatTask("ta-1", { surface_name: "HTTP 解析器", method_node_id: "ODH-PROTO-01", method_name: "协议长度计数与帧边界失配" }),
      threatTask("ta-2", { surface_name: "", method_node_id: "", method_name: "" }),
    ],
  });
  const legacyRoot = await mountPanel({ scan: legacyScan, patternMode: false });
  assert.equal(rowButtons(legacyRoot).length, 2);
  await act(async () => filterTrigger(legacyRoot, "模块").props.onClick());
  await act(async () => filterOption(legacyRoot, "未命名叶子节点").props.onClick());
  assert.equal(rowButtons(legacyRoot).length, 1);
  await act(async () => filterTrigger(legacyRoot, "类型").props.onClick());
  await act(async () => filterOption(legacyRoot, "未命名攻击模式").props.onClick());
  assert.equal(rowButtons(legacyRoot).length, 1);
});

test("iterative audit clears module/type filters on adjacent-round navigation and scan switches", async () => {
  const iterEngine = engines.THREAT_PATTERN_ITERATIVE_ENGINE_ID;
  const iterTasks = [
    patternTask("iter-1", {
      engine_id: iterEngine,
      iteration: 1,
      module_name: "认证模块",
      pattern_id: "ODH-NATIVE-01",
      pattern_name: "越界写入破坏内存状态",
      has_more_findings: true,
      followup_clues: "继续追踪下一轮",
      created_at: "2026-11-24T00:00:01Z",
    }),
    patternTask("iter-2", {
      engine_id: iterEngine,
      iteration: 2,
      parent_task_id: "iter-1",
      module_name: "认证模块",
      pattern_id: "ODH-NATIVE-01",
      pattern_name: "越界写入破坏内存状态",
      created_at: "2026-11-24T00:00:02Z",
    }),
    patternTask("iter-other", {
      engine_id: iterEngine,
      iteration: 1,
      module_name: "日志模块",
      pattern_id: "ODH-SYS-08",
      pattern_name: "日志错误与崩溃产物泄露敏感信息",
      created_at: "2026-11-24T00:00:03Z",
    }),
  ];
  installEmptyResultsApi(async (config) => {
    if (config.url.endsWith("/threat-pattern-audit-tasks")) {
      return { items: iterTasks, next_cursor: null, has_more: false };
    }
    if (config.url.includes("/threat-pattern-audit-tasks/")) {
      const target = iterTasks.find((item) => config.url.endsWith(`/${item.task_id}`));
      return { ...target, next_task_id: iterTasks.find((item) => item.parent_task_id === target.task_id)?.task_id || "" };
    }
    return undefined;
  });

  const scan1 = makeScan({
    scan_id: "scan-1",
    threat_pattern_audit_tasks: iterTasks,
    detail_counts: {
      threat_pattern_audit_by_engine: {
        [iterEngine]: { tasks: 3, current: 3, completed: 3, pending: 0, queued: 0, running: 0, failed: 0, cancelled: 0, superseded: 0 },
      },
    },
  });
  const root = await mountPanel({
    scan: scan1,
    patternMode: true,
    engineId: iterEngine,
  });

  // Apply module filter for 认证模块 (keeps iter-1 and iter-2) then also filter status = failed? No, keep iter-1 visible and navigate to next round.
  await act(async () => filterTrigger(root, "模块").props.onClick());
  await act(async () => filterOption(root, "认证模块").props.onClick());
  assert.equal(rowButtons(root).length, 2);

  // Navigate to next round -> clears active filters so all tasks are accessible again and iter-2 is selected.
  const nextRoundBtn = root.root.findAllByType("button").find((item) => text(item) === "下一轮 · 第 2 轮");
  assert.ok(nextRoundBtn);
  await act(async () => nextRoundBtn.props.onClick());
  assert.equal(text(filterTrigger(root, "模块")), "全部");
  assert.equal(rowButtons(root).length, 3);
  assert.equal(rowButtons(root)[1].props["aria-current"], "true");

  // Apply a filter again, then switch scan_id -> filters reset cleanly.
  await act(async () => filterTrigger(root, "类型").props.onClick());
  await act(async () => filterOption(root, "ODH-SYS-08").props.onClick());
  assert.equal(rowButtons(root).length, 1);

  const scan2 = makeScan({
    scan_id: "scan-2",
    threat_pattern_audit_tasks: iterTasks.map((item) => ({ ...item, scan_id: "scan-2" })),
    detail_counts: scan1.detail_counts,
  });
  await act(async () => root.update(createElement(ThreatAuditPanel, {
    scan: scan2,
    patternMode: true,
    engineId: iterEngine,
    events: [],
    fpReview: null,
    resultRevision: 0,
    onOpenIssue() {},
  })));
  assert.equal(text(filterTrigger(root, "类型")), "全部");
  assert.equal(rowButtons(root).length, 3);
});
