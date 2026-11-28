import assert from "node:assert/strict";
import test, { after, afterEach, beforeEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "./helpers/reactTestEnv.mjs";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({
  appType: "custom",
  logLevel: "silent",
  server: { middlewareMode: true, hmr: false },
});

const client = await server.ssrLoadModule("/src/api/client.ts");
const { default: UserManagement } = await server.ssrLoadModule("/src/components/UserManagement.tsx");
const { ThemeProvider } = await server.ssrLoadModule("/src/theme/ThemeProvider.tsx");
const model = await server.ssrLoadModule("/src/features/userManagement/userManagementModel.ts");

const originalAdapter = client.api.defaults.adapter;
const roots = [];
const stored = new Map();

globalThis.localStorage = {
  getItem: (key) => stored.get(key) ?? null,
  setItem: (key, value) => stored.set(key, value),
  removeItem: (key) => stored.delete(key),
};
globalThis.window = Object.assign(new EventTarget(), {
  localStorage,
  location: { origin: "https://example.test" },
});
globalThis.document = Object.assign(new EventTarget(), {
  documentElement: { dataset: {}, style: {} },
});

const textOf = (node) =>
  typeof node === "string" || typeof node === "number"
    ? String(node)
    : Array.isArray(node)
      ? node.map(textOf).join("")
      : textOf(node?.children ?? "");

const response = (config, data) => ({
  config,
  data,
  status: 200,
  statusText: "OK",
  headers: {},
});

let state;
let getUsersCount;
let getDeptsCount;

beforeEach(() => {
  getUsersCount = 0;
  getDeptsCount = 0;
  state = {
    departments: [
      {
        department_id: "dept-sec",
        name: "安全研究部",
        user_count: 2,
        created_at: "2026-11-01T00:00:00Z",
        updated_at: "2026-11-01T00:00:00Z",
      },
      {
        department_id: "dept-dev",
        name: "平台研发部",
        user_count: 1,
        created_at: "2026-11-02T00:00:00Z",
        updated_at: "2026-11-02T00:00:00Z",
      },
    ],
    users: [
      {
        user_id: "u-admin",
        username: "admin",
        role: "admin",
        agent_token: "t1",
        created_at: "2026-11-01T00:00:00Z",
        employee_id: "A001",
        department_id: "dept-sec",
        department_name: "安全研究部",
        scan_count: 3,
        suspected_issue_count: 5,
      },
      {
        user_id: "u-alice",
        username: "alice",
        role: "user",
        agent_token: "t2",
        created_at: "2026-11-02T00:00:00Z",
        employee_id: "E102",
        department_id: "dept-sec",
        department_name: "安全研究部",
        scan_count: 8,
        suspected_issue_count: 2,
      },
      {
        user_id: "u-bob",
        username: "bob",
        role: "user",
        agent_token: "t3",
        created_at: "2026-11-03T00:00:00Z",
        employee_id: "E205",
        department_id: "dept-dev",
        department_name: "平台研发部",
        scan_count: 1,
        suspected_issue_count: 9,
      },
      {
        user_id: "u-carol",
        username: "carol",
        role: "user",
        agent_token: "t4",
        created_at: "2026-11-04T00:00:00Z",
        employee_id: "",
        department_id: "",
        department_name: "",
        scan_count: 0,
        suspected_issue_count: 0,
      },
    ],
  };

  const recomputeCounts = () => {
    for (const dept of state.departments) {
      dept.user_count = state.users.filter((u) => u.department_id === dept.department_id).length;
    }
    for (const u of state.users) {
      const dept = state.departments.find((d) => d.department_id === u.department_id);
      if (!dept) {
        u.department_id = "";
        u.department_name = "";
      } else {
        u.department_name = dept.name;
      }
    }
  };

  client.api.defaults.adapter = async (config) => {
    const method = (config.method || "get").toLowerCase();
    const url = config.url;
    const body = config.data ? JSON.parse(config.data) : {};

    if (method === "get" && url === "/api/auth/users") {
      getUsersCount += 1;
      recomputeCounts();
      return response(config, state.users.map((u) => ({ ...u })));
    }
    if (method === "get" && url === "/api/auth/departments") {
      getDeptsCount += 1;
      recomputeCounts();
      return response(config, state.departments.map((d) => ({ ...d })));
    }
    if (method === "post" && url === "/api/auth/users") {
      const dept = state.departments.find((d) => d.department_id === body.department_id);
      const created = {
        user_id: `u-${state.users.length + 1}`,
        username: body.username,
        role: body.role,
        agent_token: "tok",
        created_at: "2026-11-05T00:00:00Z",
        employee_id: body.employee_id || "",
        department_id: dept ? dept.department_id : "",
        department_name: dept ? dept.name : "",
        scan_count: 0,
        suspected_issue_count: 0,
      };
      state.users.push(created);
      recomputeCounts();
      return response(config, created);
    }
    const profileMatch = url.match(/^\/api\/auth\/users\/([^/]+)\/profile$/);
    if (method === "put" && profileMatch) {
      const target = state.users.find((u) => u.user_id === profileMatch[1]);
      assert.ok(target);
      target.employee_id = body.employee_id || "";
      target.department_id = body.department_id || "";
      recomputeCounts();
      return response(config, { ...target });
    }
    if (method === "post" && url === "/api/auth/departments") {
      const dept = {
        department_id: `dept-${state.departments.length + 1}`,
        name: body.name.trim(),
        user_count: 0,
        created_at: "2026-11-06T00:00:00Z",
        updated_at: "2026-11-06T00:00:00Z",
      };
      state.departments.push(dept);
      return response(config, dept);
    }
    const deptMatch = url.match(/^\/api\/auth\/departments\/([^/]+)$/);
    if (method === "put" && deptMatch) {
      const dept = state.departments.find((d) => d.department_id === deptMatch[1]);
      assert.ok(dept);
      dept.name = body.name.trim();
      recomputeCounts();
      return response(config, { ...dept });
    }
    if (method === "delete" && deptMatch) {
      const deptId = deptMatch[1];
      const cleared = state.users.filter((u) => u.department_id === deptId).length;
      state.departments = state.departments.filter((d) => d.department_id !== deptId);
      recomputeCounts();
      return response(config, {
        ok: true,
        department_id: deptId,
        cleared_user_count: cleared,
      });
    }
    assert.fail(`Unhandled request: ${method.toUpperCase()} ${url}`);
  };
});

afterEach(async () => {
  await act(async () => roots.splice(0).forEach((root) => root.unmount()));
  client.api.defaults.adapter = originalAdapter;
  stored.clear();
});

after(async () => {
  await server.close();
  for (const key of ["window", "document", "localStorage"]) delete globalThis[key];
});

async function mountUserManagement() {
  let root;
  const adminUser = {
    user_id: "u-admin",
    username: "admin",
    role: "admin",
    agent_token: "t1",
    created_at: "2026-11-01T00:00:00Z",
  };
  await act(async () => {
    root = create(
      createElement(
        ThemeProvider,
        null,
        createElement(UserManagement, { user: adminUser, onBack: () => {} }),
      ),
    );
  });
  roots.push(root);
  return root;
}

function rowUsernames(root) {
  const tbody = root.root.findByType("tbody");
  return tbody.findAllByType("tr").map((row) => {
    const firstCell = row.findAllByType("td")[0];
    return textOf(firstCell).replace("（当前用户）", "").trim();
  });
}

test("pure userManagementModel filters by department, summarizes totals, and cycles sort state", () => {
  const secUsers = model.filterAndSortUsers(state.users, {
    departmentFilter: "dept-sec",
    sortField: "scan_count",
    sortDirection: "desc",
  });
  assert.deepEqual(secUsers.map((u) => u.username), ["alice", "admin"]);
  assert.deepEqual(model.summarizeUsers(secUsers), {
    userCount: 2,
    totalScanCount: 11,
    totalSuspectedIssueCount: 7,
  });

  const unassigned = model.filterAndSortUsers(state.users, {
    departmentFilter: model.UNASSIGNED_DEPARTMENT_FILTER,
    sortField: "created_at",
    sortDirection: "asc",
  });
  assert.deepEqual(unassigned.map((u) => u.username), ["carol"]);

  const step1 = model.nextSortState("created_at", "asc", "suspected_issue_count");
  assert.deepEqual(step1, { sortField: "suspected_issue_count", sortDirection: "desc" });
  const step2 = model.nextSortState(step1.sortField, step1.sortDirection, "suspected_issue_count");
  assert.deepEqual(step2, { sortField: "suspected_issue_count", sortDirection: "asc" });
  const step3 = model.nextSortState(step2.sortField, step2.sortDirection, "suspected_issue_count");
  assert.deepEqual(step3, { sortField: "created_at", sortDirection: "asc" });
});

test("UserManagement displays stats, filters by department, and sorts by scans and suspected issues", async () => {
  const root = await mountUserManagement();
  const pageText = textOf(root.toJSON());
  assert.match(pageText, /累计创建扫描数12/);
  assert.match(pageText, /累计发现疑似问题数16/);
  assert.deepEqual(rowUsernames(root), ["admin", "alice", "bob", "carol"]);

  // Sort by 创建扫描数 (desc -> asc -> default)
  const scanSortBtn = root.root
    .findAllByType("button")
    .find((btn) => textOf(btn).startsWith("创建扫描数"));
  await act(async () => scanSortBtn.props.onClick());
  assert.deepEqual(rowUsernames(root), ["alice", "admin", "bob", "carol"]);
  await act(async () => scanSortBtn.props.onClick());
  assert.deepEqual(rowUsernames(root), ["carol", "bob", "admin", "alice"]);
  await act(async () => scanSortBtn.props.onClick());
  assert.deepEqual(rowUsernames(root), ["admin", "alice", "bob", "carol"]);

  // Sort by 发现疑似问题数 (desc)
  const issueSortBtn = root.root
    .findAllByType("button")
    .find((btn) => textOf(btn).startsWith("发现疑似问题数"));
  await act(async () => issueSortBtn.props.onClick());
  assert.deepEqual(rowUsernames(root), ["bob", "admin", "alice", "carol"]);

  // Filter by 安全研究部 -> updates both rows and summary cards
  const filterSelect = root.root.findByProps({ "aria-label": "部门筛选" });
  await act(async () => filterSelect.props.onChange({ target: { value: "dept-sec" } }));
  assert.deepEqual(rowUsernames(root), ["admin", "alice"]);
  const filteredText = textOf(root.toJSON());
  assert.match(filteredText, /用户数2/);
  assert.match(filteredText, /累计创建扫描数11/);
  assert.match(filteredText, /累计发现疑似问题数7/);
});

test("UserManagement edits remarks, creates users with department, and manages department pool", async () => {
  const root = await mountUserManagement();

  // Edit carol's employee ID and assign to 平台研发部
  const carolRow = root.root
    .findByType("tbody")
    .findAllByType("tr")
    .find((tr) => textOf(tr.findAllByType("td")[0]).trim() === "carol");
  const editCarolBtn = carolRow.findAllByType("button").find((b) => textOf(b) === "编辑");
  await act(async () => editCarolBtn.props.onClick());

  await act(async () => {
    root.root.findByProps({ "aria-label": "编辑工号" }).props.onChange({ target: { value: "E900" } });
    root.root
      .findByProps({ "aria-label": "编辑所属部门" })
      .props.onChange({ target: { value: "dept-dev" } });
  });
  const editDialog = root.root.findByProps({ "aria-labelledby": "edit-user-profile-title" });
  await act(async () => editDialog.props.onSubmit({ preventDefault() {} }));
  assert.equal(state.users.find((u) => u.username === "carol").employee_id, "E900");
  assert.equal(state.users.find((u) => u.username === "carol").department_name, "平台研发部");

  // Filter by 安全研究部, then open Department Pool, rename & delete 安全研究部
  await act(async () =>
    root.root.findByProps({ "aria-label": "部门筛选" }).props.onChange({ target: { value: "dept-sec" } }),
  );
  assert.deepEqual(rowUsernames(root), ["admin", "alice"]);

  const poolBtn = root.root
    .findAllByType("button")
    .find((b) => textOf(b).startsWith("部门池管理"));
  await act(async () => poolBtn.props.onClick());

  // Add a new department
  const poolDialog = root.root.findByProps({ "aria-labelledby": "department-pool-title" });
  await act(async () => {
    poolDialog.findByProps({ "aria-label": "新部门名称" }).props.onChange({ target: { value: "基础架构部" } });
  });
  await act(async () => poolDialog.findByType("form").props.onSubmit({ preventDefault() {} }));
  assert.equal(state.departments.length, 3);

  // Rename 平台研发部 -> 智能平台部
  const devItem = poolDialog
    .findAllByType("li")
    .find((li) => textOf(li).includes("平台研发部"));
  await act(async () =>
    devItem.findAllByType("button").find((b) => textOf(b) === "重命名").props.onClick(),
  );
  await act(async () => {
    poolDialog
      .findByProps({ "aria-label": "编辑部门名称" })
      .props.onChange({ target: { value: "智能平台部" } });
  });
  await act(async () =>
    poolDialog.findAllByType("button").find((b) => textOf(b) === "保存").props.onClick(),
  );
  assert.equal(state.users.find((u) => u.username === "bob").department_name, "智能平台部");

  // Delete 安全研究部 (has 2 users -> shows warning with user count, then unassigns & resets active filter)
  const secItem = poolDialog
    .findAllByType("li")
    .find((li) => textOf(li).includes("安全研究部"));
  const deleteDeptBtn = secItem.findAllByType("button").find((b) => textOf(b) === "删除");
  await act(async () => deleteDeptBtn.props.onClick());

  const alertBox = root.root.findByProps({ role: "alertdialog" });
  assert.match(textOf(alertBox), /已关联 2 名用户/);
  const confirmBtn = alertBox.findAllByType("button").find((b) => textOf(b) === "确认删除");
  await act(async () => confirmBtn.props.onClick());

  // Filter automatically falls back to ALL_DEPARTMENTS_FILTER so all 4 users remain visible
  assert.equal(root.root.findByProps({ "aria-label": "部门筛选" }).props.value, model.ALL_DEPARTMENTS_FILTER);
  assert.deepEqual(rowUsernames(root), ["admin", "alice", "bob", "carol"]);
  assert.equal(state.users.find((u) => u.username === "admin").department_id, "");
  assert.equal(state.users.find((u) => u.username === "alice").department_id, "");

  // Close pool dialog and create a new user with employee_id & department
  await act(async () =>
    poolDialog.findAllByType("button").find((b) => textOf(b) === "关闭").props.onClick(),
  );
  await act(async () =>
    root.root.findAllByType("button").find((b) => textOf(b) === "+ 新建用户").props.onClick(),
  );
  await act(async () => {
    root.root.findByProps({ "aria-label": "新建用户名" }).props.onChange({ target: { value: "dave" } });
    root.root.findByProps({ "aria-label": "新建用户密码" }).props.onChange({ target: { value: "pass123" } });
    root.root.findByProps({ "aria-label": "新建用户工号" }).props.onChange({ target: { value: "E777" } });
    root.root
      .findByProps({ "aria-label": "新建用户部门" })
      .props.onChange({ target: { value: "dept-dev" } });
  });
  await act(async () => root.root.findByType("form").props.onSubmit({ preventDefault() {} }));
  const dave = state.users.find((u) => u.username === "dave");
  assert.ok(dave);
  assert.equal(dave.employee_id, "E777");
  assert.equal(dave.department_name, "智能平台部");
  assert.deepEqual(rowUsernames(root), ["admin", "alice", "bob", "carol", "dave"]);

  // All 5 mutations above updated local state incrementally without re-querying GET /users or /departments!
  assert.equal(getUsersCount, 1);
  assert.equal(getDeptsCount, 1);

  // Explicit 刷新 button triggers an on-demand sync
  await act(async () =>
    root.root.findAllByType("button").find((b) => textOf(b) === "刷新").props.onClick(),
  );
  assert.equal(getUsersCount, 2);
  assert.equal(getDeptsCount, 2);
});
