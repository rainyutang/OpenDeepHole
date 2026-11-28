import assert from "node:assert/strict";
import test, { after, afterEach, beforeEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "./helpers/reactTestEnv.mjs";
import { AxiosError } from "axios";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({
  appType: "custom",
  logLevel: "silent",
  server: { middlewareMode: true, hmr: false },
});

const client = await server.ssrLoadModule("/src/api/client.ts");
const reports = await server.ssrLoadModule("/src/api/reports.ts");
const model = await server.ssrLoadModule("/src/features/adminExport/exportModel.ts");
const { default: AdminCheckerDashboard } = await server.ssrLoadModule("/src/components/AdminCheckerDashboard.tsx");
const { default: UserManagement } = await server.ssrLoadModule("/src/components/UserManagement.tsx");
const { ThemeProvider } = await server.ssrLoadModule("/src/theme/ThemeProvider.tsx");

const originalAdapter = client.api.defaults.adapter;
const originalCreateObjectURL = globalThis.URL?.createObjectURL;
const originalRevokeObjectURL = globalThis.URL?.revokeObjectURL;
const originalSetTimeout = globalThis.setTimeout;

const roots = [];
const stored = new Map();
const downloads = [];

globalThis.localStorage = {
  getItem: (key) => stored.get(key) ?? null,
  setItem: (key, value) => stored.set(key, value),
  removeItem: (key) => stored.delete(key),
};
globalThis.window = Object.assign(new EventTarget(), {
  localStorage,
  location: { origin: "https://deephole.example.test" },
  setTimeout: (fn) => {
    fn();
    return 0;
  },
});
globalThis.document = Object.assign(new EventTarget(), {
  documentElement: { dataset: {}, style: {} },
  body: {
    appendChild: () => {},
  },
  createElement: (tag) => {
    const node = {
      tagName: tag.toUpperCase(),
      href: "",
      download: "",
      click() {
        downloads.push({ href: this.href, download: this.download });
      },
      remove() {},
    };
    return node;
  },
});
if (globalThis.URL) {
  globalThis.URL.createObjectURL = () => "blob:mock-export";
  globalThis.URL.revokeObjectURL = () => {};
}

const textOf = (node) =>
  typeof node === "string" || typeof node === "number"
    ? String(node)
    : Array.isArray(node)
      ? node.map(textOf).join("")
      : textOf(node?.children ?? "");

const okResponse = (config, data, headers = {}) => ({
  config,
  data,
  status: 200,
  statusText: "OK",
  headers,
});

const emptyDashboard = {
  summary: {
    scan_count: 1,
    project_count: 1,
    checker_count: 1,
    static_issue_count: 1,
    llm_issue_count: 1,
    fp_review_issue_count: 1,
    fp_review_false_positive_count: 0,
    suspected_issue_count: 1,
    total_issue_count: 1,
    human_confirmed_count: 0,
    ticket_submitted_count: 0,
    accuracy_basis_count: 1,
    accuracy: null,
    ticket_accuracy: null,
  },
  checkers: [],
  products: [],
  has_unconfigured_product: false,
  token_usage: {
    scan_count: 1,
    tracked_scan_count: 1,
    usage: {
      input_tokens: 0,
      output_tokens: 0,
      reasoning_tokens: 0,
      cache_read_tokens: 0,
      cache_write_tokens: 0,
      total_tokens: 0,
      complete: true,
      by_model: [],
    },
    agents: [],
  },
};

const sampleUsers = [
  {
    user_id: "u-admin",
    username: "admin",
    role: "admin",
    agent_token: "t1",
    created_at: "2026-11-01T00:00:00Z",
    employee_id: "A001",
    department_id: "",
    department_name: "",
    scan_count: 2,
    suspected_issue_count: 3,
  },
  {
    user_id: "u-bob",
    username: "bob",
    role: "user",
    agent_token: "t2",
    created_at: "2026-11-02T00:00:00Z",
    employee_id: "E204",
    department_id: "",
    department_name: "",
    scan_count: 5,
    suspected_issue_count: 1,
  },
];

beforeEach(() => {
  downloads.length = 0;
  stored.clear();
  stored.set("auth_token", "admin-jwt");
});

afterEach(async () => {
  while (roots.length) {
    const root = roots.pop();
    await act(async () => {
      root.unmount();
    });
  }
  client.api.defaults.adapter = originalAdapter;
});

after(async () => {
  if (globalThis.URL) {
    globalThis.URL.createObjectURL = originalCreateObjectURL;
    globalThis.URL.revokeObjectURL = originalRevokeObjectURL;
  }
  globalThis.setTimeout = originalSetTimeout;
  delete globalThis.localStorage;
  delete globalThis.window;
  delete globalThis.document;
  await server.close();
});

const mount = async (element) => {
  let root;
  await act(async () => {
    root = create(createElement(ThemeProvider, null, element));
  });
  roots.push(root);
  return root;
};

test("exportModel computes presets, validates date bounds, builds query params and dedupes options", () => {
  const fixedNow = new Date(2026, 10, 23, 15, 30, 0);
  assert.deepEqual(model.resolveTimePresetRange("all", fixedNow), {
    startDate: "",
    endDate: "",
  });
  assert.deepEqual(model.resolveTimePresetRange("last7d", fixedNow), {
    startDate: "2026-11-17",
    endDate: "2026-11-23",
  });
  assert.deepEqual(model.resolveTimePresetRange("last30d", fixedNow), {
    startDate: "2026-10-25",
    endDate: "2026-11-23",
  });
  assert.deepEqual(model.resolveTimePresetRange("thisMonth", fixedNow), {
    startDate: "2026-11-01",
    endDate: "2026-11-23",
  });
  assert.equal(
    model.activeTimePreset({ startDate: "2026-11-17", endDate: "2026-11-23" }, fixedNow),
    "last7d",
  );
  assert.equal(
    model.validateExportFilter({
      startDate: "2026-11-24",
      endDate: "2026-11-20",
      username: "",
      employeeId: "",
    }),
    "开始日期不能晚于结束日期",
  );
  assert.equal(
    model.validateExportFilter({
      startDate: "2026-11-20",
      endDate: "2026-11-20",
      username: "",
      employeeId: "",
    }),
    "",
  );

  assert.deepEqual(
    model.buildAdminExportParams(
      {
        startDate: " 2026-11-01 ",
        endDate: "2026-11-23",
        username: " alice ",
        employeeId: " E102 ",
      },
      { tzOffsetMinutes: 480, shareOrigin: "https://deephole.example.test" },
    ),
    {
      start_time: "2026-11-01",
      end_time: "2026-11-23",
      username: "alice",
      employee_id: "E102",
      tz_offset_minutes: 480,
      share_origin: "https://deephole.example.test",
    },
  );

  assert.deepEqual(
    model.extractUsernameOptions([
      { username: "bob" },
      { username: "alice" },
      { username: "bob" },
      { username: "" },
    ]),
    ["alice", "bob"],
  );
  assert.deepEqual(
    model.extractEmployeeIdOptions([
      { employee_id: "E204" },
      { employee_id: "A001" },
      { employee_id: "E204" },
      { employee_id: "  " },
    ]),
    ["A001", "E204"],
  );
  assert.equal(model.formatExportSuccessNotice(0), "当前筛选条件下暂无匹配问题，已导出空表");
  assert.equal(model.formatExportSuccessNotice(12), "已成功导出 12 条问题");
});

test("exportAdminIssuesExcel forwards params, parses headers and decodes Blob error detail", async () => {
  const calls = [];
  client.api.defaults.adapter = async (config) => {
    calls.push(config);
    return okResponse(
      config,
      new Blob(["xlsx-bytes"]),
      {
        "content-disposition": 'attachment; filename="deephole-issues-20261123-160000.xlsx"',
        "x-export-row-count": "7",
      },
    );
  };

  const result = await reports.exportAdminIssuesExcel({
    start_time: "2026-11-01",
    end_time: "2026-11-23",
    username: "alice",
    employee_id: "E102",
    tz_offset_minutes: 480,
    share_origin: "https://deephole.example.test",
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "/api/admin/issues/export");
  assert.equal(calls[0].responseType, "blob");
  assert.deepEqual(calls[0].params, {
    start_time: "2026-11-01",
    end_time: "2026-11-23",
    username: "alice",
    employee_id: "E102",
    tz_offset_minutes: 480,
    share_origin: "https://deephole.example.test",
  });
  assert.equal(result.filename, "deephole-issues-20261123-160000.xlsx");
  assert.equal(result.rowCount, 7);

  client.api.defaults.adapter = async (config) => {
    const errorBlob = new Blob([JSON.stringify({ detail: "开始时间不能晚于结束时间" })], {
      type: "application/json",
    });
    throw new AxiosError("Bad Request", "ERR_BAD_REQUEST", config, null, {
      config,
      data: errorBlob,
      status: 400,
      statusText: "Bad Request",
      headers: {},
    });
  };
  await assert.rejects(
    () => client.exportAdminIssuesExcel({ start_time: "2026-11-25", end_time: "2026-11-20" }),
    /开始时间不能晚于结束时间/,
  );
});

test("AdminCheckerDashboard shows export button only for admins and lazily loads user suggestions", async () => {
  const requests = [];
  client.api.defaults.adapter = async (config) => {
    requests.push(config);
    if (config.url === "/api/v2/checker-dashboard") return okResponse(config, emptyDashboard);
    if (config.url === "/api/auth/users") return okResponse(config, sampleUsers);
    return okResponse(config, new Blob(["xlsx"]), {
      "content-disposition": 'attachment; filename="deephole-issues.xlsx"',
      "x-export-row-count": "3",
    });
  };

  const normalRoot = await mount(
    createElement(AdminCheckerDashboard, {
      user: { user_id: "u-bob", username: "bob", role: "user", agent_token: "t", created_at: "" },
      onBack: () => {},
      onViewScan: () => {},
    }),
  );
  assert.equal(
    normalRoot.root.findAllByType("button").some((btn) => textOf(btn.props.children) === "导出问题"),
    false,
  );

  const adminRoot = await mount(
    createElement(AdminCheckerDashboard, {
      user: { user_id: "u-admin", username: "admin", role: "admin", agent_token: "t", created_at: "" },
      onBack: () => {},
      onViewScan: () => {},
    }),
  );
  const exportBtn = adminRoot.root
    .findAllByType("button")
    .find((btn) => textOf(btn.props.children) === "导出问题");
  assert.ok(exportBtn);
  assert.equal(requests.filter((r) => r.url === "/api/auth/users").length, 0);

  await act(async () => {
    exportBtn.props.onClick();
  });
  assert.equal(requests.filter((r) => r.url === "/api/auth/users").length, 1);
  assert.ok(adminRoot.root.findByProps({ role: "dialog" }));
});

test("UserManagement export modal reuses loaded users without refetching and downloads filtered Excel", async () => {
  const requests = [];
  client.api.defaults.adapter = async (config) => {
    requests.push(config);
    if (config.url === "/api/auth/users") return okResponse(config, sampleUsers);
    if (config.url === "/api/auth/departments") return okResponse(config, []);
    if (config.url === "/api/admin/issues/export") {
      return okResponse(config, new Blob(["xlsx-data"]), {
        "content-disposition": 'attachment; filename="deephole-issues-filtered.xlsx"',
        "x-export-row-count": "4",
      });
    }
    throw new Error(`Unexpected url ${config.url}`);
  };

  const root = await mount(
    createElement(UserManagement, {
      user: { user_id: "u-admin", username: "admin", role: "admin", agent_token: "t", created_at: "" },
      onBack: () => {},
    }),
  );
  assert.equal(requests.filter((r) => r.url === "/api/auth/users").length, 1);

  const openBtn = root.root
    .findAllByType("button")
    .find((btn) => textOf(btn.props.children) === "导出问题");
  assert.ok(openBtn);
  await act(async () => {
    openBtn.props.onClick();
  });
  // Reused users prop — no second /api/auth/users request.
  assert.equal(requests.filter((r) => r.url === "/api/auth/users").length, 1);

  const startInput = root.root.findByProps({ "aria-label": "开始日期" });
  const endInput = root.root.findByProps({ "aria-label": "结束日期" });
  const usernameInput = root.root.findByProps({ "aria-label": "筛选用户名" });
  const empInput = root.root.findByProps({ "aria-label": "筛选工号" });

  await act(async () => {
    startInput.props.onChange({ target: { value: "2026-11-01" } });
    endInput.props.onChange({ target: { value: "2026-11-23" } });
    usernameInput.props.onChange({ target: { value: "bob" } });
    empInput.props.onChange({ target: { value: "E204" } });
  });

  const dialogForm = root.root.findByProps({ role: "dialog" });
  await act(async () => {
    await dialogForm.props.onSubmit({ preventDefault() {} });
  });

  const exportReq = requests.find((r) => r.url === "/api/admin/issues/export");
  assert.ok(exportReq);
  assert.equal(exportReq.params.start_time, "2026-11-01");
  assert.equal(exportReq.params.end_time, "2026-11-23");
  assert.equal(exportReq.params.username, "bob");
  assert.equal(exportReq.params.employee_id, "E204");
  assert.equal(exportReq.params.share_origin, "https://deephole.example.test");
  assert.equal(downloads.length, 1);
  assert.equal(downloads[0].download, "deephole-issues-filtered.xlsx");
  assert.match(textOf(root.toJSON()), /已成功导出 4 条问题/);
});
