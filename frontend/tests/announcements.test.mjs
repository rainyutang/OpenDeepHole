import assert from "node:assert/strict";
import test, { after, afterEach, beforeEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "./helpers/reactTestEnv.mjs";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true, hmr: false } });
const client = await server.ssrLoadModule("/src/api/client.ts");
const { default: AnnouncementBoard, announcementDate } = await server.ssrLoadModule("/src/components/AnnouncementBoard.tsx");
const { default: ScanHistory } = await server.ssrLoadModule("/src/components/ScanHistory.tsx");
const { ThemeProvider } = await server.ssrLoadModule("/src/theme/ThemeProvider.tsx");
const originalAdapter = client.api.defaults.adapter;
const roots = [];
const stored = new Map();

beforeEach(() => {
  stored.clear();
  globalThis.localStorage = {
    getItem: (key) => stored.get(key) ?? null,
    setItem: (key, value) => stored.set(key, String(value)),
    removeItem: (key) => stored.delete(key),
  };
  globalThis.window = Object.assign(new EventTarget(), {
    localStorage: globalThis.localStorage,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    confirm: () => true,
    location: { origin: "http://localhost", href: "http://localhost/" },
  });
  globalThis.document = Object.assign(new EventTarget(), {
    visibilityState: "visible",
    documentElement: { dataset: {}, style: {} },
  });
});

afterEach(async () => {
  await act(async () => roots.splice(0).forEach((root) => root.unmount()));
  client.api.defaults.adapter = originalAdapter;
  for (const key of ["window", "document", "localStorage"]) delete globalThis[key];
});

after(async () => {
  await server.close();
});

const content = (node) => typeof node === "string" || typeof node === "number" ? String(node)
  : Array.isArray(node) ? node.map(content).join("") : content(node?.children ?? "");
const user = { user_id: "reader", username: "reader", role: "user" };
const admin = { user_id: "admin-1", username: "admin", role: "admin" };

const fixture = () => Array.from({ length: 25 }, (_, index) => {
  const date = `2026-11-${String(25 - index).padStart(2, "0")}T00:00:00Z`;
  return {
    announcement_id: `announcement-${index}`,
    content: `正文 ${index}\n第二行`,
    published: true,
    published_at: date,
    created_at: date,
    updated_at: date,
  };
});

function mockFeed(getFeed) {
  client.api.defaults.adapter = async (config) => {
    assert.equal(config.url, "/api/announcements");
    const feed = getFeed();
    const data = config.params?.limit == null ? feed : feed.slice(0, config.params.limit);
    return { config, data, status: 200, statusText: "OK", headers: {} };
  };
}

async function mountBoard(onPublishedVersionChange = () => {}, overrides = {}) {
  const props = {
    user,
    open: true,
    refreshKey: 0,
    onClose() {},
    onPublishedVersionChange,
    ...overrides,
  };
  let root;
  await act(async () => { root = create(createElement(AnnouncementBoard, props)); });
  roots.push(root);
  return { root, props };
}

async function mountHistory(getFeed, overrides = {}) {
  const requests = [];
  client.api.defaults.adapter = async (config) => {
    requests.push(config);
    if (config.url === "/api/announcements") {
      return { config, data: await getFeed(config), status: 200, statusText: "OK", headers: {} };
    }
    if (config.url === "/api/admin/announcements" && config.method === "get") {
      return { config, data: await getFeed(config), status: 200, statusText: "OK", headers: {} };
    }
    if (config.url === "/api/admin/announcements" && config.method === "post") {
      const body = JSON.parse(config.data);
      const created = {
        announcement_id: `created-${requests.length}`,
        content: body.content,
        published: body.published,
        published_at: body.published ? "2026-11-26T06:00:00Z" : "",
        created_at: "2026-11-26T06:00:00Z",
        updated_at: "2026-11-26T06:00:00Z",
      };
      if (overrides.onCreate) overrides.onCreate(created, body);
      return { config, data: created, status: 200, statusText: "OK", headers: {} };
    }
    if (config.url === "/api/v2/scans") {
      return { config, data: { items: [], next_cursor: null, has_more: false }, status: 200, statusText: "OK", headers: {} };
    }
    assert.fail(`Unexpected request: ${config.method} ${config.url}`);
  };
  let root;
  await act(async () => {
    root = create(createElement(ThemeProvider, null, createElement(ScanHistory, {
      user: overrides.user ?? user,
      onViewScan() {},
      onDownloadAgent() {},
      onAgentConfig() {},
      onNewScan() {},
      onLogout() {},
      onManageUsers() {},
      onCheckerDashboard() {},
      onCheckerCatalog() {},
    })));
  });
  roots.push(root);
  return { root, requests };
}

function findButton(root, label) {
  const match = root.root.findAllByType("button").find((node) => content(node) === label);
  assert.ok(match, `Missing button: ${label}`);
  return match;
}

test("ordinary users can read all 25 published announcements grouped by publish date without titles", async () => {
  const feed = fixture();
  mockFeed(() => feed);
  const { root } = await mountBoard();
  const items = root.root.findAllByType("li");
  assert.equal(items.length, feed.length);
  assert.deepEqual(
    items.map((item) => item.findAllByType("p").map(content)),
    feed.map((announcement) => [announcement.content]),
  );
  const times = root.root.findAllByType("time").map(content);
  assert.deepEqual(times, feed.map((announcement) => announcementDate(announcement.published_at)));
});

test("multiple announcements published on the same date share one date divider group", async () => {
  const sameDayFeed = [
    {
      announcement_id: "a-2",
      content: "同一天第二条公告",
      published: true,
      published_at: "2026-11-23T09:00:00Z",
      created_at: "2026-11-23T09:00:00Z",
      updated_at: "2026-11-23T09:00:00Z",
    },
    {
      announcement_id: "a-1",
      content: "同一天第一条公告",
      published: true,
      published_at: "2026-11-23T01:00:00Z",
      created_at: "2026-11-23T01:00:00Z",
      updated_at: "2026-11-23T01:00:00Z",
    },
    {
      announcement_id: "b-1",
      content: "前一天公告",
      published: true,
      published_at: "2026-11-22T02:00:00Z",
      created_at: "2026-11-22T02:00:00Z",
      updated_at: "2026-11-22T02:00:00Z",
    },
  ];
  mockFeed(() => sameDayFeed);
  const { root } = await mountBoard();
  const dayOne = announcementDate("2026-11-23T09:00:00Z");
  const dayZero = announcementDate("2026-11-22T02:00:00Z");
  const times = root.root.findAllByType("time").map(content);
  assert.deepEqual(times, [dayOne, dayZero]);

  const firstGroup = root.root.findByProps({ "aria-label": dayOne });
  assert.deepEqual(
    firstGroup.findAllByType("li").map((item) => content(item.findByType("p"))),
    ["同一天第二条公告", "同一天第一条公告"],
  );
  const secondGroup = root.root.findByProps({ "aria-label": dayZero });
  assert.deepEqual(
    secondGroup.findAllByType("li").map((item) => content(item.findByType("p"))),
    ["前一天公告"],
  );
});

test("refresh includes updates to the oldest announcement in the unread version", async () => {
  let feed = fixture();
  const versions = [];
  mockFeed(() => feed);
  const { root, props } = await mountBoard((version) => versions.push(version));
  assert.deepEqual(versions, [feed[0].updated_at]);

  const updatedAt = "2026-11-26T00:00:00Z";
  feed = feed.map((announcement, index) => index === feed.length - 1
    ? { ...announcement, content: "最早公告的更新正文", updated_at: updatedAt }
    : announcement);
  await act(async () => { root.update(createElement(AnnouncementBoard, { ...props, refreshKey: 1 })); });

  assert.deepEqual(versions, [feed[0].updated_at, updatedAt]);
  const lastItem = root.root.findAllByType("li").at(-1);
  assert.equal(content(lastItem.findByType("p")), "最早公告的更新正文");
});

test("an empty published feed shows the empty state and clears the published version", async () => {
  const versions = [];
  mockFeed(() => []);
  const { root } = await mountBoard((version) => versions.push(version));
  assert.equal(root.root.findAllByType("li").length, 0);
  assert.ok(content(root.toJSON()).includes("暂无已发布公告。"));
  assert.deepEqual(versions, [""]);
});

test("first entry auto-opens the top-right announcement popup without a red dot, and subsequent visits stay closed until updated", async () => {
  let feed = [
    {
      announcement_id: "ann-1",
      content: "第一版发布说明",
      published: true,
      published_at: "2026-11-23T01:00:00Z",
      created_at: "2026-11-23T01:00:00Z",
      updated_at: "2026-11-23T01:00:00Z",
    },
  ];

  // First visit: auto-opens top-right popup and marks version seen; no red dot on button.
  const firstVisit = await mountHistory(() => feed);
  const viewer = firstVisit.root.root.findByProps({ "aria-labelledby": "announcement-viewer-title" });
  assert.equal(viewer.props["aria-modal"], "false");
  assert.match(viewer.props.className, /fixed right-4 top-20/);
  assert.match(content(viewer), /第一版发布说明/);
  assert.equal(stored.get(`opendeephole.announcements.lastSeen.${user.user_id}`), "2026-11-23T01:00:00Z");

  const announceBtn = findButton(firstVisit.root, "公告");
  assert.equal(announceBtn.findAllByType("span").length, 0);
  assert.doesNotMatch(announceBtn.props["aria-label"], /未读/);

  // Clicking the announcement button closes the popup; clicking again reopens it.
  await act(async () => announceBtn.props.onClick());
  assert.equal(firstVisit.root.root.findAllByProps({ "aria-labelledby": "announcement-viewer-title" }).length, 0);
  await act(async () => findButton(firstVisit.root, "公告").props.onClick());
  assert.equal(firstVisit.root.root.findAllByProps({ "aria-labelledby": "announcement-viewer-title" }).length, 1);

  // Second visit with same version: stays closed.
  await act(async () => firstVisit.root.unmount());
  roots.splice(roots.indexOf(firstVisit.root), 1);

  const secondVisit = await mountHistory(() => feed);
  assert.equal(secondVisit.root.root.findAllByProps({ "aria-labelledby": "announcement-viewer-title" }).length, 0);

  // After an announcement is updated, returning to the tab auto-opens the popup again.
  feed = [
    {
      ...feed[0],
      content: "修改后的公告正文",
      updated_at: "2026-11-23T05:00:00Z",
    },
  ];
  await act(async () => document.dispatchEvent(new Event("visibilitychange")));
  const updatedViewer = secondVisit.root.root.findByProps({ "aria-labelledby": "announcement-viewer-title" });
  assert.match(content(updatedViewer), /修改后的公告正文/);
  assert.equal(stored.get(`opendeephole.announcements.lastSeen.${user.user_id}`), "2026-11-23T05:00:00Z");
});

test("admin management omits title input and saving inside the manager does not auto-open the corner popup", async () => {
  let feed = [
    {
      announcement_id: "ann-1",
      content: "已有公告内容",
      published: true,
      published_at: "2026-11-23T01:00:00Z",
      created_at: "2026-11-23T01:00:00Z",
      updated_at: "2026-11-23T01:00:00Z",
    },
  ];
  const createdPayloads = [];
  stored.set(`opendeephole.announcements.lastSeen.${admin.user_id}`, "2026-11-23T01:00:00Z");

  const { root } = await mountHistory(() => feed, {
    user: admin,
    onCreate(created, body) {
      createdPayloads.push(body);
      feed = [created, ...feed];
    },
  });

  // Open viewer manually, then open admin manager.
  await act(async () => findButton(root, "公告").props.onClick());
  await act(async () => findButton(root, "管理公告").props.onClick());

  const manager = root.root.findByProps({ "aria-labelledby": "announcement-manager-title" });
  assert.equal(manager.findAllByType("input").filter((node) => node.props.type !== "checkbox").length, 0);
  const textarea = manager.findByProps({ "aria-label": "公告内容" });
  await act(async () => textarea.props.onChange({ target: { value: "新增的无标题公告" } }));
  await act(async () => manager.findByType("form").props.onSubmit({ preventDefault() {} }));

  assert.deepEqual(createdPayloads, [{ content: "新增的无标题公告", published: true }]);
  // Viewer must not pop up while admin is still in the management modal.
  assert.equal(root.root.findAllByProps({ "aria-labelledby": "announcement-viewer-title" }).length, 0);
});
