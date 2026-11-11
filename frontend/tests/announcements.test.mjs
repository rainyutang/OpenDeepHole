import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true, hmr: false } });
const client = await server.ssrLoadModule("/src/api/client.ts");
const { default: AnnouncementBoard } = await server.ssrLoadModule("/src/components/AnnouncementBoard.tsx");
const originalAdapter = client.api.defaults.adapter;
const roots = [];
globalThis.localStorage = { getItem: () => null };

afterEach(async () => {
  await act(async () => roots.splice(0).forEach((root) => root.unmount()));
  client.api.defaults.adapter = originalAdapter;
});
after(async () => {
  delete globalThis.localStorage;
  await server.close();
});

const content = (node) => typeof node === "string" || typeof node === "number" ? String(node)
  : Array.isArray(node) ? node.map(content).join("") : content(node?.children ?? "");
const user = { user_id: "reader", username: "reader", role: "user" };
const fixture = () => Array.from({ length: 25 }, (_, index) => {
  const date = `2026-11-${String(25 - index).padStart(2, "0")}T00:00:00Z`;
  return {
    announcement_id: `announcement-${index}`, title: `公告 ${index}`, content: `正文 ${index}\n第二行`,
    published: true, published_at: date, created_at: date, updated_at: date,
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

async function mount(onPublishedVersionChange = () => {}) {
  const props = { user, open: true, refreshKey: 0, onClose() {}, onPublishedVersionChange };
  let root;
  await act(async () => { root = create(createElement(AnnouncementBoard, props)); });
  roots.push(root);
  return { root, props };
}

test("ordinary users can read all 25 published announcements in feed order", async () => {
  const feed = fixture();
  mockFeed(() => feed);
  const { root } = await mount();
  const articles = root.root.findAllByType("article");
  assert.equal(articles.length, feed.length);
  assert.deepEqual(articles.map((article) => article.findAllByType("p").map(content)),
    feed.map((announcement) => [announcement.title, announcement.content]));
});

test("refresh includes updates to the oldest announcement in the unread version", async () => {
  let feed = fixture();
  const versions = [];
  mockFeed(() => feed);
  const { root, props } = await mount((version) => versions.push(version));
  assert.deepEqual(versions, [feed[0].updated_at]);

  const updatedAt = "2026-11-26T00:00:00Z";
  feed = feed.map((announcement, index) => index === feed.length - 1
    ? { ...announcement, content: "最早公告的更新正文", updated_at: updatedAt }
    : announcement);
  await act(async () => { root.update(createElement(AnnouncementBoard, { ...props, refreshKey: 1 })); });

  assert.deepEqual(versions, [feed[0].updated_at, updatedAt]);
  const lastArticle = root.root.findAllByType("article").at(-1);
  assert.equal(content(lastArticle.findAllByType("p").at(-1)), "最早公告的更新正文");
});

test("an empty published feed shows the empty state and clears the published version", async () => {
  const versions = [];
  mockFeed(() => []);
  const { root } = await mount((version) => versions.push(version));
  assert.equal(root.root.findAllByType("article").length, 0);
  assert.ok(content(root.toJSON()).includes("暂无已发布公告。"));
  assert.deepEqual(versions, [""]);
});
