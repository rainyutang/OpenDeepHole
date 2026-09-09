import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
const client = await server.ssrLoadModule("/src/api/client.ts");
const { default: ScanStatus, FpReviewPanel } = await server.ssrLoadModule("/src/components/ScanStatus.tsx");
const { default: VulnerabilityList } = await server.ssrLoadModule("/src/components/VulnerabilityList.tsx");
const { ThemeProvider } = await server.ssrLoadModule("/src/theme/ThemeProvider.tsx");
const originalAdapter = client.api.defaults.adapter;
const roots = [];
const streams = [];
globalThis.localStorage = { getItem: () => null, setItem() {} };
globalThis.window = Object.assign(new EventTarget(), {
  localStorage, setTimeout, clearTimeout, setInterval, clearInterval, location: { origin: "http://localhost" },
});
globalThis.document = Object.assign(new EventTarget(), {
  hidden: false, documentElement: { dataset: {}, style: {} },
});
globalThis.EventSource = class extends EventTarget {
  constructor() { super(); streams.push(this); }
  close() {}
  emit(type, data) { this.dispatchEvent(new MessageEvent(type, { data: JSON.stringify(data) })); }
};

afterEach(async () => {
  await act(async () => { roots.splice(0).forEach((root) => root.unmount()); });
  streams.length = 0;
  client.api.defaults.adapter = originalAdapter;
  client.setPublicScanAccess(null);
});
after(async () => {
  delete globalThis.window;
  delete globalThis.document;
  delete globalThis.localStorage;
  delete globalThis.EventSource;
  await server.close();
});

function response(config, data) { return { config, data, status: 200, statusText: "OK", headers: {} }; }
function text(node) {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(text).join("");
  return text(node?.children ?? node?.props?.children ?? "");
}
function button(root, label) {
  const found = root.root.findAllByType("button").find((item) => text(item) === label);
  assert.ok(found, `Missing button: ${label}`);
  return found;
}
function issueProps(root) { return root.root.findByType(VulnerabilityList).props; }
function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}
function component(scanId) {
  return createElement(ThemeProvider, null, createElement(ScanStatus, { scanId, onBack() {} }));
}
async function mount(scanId = "s") {
  let root;
  await act(async () => { root = create(component(scanId)); });
  roots.push(root);
  return root;
}
async function openIssues(root) { await act(async () => button(root, "疑似问题").props.onClick()); }
async function openReviews(root) {
  const target = root.root.findAllByType("button").find((node) => text(node).startsWith("adversarial"));
  assert.ok(target, "Missing review navigation button");
  await act(async () => target.props.onClick());
}

function fixture(count = 105, scanId = "s") {
  const vulnerabilities = Array.from({ length: count }, (_, ordinal) => ({
    vuln_index: ordinal * 3, file: `${scanId}/issue-${ordinal}.c`, line: 17, function: "parse",
    vuln_type: ordinal === count - 1 ? "last_only" : "oob", severity: "high", confirmed: true,
    ai_verdict: "confirmed", analysis_source: "static_candidate", description: `问题 ${ordinal}`,
    vulnerability_report: `# 完整报告 ${ordinal}`, user_verdict: ordinal === count - 1 ? "confirmed" : "",
  }));
  const results = vulnerabilities.map((v, ordinal) => ({
    vuln_index: v.vuln_index, verdict: ordinal < 50 ? "fp" : "tp", severity: "high",
    reason: `有效结论 ${ordinal}`, vulnerability_report: `# 复核报告 ${ordinal}`,
  }));
  return {
    scanId, vulnerabilities, results,
    validations: vulnerabilities.map((v, ordinal) => ({ vuln_index: v.vuln_index, status: ordinal === count - 1 ? "verified" : "pending" })),
  };
}

function installApi(fixtures = [fixture()], intercept = async () => undefined) {
  const calls = [];
  client.api.defaults.adapter = async (config) => {
    calls.push(config);
    const overridden = await intercept(config);
    if (overridden !== undefined) return response(config, overridden);
    if (config.url === "/api/mining-engines") return response(config, { engines: [] });
    if (config.url.includes("checkers")) return response(config, []);
    const value = fixtures.find((item) => config.url.includes(`/${item.scanId}/`));
    assert.ok(value, `Unexpected request: ${config.url}`);
    if (client.isPublicScan(value.scanId)) assert.equal(config.params.token, "public-token");
    const { scanId, vulnerabilities, results, validations } = value;
    if (config.url.endsWith("/fp-review/overview")) return response(config, {
      review_id: `review-${scanId}`, scan_id: scanId, status: "complete", execution_revision: 1,
      total: results.length, processed: results.length, results: [],
      result_counts: { tp: results.filter((item) => item.verdict === "tp").length, fp: Math.min(50, results.length), unresolved: 0 },
    });
    if (config.url.endsWith("/overview")) return response(config, {
      scan_id: scanId, status: "complete", scan_items: [], vulnerabilities: [], candidates: [], events: [],
      detail_counts: { human_confirmed_issue_count: 1, vulnerabilities: vulnerabilities.length },
    });
    const afterIndex = config.params?.after ?? -1;
    const paginate = (items, index) => {
      const remaining = items.filter((item) => index(item) > afterIndex);
      const page = remaining.slice(0, 50);
      return { items: page, next_cursor: remaining.length > 50 ? index(page.at(-1)) : null, has_more: remaining.length > 50 };
    };
    if (config.url.endsWith("/fp-review/results")) {
      const page = paginate(results, (item) => item.vuln_index);
      return response(config, { ...page, vulnerabilities: vulnerabilities.filter((v) => page.items.some((r) => r.vuln_index === v.vuln_index)) });
    }
    if (config.url.endsWith("/vulnerabilities")) return response(config,
      paginate(vulnerabilities.map((vulnerability) => ({ index: vulnerability.vuln_index, vulnerability })), (item) => item.index));
    if (config.url.endsWith("/validations")) return response(config, paginate(validations, (item) => item.vuln_index));
    if (/\/(events|event-history|candidates|threat-audit-tasks)$/.test(config.url)) return response(config,
      { items: [], next_cursor: config.url.endsWith("threat-audit-tasks") ? "task-cursor" : 900, has_more: true });
    if (config.url.endsWith("/index-status")) return response(config, { status: "skipped" });
    if (config.url.endsWith("/git_history")) return response(config, []);
    if (config.url.endsWith("/threat-analysis")) return response(config, null);
    assert.fail(`Unexpected request: ${config.url}`);
  };
  return calls;
}

for (const publicAccess of [false, true]) {
  test(`opening issues loads all three pages and complete filters (${publicAccess ? "public" : "authenticated"})`, async () => {
    if (publicAccess) client.setPublicScanAccess({ scanId: "s", token: "public-token" });
    const calls = installApi();
    const root = await mount();
    assert.equal(calls.filter((c) => c.url.endsWith("/vulnerabilities")).length, 1);
    await openIssues(root);
    const props = issueProps(root);
    assert.equal(props.vulnerabilities.length, 105);
    assert.equal(new Set(props.vulnerabilities.map((v) => v.vuln_index)).size, 105);
    assert.equal(props.fpReview.results.length, 105);
    assert.equal(props.validations.length, 105);
    assert.match(text(root.toJSON()), /疑似问题\s*55/);
    assert.match(text(root.toJSON()), /确认问题 1/);
    assert.doesNotMatch(text(root.toJSON()), /加载更多|已加载当前部分记录|正在加载全部问题/);
    for (const resource of ["vulnerabilities", "validations", "fp-review/results"]) {
      const pages = calls.filter((c) => c.url.endsWith(`/${resource}`));
      assert.deepEqual(pages.map((c) => c.params.after ?? -1), [-1, 147, 297]);
      assert.ok(pages.slice(1).every((c) => c.signal));
    }
    assert.equal(calls.filter((c) => /\/(events|event-history|candidates|threat-audit-tasks)$/.test(c.url)).length, 3);
    const typeFilter = root.root.findAllByType("select").find((node) => text(node.parent).startsWith("类型"));
    await act(async () => typeFilter.props.onChange({ target: { value: "last_only" } }));
    assert.match(text(root.toJSON()), /完整报告 104/);
    assert.match(text(root.toJSON()), /有效结论 104/);
    assert.match(text(root.toJSON()), /已完成验证 \(1\)/);
    const requestCount = calls.length;
    await openIssues(root);
    assert.equal(calls.length, requestCount, "Revisiting a complete list should reuse loaded pages");
  });
}

for (const failure of ["network", "stalled cursor"]) {
  test(`a failed last review page can resume without reloading completed pages (${failure})`, async () => {
    let fail = true;
    const calls = installApi([fixture()], async (config) => {
      if (config.url.endsWith("/fp-review/results") && config.params.after === 297 && fail) {
        if (failure === "network") throw new Error("Temporary failure");
        return { items: [], vulnerabilities: [], next_cursor: 297, has_more: true };
      }
    });
    const root = await mount();
    await openIssues(root);
    assert.equal(issueProps(root).fpReview.results.length, 100);
    assert.match(text(root.toJSON()), /部分详情加载失败/);
    assert.equal(calls.filter((c) => c.url.endsWith("/fp-review/results")).length, 3);
    fail = false;
    await act(async () => button(root, "重试加载问题").props.onClick());
    assert.equal(issueProps(root).fpReview.results.length, 105);
    assert.deepEqual(calls.filter((c) => c.url.endsWith("/fp-review/results")).map((c) => c.params.after), [-1, 147, 297, 297]);
    assert.doesNotMatch(text(root.toJSON()), /部分详情加载失败|正在加载全部问题/);
  });
}

test("an SSE resync automatically reloads the complete issues list", async () => {
  const value = fixture();
  installApi([value]);
  const root = await mount();
  await openIssues(root);
  Object.assign(value, fixture(106));
  await act(async () => {
    streams[0].emit("resync_required", {});
    await new Promise((resolve) => setTimeout(resolve, 200));
  });
  assert.equal(issueProps(root).vulnerabilities.length, 106);
  assert.equal(issueProps(root).fpReview.results.length, 106);
  assert.equal(issueProps(root).validations.length, 106);
  assert.match(text(root.toJSON()), /疑似问题\s*56/);
});

for (const resource of ["vulnerabilities", "validations"]) {
  test(`an invalid ${resource} cursor stops automatic requests and allows retry`, async (t) => {
    t.mock.method(console, "warn", () => {});
    let fail = true;
    const calls = installApi([fixture()], async (config) => {
      if (config.url.endsWith(`/${resource}`) && config.params.after === 297 && fail) {
        return { items: [], next_cursor: 147, has_more: true };
      }
    });
    const root = await mount();
    await openIssues(root);
    assert.equal(issueProps(root)[resource].length, 100);
    assert.match(text(root.toJSON()), /部分详情加载失败/);
    fail = false;
    await act(async () => button(root, "重试加载问题").props.onClick());
    assert.equal(issueProps(root)[resource].length, 105);
    assert.deepEqual(calls.filter((c) => c.url.endsWith(`/${resource}`)).map((c) => c.params.after ?? -1), [-1, 147, 297, 297]);
    assert.doesNotMatch(text(root.toJSON()), /部分详情加载失败|正在加载全部问题/);
  });
}

test("switching scans cancels pending pages and ignores their late responses", async () => {
  const pending = deferred();
  const signals = [];
  installApi([fixture(), fixture(1, "other")], async (config) => {
    if (config.url.includes("/s/") && config.params?.after === 147) {
      signals.push(config.signal);
      await pending.promise;
    }
  });
  const root = await mount();
  await openIssues(root);
  assert.equal(signals.length, 3);
  assert.match(text(root.toJSON()), /正在加载全部问题/);
  await act(async () => root.update(component("other")));
  assert.ok(signals.every((signal) => signal.aborted));
  await act(async () => pending.resolve());
  assert.equal(issueProps(root).vulnerabilities.length, 1);
  assert.equal(issueProps(root).vulnerabilities[0].file, "other/issue-0.c");
  assert.equal(issueProps(root).fpReview.results.length, 1);
  assert.equal(issueProps(root).fpReview.scan_id, "other");
  assert.doesNotMatch(text(root.toJSON()), /部分详情加载失败|正在加载全部问题/);
});

test("a live review received during pagination takes precedence over the older page", async () => {
  const pending = deferred();
  installApi([fixture()], async (config) => {
    if (config.url.endsWith("/fp-review/results") && config.params.after === 147) await pending.promise;
  });
  const root = await mount();
  await openIssues(root);
  await act(async () => streams[0].emit("fp_review_result", {
    review_id: "review-s", vuln_index: 150, verdict: "fp", severity: "high", reason: "最新实时结论",
  }));
  await act(async () => pending.resolve());
  const props = issueProps(root);
  assert.equal(props.fpReview.results.length, 105);
  assert.equal(props.fpReview.results.find((r) => r.vuln_index === 150).reason, "最新实时结论");
  assert.match(text(root.toJSON()), /疑似问题\s*54/);
});

for (const publicAccess of [false, true]) {
  test(`review page loads all records and round-trips to a human-confirmed issue across pages (${publicAccess ? "public" : "authenticated"})`, async () => {
    if (publicAccess) client.setPublicScanAccess({ scanId: "s", token: "public-token" });
    const calls = installApi();
    const root = await mount();
    await openReviews(root);
    const review = root.root.findByType(FpReviewPanel);
    assert.equal(review.props.fpReview.results.length, 105);
    assert.equal(review.props.reviewDataLoaded, true);
    assert.match(text(root.toJSON()), /第 1\/6 页 · 共 105 条/);
    assert.deepEqual(calls.filter((c) => c.url.endsWith("/fp-review/results")).map((c) => c.params.after), [-1, 147, 297]);
    for (let i = 0; i < 5; i += 1) await act(async () => button(root, "下一页").props.onClick());
    const target = root.root.findAllByType("button").find((node) => node.parent?.type === "li" && text(node).startsWith("#312"));
    assert.ok(target);
    await act(async () => target.props.onClick());
    await act(async () => button(root, "查看疑似问题").props.onClick());
    assert.equal(issueProps(root).focusRequest.key, 312);
    assert.match(text(root.toJSON()), /第 3\/3 页/);
    const count = calls.length;
    await act(async () => button(root, "查看去误报详情").props.onClick());
    assert.match(text(root.toJSON()), /第 6\/6 页 · 共 105 条/);
    assert.match(text(root.toJSON()), /有效结论 104/);
    assert.equal(calls.length, count, "A round trip should reuse the loaded review and finding");
  });
}

test("review page retries a failed result page without losing prior pages", async () => {
  let fail = true;
  const calls = installApi([fixture()], async (config) => {
    if (config.url.endsWith("/fp-review/results") && config.params.after === 297 && fail) throw new Error("offline");
  });
  const root = await mount();
  await openReviews(root);
  assert.equal(root.root.findByType(FpReviewPanel).props.fpReview.results.length, 100);
  assert.equal(root.root.findByType(FpReviewPanel).props.reviewDataLoaded, false);
  assert.match(text(root.toJSON()), /部分详情加载失败/);
  fail = false;
  await act(async () => button(root, "重试加载复核记录").props.onClick());
  assert.equal(root.root.findByType(FpReviewPanel).props.fpReview.results.length, 105);
  assert.equal(root.root.findByType(FpReviewPanel).props.reviewDataLoaded, true);
  assert.deepEqual(calls.filter((c) => c.url.endsWith("/fp-review/results")).map((c) => c.params.after), [-1, 147, 297, 297]);
});

test("a review starting during pagination retains the cursor and ignores the previous request", async () => {
  const pending = deferred();
  let oldSignal;
  installApi([fixture()], async (config) => {
    if (config.url.endsWith("/fp-review/results") && config.params.after === 147 && !oldSignal) {
      oldSignal = config.signal;
      await pending.promise;
    }
  });
  const root = await mount();
  await openReviews(root);
  assert.equal(root.root.findByType(FpReviewPanel).props.fpReview.results.length, 50);
  await act(async () => streams[0].emit("fp_review_started", { review_id: "next-review", status: "running", total: 105 }));
  assert.equal(oldSignal.aborted, true);
  assert.equal(root.root.findByType(FpReviewPanel).props.fpReview.results.length, 105);
  await act(async () => pending.resolve());
  const job = root.root.findByType(FpReviewPanel).props.fpReview;
  assert.equal(job.review_id, "next-review");
  assert.equal(job.results.length, 105);
  assert.equal(job.next_cursor, null);
});
