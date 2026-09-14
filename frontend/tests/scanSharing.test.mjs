import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { AxiosError } from "axios";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
const client = await server.ssrLoadModule("/src/api/client.ts");
const { parsePublicScanAccess } = await server.ssrLoadModule("/src/App.tsx");
const { default: ScanStatus, FpReviewPanel } = await server.ssrLoadModule("/src/components/ScanStatus.tsx");
const { default: ShareButton } = await server.ssrLoadModule("/src/components/ScanShareButton.tsx");
const { default: SharedView } = await server.ssrLoadModule("/src/components/SharedScanView.tsx");
const { default: VulnerabilityList } = await server.ssrLoadModule("/src/components/VulnerabilityList.tsx");
const { ThemeProvider } = await server.ssrLoadModule("/src/theme/ThemeProvider.tsx");
const originalAdapter = client.api.defaults.adapter;
const roots = [], streams = [], removedKeys = [];
globalThis.localStorage = { getItem: () => "existing-owner-jwt", setItem() {}, removeItem(key) { removedKeys.push(key); } };
globalThis.window = Object.assign(new EventTarget(), {
  localStorage, setTimeout, clearTimeout, setInterval, clearInterval,
  location: { origin: "https://example.test", href: "https://example.test/#/history", hash: "" },
});
globalThis.document = Object.assign(new EventTarget(), { hidden: false, documentElement: { dataset: {}, style: {} } });
globalThis.EventSource = class extends EventTarget {
  constructor(url) { super(); this.url = url; this.closed = false; streams.push(this); }
  close() { this.closed = true; }
  emit(type, data) { this.dispatchEvent(new MessageEvent(type, { data: JSON.stringify(data) })); }
};

afterEach(async () => {
  await act(async () => roots.splice(0).forEach((root) => root.unmount()));
  client.api.defaults.adapter = originalAdapter;
  client.setPublicScanAccess(null);
  streams.length = 0; removedKeys.length = 0;
});
after(async () => {
  for (const key of ["window", "document", "localStorage", "EventSource"]) delete globalThis[key];
  await server.close();
});

const access = { scanId: "s", token: "share-token", kind: "shared" };
const response = (config, data) => ({ config, data, status: 200, statusText: "OK", headers: {} });
const content = (node) => typeof node === "string" || typeof node === "number" ? String(node)
  : Array.isArray(node) ? node.map(content).join("") : content(node?.children ?? node?.props?.children ?? "");
const buttons = (root) => root.root.findAllByType("button");
const button = (root, label) => {
  const value = buttons(root).find((node) => content(node) === label);
  assert.ok(value, `Missing button: ${label}`); return value;
};
async function mount(Component, props = {}) {
  let root;
  await act(async () => { root = create(createElement(ThemeProvider, null, createElement(Component, props))); });
  roots.push(root); return root;
}

function installApi(status = "complete", intercept = () => undefined) {
  const calls = [];
  const vulnerabilities = Array.from({ length: 53 }, (_, ordinal) => ({
    vuln_index: ordinal * 3, file: `issue-${ordinal}.c`, function: "parse", line: 10, vuln_type: "npd",
    severity: "high", confirmed: true, ai_verdict: "confirmed", description: `问题 ${ordinal}`,
    ai_analysis: "analysis", vulnerability_report: `# 报告 ${ordinal}`,
  }));
  const results = vulnerabilities.map((v) => ({ vuln_index: v.vuln_index, verdict: "tp", reason: "有效结论" }));
  client.api.defaults.adapter = async (config) => {
    calls.push(config);
    const override = await intercept(config);
    if (override !== undefined) return response(config, override);
    if (config.url === "/api/mining-engines") return response(config, { engines: [] });
    if (config.url.endsWith("/checkers") || config.url.endsWith("/checkers/catalog")) return response(config, []);
    if (config.url.endsWith("/overview") && !config.url.includes("fp-review")) return response(config, {
      scan_id: "s", project_id: "p", status, progress: 0.5, total_candidates: 53, processed_candidates: 20,
      auto_fp_review: true, fp_review_method: "adversarial", agent_online: true,
      vulnerability_validation_enabled: true, can_continue: true, continuable_task_count: 1,
      scan_items: [], detail_counts: { vulnerabilities: 53, human_confirmed_issue_count: 0 },
    });
    if (config.url.endsWith("/fp-review/overview")) return response(config, {
      review_id: "review-s", scan_id: "s", status: "running", method: "adversarial", total: 53, processed: 52, results: [],
    });
    const afterIndex = config.params?.after ?? -1;
    const page = (items, index) => {
      const remaining = items.filter((item) => index(item) > afterIndex);
      const selected = remaining.slice(0, 50);
      return { items: selected, next_cursor: remaining.length > 50 ? index(selected.at(-1)) : null, has_more: remaining.length > 50 };
    };
    if (config.url.endsWith("/vulnerabilities")) return response(config, page(vulnerabilities.map((vulnerability) => ({ index: vulnerability.vuln_index, vulnerability })), (v) => v.index));
    if (config.url.endsWith("/fp-review/results")) return response(config, { ...page(results, (r) => r.vuln_index), vulnerabilities });
    if (/\/(candidates|event-history|events|threat-audit-tasks|validations)$/.test(config.url)) return response(config, { items: [], next_cursor: null, has_more: false });
    if (config.url.endsWith("/index-status")) return response(config, { status: "skipped" });
    if (config.url.endsWith("/git_history")) return response(config, []);
    if (config.url.endsWith("/threat-analysis")) return response(config, null);
    if (config.url.includes("/details/vulnerabilities/")) return response(config,
      { ...vulnerabilities.find((v) => v.vuln_index === Number(config.url.split("/").at(-1))), user_verdict: "confirmed" });
    assert.fail(`Unexpected request: ${config.url}`);
  };
  return calls;
}

test("share hash parsing keeps invalid share links out of login and preserves legacy links", () => {
  assert.deepEqual(parsePublicScanAccess("#/shared-scan/s?token=share-token"), access);
  assert.equal(parsePublicScanAccess("#/shared-scan/s").kind, "shared");
  assert.equal(parsePublicScanAccess("#/shared-scan/%ZZ?token=x").kind, "shared");
  assert.equal(parsePublicScanAccess("#/public-scan/s?token=old").kind, "integration");
  assert.equal(parsePublicScanAccess("#/public-scan/s"), null);
});

for (const status of ["auditing", "complete"]) {
  test(`share controls and pagination remain scoped with an owner JWT (${status})`, async () => {
    client.setPublicScanAccess(access);
    const calls = installApi(status);
    const root = await mount(ScanStatus, { scanId: "s", onBack() {} });
    for (const forbidden of ["停止扫描", "续扫", "分享", "误报屏蔽规则"]) {
      assert.ok(!buttons(root).some((node) => content(node).includes(forbidden)), forbidden);
    }
    assert.ok(button(root, "导出报告"));
    await act(async () => button(root, "疑似问题").props.onClick());
    const props = root.root.findByType(VulnerabilityList).props;
    assert.equal(props.vulnerabilities.length, 53);
    assert.equal(props.vulnerabilities.at(-1).vuln_index, 156);
    assert.equal(props.onTriggerValidation, undefined);
    assert.equal(props.onStopValidation, undefined);
    assert.equal(props.onFeedbackCreated, undefined);
    const reviewNav = buttons(root).find((node) => content(node).startsWith("adversarial"));
    assert.ok(reviewNav);
    await act(async () => reviewNav.props.onClick());
    assert.equal(root.root.findByType(FpReviewPanel).props.canControl, false);
    for (const label of ["停止复核", "启动复核", "重新复核", "停止验证"]) {
      assert.ok(!buttons(root).some((node) => content(node) === label), label);
    }
    assert.ok(streams[0].url.includes("/api/shared/scans/s/events?token=share-token"));
    for (const call of calls.filter((c) => c.url.includes("/scans/"))) {
      assert.ok(call.url.startsWith("/api/shared/scans/s/"));
      assert.equal(call.params.token, access.token);
      assert.equal(call.headers.get("Authorization"), undefined);
    }
  });
}

test("shared mutation requests cannot fall back to owner credentials", async () => {
  client.setPublicScanAccess(access);
  let requests = 0;
  client.api.defaults.adapter = async () => { requests++; assert.fail("forbidden request reached transport"); };
  for (const operation of [() => client.stopScan("s"), () => client.resumeScan("s"), () => client.deleteScan("s"),
    () => client.triggerFpReview("s"), () => client.stopFpReview("s"),
    () => client.triggerVulnerabilityValidation("s", 0), () => client.stopVulnerabilityValidation("s", 0),
    () => client.updateScanFeedback("s", ["feedback"]), () => client.createScanShare("s"), () => client.revokeScanShare("s")]) {
    await assert.rejects(operation, /分享链接仅支持/);
  }
  assert.equal(requests, 0);
});

test("share dialog generates browser-origin links and can revoke and regenerate", async () => {
  let generation = 1;
  client.api.defaults.adapter = async (config) => response(config, config.method === "delete" ? (generation++, { ok: true }) : { scan_id: "s", token: `token-${generation}` });
  const root = await mount(ShareButton, { scanId: "s" });
  await act(async () => button(root, "分享").props.onClick());
  assert.equal(root.root.findByType("input").props.value, "https://example.test/#/shared-scan/s?token=token-1");
  await act(async () => button(root, "关闭分享").props.onClick());
  assert.ok(content(root.toJSON()).includes("原链接已失效"));
  await act(async () => button(root, "重新开启分享").props.onClick());
  assert.ok(root.root.findByType("input").props.value.endsWith("token=token-2"));
});

test("shared marking and every download use share credentials", async () => {
  client.setPublicScanAccess(access);
  const calls = [];
  client.api.defaults.adapter = async (config) => {
    calls.push(config);
    return response(config, config.method === "post" ? { ok: true, feedback_id: "f", removed_feedback_ids: [] } : new Blob(["report"]));
  };
  await client.markVulnerability("s", 156, "confirmed", "人工确认");
  await client.downloadScanReport("s");
  await client.downloadScanReportZip("s");
  await client.downloadVulnerabilityReport("s", 156);
  assert.equal(JSON.parse(calls[0].data).index, 156);
  assert.deepEqual(calls.map((c) => c.url), ["/api/shared/scans/s/mark", "/api/shared/scans/s/report", "/api/shared/scans/s/report.zip", "/api/shared/scans/s/vulnerability/156/report"]);
  calls.forEach((config) => {
    assert.equal(config.params.token, access.token);
    assert.equal(config.headers.get("Authorization"), undefined);
  });
});

test("manual verdict notifications refresh the stable issue on the open page", async () => {
  client.setPublicScanAccess(access);
  installApi();
  const root = await mount(ScanStatus, { scanId: "s", onBack() {} });
  await act(async () => button(root, "疑似问题").props.onClick());
  await act(async () => {
    streams[0].emit("resource_changed", { resource: "vulnerabilities", index: 156 });
    await new Promise((resolve) => setTimeout(resolve, 220));
  });
  assert.equal(root.root.findByType(VulnerabilityList).props.vulnerabilities.at(-1).user_verdict, "confirmed");
});

test("revocation closes the stream and unmounts the detail without logging out", async () => {
  client.setPublicScanAccess(access); installApi();
  const root = await mount(SharedView, { access, onBack() {} });
  await act(async () => client.notifyShareUnavailable("s", "old-token"));
  assert.equal(root.root.findAllByType(ScanStatus).length, 1);
  await act(async () => streams[0].emit("share_unavailable", { scan_id: "s" }));
  assert.ok(content(root.toJSON()).includes("分享已关闭或链接无效"));
  assert.equal(root.root.findAllByType(ScanStatus).length, 0);
  assert.ok(streams[0].closed);
  assert.deepEqual(removedKeys, []);
});

test("invalid share response displays an error, including a blob download failure", async () => {
  client.setPublicScanAccess(access); installApi();
  const root = await mount(SharedView, { access, onBack() {} });
  client.api.defaults.adapter = async (config) => {
    throw new AxiosError("Forbidden", "ERR_BAD_REQUEST", config, null, { ...response(config, new Blob()), status: 403 });
  };
  await act(async () => { await assert.rejects(() => client.downloadScanReport("s")); });
  assert.ok(content(root.toJSON()).includes("分享已关闭或链接无效"));
  assert.deepEqual(removedKeys, []);
});
