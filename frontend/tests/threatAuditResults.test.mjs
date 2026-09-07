import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
const { ThreatAuditFindingBadge, ThreatAuditResults } = await server.ssrLoadModule("/src/features/threatAudit/ThreatAuditResults.tsx");
const client = await server.ssrLoadModule("/src/api/client.ts");
const originalAdapter = client.api.defaults.adapter;
globalThis.localStorage = { getItem: () => null };

afterEach(() => {
  client.api.defaults.adapter = originalAdapter;
  client.setPublicScanAccess(null);
});
after(async () => { delete globalThis.localStorage; await server.close(); });

function finding(overrides = {}) {
  return {
    vuln_index: 207, vuln_type: "越界读取", severity: "high", description: "长度未校验，可通过外部输入触发。",
    file: "src/parser.c", line: 17, function: "parse_packet", verdict: "confirmed", verdict_source: "fp_review",
    ...overrides,
  };
}
function result(findings = [finding()], overrides = {}) {
  return {
    task_id: "task-a", findings, confirmed_issue_count: findings.filter((item) => item.verdict === "confirmed").length,
    association_complete: true, ...overrides,
  };
}
function renderResult(value, props = {}) {
  return renderToStaticMarkup(createElement(ThreatAuditResults, {
    result: value, status: "completed", loading: false, error: "", onRetry: () => {}, ...props,
  }));
}

test("only confirmed findings get a task badge; subsequent false-positive removes it", () => {
  assert.match(renderToStaticMarkup(createElement(ThreatAuditFindingBadge, { result: result() })), /发现问题/);
  for (const value of [undefined, result([]), result([finding({ verdict: "unreviewed" })]), result([finding({ verdict: "false_positive" })])]) {
    assert.equal(renderToStaticMarkup(createElement(ThreatAuditFindingBadge, { result: value })), "");
  }
});

test("shows every historical finding, stable index, description and latest conclusion", () => {
  const html = renderResult(result([
    finding(), finding({ vuln_index: 8, verdict: "false_positive", verdict_source: "human", description: "已确认 Guard 阻断。" }),
  ]));
  assert.match(html, /#207/);
  assert.match(html, /#8/);
  assert.match(html, /长度未校验，可通过外部输入触发。/);
  assert.match(html, /去误报复核 · 确认问题/);
  assert.match(html, /人工判定 · 非问题/);
  assert.match(html, /src\/parser.c:17/);
  assert.match(html, /parse_packet/);
});

test("missing historical links, failed audits, and loading never claim no issues were found", () => {
  assert.match(renderResult(undefined, { loading: true }), /正在读取审计结果/);
  assert.match(renderResult(result([])), /未关联到问题结果/);
  assert.match(renderResult(result([]), { status: "running" }), /审计尚未完成/);
  assert.match(renderResult(result([]), { status: "failed" }), /审计未成功/);
  const partial = renderResult(result([finding()], { association_complete: false }));
  assert.match(partial, /无法还原完整审计结果/);
  assert.match(partial, /#207/);
  assert.doesNotMatch(partial, /未发现问题/);
  const failed = renderResult(result(), { error: "审计结果读取失败" });
  assert.match(failed, /role="alert"/);
  assert.match(failed, /重试/);
  assert.doesNotMatch(failed, /#207/);
});

test("renders stored descriptions safely and explains missing descriptions", () => {
  const html = renderResult(result([finding({ description: "<img src=x onerror=alert(1)>" })]));
  assert.doesNotMatch(html, /<img/);
  assert.match(html, /&lt;img/);
  assert.match(renderResult(result([finding({ description: "" })])), /未保存问题简介/);
});

test("batch client uses repeated task IDs, deduplicates them, and forwards cancellation", async () => {
  const calls = [];
  client.api.defaults.adapter = async (config) => {
    calls.push(config);
    return { config, status: 200, statusText: "OK", headers: {}, data: [result()] };
  };
  const controller = new AbortController();
  await client.getScanThreatAuditResults("scan-a", ["task-a", "task-a"], controller.signal);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "/api/v2/scans/scan-a/threat-audit-results");
  assert.deepEqual(calls[0].params.getAll("task_ids"), ["task-a"]);
  assert.equal(calls[0].signal, controller.signal);
  await client.getScanThreatAuditResults("scan-a", []);
  assert.equal(calls.length, 1);
  await assert.rejects(client.getScanThreatAuditResults("scan-a", Array.from({ length: 101 }, (_, i) => `t${i}`)), /最多读取/);
  assert.equal(calls.length, 1);
});

test("public result requests use the existing scan token and reject mismatched results", async () => {
  client.setPublicScanAccess({ scanId: "public-scan", token: "access-token" });
  client.api.defaults.adapter = async (config) => {
    assert.equal(config.url, "/api/public/scans/public-scan/threat-audit-results");
    assert.equal(config.params.get("token"), "access-token");
    return { config, status: 200, statusText: "OK", headers: {}, data: [result()] };
  };
  assert.equal((await client.getScanThreatAuditResults("public-scan", ["task-a"]))[0].confirmed_issue_count, 1);
  await assert.rejects(client.getScanThreatAuditResults("public-scan", ["another-task"]), /响应无效/);
});
