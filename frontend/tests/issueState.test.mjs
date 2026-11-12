import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
const { default: VulnerabilityList } = await server.ssrLoadModule("/src/components/VulnerabilityList.tsx");
const { default: FeatureList } = await server.ssrLoadModule("/src/features/issues/VulnerabilityList.tsx");
const { api, setPublicScanAccess } = await server.ssrLoadModule("/src/api/client.ts");
const originalAdapter = api.defaults.adapter;
const roots = [];
globalThis.localStorage = { getItem: () => null };
afterEach(async () => {
  await act(async () => roots.splice(0).forEach((root) => root.unmount()));
  api.defaults.adapter = originalAdapter;
  setPublicScanAccess(null);
});
after(async () => { delete globalThis.localStorage; await server.close(); });
const content = (node) => typeof node === "string" || typeof node === "number" ? String(node)
  : Array.isArray(node) ? node.map(content).join("") : content(node?.children ?? node?.props?.children ?? "");
const issue = (index, overrides = {}) => ({
  vuln_index: index, file: `src/issue-${index}.c`, line: 17, function: "parse", vuln_type: "oob",
  severity: "high", confirmed: true, ai_verdict: "confirmed", ai_analysis: "", description: "issue",
  vulnerability_report: `# Issue ${index}`, ...overrides,
});
const button = (root, label) => {
  const found = root.root.findAllByType("button").find((node) => content(node) === label);
  assert.ok(found, `Missing button: ${label}`);
  return found;
};
const input = (root, placeholder) => root.root.findAllByType("input").find((node) => node.props.placeholder === placeholder);
async function mount(props) {
  let root;
  await act(async () => { root = create(createElement(VulnerabilityList, props)); });
  roots.push(root);
  return root;
}

test("compatibility imports preserve the component identity", () => {
  assert.equal(VulnerabilityList, FeatureList);
});

test("live updates keep the selected stable index and its unsaved feedback draft", async () => {
  const props = { scanId: "s", vulnerabilities: [issue(0), issue(207)] };
  const root = await mount(props);
  const row = root.root.findAllByType("button").find((node) => node.parent?.type === "li" && content(node).includes("issue-207.c"));
  await act(async () => row.props.onClick());
  await act(async () => button(root, "添加人工反馈").props.onClick());
  await act(async () => input(root, "输入理由...").props.onChange({ target: { value: "unsaved evidence" } }));
  await act(async () => root.update(createElement(VulnerabilityList, {
    ...props, vulnerabilities: [issue(7), ...props.vulnerabilities.map((v) => ({ ...v, description: "updated" }))],
  })));
  assert.match(content(root.toJSON()), /Issue 207/);
  assert.equal(input(root, "输入理由...").props.value, "unsaved evidence");
  await act(async () => root.root.findAllByType("button").find((node) => node.parent?.type === "li" && content(node).includes("issue-0.c")).props.onClick());
  assert.equal(input(root, "输入理由..."), undefined);
  assert.ok(button(root, "添加人工反馈"));
});

test("shared feedback keeps backend indices and callback order after the split", async () => {
  setPublicScanAccess({ scanId: "s", token: "share-token", kind: "shared" });
  const calls = [], notifications = [];
  api.defaults.adapter = async (config) => {
    calls.push(config);
    return { config, data: { ok: true, feedback_id: "new-feedback", removed_feedback_ids: ["old-feedback"] },
      status: 200, statusText: "OK", headers: {} };
  };
  const root = await mount({ scanId: "s", vulnerabilities: [issue(207)],
    onFeedbackCreated: (ids) => notifications.push(["created", ids]),
    onFeedbackRemoved: (ids) => notifications.push(["removed", ids]),
    onVulnMarked: () => notifications.push(["marked"]),
  });
  await act(async () => button(root, "添加人工反馈").props.onClick());
  await act(async () => input(root, "输入理由...").props.onChange({ target: { value: "confirmed evidence" } }));
  await act(async () => button(root, "提交").props.onClick());
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "/api/shared/scans/s/mark");
  assert.equal(calls[0].params.token, "share-token");
  assert.equal(JSON.parse(calls[0].data).index, 207);
  assert.deepEqual(notifications, [["created", ["new-feedback"]], ["removed", ["old-feedback"]], ["marked"]]);
  assert.match(content(root.toJSON()), /confirmed evidence/);
  assert.ok(button(root, "修改"));
});

test("review stage and dialogue expansion survive live snapshots of the same issue", async () => {
  const fpReview = { results: [{ vuln_index: 207, verdict: "tp", reason: "confirmed", stage_outputs: { proof: "proof evidence", final_judge: "final evidence" } }] };
  const props = { scanId: "s", vulnerabilities: [issue(207)], fpReview,
    fpReviewStages: [{ key: "proof", label: "Proof" }, { key: "final_judge", label: "Final" }],
    events: [{ phase: "opencode_output", candidate_index: 207, message: "original dialogue" }],
  };
  const root = await mount(props);
  await act(async () => button(root, "Proof").props.onClick());
  await act(async () => button(root, "查看对话日志 (1 行)").props.onClick());
  await act(async () => root.update(createElement(VulnerabilityList, {
    ...props, vulnerabilities: [issue(207, { description: "updated" })],
    fpReview: { results: [{ ...fpReview.results[0], stage_outputs: { proof: "updated proof", final_judge: "updated final" } }] },
    events: [...props.events, { phase: "opencode_output", candidate_index: 207, message: "new dialogue" }],
  })));
  assert.match(content(root.toJSON()), /updated proof/);
  assert.doesNotMatch(content(root.toJSON()), /updated final/);
  assert.ok(button(root, "隐藏对话日志"));
  assert.match(content(root.toJSON()), /new dialogue/);
});
