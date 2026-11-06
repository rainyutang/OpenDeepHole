import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
const { ThreatAnalysisPanel, getThreatAnalysisResultCounts } = await server.ssrLoadModule("/src/features/threatAnalysis/ThreatAnalysisPanel.tsx");
const roots = [];
globalThis.document = Object.assign(new EventTarget(), { hidden: false });

afterEach(async () => { await act(async () => roots.splice(0).forEach((root) => root.unmount())); });
after(async () => { delete globalThis.document; await server.close(); });

function text(node) {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(text).join("");
  return text(node?.children ?? node?.props?.children ?? "");
}
const pattern = (id, name) => ({ pattern_id: id, pattern_name: name, association_description: "系统补充审计" });
const baseline = (name, node, patterns) => ({ module_name: name, node_id: node, source: "compact_baseline", attack_patterns: patterns });
function tree(id) {
  return {
    tree_id: id, value_asset: { asset_name: `资产 ${id}` },
    nodes: [
      { node_id: "root", node_type: "根节点", node_name: "资产目标" },
      { node_id: "internal", node_type: "内部节点", module_name: "共享内部模块", is_high_risk_module: true },
      { node_id: "leaf", node_type: "叶子节点", module_name: "入口模块", is_high_risk_module: true },
    ],
    edges: [{ source_node_id: "leaf", target_node_id: "internal" }, { source_node_id: "internal", target_node_id: "root" }],
    attack_paths: [{ node_ids: ["leaf", "internal", "root"], attack_patterns: [pattern("AI-1", "AI 路径模式")] }],
  };
}
function analysis(trees, unassigned) {
  return { entrypoint_result: { result: true }, artifacts: {
    value_asset_path: { content: [] }, high_risk_modules_path: { content: [] },
    attack_tree_path: { content: { attack_trees: trees, ...(unassigned ? { unassigned_module_pattern_baselines: unassigned } : {}) } },
  } };
}
async function mount(value) {
  let root;
  await act(async () => { root = create(createElement(ThreatAnalysisPanel, {
    scanId: "baseline", coverageRevision: 0, analysis: value, events: [], loading: false, isDone: true,
    methodLabel: "精简威胁分析", resultTab: "attackTrees", onResultTabChange() {},
    coverageState: { data: null, tree: null, loading: false, error: "", refresh() {} },
  })); });
  roots.push(root);
  return root;
}

test("baselines follow their persisted tree and include internal modules only once across shared trees", async () => {
  const first = tree("T1"), second = tree("T2");
  first.module_pattern_baselines = [baseline("入口模块", "leaf", [pattern("N1", "越界写入")])];
  second.module_pattern_baselines = [baseline("共享内部模块", "internal", [pattern("N2", "失效对象继续使用")])];
  const value = analysis([first, second], [baseline("独立模块", null, [pattern("S1", "资源耗尽")])]);
  const root = await mount(value);
  const trees = root.root.findAllByType("article");
  assert.equal(trees.length, 2);
  const firstGroups = trees[0].findByProps({ "aria-label": "高风险模块固定审计模式" });
  const secondGroups = trees[1].findByProps({ "aria-label": "高风险模块固定审计模式" });
  assert.match(text(firstGroups), /入口模块.*越界写入/);
  assert.doesNotMatch(text(firstGroups), /失效对象继续使用/);
  assert.match(text(secondGroups), /共享内部模块.*失效对象继续使用/);
  assert.equal(text(root.toJSON()).split("失效对象继续使用").length - 1, 1);
  assert.match(text(root.root.findByProps({ "aria-label": "未关联攻击路径的高风险模块" })), /独立模块.*资源耗尽/);
  assert.equal(getThreatAnalysisResultCounts(value).attackTrees, 2);
});

test("unassigned modules remain visible without fabricating an attack tree", async () => {
  const value = analysis([], [baseline("独立模块", null, [pattern("S1", "资源耗尽")])]);
  const root = await mount(value);
  assert.match(text(root.toJSON()), /0 棵攻击树/);
  assert.match(text(root.toJSON()), /未关联攻击路径的高风险模块.*独立模块.*资源耗尽/);
  assert.equal(root.root.findAllByType("article").length, 0);
  assert.equal(getThreatAnalysisResultCounts(value).attackTrees, 0);
});

test("historical artifacts retain the original leaf patterns and empty-tree state", async () => {
  const root = await mount(analysis([tree("old")]));
  assert.match(text(root.toJSON()), /叶子节点匹配攻击模式.*AI 路径模式/);
  assert.doesNotMatch(text(root.toJSON()), /固定审计|未关联攻击路径的高风险模块/);
  const empty = await mount(analysis([]));
  assert.match(text(empty.toJSON()), /暂无攻击树/);
});

test("fixed-audit explanation is available on keyboard focus and dismisses with Escape", async () => {
  const value = tree("T1");
  value.module_pattern_baselines = [baseline("入口模块", "leaf", [pattern("N1", "越界写入")])];
  const root = await mount(analysis([value]));
  const label = root.root.findByProps({ className: "baseline-audit-label" });
  assert.equal(label.props.tabIndex, 0);
  await act(async () => label.props.onFocus());
  const tooltip = root.root.findByProps({ role: "tooltip" });
  assert.equal(label.props["aria-describedby"], tooltip.props.id);
  assert.match(text(tooltip), /系统补充的审计范围，是否存在问题由审计确认/);
  await act(async () => label.props.onKeyDown({ key: "Escape" }));
  assert.equal(root.root.findAllByProps({ role: "tooltip" }).length, 0);
  await act(async () => label.props.onMouseEnter());
  assert.equal(root.root.findAllByProps({ role: "tooltip" }).length, 1);
  await act(async () => label.props.onMouseLeave());
  assert.equal(root.root.findAllByProps({ role: "tooltip" }).length, 0);
});
