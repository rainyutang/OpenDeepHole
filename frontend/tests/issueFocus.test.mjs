import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({
  root: process.env.OPENDEEPHOLE_TEST_FRONTEND_ROOT || process.cwd(),
  appType: "custom", logLevel: "silent", server: { middlewareMode: true },
});
const { default: VulnerabilityList } = await server.ssrLoadModule("/src/components/VulnerabilityList.tsx");
const roots = [];
afterEach(async () => { await act(async () => roots.splice(0).forEach((root) => root.unmount())); });
after(async () => { await server.close(); });
const content = (node) => typeof node === "string" || typeof node === "number" ? String(node)
  : Array.isArray(node) ? node.map(content).join("") : content(node?.children ?? node?.props?.children ?? "");
const issue = (index) => ({
  vuln_index: index, file: `src/issue-${index}.c`, line: 17, function: "parse", vuln_type: "oob",
  severity: "high", confirmed: true, ai_verdict: "confirmed", ai_analysis: "", description: "issue",
  vulnerability_report: `# Issue ${index}`,
});

async function mount(props, options) {
  let root;
  await act(async () => { root = create(createElement(VulnerabilityList, props), options); });
  roots.push(root);
  return root;
}

test("ordinary issue navigation scrolls to the stable index on a later page", async () => {
  const vulnerabilities = [...Array.from({ length: 45 }, (_, i) => issue(i * 3)), issue(207)];
  const scrolls = [];
  const root = await mount({ scanId: "s", vulnerabilities, focusRequest: { key: 207, revision: 1 } }, {
    createNodeMock: (element) => element.type === "button"
      ? { scrollIntoView: (options) => scrolls.push({ label: content(element), options }) } : null,
  });
  assert.match(content(root.toJSON()), /第 3\/3 页/);
  assert.match(content(root.toJSON()), /Issue 207/);
  assert.equal(scrolls.length, 1);
  assert.match(scrolls[0].label, /issue-207.c/);
  assert.deepEqual(scrolls[0].options, { block: "nearest", inline: "nearest" });
});

test("ordinary issue rows expose the selected item to assistive navigation", async () => {
  const root = await mount({ scanId: "s", vulnerabilities: [issue(0), issue(207)] });
  const current = () => root.root.findAllByType("button").filter((node) => node.props["aria-current"] === "true");
  assert.equal(current().length, 1);
  assert.match(content(current()[0]), /issue-0.c/);
  const next = root.root.findAllByType("button").find((node) => node.parent?.type === "li" && content(node).includes("issue-207.c"));
  await act(async () => next.props.onClick());
  assert.equal(current().length, 1);
  assert.match(content(current()[0]), /issue-207.c/);
});
