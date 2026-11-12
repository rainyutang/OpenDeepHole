import assert from "node:assert/strict";
import test, { after } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true, hmr: false } });
const { default: VulnerabilityMarkdownReport } = await server.ssrLoadModule("/src/components/VulnerabilityMarkdownReport.tsx");
const { MarkdownReport } = await server.ssrLoadModule("/src/features/issues/presentation.tsx");
after(() => server.close());

for (const [name, Component] of [["mining report", VulnerabilityMarkdownReport], ["review report", MarkdownReport]]) {
  test(`${name} retains unchanged Markdown output and renders streamed replacements`, async () => {
    let root;
    try {
      await act(async () => { root = create(createElement(Component, { content: "Saved report" })); });
      const paragraphProps = root.root.findByType("p").props;
      await act(async () => root.update(createElement(Component, { content: "Saved report" })));
      assert.equal(root.root.findByType("p").props, paragraphProps, "Unrelated parent updates must reuse the parsed report subtree");
      await act(async () => root.update(createElement(Component, { content: "Updated **report**" })));
      assert.notEqual(root.root.findByType("p").props, paragraphProps);
      assert.deepEqual(root.root.findByType("strong").children, ["report"]);
      await act(async () => root.update(createElement(Component, { content: "" })));
      assert.equal(root.root.findAllByType("p").length, 0);
    } finally {
      if (root) await act(async () => root.unmount());
    }
  });
}
