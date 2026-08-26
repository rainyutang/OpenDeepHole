import assert from "node:assert/strict";
import test, { after } from "node:test";
import { createServer } from "vite";

const server = await createServer({
  appType: "custom",
  logLevel: "silent",
  server: { middlewareMode: true },
});
const runtime = await server.ssrLoadModule("/src/scanRuntime.ts");

after(async () => {
  await server.close();
});

function vulnerability(file, variantOf = "") {
  return {
    file,
    line: 1,
    function: "target",
    vuln_type: "npd",
    severity: "high",
    description: "description",
    ai_analysis: "analysis",
    confirmed: true,
    variant_of: variantOf,
  };
}

test("normalizes legacy arrays without materializing invalid entries", () => {
  const normalized = runtime.normalizeIndexedVulnerabilities([
    null,
    vulnerability("kept.c"),
  ]);

  assert.deepEqual(normalized.map((item) => item.vuln_index), [1]);
  assert.equal(normalized[0].file, "kept.c");
});

test("merges non-contiguous backend indexes into a dense collection", () => {
  const first = runtime.mergeIndexedVulnerabilities([], [
    { index: 1, vulnerability: vulnerability("one.c") },
  ]);
  const merged = runtime.mergeIndexedVulnerabilities(first, [
    { index: 3, vulnerability: vulnerability("three.c", "history") },
    { index: 1, vulnerability: vulnerability("one-updated.c") },
  ]);

  assert.deepEqual(merged.map((item) => item.vuln_index), [1, 3]);
  assert.equal(merged[0].file, "one-updated.c");
  assert.equal(merged.filter((item) => item.variant_of).length, 1);
  assert.ok(merged.every(Boolean));
});

test("finds vulnerabilities by stable index instead of array position", () => {
  const merged = runtime.mergeIndexedVulnerabilities([], [
    { index: 4, vulnerability: vulnerability("four.c") },
    { index: 9, vulnerability: vulnerability("nine.c") },
  ]);

  assert.equal(runtime.findIndexedVulnerability(merged, 9)?.file, "nine.c");
  assert.equal(runtime.findIndexedVulnerability(merged, 1), undefined);
});
