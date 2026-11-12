import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import ts from "typescript";

const src = path.resolve("src");
const walk = (directory) => readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
  const file = path.join(directory, entry.name);
  return entry.isDirectory() ? walk(file) : /\.tsx?$/.test(file) && !file.endsWith(".d.ts") ? [file] : [];
});
const files = walk(src);
const fileSet = new Set(files);
const relative = (file) => path.relative(src, file).split(path.sep).join("/");
const parse = (file, text) => ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
const resolve = (file, specifier) => {
  if (!specifier.startsWith(".")) return null;
  const target = path.resolve(path.dirname(file), specifier);
  return [target, `${target}.ts`, `${target}.tsx`, path.join(target, "index.ts"), path.join(target, "index.tsx")]
    .find((candidate) => fileSet.has(candidate)) ?? null;
};
const moduleSpecifiers = (source) => {
  const imports = [];
  const visit = (node) => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
      imports.push(node.moduleSpecifier.text);
    } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword && ts.isStringLiteral(node.arguments[0])) {
      imports.push(node.arguments[0].text);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return imports;
};

// Type-only imports disappear before building the runtime graph.
const sources = new Map(files.map((file) => [file, readFileSync(file, "utf8")]));
const runtimeImports = new Map(files.map((file) => {
  const emitted = ts.transpileModule(sources.get(file), {
    fileName: file,
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020, jsx: ts.JsxEmit.ReactJSX },
  }).outputText;
  return [file, moduleSpecifiers(parse(`${file}.js`, emitted))];
}));
const graph = new Map(files.map((file) => [file, runtimeImports.get(file).map((specifier) => resolve(file, specifier)).filter(Boolean)]));

test("frontend runtime modules have no circular dependencies", () => {
  const complete = new Set(), active = new Set(), chain = [], cycles = [];
  const visit = (file) => {
    if (active.has(file)) {
      cycles.push([...chain.slice(chain.indexOf(file)), file].map(relative).join(" -> "));
      return;
    }
    if (complete.has(file)) return;
    active.add(file);
    chain.push(file);
    graph.get(file).forEach(visit);
    chain.pop();
    active.delete(file);
    complete.add(file);
  };
  files.forEach(visit);
  assert.deepEqual(cycles, [], `Runtime dependency cycles:\n${cycles.join("\n")}`);
});

const compatibilityEntries = new Set([
  "api/client.ts", "types.ts", "scanRuntime.ts", "hooks/useScanSSE.ts",
  "components/ScanStatus.tsx", "components/VulnerabilityList.tsx", "components/ModelPoolDashboard.tsx",
  "components/NewScanForm.tsx", "components/AgentConfig.tsx", "components/ScanHistory.tsx",
  "features/threatAnalysis/index.ts",
]);
const implementationRoots = [
  "api/", "types/", "scanRuntime/", "hooks/scanSSE/",
  ...["scanDetail", "issues", "modelPool", "newScan", "agentConfig", "scanHistory", "threatAnalysis"].map((feature) => `features/${feature}/`),
];

test("domain implementations import owners instead of compatibility entry points", () => {
  const violations = [];
  for (const file of files) {
    const name = relative(file);
    if (compatibilityEntries.has(name) || !implementationRoots.some((root) => name.startsWith(root))) continue;
    for (const specifier of moduleSpecifiers(parse(file, sources.get(file)))) {
      const target = resolve(file, specifier);
      if (target && compatibilityEntries.has(relative(target))) violations.push(`${name} -> ${relative(target)}`);
    }
  }
  assert.deepEqual(violations, [], `Reverse compatibility imports:\n${violations.join("\n")}`);
});

const pureModels = files.filter((file) => {
  const name = relative(file);
  return name.startsWith("scanRuntime/") || name.startsWith("features/scanDetail/model/")
    || ["features/issues/model.ts", "features/issues/reportModel.ts", "features/modelPool/presentation.ts",
      "features/newScan/draftModel.ts", "features/newScan/codeGraphDefaults.ts",
      "features/agentConfig/configModel.ts", "features/scanHistory/historyModel.ts",
      "features/threatAnalysis/analysisModel.ts"].includes(name);
});

test("pure models stay independent of React, Axios, and browser state", () => {
  const reachable = new Set();
  const visit = (file) => {
    if (reachable.has(file)) return;
    reachable.add(file);
    graph.get(file).forEach(visit);
  };
  pureModels.forEach(visit);
  const program = ts.createProgram(files, {
    target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.ESNext, moduleResolution: ts.ModuleResolutionKind.Bundler,
    jsx: ts.JsxEmit.ReactJSX, skipLibCheck: true, noEmit: true,
  });
  const checker = program.getTypeChecker();
  const browserNames = new Set(["window", "document", "navigator", "localStorage", "sessionStorage", "fetch",
    "EventSource", "WebSocket", "XMLHttpRequest", "location", "history", "alert", "confirm"]);
  const violations = new Set();
  for (const file of reachable) {
    for (const specifier of runtimeImports.get(file)) {
      if (/^(react(?:-dom)?(?:\/|$)|axios(?:\/|$))/.test(specifier)) violations.add(`${relative(file)} imports ${specifier}`);
    }
    const source = program.getSourceFile(file);
    const inspect = (node) => {
      if (ts.isTypeNode(node) || ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) return;
      if (ts.isIdentifier(node) && browserNames.has(node.text)) {
        const member = ts.isPropertyAccessExpression(node.parent) && node.parent.name === node;
        const globalMember = member && ts.isIdentifier(node.parent.expression) && node.parent.expression.text === "globalThis";
        if (!member || globalMember) {
          const symbol = checker.getSymbolAtLocation(node);
          // A local parameter named "window" represents data, not browser state.
          const locallyDeclared = symbol?.declarations?.some((declaration) => declaration.getSourceFile().fileName === file);
          if (!locallyDeclared || globalMember) violations.add(`${relative(file)} reads browser global ${node.text}`);
        }
      }
      ts.forEachChild(node, inspect);
    };
    inspect(source);
  }
  assert.deepEqual([...violations], [], `Impure model dependencies:\n${[...violations].join("\n")}`);
});
