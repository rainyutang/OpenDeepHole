export interface CoverageInventory {
  snapshot_id: string;
  status: "collecting" | "complete" | "partial" | "failed" | "cancelled";
  project_path: string;
  scan_root: string;
  captured_at: string;
  entries: Array<{ path: string; kind: "file" | "directory" }>;
  issues: Array<{ path: string; reason: string }>;
  issue_count: number;
  excluded_paths: string[];
  error_message: string;
}
export interface CoverageModule {
  id: string;
  name: string;
  paths: string[];
  scan_relative_paths?: string[];
  mapped_paths: string[];
}
export interface CoverageTarget {
  id: string;
  module_name: string;
  pattern_id: string;
  pattern_name: string;
  paths: string[];
  scan_relative_paths?: string[];
  mapped_paths: string[];
  fallback: boolean;
  sources: Array<{ tree_id: string; path_id: string; path_name: string; description: string }>;
}
export interface ThreatCoverage {
  inventory: CoverageInventory | null;
  analysis_ready: boolean;
  modules: CoverageModule[];
  targets: CoverageTarget[];
  unmapped: Array<{ kind: "module" | "target"; id: string; path: string }>;
}
export interface CoverageNode {
  path: string;
  name: string;
  kind: "file" | "directory";
  children: CoverageNode[];
  directModules: ReadonlySet<string>;
  moduleIds: ReadonlySet<string>;
  targetIds: ReadonlySet<string>;
  files: number;
  highRisk: number;
  riskOnly: number;
  covered: number;
}

/** Source comparison only; path resolution belongs to the shared backend resolver. */
export function moduleSourcePaths(value: unknown): string[] {
  const values = Array.isArray(value) ? value : [value];
  return [...new Set(values.map((item) => {
    let path = String(item || "").trim().replace(/\\/g, "/").replace(/\/+/g, "/");
    while (path.startsWith("./")) path = path.slice(2);
    return path === "/" ? path : path.replace(/\/+$/, "");
  }).filter(Boolean))];
}

export function scanRelativePaths(item: CoverageModule | CoverageTarget): string[] {
  // During a rolling backend upgrade, mapped paths already use the scan root.
  return item.scan_relative_paths ?? item.mapped_paths;
}

const EMPTY_IDS: ReadonlySet<string> = new Set<string>();

function node(path: string, kind: CoverageNode["kind"]): CoverageNode {
  return {
    path, name: path === "." ? "扫描范围" : path.split("/").pop() ?? path,
    kind, children: [], directModules: EMPTY_IDS, moduleIds: EMPTY_IDS, targetIds: EMPTY_IDS,
    files: 0, highRisk: 0, riskOnly: 0, covered: 0,
  };
}

function collectScopes(items: Array<{ id: string; mapped_paths: string[] }>): ReadonlyMap<string, ReadonlySet<string>> {
  const scopes = new Map<string, Set<string>>();
  for (const item of items) {
    for (const path of item.mapped_paths) {
      let scope = scopes.get(path);
      if (!scope) scopes.set(path, scope = new Set());
      scope.add(item.id);
    }
  }
  return scopes;
}

/** Keep insertion order and share the first scope until an addition needs a copy.
 * A directory may contain thousands of children with the exact same scope. */
function mergeScopes(scopes: Iterable<ReadonlySet<string>>): ReadonlySet<string> {
  let result = EMPTY_IDS;
  let combined: Set<string> | undefined;
  const seen = new Set<ReadonlySet<string>>();
  for (const scope of scopes) {
    if (!scope.size || seen.has(scope)) continue;
    seen.add(scope);
    if (!result.size) {
      result = scope;
      continue;
    }
    for (const id of scope) {
      if (result.has(id)) continue;
      if (!combined) result = combined = new Set(result);
      combined.add(id);
    }
  }
  return result;
}

function inheritScope(local: ReadonlySet<string>, inherited: ReadonlySet<string>): ReadonlySet<string> {
  if (!local.size) return inherited;
  if (!inherited.size || local === inherited) return local;
  // Local annotations precede inherited ones, including the tooltip's first ID.
  return mergeScopes([local, inherited]);
}

function* descendantScopes(parent: CoverageNode, key: "moduleIds" | "targetIds") {
  yield parent[key];
  for (const child of parent.children) yield child[key];
}

/** Share directory scopes with descendants, then aggregate up the original tree. */
export function buildCoverageTree(data: ThreatCoverage) {
  const root = node(".", "directory");
  const byPath = new Map<string, CoverageNode>([[".", root]]);
  for (const entry of data.inventory?.entries ?? []) {
    if (entry.path !== ".") byPath.set(entry.path, node(entry.path, entry.kind));
  }
  const moduleScopes = collectScopes(data.modules);
  const targetScopes = collectScopes(data.targets);
  for (const item of byPath.values()) {
    item.directModules = item.moduleIds = moduleScopes.get(item.path) ?? EMPTY_IDS;
    item.targetIds = targetScopes.get(item.path) ?? EMPTY_IDS;
    if (item === root) continue;
    const slash = item.path.lastIndexOf("/");
    byPath.get(slash < 0 ? "." : item.path.slice(0, slash))?.children.push(item);
  }
  function visit(item: CoverageNode, inheritedModules: ReadonlySet<string>, inheritedTargets: ReadonlySet<string>) {
    const modules = item.moduleIds = inheritScope(item.moduleIds, inheritedModules);
    const targets = item.targetIds = inheritScope(item.targetIds, inheritedTargets);
    if (item.kind === "file") {
      item.files = 1;
      item.highRisk = Number(item.moduleIds.size > 0);
      item.covered = Number(item.targetIds.size > 0);
      item.riskOnly = Number(item.highRisk > 0 && item.covered === 0);
    } else {
      // Pass only this directory's scope to children. Aggregating descendants
      // must neither mutate shared scopes nor leak annotations into siblings.
      for (const child of item.children) {
        visit(child, modules, targets);
        item.files += child.files;
        item.highRisk += child.highRisk;
        item.riskOnly += child.riskOnly;
        item.covered += child.covered;
      }
      item.moduleIds = mergeScopes(descendantScopes(item, "moduleIds"));
      item.targetIds = mergeScopes(descendantScopes(item, "targetIds"));
      item.children.sort((a, b) => b.files - a.files || a.path.localeCompare(b.path));
    }
  }
  visit(root, EMPTY_IDS, EMPTY_IDS);
  return { root, byPath };
}

/** One matcher per filter snapshot; shared scopes need only one intersection.
 * Weak keys let replaced coverage trees be collected without retaining a cache. */
export function createCoverageMatcher(selected: ReadonlySet<string> | null): (scope: ReadonlySet<string>) => boolean {
  if (selected === null) return () => true;
  if (!selected.size) return () => false;
  const matches = new WeakMap<ReadonlySet<string>, boolean>();
  return (scope) => {
    const cached = matches.get(scope);
    if (cached !== undefined) return cached;
    const [smaller, larger] = scope.size < selected.size ? [scope, selected] : [selected, scope];
    let matched = false;
    for (const id of smaller) {
      if (larger.has(id)) { matched = true; break; }
    }
    matches.set(scope, matched);
    return matched;
  };
}

export interface CoverageTile { node: CoverageNode; x: number; y: number; width: number; height: number }

/** Balanced binary treemap, weighted by file count (empty dirs get one unit). */
export function layoutTreemap(nodes: CoverageNode[], width: number, height: number): CoverageTile[] {
  const prefix = [0];
  nodes.forEach((item) => prefix.push(prefix[prefix.length - 1] + Math.max(1, item.files)));
  const result: CoverageTile[] = [];
  function split(start: number, end: number, x: number, y: number, w: number, h: number) {
    if (start >= end) return;
    if (end - start === 1) {
      result.push({ node: nodes[start], x, y, width: w, height: h });
      return;
    }
    const total = prefix[end] - prefix[start];
    let middle = start + 1;
    while (middle < end - 1 && prefix[middle] - prefix[start] < total / 2) middle++;
    if (middle > start + 1 && Math.abs(prefix[middle - 1] - prefix[start] - total / 2) < Math.abs(prefix[middle] - prefix[start] - total / 2)) middle--;
    const ratio = (prefix[middle] - prefix[start]) / total;
    if (w >= h) {
      split(start, middle, x, y, w * ratio, h);
      split(middle, end, x + w * ratio, y, w * (1 - ratio), h);
    } else {
      split(start, middle, x, y, w, h * ratio);
      split(middle, end, x, y + h * ratio, w, h * (1 - ratio));
    }
  }
  split(0, nodes.length, 0, 0, width, height);
  return result;
}

export interface CoverageTreeTile extends CoverageTile { nested: boolean }

/** Fit every item into the viewport. Risk module directories remain a single
 * scope until opened; other directories show their descendants without paging.
 * Tiny cells lose labels/padding, never their area or annotations. */
export function layoutCoverageTree(parent: CoverageNode, width: number, height: number): CoverageTreeTile[] {
  const result: CoverageTreeTile[] = [];
  if (width <= 0 || height <= 0) return result;
  function visit(item: CoverageNode, x: number, y: number, w: number, h: number) {
    for (const tile of layoutTreemap(item.children, w, h)) {
      const nested = tile.node.children.length > 0 && tile.node.directModules.size === 0;
      const placed = { ...tile, x: x + tile.x, y: y + tile.y, nested };
      result.push(placed);
      if (nested) {
        const inset = Math.min(tile.width, tile.height) >= 16 ? 1 : 0;
        const header = tile.width >= 64 && tile.height >= 40 ? 16 : 0;
        visit(tile.node, placed.x + inset, placed.y + header + inset,
          tile.width - 2 * inset, tile.height - header - 2 * inset);
      }
    }
  }
  visit(parent, 0, 0, width, height);
  return result;
}

export function hitCoverageTile(tiles: CoverageTreeTile[], x: number, y: number): CoverageTreeTile | undefined {
  // Descendants are painted after their parents, so pick the deepest scope.
  for (let index = tiles.length - 1; index >= 0; index--) {
    const tile = tiles[index];
    if (x >= tile.x && y >= tile.y && x < tile.x + tile.width && y < tile.y + tile.height) return tile;
  }
}

export function coveragePercent(count: number, total: number): string {
  return total ? `${(count / total * 100).toFixed(1)}%` : "—";
}

export function coverageBackground(item: CoverageNode): string {
  if (!item.files) return "var(--coverage-neutral)";
  const covered = item.covered / item.files * 100;
  const risk = covered + item.riskOnly / item.files * 100;
  return `linear-gradient(90deg, var(--coverage-covered) 0% ${covered}%, var(--coverage-risk) ${covered}% ${risk}%, var(--coverage-neutral) ${risk}% 100%)`;
}
