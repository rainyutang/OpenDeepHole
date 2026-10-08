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
  mapped_paths: string[];
}
export interface CoverageTarget {
  id: string;
  module_name: string;
  pattern_id: string;
  pattern_name: string;
  paths: string[];
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
  directModules: Set<string>;
  moduleIds: Set<string>;
  targetIds: Set<string>;
  files: number;
  highRisk: number;
  riskOnly: number;
  covered: number;
}

function node(path: string, kind: CoverageNode["kind"]): CoverageNode {
  return {
    path, name: path === "." ? "扫描范围" : path.split("/").pop() ?? path,
    kind, children: [], directModules: new Set(), moduleIds: new Set(), targetIds: new Set(),
    files: 0, highRisk: 0, riskOnly: 0, covered: 0,
  };
}
function union(target: Set<string>, source: Set<string>) { source.forEach((id) => target.add(id)); }
function sumChildren(parent: CoverageNode) {
  parent.children.forEach((child) => {
    for (const key of ["files", "highRisk", "riskOnly", "covered"] as const) parent[key] += child[key];
    union(parent.moduleIds, child.moduleIds);
    union(parent.targetIds, child.targetIds);
  });
}

/** Expand directory scopes once per file, then aggregate up the original tree. */
export function buildCoverageTree(data: ThreatCoverage) {
  const root = node(".", "directory");
  const byPath = new Map<string, CoverageNode>([[".", root]]);
  for (const entry of data.inventory?.entries ?? []) {
    if (entry.path !== ".") byPath.set(entry.path, node(entry.path, entry.kind));
  }
  for (const item of byPath.values()) {
    if (item === root) continue;
    const slash = item.path.lastIndexOf("/");
    byPath.get(slash < 0 ? "." : item.path.slice(0, slash))?.children.push(item);
  }
  data.modules.forEach((module) => module.mapped_paths.forEach((path) => {
    byPath.get(path)?.directModules.add(module.id);
    byPath.get(path)?.moduleIds.add(module.id);
  }));
  data.targets.forEach((target) => target.mapped_paths.forEach((path) => byPath.get(path)?.targetIds.add(target.id)));
  function visit(item: CoverageNode, inheritedModules: Set<string>, inheritedTargets: Set<string>) {
    union(item.moduleIds, inheritedModules);
    union(item.targetIds, inheritedTargets);
    if (item.kind === "file") {
      item.files = 1;
      item.highRisk = Number(item.moduleIds.size > 0);
      item.covered = Number(item.targetIds.size > 0);
      item.riskOnly = Number(item.highRisk > 0 && item.covered === 0);
    } else {
      // Aggregate descendants only after inheritance; otherwise a preceding
      // sibling's annotations would leak into later siblings.
      item.children.forEach((child) => visit(child, item.moduleIds, item.targetIds));
      sumChildren(item);
      item.children.sort((a, b) => b.files - a.files || a.path.localeCompare(b.path));
    }
  }
  visit(root, new Set(), new Set());
  return { root, byPath };
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
