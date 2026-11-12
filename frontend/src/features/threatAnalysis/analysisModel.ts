import type {
  NativeThreatAttackPath,
  NativeThreatAttackTree,
  NativeThreatHighRiskModule,
  NativeThreatTreeNode,
  NativeThreatValueAsset,
  ThreatAnalysis,
} from "../../types/threatAnalysis";

export type ThreatAnalysisResultTab = "valueAssets" | "highRiskModules" | "internalNodes" | "attackTrees";

export interface TreeNodeLike {
  node_id?: string | null;
  node_type?: string | null;
  node_name?: string | null;
  module_name?: string | null;
  description?: string | null;
}

export interface LeafPatternGroup {
  key: string;
  title: string;
  patternTitles: string[];
}

export interface MutableLeafPatternGroup extends LeafPatternGroup {
  seenPatternTitles: Set<string>;
}

export const HIGH_RISK_FIELDS = {
  management: "是否涉及设备或系统对外提供管理和控制接口相关的代码",
  untrusted: "是否涉及对不可信来源数据进行解析或处理的代码",
  security:
    "是否涉及安全相关类代码(如，认证、授权、接入控制、加解密、密钥管理、日志审计、软件完整性保护等模块)",
  sensitive: "是否涉及个人数据或者敏感数据的代码",
  web: "是否涉及web相关处理",
  external: "是否外部暴露面",
} as const;

export type ThreatAnalysisResultCounts = Record<ThreatAnalysisResultTab, number>;

export const THREAT_ANALYSIS_RESULT_TABS: Array<{
  key: ThreatAnalysisResultTab;
  label: string;
  unit: "项" | "棵";
}> = [
    { key: "valueAssets", label: "价值资产", unit: "项" },
    { key: "highRiskModules", label: "高风险模块", unit: "项" },
    { key: "internalNodes", label: "内部节点", unit: "项" },
    { key: "attackTrees", label: "攻击树", unit: "棵" },
  ];

export function isThreatAnalysisResultReady(analysis: ThreatAnalysis | null | undefined): analysis is ThreatAnalysis {
  if (analysis?.entrypoint_result?.result !== true || !analysis.artifacts) return false;
  const assets = analysis.artifacts.value_asset_path?.content;
  const modules = analysis.artifacts.high_risk_modules_path?.content;
  const attackTrees = analysis.artifacts.attack_tree_path?.content;
  return Array.isArray(assets)
    && Array.isArray(modules)
    && Boolean(
      attackTrees
      && typeof attackTrees === "object"
      && Array.isArray(attackTrees.attack_trees),
    );
}

export function getThreatAnalysisResultCounts(
  analysis: ThreatAnalysis | null | undefined,
): ThreatAnalysisResultCounts {
  const normalized = analysis ?? null;
  const assets = artifactArray<NativeThreatValueAsset>(normalized, "value_asset_path");
  const modules = artifactArray<NativeThreatHighRiskModule>(normalized, "high_risk_modules_path");
  const trees = attackTreesFromAnalysis(normalized);
  return {
    valueAssets: assets.length,
    highRiskModules: modules.length,
    internalNodes: collectInternalNodes(trees).length,
    attackTrees: trees.length,
  };
}

export function artifactContent(
  analysis: ThreatAnalysis | null,
  key: string,
): unknown {
  const artifact = analysis?.artifacts?.[key];
  return isRecord(artifact) ? artifact.content : undefined;
}

export function artifactArray<T>(
  analysis: ThreatAnalysis | null,
  key: string,
): T[] {
  const content = artifactContent(analysis, key);
  return recordItems<T>(content);
}

export function attackTreesFromAnalysis(
  analysis: ThreatAnalysis | null,
): NativeThreatAttackTree[] {
  const content = artifactContent(analysis, "attack_tree_path");
  if (Array.isArray(content)) {
    return recordItems<NativeThreatAttackTree>(content);
  }
  if (!isRecord(content) || !Array.isArray(content.attack_trees)) {
    return [];
  }
  return recordItems<NativeThreatAttackTree>(content.attack_trees);
}

export function collectInternalNodes(
  trees: NativeThreatAttackTree[],
): NativeThreatTreeNode[] {
  const seen = new Set<string>();
  const nodes: NativeThreatTreeNode[] = [];

  trees.forEach((tree) => {
    const treeNodes = recordItems<NativeThreatTreeNode>(tree.nodes);
    treeNodes.forEach((node) => {
      if (node.node_type !== "内部节点") {
        return;
      }
      const name = nodeDisplayName(node);
      const key = `${name}\n${node.description || ""}`;
      if (seen.has(key)) {
        return;
      }
      seen.add(key);
      nodes.push(node);
    });
  });

  return nodes;
}

export function getRootNodes(
  nodes: NativeThreatTreeNode[],
): NativeThreatTreeNode[] {
  const roots = nodes.filter((node) => node.node_type === "根节点");
  return roots.length > 0 ? roots : nodes.slice(0, 1);
}

export function buildNodeIndex(
  nodes: NativeThreatTreeNode[],
): Map<string, NativeThreatTreeNode> {
  const index = new Map<string, NativeThreatTreeNode>();
  nodes.forEach((node) => {
    const nodeId = String(node.node_id || "");
    if (nodeId && !index.has(nodeId)) {
      index.set(nodeId, node);
    }
  });
  return index;
}

export function buildInboundIndex(
  edges: NativeThreatAttackTree["edges"],
): Map<string, string[]> {
  const index = new Map<string, string[]>();
  edges.forEach((edge) => {
    const target = String(edge.target_node_id || "");
    const source = String(edge.source_node_id || "");
    if (!target || !source) {
      return;
    }
    const sources = index.get(target) || [];
    if (!sources.includes(source)) {
      sources.push(source);
    }
    index.set(target, sources);
  });
  return index;
}

export function treeNodeClass(node: NativeThreatTreeNode): string {
  if (node.node_type === "根节点") {
    return "is-root";
  }
  if (node.node_type === "叶子节点") {
    return "is-leaf";
  }
  return "is-internal";
}

export function nodeDisplayName(node: TreeNodeLike): string {
  return String(node.node_name || node.module_name || node.node_id || "未命名节点");
}

export function collectLeafPatternGroups(
  tree: NativeThreatAttackTree,
  nodesById: Map<string, NativeThreatTreeNode>,
): LeafPatternGroup[] {
  const groups = new Map<string, MutableLeafPatternGroup>();
  const nodes = recordItems<NativeThreatTreeNode>(tree.nodes);
  const attackPaths = recordItems<NativeThreatAttackPath>(tree.attack_paths);

  nodes
    .filter((node) => node.node_type === "叶子节点")
    .forEach((node) => ensureLeafPatternGroup(groups, node));

  attackPaths.forEach((path) => {
    const leafNode = findPathLeafNode(path, nodesById)
      || leafNodeFromPathMetadata(path);
    if (!leafNode) {
      return;
    }

    const group = ensureLeafPatternGroup(groups, leafNode);
    const patterns = Array.isArray(path.attack_patterns) ? path.attack_patterns : [];
    patterns.forEach((pattern) => addPatternTitle(group, pattern));
  });

  return Array.from(groups.values()).map((group) => ({
    key: group.key,
    title: group.title,
    patternTitles: group.patternTitles,
  }));
}

export function ensureLeafPatternGroup(
  groups: Map<string, MutableLeafPatternGroup>,
  node: TreeNodeLike,
): MutableLeafPatternGroup {
  const key = String(
    node.node_id || node.module_name || node.node_name || `leaf-${groups.size + 1}`,
  );
  const existing = groups.get(key);
  if (existing) {
    return existing;
  }

  const group: MutableLeafPatternGroup = {
    key,
    title: nodeDisplayName(node),
    patternTitles: [],
    seenPatternTitles: new Set<string>(),
  };
  groups.set(key, group);
  return group;
}

export function findPathLeafNode(
  path: NativeThreatAttackPath,
  nodesById: Map<string, NativeThreatTreeNode>,
): NativeThreatTreeNode | null {
  const nodeIds = Array.isArray(path.node_ids) ? path.node_ids : [];
  for (const nodeId of nodeIds) {
    const node = nodesById.get(String(nodeId));
    if (node?.node_type === "叶子节点") {
      return node;
    }
  }
  if (nodeIds.length === 0) {
    return null;
  }
  return nodesById.get(String(nodeIds[0])) || null;
}

export function leafNodeFromPathMetadata(
  path: NativeThreatAttackPath,
): TreeNodeLike | null {
  const relatedModules = recordItems<NativeThreatAttackPath["related_high_risk_modules"][number]>(
    path.related_high_risk_modules,
  );
  const leafModule = relatedModules.find(
    (module) => module.path_role === "外部攻击入口"
      || module.external_exposure === true,
  );
  if (!leafModule) {
    return null;
  }
  return {
    node_id: leafModule.node_id,
    node_name: leafModule.module_name,
    module_name: leafModule.module_name,
  };
}

export function addPatternTitle(
  group: MutableLeafPatternGroup,
  pattern: unknown,
) {
  const title = patternTitle(pattern);
  const key = title.toLocaleLowerCase();
  if (!title || group.seenPatternTitles.has(key)) {
    return;
  }
  group.seenPatternTitles.add(key);
  group.patternTitles.push(title);
}

export function patternTitle(pattern: unknown): string {
  if (typeof pattern === "string") {
    return pattern.trim();
  }
  if (!isRecord(pattern)) {
    return "";
  }
  const value = pattern.pattern_name
    || pattern["攻击模式名称"]
    || pattern.title
    || pattern.name;
  return typeof value === "string" ? value.trim() : "";
}

export function formatValue(value: unknown): string {
  if (value == null) {
    return "";
  }
  if (Array.isArray(value)) {
    return value.map(formatValue).filter(Boolean).join(", ");
  }
  if (typeof value === "object") {
    return JSON.stringify(value, null, 2);
  }
  return String(value);
}

export function displayValue(value: unknown): string {
  return formatValue(value) || "—";
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function recordItems<T>(value: unknown): T[] {
  return Array.isArray(value) ? value.filter(isRecord) as T[] : [];
}
