import { useMemo, useState } from "react";
import type { KeyboardEvent } from "react";
import type {
  NativeThreatAttackPath,
  NativeThreatAttackTree,
  NativeThreatHighRiskModule,
  NativeThreatTreeNode,
  NativeThreatValueAsset,
  ScanEvent,
  ThreatAnalysis,
} from "../../types";
import "./ThreatAnalysisPanel.css";

interface ThreatAnalysisPanelProps {
  analysis: ThreatAnalysis | null;
  events: ScanEvent[];
  loading: boolean;
  isDone: boolean;
  methodLabel: string;
  errorMessage?: string;
}

type Tab = "valueAssets" | "highRiskModules" | "internalNodes" | "attackTrees";

interface TreeNodeLike {
  node_id?: string | null;
  node_type?: string | null;
  node_name?: string | null;
  module_name?: string | null;
  description?: string | null;
}

interface LeafPatternGroup {
  key: string;
  title: string;
  patternTitles: string[];
}

interface MutableLeafPatternGroup extends LeafPatternGroup {
  seenPatternTitles: Set<string>;
}

const HIGH_RISK_FIELDS = {
  management: "是否涉及设备或系统对外提供管理和控制接口相关的代码",
  untrusted: "是否涉及对不可信来源数据进行解析或处理的代码",
  security:
    "是否涉及安全相关类代码(如，认证、授权、接入控制、加解密、密钥管理、日志审计、软件完整性保护等模块)",
  sensitive: "是否涉及个人数据或者敏感数据的代码",
  web: "是否涉及web相关处理",
  external: "是否外部暴露面",
} as const;

const RESULT_TABS: Array<{ key: Tab; label: string }> = [
  { key: "valueAssets", label: "价值资产" },
  { key: "highRiskModules", label: "高风险模块" },
  { key: "internalNodes", label: "内部节点" },
  { key: "attackTrees", label: "攻击树" },
];

export function ThreatAnalysisPanel({
  analysis,
  events,
  loading,
  isDone,
  methodLabel,
  errorMessage = "",
}: ThreatAnalysisPanelProps) {
  const [tab, setTab] = useState<Tab>("valueAssets");
  const assets = artifactArray<NativeThreatValueAsset>(
    analysis,
    "value_asset_path",
  );
  const modules = artifactArray<NativeThreatHighRiskModule>(
    analysis,
    "high_risk_modules_path",
  );
  const trees = attackTreesFromAnalysis(analysis);
  const internalNodes = useMemo(() => collectInternalNodes(trees), [trees]);

  if (!analysis) {
    return (
      <div className="space-y-4">
        {errorMessage && (
          <ThreatAnalysisError methodLabel={methodLabel} message={errorMessage} />
        )}
        <EmptyState
          text={
            loading
              ? "威胁分析运行中，完成后会展示原生产物。"
              : isDone
                ? "当前扫描未生成威胁分析产物。"
                : "等待威胁分析结果。"
          }
        />
        <ThreatEventList events={events} />
      </div>
    );
  }

  if (
    !analysis.entrypoint_result
    || analysis.entrypoint_result.result !== true
    || !analysis.artifacts
  ) {
    return (
      <div className="space-y-4">
        {errorMessage && (
          <ThreatAnalysisError methodLabel={methodLabel} message={errorMessage} />
        )}
        <EmptyState text="该扫描使用旧版威胁分析格式，当前版本不再提供兼容展示。" />
        <ThreatEventList events={events} />
      </div>
    );
  }

  const counts: Record<Tab, number> = {
    valueAssets: assets.length,
    highRiskModules: modules.length,
    internalNodes: internalNodes.length,
    attackTrees: trees.length,
  };

  const handleTabKeyDown = (
    event: KeyboardEvent<HTMLButtonElement>,
    current: Tab,
  ) => {
    const currentIndex = RESULT_TABS.findIndex((item) => item.key === current);
    let nextIndex: number | null = null;
    if (event.key === "ArrowRight") nextIndex = (currentIndex + 1) % RESULT_TABS.length;
    if (event.key === "ArrowLeft") nextIndex = (currentIndex - 1 + RESULT_TABS.length) % RESULT_TABS.length;
    if (event.key === "Home") nextIndex = 0;
    if (event.key === "End") nextIndex = RESULT_TABS.length - 1;
    if (nextIndex === null) return;
    event.preventDefault();
    const nextTab = RESULT_TABS[nextIndex].key;
    setTab(nextTab);
    document.getElementById(`threat-analysis-tab-${nextTab}`)?.focus();
  };

  return (
    <div className="space-y-4">
      {errorMessage && (
        <ThreatAnalysisError methodLabel={methodLabel} message={errorMessage} />
      )}
      <section className="threat-analysis-viewer">
        <header className="threat-analysis-viewer__header">
          <h2 className="threat-analysis-viewer__title">威胁分析结果</h2>
          <p className="threat-analysis-viewer__summary">
            方法：{methodLabel} · {assets.length} 个价值资产 / {modules.length} 个高风险模块 /{" "}
            {internalNodes.length} 个内部节点 / {trees.length} 棵攻击树
          </p>
        </header>

        <nav
          className="threat-analysis-viewer__tabs"
          aria-label="威胁分析结果页签"
          role="tablist"
        >
          {RESULT_TABS.map((item) => (
            <button
              key={item.key}
              id={`threat-analysis-tab-${item.key}`}
              type="button"
              role="tab"
              aria-controls={`threat-analysis-panel-${item.key}`}
              aria-selected={tab === item.key}
              tabIndex={tab === item.key ? 0 : -1}
              onKeyDown={(event) => handleTabKeyDown(event, item.key)}
              onClick={() => setTab(item.key)}
              className={`threat-analysis-viewer__tab ${
                tab === item.key ? "is-active" : ""
              }`}
            >
              {item.label}
            </button>
          ))}
        </nav>

        <section
          id={`threat-analysis-panel-${tab}`}
          role="tabpanel"
          aria-labelledby={`threat-analysis-tab-${tab}`}
          className="threat-analysis-viewer__panel"
        >
          <PanelHeading
            title={RESULT_TABS.find((item) => item.key === tab)?.label ?? ""}
            count={counts[tab]}
            unit={tab === "attackTrees" ? "棵" : "项"}
          />
          {tab === "valueAssets" && <ValueAssetsTable assets={assets} />}
          {tab === "highRiskModules" && <HighRiskModulesTable modules={modules} />}
          {tab === "internalNodes" && <InternalNodesTable nodes={internalNodes} />}
          {tab === "attackTrees" && <AttackTrees trees={trees} />}
        </section>
      </section>

      <ArtifactPaths analysis={analysis} />
      <ThreatEventList events={events} />
    </div>
  );
}

function ThreatAnalysisError({
  methodLabel,
  message,
}: {
  methodLabel: string;
  message: string;
}) {
  return (
    <section className="threat-analysis-viewer__error" role="alert">
      <strong>{methodLabel}执行失败</strong>
      <p>{message}</p>
    </section>
  );
}

function artifactContent(
  analysis: ThreatAnalysis | null,
  key: string,
): unknown {
  const artifact = analysis?.artifacts?.[key];
  return isRecord(artifact) ? artifact.content : undefined;
}

function artifactArray<T>(
  analysis: ThreatAnalysis | null,
  key: string,
): T[] {
  const content = artifactContent(analysis, key);
  return recordItems<T>(content);
}

function attackTreesFromAnalysis(
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

function PanelHeading({
  title,
  count,
  unit,
}: {
  title: string;
  count: number;
  unit: "项" | "棵";
}) {
  return (
    <div className="threat-analysis-viewer__panel-heading">
      <h3>{title}</h3>
      <output>{count} {unit}</output>
    </div>
  );
}

function ValueAssetsTable({ assets }: { assets: NativeThreatValueAsset[] }) {
  const headers = ["资产名", "资产类别", "资产描述", "攻击损失", "判断为价值资产的原因"];

  return (
    <div role="region" aria-label="价值资产表格" tabIndex={0} className="threat-analysis-viewer__table-wrap">
      <table className="threat-analysis-viewer__table threat-analysis-viewer__table--assets">
        <thead>
          <tr>
            {headers.map((header) => <th key={header} scope="col">{header}</th>)}
          </tr>
        </thead>
        <tbody>
          {assets.length === 0 ? (
            <EmptyTableRow colSpan={headers.length} text="暂无价值资产" />
          ) : assets.map((asset, index) => (
            <tr key={`${asset["资产名"]}-${index}`}>
              <td>{displayValue(asset["资产名"])}</td>
              <td>{displayValue(asset["资产类别"])}</td>
              <td>{displayValue(asset["资产描述"])}</td>
              <td>{displayValue(asset["攻击损失"])}</td>
              <td>{displayValue(asset["判断为价值资产的原因"])}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function HighRiskModulesTable({
  modules,
}: {
  modules: NativeThreatHighRiskModule[];
}) {
  const headers = [
    "模块名称",
    "代码目录",
    "面临威胁",
    "管理控制",
    "不可信数据",
    "安全相关",
    "敏感数据",
    "Web 处理",
    "外部暴露面",
    "判断原因",
  ];

  return (
    <div role="region" aria-label="高风险模块表格" tabIndex={0} className="threat-analysis-viewer__table-wrap">
      <table className="threat-analysis-viewer__table threat-analysis-viewer__table--modules">
        <thead>
          <tr>
            {headers.map((header) => <th key={header} scope="col">{header}</th>)}
          </tr>
        </thead>
        <tbody>
          {modules.length === 0 ? (
            <EmptyTableRow colSpan={headers.length} text="暂无高风险模块" />
          ) : modules.map((module, index) => (
            <tr key={`${module["模块名称"]}-${index}`}>
              <td>{displayValue(module["模块名称"])}</td>
              <td>{displayValue(module["代码目录"])}</td>
              <td>{displayValue(module["面临威胁"])}</td>
              <td><YesNoBadge value={module[HIGH_RISK_FIELDS.management]} /></td>
              <td><YesNoBadge value={module[HIGH_RISK_FIELDS.untrusted]} /></td>
              <td><YesNoBadge value={module[HIGH_RISK_FIELDS.security]} /></td>
              <td><YesNoBadge value={module[HIGH_RISK_FIELDS.sensitive]} /></td>
              <td><YesNoBadge value={module[HIGH_RISK_FIELDS.web]} /></td>
              <td><YesNoBadge value={module[HIGH_RISK_FIELDS.external]} /></td>
              <td>{displayValue(module["判断为高风险模块的原因"])}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function InternalNodesTable({ nodes }: { nodes: NativeThreatTreeNode[] }) {
  const headers = ["内部节点名称", "描述"];

  return (
    <div role="region" aria-label="内部节点表格" tabIndex={0} className="threat-analysis-viewer__table-wrap">
      <table className="threat-analysis-viewer__table threat-analysis-viewer__table--nodes">
        <thead>
          <tr>
            {headers.map((header) => <th key={header} scope="col">{header}</th>)}
          </tr>
        </thead>
        <tbody>
          {nodes.length === 0 ? (
            <EmptyTableRow colSpan={headers.length} text="暂无内部节点" />
          ) : nodes.map((node, index) => (
            <tr key={`${nodeDisplayName(node)}-${node.description}-${index}`}>
              <td>{displayValue(nodeDisplayName(node))}</td>
              <td>{displayValue(node.description)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function EmptyTableRow({
  colSpan,
  text,
}: {
  colSpan: number;
  text: string;
}) {
  return (
    <tr className="threat-analysis-viewer__empty-row">
      <td colSpan={colSpan}>{text}</td>
    </tr>
  );
}

function YesNoBadge({ value }: { value: unknown }) {
  const text = formatValue(value) || "否";
  return (
    <span
      className={`threat-analysis-viewer__badge ${
        text === "是" ? "is-yes" : "is-no"
      }`}
    >
      {text}
    </span>
  );
}

function collectInternalNodes(
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

function AttackTrees({ trees }: { trees: NativeThreatAttackTree[] }) {
  if (trees.length === 0) {
    return <ViewerEmptyBlock text="暂无攻击树" />;
  }

  return (
    <div className="threat-analysis-viewer__tree-list">
      {trees.map((tree, index) => (
        <AttackTreeView
          key={`${tree.tree_id || "attack-tree"}-${index}`}
          tree={tree}
          index={index}
        />
      ))}
    </div>
  );
}

function AttackTreeView({
  tree,
  index,
}: {
  tree: NativeThreatAttackTree;
  index: number;
}) {
  const nodes = recordItems<NativeThreatTreeNode>(tree.nodes);
  const edges = recordItems<NativeThreatAttackTree["edges"][number]>(tree.edges);
  const roots = getRootNodes(nodes);
  const inbound = buildInboundIndex(edges);
  const nodesById = buildNodeIndex(nodes);
  const leafPatternGroups = collectLeafPatternGroups(tree, nodesById);

  return (
    <article className="threat-analysis-viewer__tree">
      <header className="threat-analysis-viewer__tree-header">
        <strong>
          {tree.value_asset?.asset_name || tree.tree_id || `攻击树 ${index + 1}`}
        </strong>
        <span>{tree.tree_id || `#${index + 1}`}</span>
      </header>

      <div
        role="region"
        aria-label={`${tree.value_asset?.asset_name || tree.tree_id || `攻击树 ${index + 1}`}图`}
        tabIndex={0}
        className="threat-analysis-viewer__tree-body"
      >
        {roots.length === 0 ? (
          <ViewerEmptyBlock text="暂无可展示节点" />
        ) : (
          <ul className="threat-analysis-viewer__tree-diagram">
            {roots.map((root, rootIndex) => (
              <AttackTreeNode
                key={`${root.node_id || "root"}-${rootIndex}`}
                node={root}
                nodesById={nodesById}
                inbound={inbound}
                visited={new Set<string>()}
              />
            ))}
          </ul>
        )}
      </div>

      {leafPatternGroups.length > 0 && (
        <LeafPatternPanel groups={leafPatternGroups} />
      )}
    </article>
  );
}

function AttackTreeNode({
  node,
  nodesById,
  inbound,
  visited,
}: {
  node: NativeThreatTreeNode;
  nodesById: Map<string, NativeThreatTreeNode>;
  inbound: Map<string, string[]>;
  visited: Set<string>;
}) {
  const nodeId = String(node.node_id || "");
  const nextVisited = new Set(visited);
  if (nodeId) {
    nextVisited.add(nodeId);
  }

  const children = (inbound.get(nodeId) || [])
    .filter((id) => !nextVisited.has(id))
    .map((id) => nodesById.get(id))
    .filter((child): child is NativeThreatTreeNode => Boolean(child));

  return (
    <li>
      <div
        className={`threat-analysis-viewer__tree-node ${treeNodeClass(node)}`}
        title={node.description || undefined}
      >
        <span>{nodeDisplayName(node)}</span>
      </div>
      {children.length > 0 && (
        <ul>
          {children.map((child, index) => (
            <AttackTreeNode
              key={`${child.node_id || "node"}-${index}`}
              node={child}
              nodesById={nodesById}
              inbound={inbound}
              visited={nextVisited}
            />
          ))}
        </ul>
      )}
    </li>
  );
}

function getRootNodes(
  nodes: NativeThreatTreeNode[],
): NativeThreatTreeNode[] {
  const roots = nodes.filter((node) => node.node_type === "根节点");
  return roots.length > 0 ? roots : nodes.slice(0, 1);
}

function buildNodeIndex(
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

function buildInboundIndex(
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

function treeNodeClass(node: NativeThreatTreeNode): string {
  if (node.node_type === "根节点") {
    return "is-root";
  }
  if (node.node_type === "叶子节点") {
    return "is-leaf";
  }
  return "is-internal";
}

function nodeDisplayName(node: TreeNodeLike): string {
  return String(node.node_name || node.module_name || node.node_id || "未命名节点");
}

function collectLeafPatternGroups(
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

function ensureLeafPatternGroup(
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

function findPathLeafNode(
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

function leafNodeFromPathMetadata(
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

function addPatternTitle(
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

function patternTitle(pattern: unknown): string {
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

function LeafPatternPanel({ groups }: { groups: LeafPatternGroup[] }) {
  return (
    <section className="threat-analysis-viewer__leaf-patterns">
      <h4>叶子节点匹配攻击模式</h4>
      <div className="threat-analysis-viewer__leaf-pattern-list">
        {groups.map((group) => (
          <section
            key={group.key}
            className="threat-analysis-viewer__leaf-pattern-row"
          >
            <h5>{group.title}</h5>
            <ul>
              {group.patternTitles.length > 0 ? (
                group.patternTitles.map((title) => (
                  <li key={title}>{title}</li>
                ))
              ) : (
                <li className="is-empty">暂无匹配攻击模式</li>
              )}
            </ul>
          </section>
        ))}
      </div>
    </section>
  );
}

function ViewerEmptyBlock({ text }: { text: string }) {
  return (
    <div className="threat-analysis-viewer__empty-block">
      <div>{text}</div>
    </div>
  );
}

function formatValue(value: unknown): string {
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

function displayValue(value: unknown): string {
  return formatValue(value) || "—";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function recordItems<T>(value: unknown): T[] {
  return Array.isArray(value) ? value.filter(isRecord) as T[] : [];
}

function ArtifactPaths({ analysis }: { analysis: ThreatAnalysis }) {
  const artifacts = isRecord(analysis.artifacts) ? analysis.artifacts : {};
  return (
    <details className="rounded-lg border border-slate-800 bg-slate-900/60">
      <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-slate-300">
        原生产物
      </summary>
      <div className="space-y-2 border-t border-slate-800 p-4">
        {Object.entries(artifacts).map(([key, artifact]) => (
          isRecord(artifact) && (
            <div key={key} className="flex flex-wrap gap-2 text-xs">
              <span className="text-slate-500">{key}</span>
              <code className="break-all text-cyan-200">{displayValue(artifact.path)}</code>
            </div>
          )
        ))}
      </div>
    </details>
  );
}

function ThreatEventList({ events }: { events: ScanEvent[] }) {
  if (events.length === 0) return null;
  return (
    <details className="rounded-lg border border-slate-800 bg-slate-900/60">
      <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-slate-300">
        运行日志 · {events.length}
      </summary>
      <div className="max-h-64 divide-y divide-slate-800 overflow-auto border-t border-slate-800 px-4">
        {events.map((event, index) => (
          <div key={`${event.timestamp}-${index}`} className="py-2 text-xs">
            <span className="mr-2 text-slate-600">{event.timestamp}</span>
            <span className="mr-2 text-cyan-300">{event.phase}</span>
            <span className="text-slate-300">{event.message}</span>
          </div>
        ))}
      </div>
    </details>
  );
}

function EmptyState({ text }: { text: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-5 text-sm text-slate-400">
      {text}
    </div>
  );
}
