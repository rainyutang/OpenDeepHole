import type { NativeThreatAttackTree, NativeThreatModulePatternBaseline, NativeThreatTreeNode } from "../../types/threatAnalysis";

import { BaselineAuditLabel } from "./BaselineAuditLabel";
import {
  LeafPatternGroup,
  getRootNodes,
  buildNodeIndex,
  buildInboundIndex,
  treeNodeClass,
  nodeDisplayName,
  collectLeafPatternGroups,
  recordItems,
} from './analysisModel';

export function AttackTrees({ trees, unassignedBaselines }: {
  trees: NativeThreatAttackTree[];
  unassignedBaselines: NativeThreatModulePatternBaseline[];
}) {
  if (trees.length === 0 && unassignedBaselines.length === 0) {
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
      <ModuleBaselinePanel groups={unassignedBaselines} title="未关联攻击路径的高风险模块" />
    </div>
  );
}

export function AttackTreeView({
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
      <ModuleBaselinePanel groups={recordItems<NativeThreatModulePatternBaseline>(tree.module_pattern_baselines)} />
    </article>
  );
}

export function AttackTreeNode({
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

export function LeafPatternPanel({ groups }: { groups: LeafPatternGroup[] }) {
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

export function ModuleBaselinePanel({ groups, title = "高风险模块固定审计模式" }: {
  groups: NativeThreatModulePatternBaseline[];
  title?: string;
}) {
  if (!groups.length) return null;
  return <section className="threat-analysis-viewer__leaf-patterns" aria-label={title}>
    <h4>{title}<BaselineAuditLabel /></h4>
    <div className="threat-analysis-viewer__leaf-pattern-list">
      {groups.map((group, index) => <section
        key={`${group.module_name}-${group.node_id ?? "unassigned"}-${index}`}

        className="threat-analysis-viewer__leaf-pattern-row">
        <h5>{group.module_name}</h5>
        <ul>{recordItems<NativeThreatModulePatternBaseline["attack_patterns"][number]>(group.attack_patterns)
          .map((pattern) => <li key={pattern.pattern_id || pattern.pattern_name}>{pattern.pattern_name}</li>)}</ul>
      </section>)}
    </div>
  </section>;
}

export function ViewerEmptyBlock({ text }: { text: string }) {
  return (
    <div className="threat-analysis-viewer__empty-block">
      <div>{text}</div>
    </div>
  );
}
