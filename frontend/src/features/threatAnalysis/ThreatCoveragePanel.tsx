import { useMemo, useState } from "react";
import type { CoverageNode, CoverageTarget, ThreatCoverage } from "./coverage";
import { buildCoverageTree, coverageBackground, coveragePercent, layoutTreemap, visibleChildren } from "./coverage";
import { useThreatCoverage } from "./useThreatCoverage";
import "./ThreatCoveragePanel.css";

const ISSUE_LABELS: Record<string, string> = {
  symlink: "未跟随符号链接", unreadable: "无法读取", special_file: "特殊文件",
  entry_limit: "达到清单数量上限", time_limit: "达到遍历时限",
  path_limit: "路径长度超过清单限制",
};

function resolveNode(byPath: Map<string, CoverageNode>, path: string): CoverageNode | undefined {
  const parts = path.split("/\0remaining");
  let result = byPath.get(parts[0]);
  for (let index = 1; result && index < parts.length; index++) {
    result = visibleChildren(result).find((item) => item.kind === "group");
  }
  return result;
}

function TreemapTiles({ parent, width, height, depth = 0, selected, highlighted, targets, onSelect, onOpen }: {
  parent: CoverageNode; width: number; height: number; depth?: number; selected: string;
  highlighted: Set<string> | null; targets: Map<string, CoverageTarget>;
  onSelect: (path: string) => void; onOpen: (path: string) => void;
}) {
  const tiles = layoutTreemap(visibleChildren(parent), width, height);
  return <>{tiles.map(({ node, x, y, width: w, height: h }) => {
    const nested = node.children.length > 0 && node.kind !== "group" && depth < 2
      && node.directModules.size === 0 && w > 180 && h > 110;
    const matches = !highlighted || [...node.targetIds].some((id) => highlighted.has(id));
    const firstPattern = targets.get([...node.targetIds][0])?.pattern_name;
    return <div key={node.path} className={`coverage-tile ${selected === node.path ? "is-selected" : ""} ${matches ? "" : "is-dimmed"}`}
      style={{ left: `${x / width * 100}%`, top: `${y / height * 100}%`, width: `${w / width * 100}%`, height: `${h / height * 100}%` }}>
      <button type="button" className="coverage-tile__surface" style={{ background: coverageBackground(node) }}
        aria-label={`${node.name}，${node.files} 个文件，${node.highRisk} 个高风险文件，${node.covered} 个文件关联攻击模式`}
        aria-pressed={selected === node.path}
        title={`${node.kind === "group" ? node.name : node.path}\n${node.files} 个文件 · ${node.highRisk} 个高风险文件 · ${node.covered} 个文件关联攻击模式${firstPattern ? `\n${firstPattern}` : ""}\n单击查看关联，双击目录下钻`}
        onClick={() => onSelect(node.path)} onDoubleClick={() => { if (node.kind !== "file") onOpen(node.path); }}>
        <span className="coverage-tile__name">{node.kind === "file" ? "·" : "▱"} {node.name}</span>
        {!nested && w > 90 && h > 62 && <span className="coverage-tile__body">
          <strong>{node.files.toLocaleString()} <small>个文件</small></strong>
          {node.directModules.size > 0 && <span>高风险模块范围</span>}
          {firstPattern && h > 115 && <span className="coverage-tile__pattern">{firstPattern}{node.targetIds.size > 1 ? ` +${node.targetIds.size - 1}` : ""}</span>}
        </span>}
      </button>
      {nested && <div className="coverage-tile__children"><TreemapTiles parent={node} width={Math.max(1, w - 8)} height={Math.max(1, h - 30)}
        depth={depth + 1} selected={selected} highlighted={highlighted} targets={targets} onSelect={onSelect} onOpen={onOpen} /></div>}
    </div>;
  })}</>;
}

function SelectionDetails({ node, data, onOpen }: { node: CoverageNode; data: ThreatCoverage; onOpen: (path: string) => void }) {
  const [page, setPage] = useState(0);
  const targets = data.targets.filter((target) => node.targetIds.has(target.id));
  const modules = data.modules.filter((module) => node.moduleIds.has(module.id));
  const pages = Math.max(1, Math.ceil(targets.length / 8));
  const currentPage = Math.min(page, pages - 1);
  return <aside className="coverage-detail" aria-label="路径覆盖详情">
    <span className="coverage-eyebrow">{node.kind === "file" ? "文件" : node.kind === "group" ? "聚合路径" : "目录"}</span>
    <h3>{node.kind === "group" ? node.name : node.path}</h3>
    <p>{node.files.toLocaleString()} 个文件 · {node.highRisk.toLocaleString()} 个高风险文件</p>
    {node.kind !== "file" && <button type="button" className="coverage-button" onClick={() => onOpen(node.path)}>进入此目录</button>}
    <h4>高风险模块 <span>{modules.length}</span></h4>
    {modules.length ? <div className="coverage-module-list">{modules.map((module) => <div key={module.id} title={module.paths.join("\n")}>{module.name}</div>)}</div>
      : <p className="coverage-muted">{data.analysis_ready ? "此范围未标注高风险模块。" : "等待威胁分析结果。"}</p>}
    <h4>攻击模式关联 <span>{targets.length}</span></h4>
    {targets.slice(currentPage * 8, currentPage * 8 + 8).map((target) => <details className="coverage-pattern" key={target.id}>
      <summary><span>{target.pattern_id || "未编号"}</span><strong>{target.pattern_name}</strong><small>{target.module_name}</small></summary>
      {target.fallback && <p className="coverage-warning">产物缺少模块路径，按现有目标构建规则回退到扫描根目录。</p>}
      <p className="coverage-paths">{target.paths.join("\n")}</p>
      {target.sources.map((source, index) => <div key={index} className="coverage-source">
        <strong>{source.path_name || source.path_id || "攻击路径"}</strong>
        <small>{[source.tree_id, source.path_id].filter(Boolean).join(" / ")}</small>
        <p>{source.description || "产物未提供关联说明。"}</p>
      </div>)}
    </details>)}
    {!targets.length && <p className="coverage-muted">{data.analysis_ready ? "此范围尚未关联攻击模式。" : "分析完成后显示对应模式。"}</p>}
    {pages > 1 && <div className="coverage-pagination"><button type="button" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>上一页</button>
      <span>{currentPage + 1} / {pages}</span><button type="button" disabled={currentPage + 1 === pages} onClick={() => setPage(currentPage + 1)}>下一页</button></div>}
  </aside>;
}

export function ThreatCoveragePanel({ scanId, revision, analysisStatus = "" }: { scanId: string; revision: number; analysisStatus?: string }) {
  const { data, loading, error, refresh } = useThreatCoverage(scanId, revision);
  const [history, setHistory] = useState<string[]>(["."]);
  const [selected, setSelected] = useState(".");
  const [query, setQuery] = useState("");
  const [pattern, setPattern] = useState("");
  const tree = useMemo(() => data ? buildCoverageTree(data) : null, [data]);
  const targetMap = useMemo(() => new Map(data?.targets.map((target) => [target.id, target]) ?? []), [data]);
  const patterns = useMemo(() => [...new Map(data?.targets.map((target) => [target.pattern_id || target.pattern_name,
    `${target.pattern_id} ${target.pattern_name}`.trim()]) ?? []).entries()].sort((a, b) => a[1].localeCompare(b[1])), [data]);
  const highlighted = useMemo(() => pattern ? new Set(data?.targets.filter((target) => (target.pattern_id || target.pattern_name) === pattern).map((target) => target.id)) : null, [data, pattern]);
  const searchResults = useMemo(() => {
    const text = query.trim().toLowerCase();
    if (!text || !tree || !data) return [];
    const moduleIds = new Set(data.modules.filter((module) => module.name.toLowerCase().includes(text)).map((module) => module.id));
    const matches = [];
    for (const item of tree.byPath.values()) {
      if (item.path !== "." && (item.path.toLowerCase().includes(text) || [...item.moduleIds].some((id) => moduleIds.has(id)))) matches.push(item);
      if (matches.length === 100) break;
    }
    return matches;
  }, [query, tree, data]);
  const inventory = data?.inventory;
  const hasTree = Boolean(inventory?.entries.length && tree);
  const root = tree?.root;
  const view = tree ? resolveNode(tree.byPath, history[history.length - 1]) ?? tree.root : null;
  const detail = tree ? resolveNode(tree.byPath, selected) ?? tree.root : null;
  const percent = (count: number) => data?.analysis_ready && inventory?.status === "complete" ? coveragePercent(count, root?.files ?? 0) : "—";
  const open = (path: string) => {
    if (path !== history[history.length - 1]) setHistory([...history, path]);
    setSelected(path);
  };
  const locate = (item: CoverageNode) => {
    const parent = item.kind === "directory" ? item.path : item.path.includes("/") ? item.path.slice(0, item.path.lastIndexOf("/")) : ".";
    const steps = parent === "." ? [] : parent.split("/").map((_part, index, parts) => parts.slice(0, index + 1).join("/"));
    setHistory([".", ...steps]); setSelected(item.path); setQuery("");
  };

  return <section className="threat-coverage" aria-label="威胁分析覆盖图">
    <header className="coverage-header"><div><span className="coverage-eyebrow">扫描范围 / 覆盖统计</span><h2>威胁分析覆盖图</h2>
      <p>面积按文件数量计算，标注来自高风险模块与攻击树产物。</p></div>
      <button type="button" className="coverage-button" onClick={refresh} disabled={loading}>{loading ? "加载中…" : "刷新"}</button></header>
    {error && <p role="alert" className="coverage-warning">{error}</p>}
    {!hasTree && <div className="coverage-empty" role="status">
      {inventory?.status === "failed" ? `文件清单采集失败：${inventory.error_message}`
        : inventory?.status === "cancelled" ? "文件清单采集已取消，续扫时可重新采集。"
        : inventory?.status === "collecting" ? "正在遍历扫描目录，文件清单上报后将先显示底图。"
        : loading ? "正在加载文件清单…"
        : analysisStatus === "running" ? "等待独立文件清单上报，威胁分析正在运行。"
        : "当前扫描尚无独立文件清单。新扫描或续扫采集后即可显示覆盖图。"}
    </div>}
    {hasTree && root && view && detail && data && inventory && <>
      <div className="coverage-scope"><code>{inventory.scan_root}</code><span>采集于 {new Date(inventory.captured_at).toLocaleString()}</span></div>
      {!data.analysis_ready && <p className="coverage-notice" role="status">{analysisStatus === "error" || analysisStatus === "cancelled"
        ? "威胁分析尚无可用结果，已保留文件树底图。" : "文件清单已就绪，等待威胁分析结果；完成后自动更新标注。"}</p>}
      {inventory.status !== "complete" && <p className="coverage-warning" role="status">文件清单不完整：仅展示已采集范围，暂不计算全量覆盖率。{inventory.issue_count > 0 ? ` ${inventory.issue_count} 处路径未完整采集。` : ""}</p>}
      <div className="coverage-stats">
        <div><span>扫描文件</span><strong>{root.files.toLocaleString()}</strong><small>{inventory.status === "complete" ? "完整文件清单" : "已采集文件"}</small></div>
        <div><span>高风险范围</span><strong>{data.analysis_ready ? root.highRisk.toLocaleString() : "—"}<em>{percent(root.highRisk)}</em></strong><small>高风险模块涉及的去重文件</small></div>
        <div><span>攻击模式关联</span><strong>{data.analysis_ready ? root.covered.toLocaleString() : "—"}<em>{percent(root.covered)}</em></strong><small>关联攻击模式的去重文件</small></div>
        <div><span>模块 / 攻击模式</span><strong>{data.analysis_ready ? `${data.modules.length} / ${patterns.length}` : "—"}</strong><small>{data.analysis_ready ? `${data.targets.length} 个模块 × 模式关联` : "等待分析产物"}</small></div>
      </div>
      <div className="coverage-toolbar">
        <label><span>搜索路径或模块</span><input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="例如 src/auth 或认证模块" /></label>
        <label><span>高亮攻击模式</span><select value={pattern} onChange={(event) => setPattern(event.target.value)}><option value="">全部攻击模式</option>{patterns.map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label>
      </div>
      {query.trim() && <div className="coverage-search-results" aria-label="路径搜索结果">
        {searchResults.map((item) => <button type="button" key={item.path} onClick={() => locate(item)}><code>{item.path}</code><span>{item.files} 个文件</span></button>)}
        <p>{searchResults.length ? `显示 ${searchResults.length} 项${searchResults.length === 100 ? "，可缩小搜索范围查看其它路径" : ""}` : "没有匹配的路径或模块。"}</p>
      </div>}
      <div className="coverage-legend"><span><i className="is-neutral" />{data.analysis_ready ? "未标注" : "尚未标注"}</span><span><i className="is-risk" />高风险未关联模式</span><span><i className="is-covered" />已关联攻击模式</span><small>筛选高亮不改变全扫描统计</small></div>
      <nav className="coverage-breadcrumb" aria-label="覆盖图目录">
        {history.map((path, index) => <button type="button" key={`${index}:${path}`} onClick={() => { setHistory(history.slice(0, index + 1)); setSelected(path); }}
          aria-current={index === history.length - 1 ? "location" : undefined}>{index ? "› " : ""}{resolveNode(tree!.byPath, path)?.name ?? "扫描范围"}</button>)}
      </nav>
      <div className="coverage-workspace"><div><div className="coverage-canvas" aria-label="文件树矩形图">
        {view.children.length ? <TreemapTiles parent={view} width={1000} height={480} selected={selected} highlighted={highlighted} targets={targetMap} onSelect={setSelected} onOpen={open} />
          : <div className="coverage-empty">此目录没有已采集文件。</div>}
      </div><p className="coverage-caption">单击查看关联，双击目录下钻。目录块按后代文件数分配面积，空目录保留最小方块。</p></div>
        <SelectionDetails key={detail.path} node={detail} data={data} onOpen={open} /></div>
      {(data.unmapped.length > 0 || inventory.issues.length > 0 || inventory.excluded_paths.length > 0) && <details className="coverage-diagnostics"><summary>范围说明与未映射路径（{data.unmapped.length + inventory.issue_count + inventory.excluded_paths.length}）</summary>
        {inventory.excluded_paths.map((path) => <p key={`excluded:${path}`}><code>{path}</code>：排除本次扫描工作目录</p>)}
        {inventory.issues.map((issue, index) => <p key={`issue:${index}`}><code>{issue.path}</code>：{ISSUE_LABELS[issue.reason] ?? issue.reason}</p>)}
        {inventory.issue_count > inventory.issues.length && <p>其余 {inventory.issue_count - inventory.issues.length} 项未逐项列出。</p>}
        {data.unmapped.map((item, index) => <p key={`unmapped:${index}`}><code>{item.path}</code>：{item.kind === "module" ? data.modules.find((module) => module.id === item.id)?.name : targetMap.get(item.id)?.module_name}，未匹配扫描清单</p>)}
      </details>}
      <p className="coverage-caption">覆盖表示威胁分析产物描述的目标范围，不表示模型逐行检查、审计已完成或不存在漏洞。</p>
    </>}
  </section>;
}
