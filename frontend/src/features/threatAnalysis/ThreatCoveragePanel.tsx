import { useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { CoverageIssues, CoverageNode, ThreatCoverage } from "./coverage";
import { buildCoverageIssueOverlay, coverageIssueRows, coveragePercent, createCoverageMatcher, scanRelativePaths } from "./coverage";
import { CoverageTreemap } from "./CoverageTreemap";
import { useCoverageIssues, useThreatCoverage } from "./useThreatCoverage";
import "./ThreatCoveragePanel.css";

const ISSUE_LABELS: Record<string, string> = {
  symlink: "未跟随符号链接", unreadable: "无法读取", special_file: "特殊文件",
  entry_limit: "达到清单数量上限", time_limit: "达到遍历时限",
  path_limit: "路径长度超过清单限制",
};

function SelectionDetails({ node, data, issues, issuesLoading, issuesError, onOpen, onOpenIssue }: {
  node: CoverageNode; data: ThreatCoverage; issues: CoverageIssues | null; issuesLoading?: boolean; issuesError?: string;
  onOpen: (path: string) => void; onOpenIssue?: (index: number) => void;
}) {
  const [page, setPage] = useState(0);
  const [issuePage, setIssuePage] = useState(0);
  const issueRows = useMemo(() => coverageIssueRows(issues, node), [issues, node]);
  const issuePages = Math.max(1, Math.ceil(issueRows.length / 8));
  const currentIssuePage = Math.min(issuePage, issuePages - 1);
  const targets = data.targets.filter((target) => node.targetIds.has(target.id));
  const modules = data.modules.filter((module) => node.moduleIds.has(module.id));
  const pages = Math.max(1, Math.ceil(targets.length / 8));
  const currentPage = Math.min(page, pages - 1);
  return <aside className="coverage-detail" aria-label="路径覆盖详情">
    <span className="coverage-eyebrow">{node.kind === "file" ? "文件" : "目录"}</span>
    <h3>{node.path}</h3>
    <p>{node.files.toLocaleString()} 个文件 · {node.highRisk.toLocaleString()} 个高风险文件</p>
    {node.kind !== "file" && <button type="button" className="coverage-button" onClick={() => onOpen(node.path)}>进入此目录</button>}
    <h4>确认问题 <span>{issues ? issueRows.length : "—"}</span></h4>
    {!issues && !issuesError && <p className="coverage-muted">{issuesLoading ? "正在加载确认问题…" : "等待确认问题数据。"}</p>}
    {issues && !issueRows.length && <p className="coverage-muted">此范围暂无去误报复核确认的问题。</p>}
    {issueRows.slice(currentIssuePage * 8, currentIssuePage * 8 + 8).map(({ path, issue }) => <button
      type="button" className="coverage-issue" key={issue.vuln_index} disabled={!onOpenIssue}
      onClick={() => onOpenIssue?.(issue.vuln_index)} aria-label={`查看问题 #${issue.vuln_index}`}>
      <strong>#{issue.vuln_index} · {issue.vuln_type}</strong><code>{path}:{issue.line}</code>
    </button>)}
    {issuePages > 1 && <div className="coverage-pagination" aria-label="确认问题分页">
      <button type="button" disabled={currentIssuePage === 0} onClick={() => setIssuePage(currentIssuePage - 1)}>上一页</button>
      <span>{currentIssuePage + 1} / {issuePages}</span>
      <button type="button" disabled={currentIssuePage + 1 === issuePages} onClick={() => setIssuePage(currentIssuePage + 1)}>下一页</button>
    </div>}
    <h4>高风险模块 <span>{modules.length}</span></h4>
    {modules.length ? <div className="coverage-module-list">{modules.map((module) => <div key={module.id} title={scanRelativePaths(module).join("\n")}>{module.name}</div>)}</div>
      : <p className="coverage-muted">{data.analysis_ready ? "此范围未标注高风险模块。" : "等待威胁分析结果。"}</p>}
    <h4>攻击模式关联 <span>{targets.length}</span></h4>
    {targets.slice(currentPage * 8, currentPage * 8 + 8).map((target) => <details className="coverage-pattern" key={target.id}>
      <summary><span>{target.pattern_id || "未编号"}</span><strong>{target.pattern_name}</strong><small>{target.module_name}</small></summary>
      {target.fallback && <p className="coverage-warning">产物缺少模块路径，按现有目标构建规则回退到扫描根目录。</p>}
      <p className="coverage-paths">{scanRelativePaths(target).join("\n") || "路径无法映射"}</p>
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

export function ThreatCoveragePanel({ scanId, revision, analysisStatus = "", onOpenIssue }: {
  scanId: string; revision: number; analysisStatus?: string; onOpenIssue?: (index: number) => void;
}) {
  const state = useThreatCoverage(scanId, revision);
  const issuesState = useCoverageIssues(scanId, String(revision), state.data?.inventory?.snapshot_id, true);
  return <ThreatCoverageView {...state} issuesState={issuesState} analysisStatus={analysisStatus} onOpenIssue={onOpenIssue} />;
}

/** The scan owns cached data; the bottom-of-page view activates it near the viewport. */
export function CoverageViewport({ onVisible, children }: { onVisible: () => void; children: ReactNode }) {
  const host = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(typeof IntersectionObserver === "undefined");
  useEffect(() => {
    if (visible) { onVisible(); return; }
    if (!host.current) return;
    const observer = new IntersectionObserver((entries) => {
      if (entries.some((entry) => entry.isIntersecting)) { setVisible(true); observer.disconnect(); }
    }, { rootMargin: "400px" });
    observer.observe(host.current);
    return () => observer.disconnect();
  }, [visible, onVisible]);
  return <div ref={host} className="coverage-viewport">{visible ? children
    : <section className="threat-coverage"><h2>威胁分析覆盖图</h2><p className="coverage-caption">滚动至此加载覆盖数据。</p></section>}</div>;
}

export function ThreatCoverageView({ data, tree, loading, error, refresh, issuesState, onOpenIssue, analysisStatus = "" }:
  ReturnType<typeof useThreatCoverage> & {
    analysisStatus?: string; issuesState?: ReturnType<typeof useCoverageIssues>; onOpenIssue?: (index: number) => void;
  }) {
  const panel = useRef<HTMLElement>(null);
  const [history, setHistory] = useState<string[]>(["."]);
  const [selected, setSelected] = useState(".");
  const [query, setQuery] = useState("");
  const [pattern, setPattern] = useState("");
  const [showDetails, setShowDetails] = useState(() => !window.matchMedia?.("(max-width: 640px)").matches);
  const [fullscreen, setFullscreen] = useState(false);
  const [fullscreenError, setFullscreenError] = useState("");
  useEffect(() => {
    const changed = () => setFullscreen(document.fullscreenElement === panel.current);
    document.addEventListener("fullscreenchange", changed);
    return () => document.removeEventListener("fullscreenchange", changed);
  }, []);
  const toggleFullscreen = async () => {
    setFullscreenError("");
    try {
      if (document.fullscreenElement === panel.current) await document.exitFullscreen();
      else if (panel.current?.requestFullscreen) await panel.current.requestFullscreen();
      else setFullscreenError("当前浏览器不支持全屏，可收起详情扩大图表。");
    } catch {
      setFullscreenError("未能进入全屏，可收起详情扩大图表。");
    }
  };
  const issues = issuesState?.data ?? null;
  const issueCounts = useMemo(() => tree ? buildCoverageIssueOverlay(tree, issues) : new Map(), [tree, issues]);
  const targetMap = useMemo(() => new Map(data?.targets.map((target) => [target.id, target]) ?? []), [data]);
  const patterns = useMemo(() => [...new Map(data?.targets.map((target) => [target.pattern_id || target.pattern_name,
    `${target.pattern_id} ${target.pattern_name}`.trim()]) ?? []).entries()].sort((a, b) => a[1].localeCompare(b[1])), [data]);
  const highlighted = useMemo(() => pattern ? new Set(data?.targets.filter((target) => (target.pattern_id || target.pattern_name) === pattern).map((target) => target.id)) : null, [data, pattern]);
  const searchResults = useMemo(() => {
    const text = query.trim().toLowerCase();
    if (!text || !tree || !data) return [];
    const moduleIds = new Set(data.modules.filter((module) => module.name.toLowerCase().includes(text)).map((module) => module.id));
    const matchesModule = createCoverageMatcher(moduleIds);
    const matches = [];
    for (const item of tree.byPath.values()) {
      if (item.path !== "." && (item.path.toLowerCase().includes(text) || matchesModule(item.moduleIds))) matches.push(item);
      if (matches.length === 100) break;
    }
    return matches;
  }, [query, tree, data]);
  const inventory = data?.inventory;
  const hasTree = Boolean(inventory?.entries.length && tree);
  const root = tree?.root;
  const view = tree ? tree.byPath.get(history[history.length - 1]) ?? tree.root : null;
  const detail = tree ? tree.byPath.get(selected) ?? tree.root : null;
  const percent = (count: number) => data?.analysis_ready && inventory?.status === "complete" ? coveragePercent(count, root?.files ?? 0) : "—";
  const open = (path: string) => {
    if (path !== history[history.length - 1]) setHistory([...history, path]);
    setSelected(path);
  };
  const locate = (item: CoverageNode) => {
    const parent = item.kind === "directory" ? item.path : item.path.includes("/") ? item.path.slice(0, item.path.lastIndexOf("/")) : ".";
    const steps = parent === "." ? [] : parent.split("/").map((_part, index, parts) => parts.slice(0, index + 1).join("/"));
    setHistory([".", ...steps]); setSelected(item.path); setQuery(""); setShowDetails(true);
  };
  const openIssue = (index: number) => {
    if (document.fullscreenElement === panel.current) void document.exitFullscreen().catch(() => {});
    onOpenIssue?.(index);
  };

  return <section ref={panel} className="threat-coverage" aria-label="威胁分析覆盖图">
    <header className="coverage-header"><div><span className="coverage-eyebrow">扫描范围 / 覆盖统计</span><h2>威胁分析覆盖图</h2>
      <p>面积按文件数量计算，红色文件表示去误报复核确认的问题。</p></div>
      <div className="coverage-actions"><button type="button" className="coverage-button" onClick={() => { refresh(); issuesState?.refresh(); }} disabled={loading || issuesState?.loading}>{loading || issuesState?.loading ? "加载中…" : "刷新"}</button>
        {hasTree && <button type="button" className="coverage-button" onClick={toggleFullscreen}>{fullscreen ? "退出全屏" : "全屏总览"}</button>}</div></header>
    {error && <p role="alert" className="coverage-warning">{error}</p>}
    {issuesState?.error && <p role="alert" className="coverage-warning">问题标注加载失败，请刷新重试；已加载的标注仍然保留。</p>}
    {fullscreenError && <p role="alert" className="coverage-warning">{fullscreenError}</p>}
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
      <p className="coverage-issue-summary">确认问题：{issues ? issues.total_issue_count.toLocaleString() : "—"} 个 ·
        涉及文件：{issues ? (issueCounts.get(".")?.files ?? 0).toLocaleString() : "—"} 个
        {issues && issues.unmapped_count > 0 ? ` · ${issues.unmapped_count} 个问题未映射到文件清单` : ""}</p>
      <div className="coverage-toolbar">
        <label><span>搜索路径或模块</span><input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="例如 src/auth 或认证模块" /></label>
        <label><span>高亮攻击模式</span><select value={pattern} onChange={(event) => setPattern(event.target.value)}><option value="">全部攻击模式</option>{patterns.map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label>
      </div>
      {query.trim() && <div className="coverage-search-results" aria-label="路径搜索结果">
        {searchResults.map((item) => <button type="button" key={item.path} onClick={() => locate(item)}><code>{item.path}</code><span>{item.files} 个文件</span></button>)}
        <p>{searchResults.length ? `显示 ${searchResults.length} 项${searchResults.length === 100 ? "，可缩小搜索范围查看其它路径" : ""}` : "没有匹配的路径或模块。"}</p>
      </div>}
      <div className="coverage-legend"><span><i className="is-neutral" />{data.analysis_ready ? "未标注" : "尚未标注"}</span><span><i className="is-risk" />高风险未关联模式</span><span><i className="is-covered" />已关联攻击模式</span><span><i className="is-issue" />确认问题文件</span><small>红色边框表示目录含问题；筛选不隐藏问题</small></div>
      <div className="coverage-navigation"><nav className="coverage-breadcrumb" aria-label="覆盖图目录">
        {history.map((path, index) => <button type="button" key={`${index}:${path}`} onClick={() => { setHistory(history.slice(0, index + 1)); setSelected(path); }}
          aria-current={index === history.length - 1 ? "location" : undefined}>{index ? "› " : ""}{tree!.byPath.get(path)?.name ?? "扫描范围"}</button>)}
      </nav><div className="coverage-actions">
        <button type="button" className="coverage-button" onClick={() => { setHistory(["."]); setSelected("."); }} disabled={history.length === 1}>返回全图</button>
        <button type="button" className="coverage-button" aria-expanded={showDetails} onClick={() => setShowDetails(!showDetails)}>{showDetails ? "收起详情" : "显示详情"}</button>
      </div></div>
      <div className={`coverage-workspace ${showDetails ? "" : "is-map-only"}`}><div className="coverage-map-column">
        <CoverageTreemap parent={view} selected={selected} highlighted={highlighted} targets={targetMap} issueCounts={issueCounts}
          onSelect={(path) => { setSelected(path); setShowDetails(true); }} onOpen={open} />
        <p className="coverage-caption">自动适配全部格子 · 单击查看关联，双击目录下钻 · 小格子可悬停或搜索查看完整路径</p></div>
        {showDetails && <SelectionDetails key={detail.path} node={detail} data={data} issues={issues}
          issuesLoading={issuesState?.loading} issuesError={issuesState?.error} onOpen={open} onOpenIssue={onOpenIssue ? openIssue : undefined} />}</div>
      {!!issues?.unmapped_count && <details className="coverage-diagnostics"><summary>未映射的确认问题（{issues.unmapped_count}）</summary>
        {issues.unmapped.map((item) => <p key={item.vuln_index}><button type="button" className="coverage-button"
          disabled={!onOpenIssue} onClick={() => openIssue(item.vuln_index)}>查看问题 #{item.vuln_index}</button> <code>{item.file}</code>：未精确匹配清单中的文件</p>)}
        {issues.unmapped_count > issues.unmapped.length && <p>仅列出前 {issues.unmapped.length} 项。</p>}
      </details>}
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
