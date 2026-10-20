import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { KeyboardEvent, MouseEvent } from "react";
import type { CoverageNode, CoverageTarget, CoverageTreeTile } from "./coverage";
import { coverageBackground, createCoverageMatcher, hitCoverageTile, layoutCoverageTree } from "./coverage";

const DOM_TILE_LIMIT = 1200;

function tileLabel(tile: CoverageTreeTile) {
  return tile.nested ? tile.width >= 64 && tile.height >= 40 : tile.width >= 40 && tile.height >= 16;
}

function tileTitle(node: CoverageNode, targets: Map<string, CoverageTarget>) {
  const first = targets.get(node.targetIds.values().next().value ?? "")?.pattern_name;
  return `${node.path}\n${node.files.toLocaleString()} 个文件 · ${node.highRisk.toLocaleString()} 个高风险文件 · ${node.covered.toLocaleString()} 个文件关联攻击模式${first ? `\n${first}${node.targetIds.size > 1 ? ` 等 ${node.targetIds.size} 个关联` : ""}` : ""}`;
}

export function CoverageTreemap({ parent, selected, highlighted, targets, onSelect, onOpen }: {
  parent: CoverageNode; selected: string; highlighted: Set<string> | null;
  targets: Map<string, CoverageTarget>; onSelect: (path: string) => void; onOpen: (path: string) => void;
}) {
  const container = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const instructions = useId();
  const [size, setSize] = useState({ width: 0, height: 0, ratio: 1 });
  const [hovered, setHovered] = useState<string | null>(null);

  useLayoutEffect(() => {
    const element = container.current;
    if (!element) return;
    const measure = () => {
      const width = element.clientWidth;
      const height = element.clientHeight;
      const ratio = window.devicePixelRatio || 1;
      setSize((previous) => previous.width === width && previous.height === height && previous.ratio === ratio
        ? previous : { width, height, ratio });
    };
    measure();
    const observer = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(measure);
    observer?.observe(element);
    window.addEventListener("resize", measure);
    return () => { observer?.disconnect(); window.removeEventListener("resize", measure); };
  }, []);

  const tiles = useMemo(() => layoutCoverageTree(parent, size.width, size.height), [parent, size.width, size.height]);
  const byPath = useMemo(() => new Map(tiles.map((tile) => [tile.node.path, tile])), [tiles]);
  const matchesPattern = useMemo(() => createCoverageMatcher(highlighted), [highlighted]);
  const dense = tiles.length > DOM_TILE_LIMIT;
  const active = byPath.get(selected);
  const hover = hovered ? byPath.get(hovered) : undefined;

  useEffect(() => {
    if (!dense || !canvas.current || !container.current) return;
    const element = canvas.current;
    const host = container.current;
    const draw = () => {
      const context = element.getContext("2d");
      if (!context) return;
      // CSS pixels drive layout and hit testing; only the backing bitmap uses
      // device pixels. Browser zoom therefore cannot stretch or blur the map.
      element.width = Math.ceil(size.width * size.ratio);
      element.height = Math.ceil(size.height * size.ratio);
      context.scale(size.ratio, size.ratio);
      const style = getComputedStyle(host);
      const color = (name: string) => style.getPropertyValue(`--coverage-${name}`).trim();
      const neutral = color("neutral"), risk = color("risk"), covered = color("covered");
      const text = color("text");
      for (const tile of tiles) {
        const { node, x, y, width, height } = tile;
        const gap = Math.min(width, height) >= 8 ? .5 : 0;
        context.globalAlpha = matchesPattern(node.targetIds) ? 1 : .22;
        context.fillStyle = neutral;
        context.fillRect(x + gap, y + gap, width - 2 * gap, height - 2 * gap);
        if (!tile.nested && node.files && (node.covered || node.riskOnly)) {
          const coveredWidth = (width - 2 * gap) * node.covered / node.files;
          const riskWidth = (width - 2 * gap) * node.riskOnly / node.files;
          context.fillStyle = covered;
          context.fillRect(x + gap, y + gap, coveredWidth, height - 2 * gap);
          context.fillStyle = risk;
          context.fillRect(x + gap + coveredWidth, y + gap, riskWidth, height - 2 * gap);
        }
        if (!tileLabel(tile)) continue;
        context.save();
        context.beginPath();
        context.rect(x + 3, y + 1, width - 6, Math.min(height - 2, 16));
        context.clip();
        context.fillStyle = text;
        context.font = "10px system-ui, sans-serif";
        context.textBaseline = "middle";
        context.fillText(node.name, x + 4, y + 8);
        context.restore();
      }
    };
    draw();
    const observer = typeof MutationObserver === "undefined" ? null : new MutationObserver(draw);
    observer?.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme", "class", "style"] });
    return () => observer?.disconnect();
  }, [dense, tiles, size, matchesPattern]);

  const pick = (event: MouseEvent<HTMLCanvasElement>) => {
    const rect = event.currentTarget.getBoundingClientRect();
    if (!rect.width || !rect.height) return undefined;
    return hitCoverageTile(tiles, (event.clientX - rect.left) * size.width / rect.width,
      (event.clientY - rect.top) * size.height / rect.height);
  };
  const navigate = (event: KeyboardEvent<HTMLCanvasElement>) => {
    const index = Math.max(0, tiles.findIndex((tile) => tile.node.path === selected));
    let next = index;
    if (event.key === "ArrowRight" || event.key === "ArrowDown") next = Math.min(tiles.length - 1, index + 1);
    else if (event.key === "ArrowLeft" || event.key === "ArrowUp") next = Math.max(0, index - 1);
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = tiles.length - 1;
    else if (event.key === "Enter" && active?.node.kind === "directory") onOpen(active.node.path);
    else if (event.key !== " ") return;
    event.preventDefault();
    if (tiles[next] && event.key !== "Enter") onSelect(tiles[next].node.path);
  };

  return <div ref={container} className="coverage-canvas" aria-label="文件树矩形图" data-renderer={dense ? "canvas" : "dom"}>
    {dense ? <>
      <canvas ref={canvas} className="coverage-bitmap" tabIndex={0} role="group" aria-label="全部路径格子"
        aria-describedby={instructions} title={hover ? tileTitle(hover.node, targets) : "单击查看关联，双击目录下钻"}
        onMouseMove={(event) => setHovered(pick(event)?.node.path ?? null)} onMouseLeave={() => setHovered(null)}
        onClick={(event) => { const tile = pick(event); if (tile) onSelect(tile.node.path); }}
        onDoubleClick={(event) => { const tile = pick(event); if (tile?.node.kind === "directory") onOpen(tile.node.path); }}
        onKeyDown={navigate} />
      {(hover || active) && <div className="coverage-tile-outline" aria-hidden="true" style={{ left: (hover || active)!.x, top: (hover || active)!.y,
        width: (hover || active)!.width, height: (hover || active)!.height }} />}
      <span id={instructions} className="sr-only">方向键切换路径，Home 和 End 跳到首尾，Enter 进入目录，也可通过上方搜索定位路径。</span>
      <span className="sr-only" aria-live="polite">{active ? tileTitle(active.node, targets) : "尚未选择路径"}</span>
    </> : tiles.map((tile) => {
      const { node, x, y, width, height, nested } = tile;
      const firstPattern = targets.get(node.targetIds.values().next().value ?? "")?.pattern_name;
      return <button key={node.path} type="button"
        className={`coverage-tile ${selected === node.path ? "is-selected" : ""} ${matchesPattern(node.targetIds) ? "" : "is-dimmed"}`}
        style={{ left: x, top: y, width, height, background: nested ? "var(--coverage-neutral)" : coverageBackground(node), borderWidth: Math.min(width, height) >= 8 ? .5 : 0 }}
        aria-label={`${node.name}，${node.files} 个文件，${node.highRisk} 个高风险文件，${node.covered} 个文件关联攻击模式`}
        aria-pressed={selected === node.path} title={tileTitle(node, targets)}
        onClick={() => onSelect(node.path)} onDoubleClick={() => { if (node.kind === "directory") onOpen(node.path); }}>
        {tileLabel(tile) && <span className="coverage-tile__name">{node.kind === "directory" ? "▱ " : ""}{node.name}</span>}
        {!nested && width >= 100 && height >= 38 && <span className="coverage-tile__body">
          <span>{node.files.toLocaleString()} 个文件{node.directModules.size ? " · 高风险模块" : ""}</span>
          {firstPattern && height >= 56 && <span className="coverage-tile__pattern">{firstPattern}{node.targetIds.size > 1 ? ` +${node.targetIds.size - 1}` : ""}</span>}
        </span>}
      </button>;
    })}
    {!parent.children.length && <div className="coverage-empty">此目录没有已采集文件。</div>}
  </div>;
}
