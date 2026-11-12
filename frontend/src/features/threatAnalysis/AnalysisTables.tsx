import type { NativeThreatHighRiskModule, NativeThreatTreeNode, NativeThreatValueAsset } from "../../types/threatAnalysis";
import { moduleSourcePaths, scanRelativePaths } from "./coverage";
import type { ThreatCoverage } from "./coverage";

import { HIGH_RISK_FIELDS, nodeDisplayName, formatValue, displayValue } from './analysisModel';

export function ValueAssetsTable({ assets }: { assets: NativeThreatValueAsset[] }) {
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

export function HighRiskModulesTable({
  modules,
  coverage,
  pathError,
}: {
  modules: NativeThreatHighRiskModule[];
  coverage: ThreatCoverage | null;
  pathError: string;
}) {
  const headers = [
    "模块名称",
    "代码目录（相对扫描路径）",
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
              <td><ModuleCodePaths module={module} index={index} coverage={coverage} error={pathError} /></td>
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

export function ModuleCodePaths({ module, index, coverage, error }: {
  module: NativeThreatHighRiskModule; index: number; coverage: ThreatCoverage | null; error: string;
}) {
  const source = moduleSourcePaths(module["代码目录"]);
  const projected = coverage?.analysis_ready
    ? coverage.modules.find((item) => item.id === `module-${index}`
      && item.name === String(module["模块名称"] || "").trim()
      && item.paths.length === source.length && item.paths.every((path, i) => path === source[i]))
    : undefined;
  // Never pair a refreshed artifact with the preceding coverage response,
  // including when multiple modules share a name.
  if (!projected) return <span>{error ? "路径解析失败，请刷新" : "正在解析路径…"}</span>;
  const paths = scanRelativePaths(projected);
  const unmapped = coverage?.unmapped.some((item) => item.kind === "module" && item.id === projected.id);
  return <>
    <span>{paths.length ? displayValue(paths) : "路径无法映射"}</span>
    {unmapped && <small className="block" title={projected.paths.join("\n")}>存在未映射路径，见范围说明</small>}
  </>;
}

export function InternalNodesTable({ nodes }: { nodes: NativeThreatTreeNode[] }) {
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

export function EmptyTableRow({
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

export function YesNoBadge({ value }: { value: unknown }) {
  const text = formatValue(value) || "否";
  return (
    <span
      className={`threat-analysis-viewer__badge ${text === "是" ? "is-yes" : "is-no"
        }`}
    >
      {text}
    </span>
  );
}
