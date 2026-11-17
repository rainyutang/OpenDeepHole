import type {
  NativeThreatModulePatternBaseline,
  NativeThreatModuleThreat,
  NativeThreatModuleThreatPattern,
} from "../../types/threatAnalysis";

import { EmptyTableRow } from "./AnalysisTables";
import { ModuleBaselinePanel, ViewerEmptyBlock } from "./AttackTrees";
import { displayValue, recordItems } from "./analysisModel";

export function ModuleThreats({
  moduleThreats,
  unassignedBaselines,
}: {
  moduleThreats: NativeThreatModuleThreat[];
  unassignedBaselines: NativeThreatModulePatternBaseline[];
}) {
  if (moduleThreats.length === 0 && unassignedBaselines.length === 0) {
    return <ViewerEmptyBlock text="暂无高风险模块攻击威胁" />;
  }

  const headers = ["面临的攻击模式", "威胁描述"];

  return (
    <div className="threat-analysis-viewer__tree-list">
      {moduleThreats.map((item, index) => {
        const patterns = recordItems<NativeThreatModuleThreatPattern>(item.attack_patterns);
        const moduleName = displayValue(item.module_name);
        return (
          <article
            key={`${moduleName}-${index}`}
            className="threat-analysis-viewer__tree"
          >
            <header className="threat-analysis-viewer__tree-header">
              <strong>{moduleName}</strong>
              <span>{patterns.length} 项攻击模式</span>
            </header>
            <div
              role="region"
              aria-label={`${moduleName}攻击威胁表格`}
              tabIndex={0}
              className="threat-analysis-viewer__table-wrap"
            >
              <table className="threat-analysis-viewer__table threat-analysis-viewer__table--nodes">
                <thead>
                  <tr>
                    {headers.map((header) => (
                      <th key={header} scope="col">{header}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {patterns.length === 0 ? (
                    <EmptyTableRow colSpan={headers.length} text="暂无匹配攻击模式" />
                  ) : (
                    patterns.map((pattern, patternIndex) => {
                      const code = String(pattern.pattern_id || "").trim();
                      const name = String(pattern.pattern_name || "").trim();
                      const label = code && name ? `${code} ${name}` : (name || code || "—");
                      return (
                        <tr key={`${code || name}-${patternIndex}`}>
                          <td>{label}</td>
                          <td>{displayValue(pattern.description)}</td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </article>
        );
      })}
      <ModuleBaselinePanel groups={unassignedBaselines} title="高风险模块固定审计模式" />
    </div>
  );
}
