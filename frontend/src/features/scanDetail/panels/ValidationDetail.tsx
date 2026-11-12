import { useEffect, useState } from "react";
import { getScanDetailItem } from "../../../api/scanDetails";
import { normalizeValidation } from "../../../scanRuntime/issues";
import type { Vulnerability, VulnerabilityValidation } from "../../../types/issues";
import { vulnerabilitySeverityLabel } from "../../modelPool/ModelPoolDashboard";
import { MarkdownContent } from "../components/MarkdownContent";
import { StatusPill } from "../components/taskUi";
import { vulnerabilityFunctionLabel, vulnerabilityLocation, vulnerabilityTypeLabel } from "../model/scan";
import {
  formatNullableBool,
  groupedValidationArtifacts,
  humanInterventionTone,
  nullableBoolTone,
  validationOutputSections,
  validationStatusLabel,
  validationTone,
} from "../model/validation";

export function ValidationDetail({
  index,
  vulnerability,
  validation: summary,
  stopping = false,
  onStopValidation,
}: {
  index: number;
  vulnerability: Vulnerability;
  validation?: VulnerabilityValidation;
  stopping?: boolean;
  onStopValidation?: (index: number) => void | Promise<void>;
}) {
  const [loaded, setLoaded] = useState<VulnerabilityValidation | null>(null);
  const [loadError, setLoadError] = useState(false);
  const scanId = summary?.scan_id;
  useEffect(() => {
    let disposed = false;
    let loading = false;
    setLoaded(null);
    setLoadError(false);
    const refresh = async () => {
      if (!scanId || disposed || loading || document.hidden) return;
      loading = true;
      try {
        const value = normalizeValidation(await getScanDetailItem(scanId, "validations", index));
        if (!disposed) { setLoaded(value); setLoadError(false); }
      } catch { if (!disposed) setLoadError(true); }
      finally { loading = false; }
    };
    void refresh();
    const timer = window.setInterval(refresh, 2000);
    return () => { disposed = true; window.clearInterval(timer); };
  }, [scanId, index, summary?.execution_revision, summary?.status]);
  const validation = loaded?.scan_id === scanId && loaded?.vuln_index === index ? {
    ...loaded, ...summary, validation_code: loaded.validation_code,
    validation_output: loaded.validation_output, final_output: loaded.final_output, intermediate_output: loaded.intermediate_output,
    output_sections: loaded.output_sections, artifacts: loaded.artifacts
  } : summary;
  const status = validation?.status || "pending";
  const tone = validationTone(validation);
  const canStop = Boolean(onStopValidation && (stopping || validation?.running || status === "queued" || status === "running"));
  return (
    <div className="max-h-[70vh] overflow-y-auto p-4">
      {loadError && <p className="mb-2 text-xs text-amber-400">验证详情读取失败，正在重试</p>}
      <div className="border-b border-slate-800 pb-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-slate-500">#{index}</span>
              <span className="text-sm font-semibold text-slate-100">{vulnerabilityTypeLabel(vulnerability)}</span>
              <span className="text-xs text-slate-500">{vulnerabilitySeverityLabel(vulnerability.severity)}</span>
            </div>
            <div className="mt-1 break-all font-mono text-xs text-slate-300">{vulnerabilityLocation(vulnerability)}</div>
            <div className="mt-1 truncate font-mono text-xs text-slate-500">{vulnerabilityFunctionLabel(vulnerability)}</div>
          </div>
          <div className="flex items-center gap-2">
            {canStop && (
              <button
                type="button"
                onClick={() => onStopValidation?.(index)}
                disabled={stopping}
                className="rounded border border-red-500/30 bg-red-500/10 px-2 py-1 text-xs font-medium text-red-300 transition-colors hover:bg-red-500/20 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {stopping ? "停止中..." : "停止验证"}
              </button>
            )}
            {validation?.running && <span className="h-3 w-3 rounded-full border border-blue-500/30 border-t-blue-300 animate-spin" />}
            <StatusPill label={validationStatusLabel(status)} tone={tone} />
          </div>
        </div>
      </div>
      <div className="mt-4 space-y-4">
        <div className="min-w-0">
          <h4 className="mb-1 text-xs font-semibold uppercase text-slate-500">漏洞摘要</h4>
          <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-2">
            <MarkdownContent content={vulnerability.description || "（无描述）"} />
          </div>
        </div>
        {validation ? (
          <div className="space-y-3">
            <div className="flex flex-wrap gap-2">
              <StatusPill
                label={`验证成功：${formatNullableBool(validation.validation_success)}`}
                tone={nullableBoolTone(validation.validation_success)}
              />
              <StatusPill
                label={`是否问题：${formatNullableBool(validation.is_problem)}`}
                tone={nullableBoolTone(validation.is_problem)}
              />
              <StatusPill
                label={`人工介入：${formatNullableBool(validation.requires_human_intervention)}`}
                tone={humanInterventionTone(validation.requires_human_intervention)}
              />
              {validation.product && <StatusPill label={`产品：${validation.product}`} tone="slate" />}
              {validation.validation_method_label && <StatusPill label={`验证方法：${validation.validation_method_label}`} tone="slate" />}
              {!validation.validation_method_label && validation.validation_environment && <StatusPill label={`旧验证环境：${validation.validation_environment}`} tone="slate" />}
            </div>
            <div className="space-y-3">
              <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
                <div className="space-y-3">
                  <ValidationOutputSections validation={validation} />
                </div>
                <div className="space-y-3">
                  <ValidationArtifacts validation={validation} />
                </div>
              </div>
              <ValidationBlock title="最终结论" content={validation.final_output || validation.validation_output} />
            </div>
          </div>
        ) : (
          <div className="rounded border border-slate-800 bg-slate-900/50 px-3 py-2 text-xs text-slate-500">等待验证脚本启动</div>
        )}
      </div>
    </div>
  );
}

function ValidationOutputSections({ validation }: { validation: VulnerabilityValidation; }) {
  const sections = validationOutputSections(validation);
  if (sections.length === 0) return null;
  return (
    <>
      {sections.map((section, idx) => (
        <ValidationBlock
          key={`${section.title}-${idx}`}
          title={section.title || "中间产出"}
          content={section.content || ""}
        />
      ))}
    </>
  );
}

function ValidationArtifacts({ validation }: { validation: VulnerabilityValidation; }) {
  const artifacts = validation.artifacts && validation.artifacts.length > 0
    ? validation.artifacts
    : validation.validation_code
      ? [{ title: "产物", name: "validation.py", kind: "code", content: validation.validation_code }]
      : [];
  const groups = groupedValidationArtifacts(artifacts);
  if (groups.length === 0) return null;
  return (
    <>
      {groups.map(([title, items]) => (
        <div key={title} className="min-w-0 rounded border border-slate-800 bg-slate-950">
          <div className="border-b border-slate-800 px-3 py-2 text-xs font-semibold text-slate-500">{title}</div>
          <div className="max-h-72 overflow-auto">
            {items.map((artifact, idx) => (
              <div key={`${artifact.name}-${idx}`} className="border-b border-slate-900 last:border-b-0">
                <div className="flex flex-wrap items-center gap-2 px-3 py-2 text-xs">
                  <span className="font-mono text-slate-200">{artifact.name}</span>
                  {artifact.kind && <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] uppercase text-slate-400">{artifact.kind}</span>}
                  {artifact.path && <span className="break-all font-mono text-[11px] text-slate-500">{artifact.path}</span>}
                </div>
                {artifact.content && (
                  <pre className="whitespace-pre-wrap break-words px-3 pb-2 font-mono text-xs leading-5 text-slate-300">
                    {artifact.content}
                  </pre>
                )}
              </div>
            ))}
          </div>
        </div>
      ))}
    </>
  );
}

function ValidationBlock({ title, content }: { title: string; content: string; }) {
  return (
    <div className="min-w-0 rounded border border-slate-800 bg-slate-950">
      <div className="border-b border-slate-800 px-3 py-2 text-xs font-semibold text-slate-500">{title}</div>
      <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words px-3 py-2 font-mono text-xs leading-5 text-slate-300">
        {content || "（暂无）"}
      </pre>
    </div>
  );
}
