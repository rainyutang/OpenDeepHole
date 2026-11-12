import type { ReactNode } from "react";
import { useRef, useState } from "react";
import { updateScanCodeGraph } from "../../../api/scans";
import { STATIC_CANDIDATE_ENGINE_ID as STATIC_ENGINE_ID, canonicalMiningEngineLabel } from "../../../miningEngines";
import { selectedScanPaths } from "../../../scanPaths";
import type { ScanCodeGraphState, ScanStatus as ScanStatusType } from "../../../types/scans";
import { formatDateTime } from "../../modelPool/presentation";
import {
  effectiveMiningEngines,
  fpReviewMethodLabel,
  isThreatAnalysisSelected,
  threatAnalysisMethodLabel,
} from "../model/scan";

function scanModeLabel(mode?: string): string {
  if (mode === "quick") return "快速模式";
  if (mode === "standard") return "标准模式";
  if (mode === "custom") return "自定义模式";
  if (mode === "full") return "历史完整模式";
  if (mode === "threat_analysis_only") return "历史威胁分析模式";
  return mode?.trim() || "未记录";
}

export function ScanInformationPanel({
  scan,
  onClose,
  onEdit,
  onCopy,
  onCodeGraphSaved,
}: {
  scan: ScanStatusType;
  onClose: () => void;
  onEdit?: () => void;
  onCopy?: () => void;
  onCodeGraphSaved?: (state: ScanCodeGraphState) => void;
}) {
  const [codeGraphSaving, setCodeGraphSaving] = useState(false);
  const codeGraphSavingRef = useRef(false);
  const [codeGraphError, setCodeGraphError] = useState("");
  const [codeGraphNotice, setCodeGraphNotice] = useState<{ revision: number; message: string; } | null>(null);
  const multiVersion = scan.scan_mode === "multi_version";
  const codeGraphPending = scan.code_graph_mcp_sync_status === "pending";
  const toggleCodeGraph = async () => {
    if (codeGraphSavingRef.current || !onCodeGraphSaved || multiVersion) return;
    codeGraphSavingRef.current = true;
    setCodeGraphSaving(true);
    setCodeGraphError("");
    try {
      const state = await updateScanCodeGraph(scan.scan_id, !scan.code_graph_mcp_enabled);
      onCodeGraphSaved(state);
      setCodeGraphNotice({ revision: state.code_graph_mcp_revision, message: state.sync_message || "" });
    } catch (caught: unknown) {
      const detail = (caught as { response?: { data?: { detail?: unknown; }; }; })?.response?.data?.detail;
      setCodeGraphError(typeof detail === "string" ? detail : "CodeGraph 配置保存失败，请稍后重试");
    } finally {
      codeGraphSavingRef.current = false;
      setCodeGraphSaving(false);
    }
  };
  const engines = effectiveMiningEngines(scan);
  const staticEngineSelected = engines.some((engine) => engine.engine_id === STATIC_ENGINE_ID);
  const threatAnalysisSelected = isThreatAnalysisSelected(scan);
  const autoFpReviewEnabled = scan.auto_fp_review !== false;
  const validationMethod = scan.validation_method_label
    || scan.validation_method_id
    || scan.validation_environment;

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/30" onClick={onClose} />
      <aside
        role="dialog"
        aria-modal="true"
        aria-label="扫描信息"
        className="fixed bottom-0 right-0 top-0 z-50 flex w-[42rem] max-w-full flex-col border-l border-slate-700 bg-slate-900 shadow-2xl"
      >
        <div className="flex items-start justify-between gap-4 border-b border-slate-700 px-5 py-4">
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200">扫描信息</h3>
            <p className="mt-1 text-xs leading-5 text-slate-500">
              {onEdit ? "产品名和扫描名称可编辑；" : "本页展示最新的产品名和扫描名称；"}CodeGraph 展示当前设置，其他流程配置保留创建扫描时的快照。
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="关闭扫描信息"
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-slate-500 transition-colors hover:bg-slate-800 hover:text-slate-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400/70"
          >
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18 18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="min-h-0 flex-1 space-y-5 overflow-y-auto p-5">
          <ScanInformationSection title="基本信息">
            {(onEdit || onCopy) && (
              <div className="mb-3 flex flex-wrap justify-end gap-2">
                {onEdit && <button type="button" onClick={onEdit} className="rounded-lg border border-slate-600 px-3 py-1.5 text-xs text-slate-200 transition-colors hover:bg-slate-800">编辑名称</button>}
                {onCopy && <button type="button" onClick={onCopy} className="rounded-lg border border-slate-600 px-3 py-1.5 text-xs text-slate-200 transition-colors hover:bg-slate-800">复制扫描</button>}
              </div>
            )}
            <div className="grid gap-3 sm:grid-cols-2">
              <ScanInformationField label="扫描名称" value={scan.scan_name || scan.project_id || "未记录"} />
              <ScanInformationField label="扫描 ID" value={scan.scan_id} mono />
              <ScanInformationField label="创建时间" value={formatDateTime(scan.created_at)} />
              <ScanInformationField label="Agent" value={scan.agent_name || "未记录"} />
              <ScanInformationField label="产品" value={scan.product || "未填写"} />
              <ScanInformationField label="扫描模式" value={scanModeLabel(scan.scan_mode)} />
            </div>
          </ScanInformationSection>

          <ScanInformationSection title="扫描范围">
            <div className="space-y-3">
              <ScanInformationField label="项目路径" value={scan.project_path || "未记录"} mono wide />
              {(scan.multi_versions?.length ? scan.multi_versions : [scan]).map((scope, index) => <div key={index} className="space-y-2">
                {"version_name" in scope && <p className="text-sm text-slate-300">{scope.version_name}</p>}
                {selectedScanPaths(scope).map((path) => <ScanInformationField key={path} label="代码扫描路径（绝对路径）" value={path} mono wide />)}
              </div>)}
            </div>
          </ScanInformationSection>

          <ScanInformationSection title="能力开关">
            <div className="grid gap-3 sm:grid-cols-2">
              <ScanInformationToggle
                label="知识库"
                enabled={scan.knowledge_base_enabled}
                detail="创建扫描时的数据库能力开关"
              />
              <ScanInformationToggle
                label="CodeGraph MCP"
                enabled={scan.code_graph_mcp_enabled}
                detail={multiVersion ? "多版本扫描不支持 CodeGraph" : "切换后对尚未开始的任务生效，正在运行的任务继续使用原设置。"}
              >
                {onCodeGraphSaved && (
                  <button
                    type="button"
                    disabled={codeGraphSaving || multiVersion}
                    onClick={toggleCodeGraph}
                    className="mt-3 rounded-lg border border-slate-600 px-3 py-1.5 text-xs text-slate-200 transition-colors hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {codeGraphSaving ? "保存中..." : scan.code_graph_mcp_enabled ? "停用 CodeGraph" : "启用 CodeGraph"}
                  </button>
                )}
                {codeGraphPending && (
                  <p role="status" className="mt-2 text-xs leading-5 text-amber-400">
                    {codeGraphNotice && codeGraphNotice.revision === scan.code_graph_mcp_revision && codeGraphNotice.message
                      ? codeGraphNotice.message : "待同步：配置已保存，等待 Agent 应用。"}
                  </p>
                )}
                {codeGraphError && <p role="alert" className="mt-2 text-xs leading-5 text-red-400">{codeGraphError}</p>}
              </ScanInformationToggle>
            </div>
          </ScanInformationSection>

          <ScanInformationSection title="扫描过程">
            <div className="space-y-3">
              <ScanInformationToggle
                label="威胁分析"
                enabled={threatAnalysisSelected}
                detail={threatAnalysisSelected ? `方法：${threatAnalysisMethodLabel(scan)}` : "本次扫描未启用"}
              />

              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-4">
                <div className="flex items-center justify-between gap-3">
                  <div className="text-sm font-medium text-slate-200">漏洞挖掘引擎</div>
                  <span className="text-xs text-slate-500">{engines.length} 个</span>
                </div>
                {engines.length > 0 ? (
                  <div className="mt-3 space-y-2">
                    {engines.map((engine) => (
                      <div key={engine.engine_id} className="rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2">
                        <div className="text-sm text-slate-200">{canonicalMiningEngineLabel(engine.engine_id, engine.engine_label)}</div>
                        <div className="mt-1 break-all font-mono text-[11px] text-slate-500">{engine.engine_id}</div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="mt-3 text-xs text-slate-500">本次扫描未选择漏洞挖掘引擎</p>
                )}
              </div>

              <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="text-sm font-medium text-slate-200">启用的静态规则</div>
                  {staticEngineSelected && (
                    <span className="rounded-full bg-cyan-500/10 px-2 py-1 text-[11px] font-medium text-cyan-300">
                      {scan.scan_items.length} 条
                    </span>
                  )}
                </div>
                {!staticEngineSelected ? (
                  <p className="mt-3 text-xs text-slate-500">未选择基于静态分析的引擎</p>
                ) : scan.scan_items.length === 0 ? (
                  <p className="mt-3 text-xs text-slate-500">未启用静态规则</p>
                ) : (
                  <div className="mt-3 flex flex-wrap gap-2" aria-label="创建扫描时启用的静态规则">
                    {scan.scan_items.map((rule, index) => (
                      <span
                        key={`${rule}-${index}`}
                        className="max-w-full break-all rounded-lg border border-cyan-500/25 bg-cyan-500/10 px-2.5 py-1.5 font-mono text-xs text-cyan-100"
                      >
                        {rule}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <ScanInformationToggle
                label="自动去误报"
                enabled={autoFpReviewEnabled}
                detail={autoFpReviewEnabled
                  ? `方法：${fpReviewMethodLabel(scan.fp_review_method, scan.fp_review_method_selection)}`
                  : "本次扫描未启用"}
              />
              <ScanInformationToggle
                label="漏洞验证"
                enabled={scan.vulnerability_validation_enabled}
                detail={scan.vulnerability_validation_enabled
                  ? `方法：${validationMethod || "未记录"}`
                  : "本次扫描未启用"}
              />
            </div>
          </ScanInformationSection>
        </div>
      </aside>
    </>
  );
}

function ScanInformationSection({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section>
      <h4 className="mb-3 text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">{title}</h4>
      {children}
    </section>
  );
}

function ScanInformationField({
  label,
  value,
  mono = false,
  wide = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
  wide?: boolean;
}) {
  return (
    <div className={`rounded-xl border border-slate-700 bg-slate-950/50 p-3 ${wide ? "w-full" : ""}`}>
      <div className="text-[11px] font-medium text-slate-500">{label}</div>
      <div className={`mt-1.5 break-all text-sm leading-6 text-slate-200 ${mono ? "font-mono text-xs" : ""}`} title={value}>
        {value}
      </div>
    </div>
  );
}

function ScanInformationToggle({
  label,
  enabled,
  detail,
  children,
}: {
  label: string;
  enabled: boolean;
  detail: string;
  children?: ReactNode;
}) {
  return (
    <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-4">
      <div className="flex items-center justify-between gap-3">
        <span className="text-sm font-medium text-slate-200">{label}</span>
        <span className={`rounded-full px-2 py-1 text-[11px] font-medium ${enabled ? "bg-emerald-500/10 text-emerald-300" : "bg-slate-800 text-slate-500"
          }`}>
          {enabled ? "已启用" : "未启用"}
        </span>
      </div>
      <p className="mt-2 text-xs leading-5 text-slate-500">{detail}</p>
      {children}
    </div>
  );
}
