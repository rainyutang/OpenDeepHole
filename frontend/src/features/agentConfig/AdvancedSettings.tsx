import type { AgentModelTaskPolicy, AgentRemoteConfig, AgentValidatorCatalog } from "../../types/agents";
import type { CheckerInfo } from "../../types/checkers";

import { AdvancedSection, CheckerProfileMode } from './configModel';

export const input = "w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-white outline-none focus:border-blue-500";

export function PolicyEditor({ value, onChange, timeoutLabel = "Session 超时（秒）" }: { value: AgentModelTaskPolicy; onChange: (value: AgentModelTaskPolicy) => void; timeoutLabel?: string }) {
  return <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
    <Field label="需要的模型能力"><select
      className={input}
      value={value.required_capability}
      onChange={(e) => onChange({ ...value, required_capability: e.target.value as AgentModelTaskPolicy["required_capability"] })}>
      <option value="low">低能力</option><option value="high">高能力</option>
    </select></Field>
    <Field label={timeoutLabel}><input
      className={input}
      type="number"
      min={1}
      value={value.timeout_seconds}
      onChange={(e) => onChange({ ...value, timeout_seconds: Number(e.target.value) })} /></Field>
    <Field label="单次对话无新内容超时（秒）"><input
      className={input}
      type="number"
      min={1}
      value={value.idle_timeout_seconds}
      onChange={(e) => onChange({ ...value, idle_timeout_seconds: Number(e.target.value) })} /></Field>
    <Field label="JSON 纠正超时（秒）"><input
      className={input}
      type="number"
      min={1}
      value={value.json_correction_timeout_seconds}
      onChange={(e) => onChange({ ...value, json_correction_timeout_seconds: Number(e.target.value) })} /></Field>
    <Field label="产物校验重试超时（秒）"><input
      className={input}
      type="number"
      min={1}
      value={value.validation_retry_timeout_seconds}
      onChange={(e) => onChange({ ...value, validation_retry_timeout_seconds: Number(e.target.value) })} /></Field>
    <Field label="模型调用重试次数"><input
      className={input}
      type="number"
      min={0}
      value={value.max_retries}
      onChange={(e) => onChange({ ...value, max_retries: Number(e.target.value) })} /></Field>
    <p className="text-xs text-slate-400 md:col-span-2">每次调用独立计时，JSON 纠正和产物校验重试重新计时。新文本、推理及工具进展刷新无新内容计时。</p>
  </div>;
}

export function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return <label className="block"><span className="mb-1.5 block text-xs font-medium text-slate-300">{label}{hint && <span className="ml-1 font-normal text-slate-500">— {hint}</span>}</span>{children}</label>;
}

export function AdvancedSettings({ config, setCfg, catalog, checkers, checkerProfileMode, setCheckerProfileMode, target }: {
  config: AgentRemoteConfig;
  setCfg: (value: AgentRemoteConfig) => void;
  catalog: AgentValidatorCatalog;
  checkers: CheckerInfo[];
  checkerProfileMode: CheckerProfileMode;
  setCheckerProfileMode: (mode: CheckerProfileMode) => void;
  target: AdvancedSection;
}) {
  const disabledCheckers = new Set(
    config.checker_selection[checkerProfileMode].disabled_checkers,
  );
  const updateCheckerGroup = (items: CheckerInfo[], enabled: boolean) => {
    const next = new Set(
      config.checker_selection[checkerProfileMode].disabled_checkers,
    );
    items.forEach((checker) => enabled ? next.delete(checker.name) : next.add(checker.name));
    setCfg({
      ...config,
      checker_selection: {
        ...config.checker_selection,
        [checkerProfileMode]: {
          disabled_checkers: Array.from(next).sort(),
        },
      },
    });
  };
  const checkerGroup = (label: string, items: CheckerInfo[]) => <div className="space-y-2">
    <div className="flex items-center justify-between gap-3">
      <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">{label}</h4>
      {items.length > 0 && <div className="flex gap-3 text-xs">
        <button type="button" className="text-blue-300 hover:text-blue-200" onClick={() => updateCheckerGroup(items, true)}>全选</button>
        <button type="button" className="text-slate-400 hover:text-slate-200" onClick={() => updateCheckerGroup(items, false)}>全不选</button>
      </div>}
    </div>
    {items.length === 0 ? <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-3 text-sm text-slate-500">暂无检查项</div> : items.map((checker) => {
      const enabled = !disabledCheckers.has(checker.name);
      return <label
        key={checker.name}
        className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 ${enabled ? "border-blue-500/50 bg-blue-500/10" : "border-slate-700 bg-slate-900/50"}`}>
        <input
          type="checkbox"
          className="mt-0.5 h-4 w-4 rounded border-slate-500 bg-slate-700 text-blue-500"
          checked={enabled}
          onChange={(event) => updateCheckerGroup([checker], event.target.checked)} />
        <span className="min-w-0"><span className="block text-sm font-medium text-slate-100">{checker.label}</span><span className="mt-1 block text-xs text-slate-500">{checker.description}</span></span>
      </label>;
    })}
  </div>;

  if (target === "threat") return <div className="space-y-5">
    <PolicyEditor
      value={config.threat_analysis.model_policy}
      onChange={(model_policy) => setCfg({ ...config, threat_analysis: { ...config.threat_analysis, model_policy } })} />
    <p className="text-sm text-slate-400">这里配置威胁分析的模型任务策略；基于威胁的代码审计超时在漏洞挖掘中设置。</p>
  </div>;
  if (target === "mining") return <div className="space-y-5">
    <div className="grid grid-cols-1 gap-4 md:grid-cols-3">{([
      ["threat_audit_timeout_seconds", "威胁审计 Session 超时（秒）"],
      ["candidate_audit_timeout_seconds", "候选点审计 Session 超时（秒）"],
      ["vulnerability_dedup_timeout_seconds", "漏洞去重 Session 超时（秒）"],
    ] as const).map(([key, label]) => <Field key={key} label={label}><input
      className={input}
      type="number"
      min={1}
      value={config.vulnerability_mining[key]}
      onChange={(e) => setCfg({ ...config, vulnerability_mining: { ...config.vulnerability_mining, [key]: Number(e.target.value) } })} /></Field>)}</div>
    <PolicyEditor
      value={config.vulnerability_mining}
      timeoutLabel="其他挖掘任务 Session 超时（秒）"
      onChange={(value) => setCfg({ ...config, vulnerability_mining: { ...config.vulnerability_mining, ...value } })} />
    <p className="text-sm text-slate-400">这里配置漏洞挖掘阶段的通用模型任务策略；自定义模式可在创建扫描时选择引擎，快速和标准模式固定运行两个内置引擎。</p>
    <div className="space-y-4 border-t border-slate-700 pt-5">
      <div><h3 className="text-sm font-semibold text-slate-200">基于代码风险点引擎规则</h3><p className="mt-1 text-xs leading-5 text-slate-500">三个模式分别保存。未出现在禁用列表中的规则默认启用，因此以后新增的可用规则也会自动选中。</p></div>
      <div className="grid grid-cols-3 gap-2 rounded-lg bg-slate-900/60 p-1">{([
        { id: "quick", label: "快速模式" },
        { id: "standard", label: "标准模式" },
        { id: "custom", label: "自定义模式" },
      ] as { id: CheckerProfileMode; label: string }[]).map((mode) => <button
        key={mode.id}
        type="button"
        onClick={() => setCheckerProfileMode(mode.id)}
        className={`rounded-md px-3 py-2 text-sm ${checkerProfileMode === mode.id ? "bg-blue-600 text-white" : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"}`}>{mode.label}</button>)}</div>
      <div className="grid gap-5 lg:grid-cols-2">
        {checkerGroup("系统内置", checkers.filter((checker) => !checker.user_created))}
        {checkerGroup("用户新建", checkers.filter((checker) => checker.user_created))}
      </div>
    </div>
  </div>;
  if (target === "fp") return <PolicyEditor value={config.false_positive} onChange={(value) => setCfg({ ...config, false_positive: value })} />;
  return <div className="space-y-6">
    {catalog.errors.length > 0 && <div className="rounded border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-200">{catalog.errors.join("；")}</div>}
    <div className="grid gap-4 md:grid-cols-3">
      <Field label="支持的漏洞类型" hint="逗号分隔，* 表示全部"><input
        className={input}
        value={config.vulnerability_validation.supported_vulnerability_types.join(", ")}
        onChange={(e) => setCfg({ ...config, vulnerability_validation: { ...config.vulnerability_validation, supported_vulnerability_types: e.target.value.split(",").map((item) => item.trim()).filter(Boolean) } })} /></Field>
      <Field label="同时验证数量"><input
        className={input}
        type="number"
        min={1}
        value={config.vulnerability_validation.concurrency}
        onChange={(e) => setCfg({ ...config, vulnerability_validation: { ...config.vulnerability_validation, concurrency: Number(e.target.value) } })} /></Field>
      <Field label="整体验证重试次数"><input
        className={input}
        type="number"
        min={0}
        value={config.vulnerability_validation.validation_max_retries}
        onChange={(e) => setCfg({ ...config, vulnerability_validation: { ...config.vulnerability_validation, validation_max_retries: Number(e.target.value) } })} /></Field>
    </div>
    <PolicyEditor
      value={config.vulnerability_validation.model_policy}
      onChange={(model_policy) => setCfg({ ...config, vulnerability_validation: { ...config.vulnerability_validation, model_policy } })} />
    <div className="border-t border-slate-700 pt-5">
      <h3 className="text-sm font-semibold text-slate-200">已安装验证方法</h3>
      <p className="mt-1 text-xs leading-5 text-slate-500">这里只配置所有验证方法共用的策略。方法选择及其 field 参数在新建扫描时填写。</p>
      {catalog.methods.length === 0 ? <p className="mt-4 text-sm text-slate-400">该客户端未安装符合新格式的 validator.yaml。</p> : <div className="mt-4 grid gap-3 md:grid-cols-2">{catalog.methods.map((method) => <div key={method.method_id} className="rounded-lg border border-slate-700 bg-slate-900/60 p-4"><div className="text-sm font-medium text-blue-200">{method.method_label}</div><div className="mt-1 text-xs text-slate-500">{method.description}</div><div className="mt-2 text-xs text-slate-400">产品：{method.products.join("、") || "未声明"} · 参数：{method.fields.length}</div></div>)}</div>}
    </div>
  </div>;
}
