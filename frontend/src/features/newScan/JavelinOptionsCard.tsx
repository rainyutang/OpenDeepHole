import type { SetStateAction } from "react";
import type { JavelinMemoryMode, JavelinMiningStrategy, JavelinScanConfig } from "../../types/scans";

interface Props {
  value: JavelinScanConfig;
  onChange: (update: SetStateAction<JavelinScanConfig>) => void;
}

const inputCls = "w-full rounded-lg border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-white placeholder-slate-500 outline-none transition-colors focus:border-blue-500";

const STRATEGY_OPTIONS: Array<{ id: JavelinMiningStrategy; label: string; desc: string }> = [
  {
    id: "focus_area",
    label: "威胁引导重点分区（Focus Area）",
    desc: "基于五层攻击面与威胁建模结果划分 Focus Area，按三视角（Tri-Lens）与 D1-D10 维度深入审计。",
  },
  {
    id: "api",
    label: "逐接口 API 深度审查",
    desc: "按提供的 HTTP/RPC 接口清单逐个接口追踪鉴权、参数绑定、SQL/表达式/文件/反序列化风险。",
  },
  {
    id: "file_sweep",
    label: "逐文件全量扫描（File Sweep）",
    desc: "先建立源码文件基线并逐文件浏览分派任务，确保高敏感模块与散落工具类全量覆盖。",
  },
];

const MEMORY_OPTIONS: Array<{ id: JavelinMemoryMode; label: string }> = [
  { id: "full", label: "完整长期记忆（full）" },
  { id: "facts_only", label: "仅事实与架构记忆（facts_only）" },
  { id: "off", label: "关闭产品记忆（off）" },
  { id: "blind", label: "盲审模式（blind）" },
];

export default function JavelinOptionsCard({ value, onChange }: Props) {
  const patch = (partial: Partial<JavelinScanConfig>) => {
    onChange((prev) => ({ ...prev, ...partial }));
  };

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-slate-700 bg-slate-800 p-5">
        <div className="mb-4 flex items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-slate-200">Javelin 漏洞挖掘策略</h2>
            <p className="mt-1 text-xs text-slate-400">
              在客户端本地完整执行任务看板规划、多领域子智能体审计、独立质量复核与 Proposer/Challenger/Moderator 三方质证。
            </p>
          </div>
          <span className="shrink-0 rounded border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-xs font-medium text-emerald-300">
            Java · Javelin
          </span>
        </div>

        <div className="grid gap-3 md:grid-cols-3">
          {STRATEGY_OPTIONS.map((item) => {
            const active = value.mining_strategy === item.id;
            return (
              <label
                key={item.id}
                className={`cursor-pointer rounded-lg border p-3.5 transition-colors ${active ? "border-blue-500 bg-blue-500/10" : "border-slate-600 hover:border-slate-500"}`}
              >
                <div className="flex items-center gap-2">
                  <input
                    type="radio"
                    checked={active}
                    onChange={() => patch({ mining_strategy: item.id })}
                  />
                  <span className="text-sm font-medium text-slate-100">{item.label}</span>
                </div>
                <p className="mt-2 text-xs leading-5 text-slate-400">{item.desc}</p>
              </label>
            );
          })}
        </div>

        {value.mining_strategy === "api" && (
          <div className="mt-4">
            <label className="mb-2 block text-sm font-medium text-slate-300">
              API 审查清单 * <span className="text-xs font-normal text-slate-500">（每行一个路由或方法签名）</span>
            </label>
            <textarea
              rows={5}
              className={inputCls}
              placeholder={"POST /api/v1/orders/export\nGET /admin/users/{id}"}
              value={value.api_inventory}
              onChange={(e) => patch({ api_inventory: e.target.value })}
            />
          </div>
        )}

        <div className="mt-5 grid gap-4 md:grid-cols-2">
          <div>
            <label className="mb-2 block text-sm font-medium text-slate-300">产品长期记忆模式</label>
            <select
              className={inputCls}
              value={value.memory_mode}
              onChange={(e) => patch({ memory_mode: e.target.value as JavelinMemoryMode })}
            >
              {MEMORY_OPTIONS.map((opt) => (
                <option key={opt.id} value={opt.id}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center justify-between rounded-lg border border-slate-700 bg-slate-900/50 px-4 py-3">
            <div>
              <div className="text-sm font-medium text-slate-200">越权专项分析（BAC）</div>
              <div className="mt-0.5 text-xs text-slate-400">自动构建权限控制矩阵并审查水平/垂直越权</div>
            </div>
            <button
              type="button"
              role="switch"
              aria-label="越权专项分析"
              aria-checked={value.bac_enabled}
              onClick={() => patch({ bac_enabled: !value.bac_enabled })}
              className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors ${value.bac_enabled ? "bg-blue-500" : "bg-slate-600"}`}
            >
              <span className={`inline-block h-5 w-5 rounded-full bg-white shadow transition-transform ${value.bac_enabled ? "translate-x-5" : "translate-x-0.5"}`} />
            </button>
          </div>
        </div>

        <div className="mt-4">
          <label className="mb-2 block text-sm font-medium text-slate-300">
            补充审计说明 <span className="text-xs font-normal text-slate-500">（可选，切勿填入密码或私钥）</span>
          </label>
          <textarea
            rows={3}
            className={inputCls}
            placeholder="例如：重点关注多租户隔离、文件导入导出与自定义网关鉴权绕过"
            value={value.additional_instructions}
            onChange={(e) => patch({ additional_instructions: e.target.value })}
          />
        </div>
      </div>

      <div className="rounded-xl border border-slate-700 bg-slate-800 p-5">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 className="text-sm font-medium text-slate-200">授权动态验证环境（可选）</h2>
            <p className="mt-1 text-xs leading-5 text-slate-400">
              开启后由漏洞验证子智能体在有界超时内对高置信候选漏洞执行动态验证。环境凭据经 AES-256-GCM 暂存并在客户端拉取启动后自动擦除，不进入任何历史配置或公开接口。
            </p>
          </div>
          <button
            type="button"
            role="switch"
            aria-label="启用授权动态验证"
            aria-checked={value.runtime_testing.enabled}
            onClick={() =>
              patch({
                runtime_testing: {
                  ...value.runtime_testing,
                  enabled: !value.runtime_testing.enabled,
                },
              })
            }
            className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors ${value.runtime_testing.enabled ? "bg-blue-500" : "bg-slate-600"}`}
          >
            <span className={`inline-block h-5 w-5 rounded-full bg-white shadow transition-transform ${value.runtime_testing.enabled ? "translate-x-5" : "translate-x-0.5"}`} />
          </button>
        </div>

        {value.runtime_testing.enabled && (
          <div className="mt-4">
            <label className="mb-2 block text-sm font-medium text-slate-300">
              测试环境地址与临时认证说明
            </label>
            <textarea
              rows={4}
              className={inputCls}
              placeholder="例如：Base URL: http://127.0.0.1:8080，测试账号与临时会话获取方式..."
              value={value.runtime_testing.test_environment_context || ""}
              onChange={(e) =>
                patch({
                  runtime_testing: {
                    ...value.runtime_testing,
                    test_environment_context: e.target.value,
                  },
                })
              }
            />
          </div>
        )}
      </div>
    </div>
  );
}
