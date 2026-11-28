import type { AgentInfo, AgentRemoteConfig } from "../../types/agents";
import { Field, input } from "./AdvancedSettings";

interface Props {
  config: AgentRemoteConfig;
  setCfg: (value: AgentRemoteConfig) => void;
  selectedAgent?: AgentInfo;
}

export default function DshBaseFields({ config, setCfg, selectedAgent }: Props) {
  const unsupportedOnline = Boolean(
    selectedAgent?.online && selectedAgent.deepseek_harness === false,
  );
  return <>
    <Field
      label="DeepSeek Harness 配置档"
      hint="固定使用最小 SDK 配置档（sdk-minimal），自动按需挂载 Skills、权限校验与扫描 MCP">
      <select
        aria-label="DeepSeek Harness 配置档"
        disabled
        className={`${input} cursor-not-allowed opacity-70`}
        value={config.base.dsh_profile ?? "sdk-minimal"}>
        <option value="sdk-minimal">sdk-minimal</option>
      </select>
    </Field>
    <Field
      label="dsh 可执行文件路径（可选）"
      hint="留空时默认使用 deepseek-harness-sdk 内置运行时或系统 PATH 中的 dsh；如需指定自定义路径可填写完整路径">
      <input
        aria-label="dsh 可执行文件路径（可选）"
        className={input}
        placeholder="留空使用 SDK 内置运行时"
        value={config.base.dsh_executable ?? ""}
        onChange={(e) => setCfg({
          ...config,
          base: {
            ...config.base,
            dsh_executable: e.target.value,
          },
        })} />
    </Field>
    {unsupportedOnline && <div className="md:col-span-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
      当前在线客户端尚未声明 DeepSeek Harness 支持，请先更新客户端运行代码后再切换到 DeepSeek Harness。
    </div>}
  </>;
}
