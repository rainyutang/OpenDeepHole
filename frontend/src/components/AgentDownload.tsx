import { useEffect, useState } from "react";
import {
  getAgentRuntimeManifest,
  getAgents,
  requestAgentRuntimeUpdate,
} from "../api/client";
import type { AgentInfo } from "../types";
import { ThemeToggle } from "./ThemeToggle";

interface Props {
  onBack: () => void;
}

export default function AgentDownload({ onBack }: Props) {
  const [downloading, setDownloading] = useState(false);
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [targetHash, setTargetHash] = useState("");
  const [agentsLoading, setAgentsLoading] = useState(true);
  const [updatingKey, setUpdatingKey] = useState("");
  const [updateMessage, setUpdateMessage] = useState("");
  const [updateError, setUpdateError] = useState("");

  const refreshAgents = async () => {
    try {
      setAgents(await getAgents());
    } catch {
      // Keep the last observable list during transient polling failures.
    }
  };

  useEffect(() => {
    let disposed = false;
    Promise.all([getAgents(), getAgentRuntimeManifest()])
      .then(([nextAgents, manifest]) => {
        if (disposed) return;
        setAgents(nextAgents);
        setTargetHash(manifest.hash);
      })
      .catch(() => {
        if (!disposed) setUpdateError("加载 Agent 更新状态失败");
      })
      .finally(() => {
        if (!disposed) setAgentsLoading(false);
      });
    const timer = window.setInterval(() => {
      if (!disposed && document.visibilityState === "visible") void refreshAgents();
    }, 3000);
    return () => {
      disposed = true;
      window.clearInterval(timer);
    };
  }, []);

  const handleDownload = async () => {
    setDownloading(true);
    try {
      const token = localStorage.getItem("auth_token");
      const response = await fetch("/api/agent/download", {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const url = URL.createObjectURL(await response.blob());
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "opendeephole-agent.zip";
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      alert(`下载失败：${error}`);
    } finally {
      setDownloading(false);
    }
  };

  const handleRuntimeUpdate = async (agent: AgentInfo) => {
    setUpdatingKey(agent.agent_key);
    setUpdateMessage("");
    setUpdateError("");
    try {
      const result = await requestAgentRuntimeUpdate(agent.agent_key);
      setUpdateMessage(result.message);
      setTargetHash(result.target_hash || targetHash);
      await refreshAgents();
    } catch (error: any) {
      setUpdateError(error?.response?.data?.detail || "提交 Agent 更新失败");
    } finally {
      setUpdatingKey("");
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-gray-100">
      <div className="mx-auto max-w-5xl px-4 py-6 sm:px-6 sm:py-8">
        <div className="mb-8 flex flex-wrap items-start justify-between gap-4">
          <div className="flex min-w-0 items-start gap-4">
            <button onClick={onBack} className="mt-1 shrink-0 text-sm text-slate-400 transition-colors hover:text-white">
              ← 返回
            </button>
            <div className="min-w-0">
              <h1 className="text-xl font-bold text-white">客户端下载</h1>
              <p className="mt-1 text-sm text-slate-400">Agent 配置已迁移到独立的“Agent 配置”页面。</p>
            </div>
          </div>
          <ThemeToggle />
        </div>

        <div className="mb-5 rounded-xl border border-slate-700 bg-slate-800/60 p-5">
          <p className="text-sm leading-relaxed text-slate-300">
            Agent 常驻在代码所在机器，负责索引、扫描、模型任务和漏洞验证；源代码不会上传到 Web 服务端。
          </p>
        </div>

        <div className="mb-5 rounded-xl border border-slate-700 bg-slate-800/60 p-5">
          <h2 className="mb-4 font-semibold text-white">1. 下载 Agent</h2>
          <button
            onClick={handleDownload}
            disabled={downloading}
            className="rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-medium text-white transition-colors hover:bg-blue-500 disabled:cursor-not-allowed disabled:bg-blue-900"
          >
            {downloading ? "正在下载…" : "下载 opendeephole-agent.zip"}
          </button>
          <p className="mt-3 text-xs text-slate-500">
            安装包需要 Python 3.10+，其中 agent.yaml 已填入当前服务地址。
          </p>
        </div>

        <div className="mb-5 rounded-xl border border-slate-700 bg-slate-800/60 p-5">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
            <h2 className="font-semibold text-white">2. 更新已安装的 Agent</h2>
            <span className="text-xs text-slate-500">更新不会中断正在执行的任务</span>
          </div>
          <p className="mb-4 text-sm leading-6 text-slate-400">
            点击后会登记更新请求。当前及后来提交的扫描继续执行，Agent 第一次完全空闲时自动更新并重连。
          </p>

          {updateMessage && (
            <div role="status" className="mb-3 rounded-lg border border-green-500/30 bg-green-500/10 px-3 py-2 text-sm text-green-300">
              {updateMessage}
            </div>
          )}
          {updateError && (
            <div role="alert" className="mb-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">
              {updateError}
            </div>
          )}

          {agentsLoading ? (
            <div role="status" className="py-8 text-center text-sm text-slate-500">正在加载 Agent…</div>
          ) : agents.length === 0 ? (
            <div className="rounded-lg border border-dashed border-slate-700 px-4 py-8 text-center text-sm text-slate-500">
              暂无 Agent，请先下载并启动客户端。
            </div>
          ) : (
            <div className="space-y-3">
              {agents.map((agent) => {
                const isLatest = Boolean(
                  targetHash
                  && agent.runtime_hash
                  && agent.runtime_hash === targetHash,
                );
                const status = agent.runtime_update_status || "";
                const isPending = status === "pending";
                const isUpdating = status === "updating";
                const isFailed = status === "failed";
                const submitting = updatingKey === agent.agent_key;
                const supportsOnlineUpdate = Boolean(agent.agent_key);
                const disabled = (
                  submitting
                  || !agent.online
                  || !supportsOnlineUpdate
                  || isLatest
                  || isPending
                  || isUpdating
                );
                const statusLabel = !supportsOnlineUpdate
                  ? "暂不支持在线更新"
                  : isLatest
                  ? "已是最新"
                  : isUpdating
                    ? "正在更新"
                    : isPending
                      ? "等待空闲"
                      : isFailed
                        ? "更新失败"
                        : agent.online
                          ? "可更新"
                          : "离线";
                const buttonLabel = submitting
                  ? "提交中…"
                  : !supportsOnlineUpdate
                    ? "请重新安装 Agent"
                  : isLatest
                    ? "已是最新"
                    : isUpdating
                      ? "正在更新…"
                      : isPending
                        ? "等待空闲更新"
                        : isFailed
                          ? "重试更新"
                          : agent.online
                            ? "更新 Agent"
                            : "Agent 离线";

                return (
                  <div key={agent.agent_key} className="rounded-lg border border-slate-700 bg-slate-950/50 p-4">
                    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="truncate text-sm font-medium text-white" title={agent.machine_name || agent.name}>
                            {agent.machine_name || agent.name}
                          </p>
                          <span className={`rounded border px-2 py-0.5 text-xs ${
                            isLatest
                              ? "border-green-500/30 bg-green-500/10 text-green-300"
                              : isFailed
                                ? "border-red-500/30 bg-red-500/10 text-red-300"
                                : isPending || isUpdating
                                  ? "border-amber-500/30 bg-amber-500/10 text-amber-300"
                                  : agent.online
                                    ? "border-blue-500/30 bg-blue-500/10 text-blue-300"
                                    : "border-slate-600 bg-slate-700 text-slate-400"
                          }`}>
                            {statusLabel}
                          </span>
                        </div>
                        <p className="mt-1 truncate text-xs text-slate-500" title={`${agent.ip}${agent.name ? ` · ${agent.name}` : ""}`}>
                          {agent.ip}{agent.name && agent.name !== agent.machine_name ? ` · ${agent.name}` : ""}
                        </p>
                        {isFailed && agent.runtime_update_error && (
                          <p className="mt-2 text-xs text-red-300">{agent.runtime_update_error}</p>
                        )}
                      </div>
                      <button
                        type="button"
                        onClick={() => void handleRuntimeUpdate(agent)}
                        disabled={disabled}
                        className="shrink-0 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-500 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
                      >
                        {buttonLabel}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="rounded-xl border border-slate-700 bg-slate-800/60 p-5">
          <h2 className="mb-4 font-semibold text-white">3. 启动 Agent</h2>
          <p className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-400">Linux / macOS</p>
          <pre className="mb-4 overflow-x-auto rounded-lg border border-slate-700 bg-slate-950 p-3 text-sm text-green-400">{`chmod +x run_agent.sh\n./run_agent.sh`}</pre>
          <p className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-400">Windows</p>
          <pre className="overflow-x-auto rounded-lg border border-slate-700 bg-slate-950 p-3 text-sm text-green-400">run_agent.bat</pre>
        </div>
      </div>
    </div>
  );
}
