import { useState } from "react";

interface Props {
  onBack: () => void;
}

export default function AgentDownload({ onBack }: Props) {
  const [downloading, setDownloading] = useState(false);

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

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-gray-100">
      <div className="mx-auto max-w-5xl px-6 py-8">
        <div className="mb-8 flex items-center gap-4">
          <button onClick={onBack} className="text-sm text-slate-400 transition-colors hover:text-white">
            ← 返回
          </button>
          <div>
            <h1 className="text-xl font-bold text-white">客户端下载</h1>
            <p className="mt-1 text-sm text-slate-400">Agent 配置已迁移到独立的“Agent 配置”页面。</p>
          </div>
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

        <div className="rounded-xl border border-slate-700 bg-slate-800/60 p-5">
          <h2 className="mb-4 font-semibold text-white">2. 启动 Agent</h2>
          <p className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-400">Linux / macOS</p>
          <pre className="mb-4 overflow-x-auto rounded-lg border border-slate-700 bg-slate-950 p-3 text-sm text-green-400">{`chmod +x run_agent.sh\n./run_agent.sh`}</pre>
          <p className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-400">Windows</p>
          <pre className="overflow-x-auto rounded-lg border border-slate-700 bg-slate-950 p-3 text-sm text-green-400">run_agent.bat</pre>
        </div>
      </div>
    </div>
  );
}
