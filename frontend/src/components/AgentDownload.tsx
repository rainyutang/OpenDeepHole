import { useState } from "react";

interface Props {
  onBack: () => void;
}

export default function AgentDownload({ onBack }: Props) {
  const [downloading, setDownloading] = useState(false);

  const handleDownload = async () => {
    setDownloading(true);
    try {
      const resp = await fetch("/api/agent/download");
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "opendeephole-agent.zip";
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      alert(`下载失败：${e}`);
    } finally {
      setDownloading(false);
    }
  };

  const origin = window.location.origin;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-gray-100">
      <div className="max-w-3xl mx-auto px-6 py-8">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <button
            onClick={onBack}
            className="text-slate-400 hover:text-slate-200 transition-colors flex items-center gap-1 text-sm"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
            返回
          </button>
          <h1 className="text-xl font-bold text-white">下载 Agent</h1>
        </div>

        {/* 简介 */}
        <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-5 mb-5">
          <p className="text-slate-300 text-sm leading-relaxed">
            Agent 是运行在你本地机器上的常驻服务程序。它启动后向 Web Server 注册，由 Web 端「新建扫描」下发任务，在本地执行代码索引、静态分析和 AI 审计，仅将漏洞结果回传到服务端展示。<span className="text-slate-400">源代码始终不离开本机。</span>
          </p>
        </div>

        {/* 第一步：下载 */}
        <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-5 mb-5">
          <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
            <span className="w-6 h-6 rounded-full bg-blue-600 text-white text-xs flex items-center justify-center font-bold">1</span>
            下载安装包
          </h2>
          <button
            onClick={handleDownload}
            disabled={downloading}
            className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors text-sm"
          >
            {downloading ? "正在下载..." : "下载 opendeephole-agent.zip"}
          </button>
          <p className="text-slate-500 text-xs mt-3">解压后即可使用，无需编译。需要 Python 3.10+。</p>
        </div>

        {/* 第二步：配置 */}
        <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-5 mb-5">
          <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
            <span className="w-6 h-6 rounded-full bg-blue-600 text-white text-xs flex items-center justify-center font-bold">2</span>
            编辑 <code className="text-blue-400 font-mono">agent.yaml</code>
          </h2>
          <p className="text-slate-400 text-sm mb-3">解压后修改以下关键配置项：</p>
          <pre className="bg-slate-900 border border-slate-700 rounded-lg p-4 text-sm text-slate-300 overflow-x-auto leading-relaxed">{`# Web Server 地址（本服务的访问地址）
server_url: "${origin}"

# Agent 监听端口（默认 7000，确保防火墙放行）
agent_port: 7000

# Agent 显示名称（在新建扫描的下拉列表中显示）
agent_name: "my-agent"

# LLM API 配置（供 mode: api 的检查项使用）
# 各检查项的调用方式在其 checker.yaml 中独立配置
llm_api:
  base_url: "https://api.anthropic.com"
  api_key: "your-api-key-here"
  model: "claude-sonnet-4-6"

# opencode CLI 配置（供 mode: opencode 的检查项使用）
opencode:
  executable: "opencode"
  timeout: 300`}</pre>
        </div>

        {/* 第三步：启动 */}
        <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-5 mb-5">
          <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
            <span className="w-6 h-6 rounded-full bg-blue-600 text-white text-xs flex items-center justify-center font-bold">3</span>
            启动 Agent 守护进程
          </h2>

          <div className="mb-4">
            <p className="text-slate-400 text-xs mb-2 font-medium uppercase tracking-wide">Linux / macOS</p>
            <pre className="bg-slate-900 border border-slate-700 rounded-lg p-3 text-sm text-green-400 overflow-x-auto">{`chmod +x run_agent.sh
./run_agent.sh`}</pre>
          </div>

          <div className="mb-5">
            <p className="text-slate-400 text-xs mb-2 font-medium uppercase tracking-wide">Windows</p>
            <pre className="bg-slate-900 border border-slate-700 rounded-lg p-3 text-sm text-green-400 overflow-x-auto">{`run_agent.bat`}</pre>
          </div>

          <p className="text-slate-400 text-sm mb-2">启动成功后，Agent 会自动注册到 Server，终端输出类似：</p>
          <pre className="bg-slate-900 border border-slate-700 rounded-lg p-3 text-xs text-slate-400 overflow-x-auto">{`OpenDeepHole Agent Daemon
  Name    : my-agent
  Server  : ${origin}
  Port    : 7000

  Registered as agent_id: a1b2c3d4...`}</pre>

          <div className="mt-4 pt-4 border-t border-slate-700">
            <p className="text-slate-400 text-xs mb-2 font-medium">可选启动参数：</p>
            <pre className="bg-slate-900 border border-slate-700 rounded-lg p-3 text-xs text-slate-400 overflow-x-auto">{`  --server URL    覆盖 agent.yaml 中的 server_url
  --port INT      覆盖监听端口（默认 7000）
  --name NAME     覆盖 Agent 显示名称
  --config FILE   指定 agent.yaml 路径`}</pre>
          </div>
        </div>

        {/* 第四步：新建扫描 */}
        <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-5 mb-5">
          <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
            <span className="w-6 h-6 rounded-full bg-blue-600 text-white text-xs flex items-center justify-center font-bold">4</span>
            在 Web 端创建扫描任务
          </h2>
          <ol className="text-slate-300 text-sm space-y-2 list-none">
            <li className="flex gap-2"><span className="text-slate-500 shrink-0">①</span>点击右上角「新建扫描」</li>
            <li className="flex gap-2"><span className="text-slate-500 shrink-0">②</span>从下拉列表选择已在线的 Agent</li>
            <li className="flex gap-2"><span className="text-slate-500 shrink-0">③</span>填写代码路径（Agent 所在机器上的绝对路径，如 <code className="text-blue-400 text-xs">/home/user/myproject</code>）</li>
            <li className="flex gap-2"><span className="text-slate-500 shrink-0">④</span>选择要运行的检查项，点击「开始扫描」</li>
            <li className="flex gap-2"><span className="text-slate-500 shrink-0">⑤</span>扫描进度实时显示在当前页面</li>
          </ol>
        </div>

        {/* 停止与恢复 */}
        <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-5 mb-5">
          <h2 className="text-base font-semibold text-white mb-3">停止与恢复</h2>
          <div className="space-y-3 text-sm">
            <div className="flex gap-3">
              <span className="text-red-400 font-medium shrink-0">停止</span>
              <span className="text-slate-300">扫描详情页点击「停止扫描」，Server 直接通知 Agent 停止。当前候选处理完成后立即停止，已处理的结果保留。</span>
            </div>
            <div className="flex gap-3">
              <span className="text-amber-400 font-medium shrink-0">恢复</span>
              <span className="text-slate-300">扫描列表页点击「恢复」，Server 通知 Agent 继续同一个扫描任务，自动跳过已处理的候选，从断点继续。无需重新启动 Agent 或重新索引代码。</span>
            </div>
          </div>
        </div>

        {/* 误报反馈 */}
        <div className="bg-blue-950/30 border border-blue-800/40 rounded-xl p-4">
          <p className="text-blue-300 text-sm leading-relaxed">
            <span className="font-semibold">误报反馈同步：</span>在 Web 端将某个漏洞标记为「误报」后，Agent 下次扫描时会自动拉取这些经验数据，合并到分析技能中，从而减少相同误报的出现。
          </p>
        </div>
      </div>
    </div>
  );
}
