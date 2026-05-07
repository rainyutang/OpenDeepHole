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
      alert(`Download failed: ${e}`);
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 p-6">
      <div className="max-w-3xl mx-auto">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <button
            onClick={onBack}
            className="text-gray-400 hover:text-gray-200 transition-colors"
          >
            ← Back
          </button>
          <h1 className="text-2xl font-bold text-white">Download Agent</h1>
        </div>

        {/* Description */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 mb-6">
          <p className="text-gray-300 mb-2">
            The agent runs on your local machine, scans your C/C++ source code, and
            sends only the vulnerability results to this server.
          </p>
          <p className="text-gray-400 text-sm">
            Source code never leaves your machine. False-positive feedback you mark in
            the UI is automatically used on the next agent run.
          </p>
        </div>

        {/* Download button */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 mb-6">
          <h2 className="text-lg font-semibold text-white mb-4">1. Download</h2>
          <button
            onClick={handleDownload}
            disabled={downloading}
            className="px-6 py-3 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors"
          >
            {downloading ? "Downloading..." : "Download opendeephole-agent.zip"}
          </button>
        </div>

        {/* Setup instructions */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 mb-6">
          <h2 className="text-lg font-semibold text-white mb-4">2. Configure</h2>
          <p className="text-gray-400 text-sm mb-3">
            Unzip the archive, then edit <code className="text-blue-400">agent.yaml</code>:
          </p>
          <pre className="bg-gray-950 border border-gray-700 rounded p-4 text-sm text-gray-300 overflow-x-auto">{`server_url: "${window.location.origin}"

mode: "api"   # or "opencode" if you have opencode CLI installed

llm_api:
  base_url: "https://api.anthropic.com"
  api_key: "your-api-key-here"
  model: "claude-sonnet-4-6"`}</pre>
        </div>

        {/* Run instructions */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 mb-6">
          <h2 className="text-lg font-semibold text-white mb-4">3. Run</h2>

          <div className="mb-4">
            <p className="text-gray-400 text-sm mb-2 font-medium">Linux / macOS:</p>
            <pre className="bg-gray-950 border border-gray-700 rounded p-3 text-sm text-green-400 overflow-x-auto">{`chmod +x run_agent.sh
./run_agent.sh /path/to/your/project --name "MyProject"`}</pre>
          </div>

          <div className="mb-4">
            <p className="text-gray-400 text-sm mb-2 font-medium">Windows:</p>
            <pre className="bg-gray-950 border border-gray-700 rounded p-3 text-sm text-green-400 overflow-x-auto">{`run_agent.bat C:\\path\\to\\your\\project --name "MyProject"`}</pre>
          </div>

          <div>
            <p className="text-gray-400 text-sm mb-2 font-medium">Options:</p>
            <pre className="bg-gray-950 border border-gray-700 rounded p-3 text-sm text-gray-400 overflow-x-auto">{`  --server URL        Override server_url from agent.yaml
  --checkers LIST     e.g. npd,oob,uaf,intoverflow
  --name NAME         Display name in the web UI
  --dry-run           Run locally without sending results to server`}</pre>
          </div>
        </div>

        {/* Feedback note */}
        <div className="bg-blue-950/30 border border-blue-800/40 rounded-lg p-4">
          <p className="text-blue-300 text-sm">
            <span className="font-semibold">Feedback sync:</span> When you mark a
            vulnerability as a false positive in the web UI, the agent automatically
            fetches this feedback on the next run and uses it to reduce false positives.
          </p>
        </div>
      </div>
    </div>
  );
}
