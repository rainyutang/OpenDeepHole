import type { ScanStatus } from "../types";
import { staticAnalysisFailures } from "../staticAudit";

export default function StaticAnalysisFailures({ scan }: { scan: Pick<ScanStatus, "mining_engine_runs" | "static_analysis_done"> }) {
  const failures = staticAnalysisFailures(scan);
  if (failures.length === 0) return null;
  return (
    <div role="alert" className="mb-4 rounded-lg border border-amber-700/50 bg-amber-950/20 p-3 text-sm text-amber-200">
      <div className="font-medium">
        {scan.static_analysis_done ? "完成（部分规则失败）" : "存在失败的静态规则"}：{failures.length} 条
      </div>
      <p className="mt-1 text-xs text-amber-200/80">失败规则未完成检测；其余规则的结果已保留。</p>
      <ul className="mt-2 space-y-2">
        {failures.map((failure) => (
          <li key={`${failure.engine_id}:${failure.version_name ?? ""}:${failure.checker_name}`}>
            <details>
              <summary className="cursor-pointer break-words">
                {failure.version_name && `[${failure.version_name}] `}
                {failure.checker_label || failure.checker_name}
                {failure.exit_code != null && ` · 退出码 ${failure.exit_code}`}
                {`：${failure.error.split("\n")[0]}`}
              </summary>
              <pre className="mt-1 max-h-60 overflow-auto whitespace-pre-wrap break-words text-xs">{failure.error}</pre>
            </details>
          </li>
        ))}
      </ul>
    </div>
  );
}
