import { useCallback, useEffect, useState } from "react";
import { getScanRedlineAuditTasksPage } from "../../api/redlines";
import type { RedlineAuditTask } from "../../types/redlines";

export function useRedlineAuditTasks(
  scanId: string,
  enabled: boolean,
  fallbackTasks: readonly RedlineAuditTask[],
  taskRevision: number,
) {
  const [tasks, setTasks] = useState<RedlineAuditTask[]>(() => [...fallbackTasks]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [manualReload, setManualReload] = useState(0);

  const reload = useCallback(() => {
    setManualReload((value) => value + 1);
  }, []);

  useEffect(() => {
    if (!enabled) {
      setTasks([...fallbackTasks]);
      setLoading(false);
      setError("");
      return;
    }
    const controller = new AbortController();
    let disposed = false;
    setLoading(true);
    setError("");
    (async () => {
      const collected: RedlineAuditTask[] = [];
      const seenCursors = new Set<string>();
      let cursor: string | null = null;
      do {
        const page = await getScanRedlineAuditTasksPage(scanId, cursor, controller.signal, 200);
        if (disposed || controller.signal.aborted) return;
        collected.push(...page.items);
        const next = page.next_cursor;
        if (!page.has_more || !next || seenCursors.has(next)) break;
        seenCursors.add(next);
        cursor = next;
      } while (cursor);
      if (!disposed && !controller.signal.aborted) {
        setTasks(collected);
      }
    })().catch((caught: unknown) => {
      if (disposed || controller.signal.aborted) return;
      const detail = (caught as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
      setError(typeof detail === "string" && detail.trim() ? detail : "加载红线排查进度失败");
    }).finally(() => {
      if (!disposed && !controller.signal.aborted) {
        setLoading(false);
      }
    });
    return () => {
      disposed = true;
      controller.abort();
    };
  }, [scanId, enabled, taskRevision, manualReload]);

  return {
    tasks: enabled ? tasks : [...fallbackTasks],
    loading,
    error,
    reload,
  };
}
