import { useCallback, useEffect, useRef, useState } from "react";
import { getScanRedlineAuditTasksPage } from "../../api/redlines";
import { createCoalescedRefresh } from "../../hooks/scanSSE/coalescedRefresh";
import type { RedlineAuditTask } from "../../types/redlines";

export function useRedlineAuditTasks(
  scanId: string,
  enabled: boolean,
  fallbackTasks: readonly RedlineAuditTask[],
  taskRevision: number,
) {
  const [tasks, setTasks] = useState<RedlineAuditTask[]>(() => [...fallbackTasks]);
  const [hasLoaded, setHasLoaded] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const revisionRef = useRef(taskRevision);
  const refreshRef = useRef<(immediate?: boolean) => void>(() => {});

  const retry = useCallback(() => {
    refreshRef.current(true);
  }, []);

  useEffect(() => {
    if (!enabled) {
      setTasks([...fallbackTasks]);
      setHasLoaded(false);
      setLoading(false);
      setError("");
      refreshRef.current = () => {};
      return;
    }
    const controller = new AbortController();
    let disposed = false;
    setTasks([...fallbackTasks]);
    setHasLoaded(false);
    setError("");
    revisionRef.current = taskRevision;

    const loadAllPages = async () => {
      if (disposed || controller.signal.aborted) return;
      setLoading(true);
      setError("");
      try {
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
          setHasLoaded(true);
        }
      } catch (caught: unknown) {
        if (disposed || controller.signal.aborted) return;
        const detail = (caught as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
        setError(typeof detail === "string" && detail.trim() ? detail : "加载红线排查进度失败");
      } finally {
        if (!disposed && !controller.signal.aborted) {
          setLoading(false);
        }
      }
    };

    const scheduler = createCoalescedRefresh(loadAllPages);
    refreshRef.current = (immediate = false) => scheduler.request(immediate);
    scheduler.request(true);
    return () => {
      disposed = true;
      scheduler.dispose();
      controller.abort();
      refreshRef.current = () => {};
    };
  }, [scanId, enabled]);

  useEffect(() => {
    if (!enabled) return;
    if (revisionRef.current === taskRevision) return;
    revisionRef.current = taskRevision;
    refreshRef.current(false);
  }, [scanId, enabled, taskRevision]);

  return {
    tasks: enabled ? tasks : [...fallbackTasks],
    hasLoaded: enabled ? hasLoaded : true,
    loading,
    error,
    retry,
  };
}
