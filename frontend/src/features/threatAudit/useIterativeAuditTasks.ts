import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getScanPatternTaskDetail, getScanPatternTasksPage } from "../../api/client";
import { mergePatternTasks } from "../../scanRuntime";
import type { ThreatPatternAuditTask } from "../../types";

/** Fetch summaries only; selected rounds load their clues separately. */
export function useIterativeAuditTasks(scanId: string, engineId: string, enabled: boolean, incoming: ThreatPatternAuditTask[], refreshRevision: number) {
  const [saved, setSaved] = useState<ThreatPatternAuditTask[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const controllerRef = useRef<AbortController | null>(null);
  const loadedPagesRef = useRef(0);
  const extraIdsRef = useRef(new Set<string>());
  const savedRef = useRef(saved);
  savedRef.current = saved;
  const failedRefreshRef = useRef(false);
  const revisionRef = useRef(refreshRevision);
  const loadPage = useCallback(async (after: string | null, refresh = false) => {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    setLoading(true);
    setError("");
    try {
      const pageCount = refresh ? Math.max(1, loadedPagesRef.current) : 1;
      let nextCursor = after;
      let pagesRead = 0;
      let loaded: ThreatPatternAuditTask[] = [];
      do {
        const page = await getScanPatternTasksPage(scanId, nextCursor, controller.signal, engineId);
        if (page.next_cursor && page.next_cursor === nextCursor) throw new Error("任务游标未前进");
        loaded = mergePatternTasks(loaded, page.items);
        nextCursor = page.next_cursor;
        pagesRead += 1;
      } while (refresh && nextCursor && pagesRead < pageCount && !controller.signal.aborted);
      if (refresh) {
        const loadedIds = new Set(loaded.map((task) => task.task_id));
        // Direct adjacent-round navigation can leave gaps in the paged list.
        for (const id of extraIdsRef.current) {
          if (loadedIds.has(id)) continue;
          loaded = mergePatternTasks(loaded, [await getScanPatternTaskDetail(scanId, id, controller.signal)]);
        }
      }
      if (controller.signal.aborted) return;
      setSaved((previous) => mergePatternTasks(previous, loaded));
      setCursor(nextCursor);
      loadedPagesRef.current = refresh ? pagesRead : loadedPagesRef.current + pagesRead;
      failedRefreshRef.current = false;
    } catch {
      if (!controller.signal.aborted) {
        failedRefreshRef.current = refresh;
        setError("审计任务加载失败");
      }
    } finally {
      if (!controller.signal.aborted) setLoading(false);
    }
  }, [scanId, engineId]);
  useEffect(() => {
    setSaved([]);
    setCursor(null);
    loadedPagesRef.current = 0;
    extraIdsRef.current.clear();
    revisionRef.current = refreshRevision;
    if (enabled) void loadPage(null, true);
    return () => controllerRef.current?.abort();
  }, [enabled, loadPage]);
  useEffect(() => {
    if (revisionRef.current === refreshRevision) return;
    revisionRef.current = refreshRevision;
    if (enabled) void loadPage(null, true);
  }, [enabled, loadPage, refreshRevision]);
  const addTask = useCallback((task: ThreatPatternAuditTask) => {
    if (!savedRef.current.some((item) => item.task_id === task.task_id)) extraIdsRef.current.add(task.task_id);
    setSaved((previous) => mergePatternTasks(previous, [task]));
  }, []);
  const tasks = useMemo(() => (enabled ? mergePatternTasks(saved, incoming) : incoming)
    .filter((task) => (task.engine_id || "threat_pattern_audit") === engineId), [saved, incoming, engineId, enabled]);
  return { tasks, loading, error, cursor, addTask,
    loadMore: () => failedRefreshRef.current ? loadPage(null, true) : loadPage(cursor) };
}
