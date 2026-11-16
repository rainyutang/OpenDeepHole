/** One request in flight, with one trailing refresh for changes received meanwhile. */
export function createCoalescedRefresh(run: () => Promise<void>, interval = 1000) {
  let timer: ReturnType<typeof setTimeout> | null = null;
  let running = false;
  let dirty = false;
  let disposed = false;
  let lastStarted = -Infinity;
  const schedule = (immediate = false) => {
    if (disposed || running || timer !== null || !dirty) return;
    if (immediate) { void flush(); return; }
    const delay = Math.max(150, lastStarted + interval - Date.now());
    timer = setTimeout(() => { void flush(); }, delay);
  };
  const flush = async () => {
    timer = null;
    if (disposed || !dirty) return;
    dirty = false;
    running = true;
    lastStarted = Date.now();
    try { await run(); }
    finally { running = false; schedule(); }
  };
  return {
    request(immediate = false) { dirty = true; schedule(immediate); },
    dispose() { disposed = true; if (timer !== null) clearTimeout(timer); },
  };
}
