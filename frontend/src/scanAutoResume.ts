import type { ScanAutoResume } from "./types/scans";

export const AUTO_RESUME_LIMIT = 3;

export function autoResumeActive(scan: ScanAutoResume): boolean {
  return scan.auto_resume_enabled === true
    && ["pending", "running", "waiting"].includes(scan.auto_resume_state ?? "idle");
}

export function autoResumeLabel(scan: ScanAutoResume): string {
  if (!scan.auto_resume_enabled) return "";
  const count = Math.max(0, scan.auto_resume_count ?? 0);
  if (scan.auto_resume_state === "exhausted") return `自动续扫已达上限（${count}/${AUTO_RESUME_LIMIT}）`;
  if (scan.auto_resume_state === "waiting") return `等待自动续扫（${count}/${AUTO_RESUME_LIMIT}）`;
  if (scan.auto_resume_state === "pending") return `准备自动续扫（${count}/${AUTO_RESUME_LIMIT}）`;
  if (scan.auto_resume_state === "running") return `自动续扫 ${count}/${AUTO_RESUME_LIMIT}`;
  if (scan.auto_resume_state === "paused") return `自动续扫已暂停（${count}/${AUTO_RESUME_LIMIT}）`;
  return `自动续扫 ${count}/${AUTO_RESUME_LIMIT}`;
}
