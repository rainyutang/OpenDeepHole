import type { TaskTone } from "./types";

export function toneText(tone: TaskTone): string {
  return {
    slate: "text-slate-300",
    cyan: "text-cyan-300",
    amber: "text-amber-300",
    green: "text-green-300",
    red: "text-red-300",
    purple: "text-purple-300",
    blue: "text-blue-300",
  }[tone];
}

export function toneBorder(tone: TaskTone): string {
  return {
    slate: "border-slate-700",
    cyan: "border-cyan-500/30",
    amber: "border-amber-500/30",
    green: "border-green-500/30",
    red: "border-red-500/30",
    purple: "border-purple-500/30",
    blue: "border-blue-500/30",
  }[tone];
}

export function toneBg(tone: TaskTone): string {
  return {
    slate: "bg-slate-800",
    cyan: "bg-cyan-500/10",
    amber: "bg-amber-500/10",
    green: "bg-green-500/10",
    red: "bg-red-500/10",
    purple: "bg-purple-500/10",
    blue: "bg-blue-500/10",
  }[tone];
}

export function toneFill(tone: TaskTone): string {
  return {
    slate: "bg-slate-500",
    cyan: "bg-cyan-400",
    amber: "bg-amber-400",
    green: "bg-green-500",
    red: "bg-red-500",
    purple: "bg-purple-500",
    blue: "bg-blue-500",
  }[tone];
}
