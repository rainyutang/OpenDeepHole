import type { VulnerabilityValidation } from "../../../types/issues";
import type { TaskTone } from "./types";

export function validationOutputSections(validation: VulnerabilityValidation) {
  const sections = (validation.output_sections ?? [])
    .filter((section) => section && (section.title || section.content))
    .map((section) => ({
      title: section.title || "中间产出",
      content: section.content || "",
      updated_at: section.updated_at || "",
    }));
  if (sections.length > 0) return sections;
  if (validation.intermediate_output) {
    return [{ title: "中间产出", content: validation.intermediate_output, updated_at: validation.updated_at }];
  }
  return [];
}

export function groupedValidationArtifacts(artifacts: NonNullable<VulnerabilityValidation["artifacts"]>) {
  const groups = new Map<string, typeof artifacts>();
  for (const artifact of artifacts) {
    const title = artifact.title?.trim() || "产物";
    const items = groups.get(title) ?? [];
    items.push(artifact);
    groups.set(title, items);
  }
  return Array.from(groups.entries());
}

export function validationStatusLabel(status: string): string {
  const labels: Record<string, string> = {
    pending: "等待",
    queued: "等待",
    running: "验证中",
    verified: "已验证",
    success: "已验证",
    failed: "未通过",
    error: "异常",
    timeout: "超时",
    cancelled: "已取消",
    skipped: "跳过",
  };
  return labels[status] ?? status;
}

export function formatNullableBool(value?: boolean | null): string {
  if (value === true) return "是";
  if (value === false) return "否";
  return "未知";
}

export function nullableBoolTone(value?: boolean | null): TaskTone {
  if (value === true) return "green";
  if (value === false) return "amber";
  return "slate";
}

export function humanInterventionTone(value?: boolean | null): TaskTone {
  if (value === true) return "amber";
  if (value === false) return "green";
  return "slate";
}

export function validationTone(validation?: VulnerabilityValidation): TaskTone {
  const status = validation?.status || "pending";
  if (validation?.running || status === "queued" || status === "running") return "blue";
  if (isValidationFailed(status)) return "red";
  if (isValidationComplete(status)) return "green";
  return "slate";
}

export function validationSortRank(validation?: VulnerabilityValidation): number {
  if (!validation) return 1;
  if (validation.running || validation.status === "running") return 0;
  if (validation.status === "queued" || validation.status === "pending") return 1;
  if (isValidationFailed(validation.status)) return 2;
  if (isValidationComplete(validation.status)) return 3;
  return 4;
}

export function isValidationComplete(status: string): boolean {
  return ["verified", "success", "failed"].includes(status);
}

export function isValidationFailed(status: string): boolean {
  return ["error", "timeout", "cancelled"].includes(status);
}
