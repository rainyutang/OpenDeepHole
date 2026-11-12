import type { OutputSource } from "./issues";

export interface CheckerInfo {
  name: string;
  label: string;
  description: string;
  visibility: "public" | "admin";
  category: string;
  category_label: string;
  modified_at: string;
  user_created: boolean;
  created_by_user_id: string;
  creator_username: string;
  can_delete: boolean;
  result_mode: string;
  timeout_seconds?: number | null;
  model_capability?: "any" | "low" | "medium" | "high" | string;
}

export interface CheckerCatalogItem {
  name: string;
  label: string;
  description: string;
  enabled: boolean;
  visibility: "public" | "admin";
  category: string;
  category_label: string;
  modified_at: string;
  introduction: string;
  introduction_source: string;
  user_created: boolean;
  created_by_user_id: string;
  creator_username: string;
  can_delete: boolean;
  result_mode: string;
  timeout_seconds?: number | null;
  model_capability?: "any" | "low" | "medium" | "high" | string;
}

export interface SkillDraft {
  skill_md: string;
  scenarios_md: string;
  summary: string;
}

export interface SkillCreateJob {
  job_id: string;
  status: "pending" | "running" | "completed" | "error";
  skill_id: string;
  name: string;
  description: string;
  input: string;
  agent_id: string;
  agent_name: string;
  user_id: string;
  created_at: string;
  updated_at: string;
  error_message: string;
  draft: SkillDraft | null;
}

export interface SkillImportFile {
  path: string;
  content_b64: string;
}

export interface SkillReport {
  id?: number | null;
  scan_id: string;
  checker_name: string;
  filename: string;
  title: string;
  content: string;
  created_at: string;
  output_source?: OutputSource;
}
