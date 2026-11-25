import { api } from "./transport";

export interface AdminKnowledgeBaseConfig {
  configured: boolean;
  name: string;
  url: string;
  timeout_seconds: number;
  header_keys: string[];
  updated_at: string;
  revision: number;
  source: "database" | "config" | "none";
}

export interface UpdateAdminKnowledgeBaseConfigInput {
  url: string;
  name?: string;
  timeout_seconds?: number;
  headers?: Record<string, string> | null;
  clear_headers?: boolean;
}

export interface KnowledgeBasePublicStatus {
  configured: boolean;
  name: string;
}

export async function getAdminKnowledgeBaseConfig(): Promise<AdminKnowledgeBaseConfig> {
  const { data } = await api.get<AdminKnowledgeBaseConfig>("/api/admin/knowledge-base");
  return data;
}

export async function updateAdminKnowledgeBaseConfig(
  body: UpdateAdminKnowledgeBaseConfigInput,
): Promise<AdminKnowledgeBaseConfig> {
  const { data } = await api.put<AdminKnowledgeBaseConfig>("/api/admin/knowledge-base", body);
  return data;
}

export async function getKnowledgeBaseStatus(): Promise<KnowledgeBasePublicStatus> {
  const { data } = await api.get<KnowledgeBasePublicStatus>("/api/knowledge-base/status");
  return data;
}
