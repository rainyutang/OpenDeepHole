import type { OutputSource } from "./issues";

export interface RedlineItem {
  item_id: string;
  code: string;
  security_attribute: string;
  attribute_description: string;
  requirement: string;
  category: string;
  guidance: string;
  remark: string;
  enabled: boolean;
  sort_order: number;
  created_at: string;
  updated_at: string;
}

export interface ScanRedlineItem {
  item_id: string;
  code: string;
  security_attribute: string;
  attribute_description: string;
  requirement: string;
  category: string;
  guidance: string;
  remark: string;
}

export interface RedlineItemInput {
  code: string;
  security_attribute: string;
  attribute_description: string;
  requirement: string;
  category: string;
  guidance: string;
  remark: string;
  enabled?: boolean;
}

export interface RedlineListResponse {
  items: RedlineItem[];
  total: number;
  enabled_count: number;
}

export interface RedlineSummaryResponse {
  total_count: number;
  enabled_count: number;
}

export interface RedlineImportResponse {
  created: number;
  updated: number;
  replaced: number;
  total: number;
  enabled_count: number;
  items: RedlineItem[];
}

export interface RedlineAuditTask {
  next_task_id?: string;
  task_id: string;
  scan_id?: string;
  redline_item_id: string;
  item_code: string;
  security_attribute: string;
  attribute_description: string;
  requirement: string;
  category: string;
  iteration: number;
  max_iterations: number;
  parent_task_id?: string;
  status: string;
  found?: boolean | null;
  stop_reason?: string;
  validation_retries?: number;
  result_vuln_indexes?: number[];
  failure_reason?: string;
  output_source?: OutputSource;
  created_at?: string;
  started_at?: string;
  finished_at?: string;
  updated_at?: string;
}

export interface RedlineAuditTaskPage {
  items: RedlineAuditTask[];
  next_cursor: string | null;
  has_more: boolean;
}
