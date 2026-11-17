export interface Department {
  department_id: string;
  name: string;
  user_count: number;
  created_at: string;
  updated_at: string;
}

export interface DeleteDepartmentResponse {
  ok: boolean;
  department_id: string;
  cleared_user_count: number;
}

export interface User {
  user_id: string;
  username: string;
  role: "admin" | "user";
  agent_token: string;
  created_at: string;
  employee_id?: string;
  department_id?: string;
  department_name?: string;
}

export interface AdminUserSummary extends User {
  employee_id: string;
  department_id: string;
  department_name: string;
  scan_count: number;
  suspected_issue_count: number;
}

export interface UserProfileInput {
  employee_id?: string;
  department_id?: string;
}

export type UserSortField = "created_at" | "scan_count" | "suspected_issue_count";
export type SortDirection = "asc" | "desc";

export interface TokenResponse {
  token: string;
  user: User;
}
