import type {
  AdminUserSummary,
  DeleteDepartmentResponse,
  Department,
  SortDirection,
  TokenResponse,
  User,
  UserProfileInput,
  UserSortField,
} from "../types/auth";
import { api } from "./transport";

export async function login(username: string, password: string): Promise<TokenResponse> {
  const { data } = await api.post<TokenResponse>("/api/auth/login", { username, password });
  localStorage.setItem("auth_token", data.token);
  localStorage.setItem("auth_user", JSON.stringify(data.user));
  return data;
}

export async function register(username: string, password: string): Promise<TokenResponse> {
  const { data } = await api.post<TokenResponse>("/api/auth/register", { username, password });
  localStorage.setItem("auth_token", data.token);
  localStorage.setItem("auth_user", JSON.stringify(data.user));
  return data;
}

export function logout(): void {
  localStorage.removeItem("auth_token");
  localStorage.removeItem("auth_user");
}

export function getStoredUser(): User | null {
  const raw = localStorage.getItem("auth_user");
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export function isAuthenticated(): boolean {
  return !!localStorage.getItem("auth_token");
}

export async function getCurrentUser(): Promise<User> {
  const { data } = await api.get<User>("/api/auth/me");
  return data;
}

export async function changePassword(oldPassword: string, newPassword: string): Promise<void> {
  await api.put("/api/auth/password", { old_password: oldPassword, new_password: newPassword });
}

export async function listUsers(params?: {
  department_id?: string;
  sort_by?: UserSortField;
  sort_order?: SortDirection;
}): Promise<AdminUserSummary[]> {
  const { data } = await api.get<AdminUserSummary[]>(
    "/api/auth/users",
    params ? { params } : undefined,
  );
  return data;
}

export async function createUser(
  username: string,
  password: string,
  role: string,
  profile?: UserProfileInput,
): Promise<AdminUserSummary> {
  const { data } = await api.post<AdminUserSummary>("/api/auth/users", {
    username,
    password,
    role,
    employee_id: profile?.employee_id ?? "",
    department_id: profile?.department_id ?? "",
  });
  return data;
}

export async function updateUserProfile(
  userId: string,
  profile: Required<UserProfileInput>,
): Promise<AdminUserSummary> {
  const { data } = await api.put<AdminUserSummary>(`/api/auth/users/${userId}/profile`, profile);
  return data;
}

export async function deleteUser(userId: string): Promise<void> {
  await api.delete(`/api/auth/users/${userId}`);
}

export async function listDepartments(): Promise<Department[]> {
  const { data } = await api.get<Department[]>("/api/auth/departments");
  return data;
}

export async function createDepartment(name: string): Promise<Department> {
  const { data } = await api.post<Department>("/api/auth/departments", { name });
  return data;
}

export async function updateDepartment(departmentId: string, name: string): Promise<Department> {
  const { data } = await api.put<Department>(`/api/auth/departments/${departmentId}`, { name });
  return data;
}

export async function deleteDepartment(departmentId: string): Promise<DeleteDepartmentResponse> {
  const { data } = await api.delete<DeleteDepartmentResponse>(`/api/auth/departments/${departmentId}`);
  return data;
}
