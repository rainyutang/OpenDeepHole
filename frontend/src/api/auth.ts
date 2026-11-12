import type { TokenResponse, User } from "../types/auth";
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

export async function listUsers(): Promise<User[]> {
  const { data } = await api.get<User[]>("/api/auth/users");
  return data;
}

export async function createUser(username: string, password: string, role: string): Promise<User> {
  const { data } = await api.post<User>("/api/auth/users", { username, password, role });
  return data;
}

export async function deleteUser(userId: string): Promise<void> {
  await api.delete(`/api/auth/users/${userId}`);
}
