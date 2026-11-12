export interface User {
  user_id: string;
  username: string;
  role: "admin" | "user";
  agent_token: string;
  created_at: string;
}

export interface TokenResponse {
  token: string;
  user: User;
}
