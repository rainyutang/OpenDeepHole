import { useState } from "react";
import { register } from "../api/client";
import type { User } from "../types";

interface Props {
  onRegister: (user: User) => void;
  onGoLogin: () => void;
}

export default function RegisterPage({ onRegister, onGoLogin }: Props) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (password !== confirmPassword) {
      setError("两次输入的密码不一致");
      return;
    }

    setLoading(true);
    try {
      const resp = await register(username, password);
      onRegister(resp.user);
    } catch (err: any) {
      const msg = err.response?.data?.detail || "注册失败";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <h1 className="text-2xl font-bold text-white">OpenDeepHole</h1>
          <p className="text-sm text-slate-400 mt-1">C/C++ Source Code Audit Tool</p>
        </div>

        <form
          onSubmit={handleSubmit}
          className="bg-slate-800/80 backdrop-blur border border-slate-700 rounded-xl shadow-2xl p-6"
        >
          <h2 className="text-lg font-semibold text-white mb-5">注册</h2>

          {error && (
            <div className="mb-4 px-3 py-2 text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg">
              {error}
            </div>
          )}

          <div className="mb-4">
            <label className="block text-sm font-medium text-slate-400 mb-1.5">
              用户名
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white text-sm placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              placeholder="至少2个字符"
              autoFocus
              required
            />
          </div>

          <div className="mb-4">
            <label className="block text-sm font-medium text-slate-400 mb-1.5">
              密码
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white text-sm placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              placeholder="至少4个字符"
              required
            />
          </div>

          <div className="mb-6">
            <label className="block text-sm font-medium text-slate-400 mb-1.5">
              确认密码
            </label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white text-sm placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              placeholder="再次输入密码"
              required
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors"
          >
            {loading ? "注册中..." : "注册"}
          </button>

          <p className="mt-4 text-center text-sm text-slate-400">
            已有账号？{" "}
            <button
              type="button"
              onClick={onGoLogin}
              className="text-blue-400 hover:text-blue-300 transition-colors"
            >
              登录
            </button>
          </p>
        </form>
      </div>
    </div>
  );
}
