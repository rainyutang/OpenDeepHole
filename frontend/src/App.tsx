import { useEffect, useState } from "react";
import { getStoredUser, isAuthenticated, logout } from "./api/client";
import ScanStatusView from "./components/ScanStatus";
import ScanHistory from "./components/ScanHistory";
import AgentDownload from "./components/AgentDownload";
import NewScanForm from "./components/NewScanForm";
import LoginPage from "./components/LoginPage";
import RegisterPage from "./components/RegisterPage";
import UserManagement from "./components/UserManagement";
import type { User } from "./types";

type Page = "history" | "newScan" | "scanning" | "agent" | "users";
type AuthPage = "login" | "register";

export default function App() {
  const [user, setUser] = useState<User | null>(getStoredUser);
  const [page, setPage] = useState<Page>("history");
  const [authPage, setAuthPage] = useState<AuthPage>("login");
  const [scanId, setScanId] = useState<string>("");

  useEffect(() => {
    const handleExpired = () => setUser(null);
    window.addEventListener("auth_expired", handleExpired);
    return () => window.removeEventListener("auth_expired", handleExpired);
  }, []);

  const handleLogin = (u: User) => {
    setUser(u);
    setPage("history");
  };

  const handleLogout = () => {
    logout();
    setUser(null);
  };

  if (!user || !isAuthenticated()) {
    if (authPage === "register") {
      return <RegisterPage onRegister={handleLogin} onGoLogin={() => setAuthPage("login")} />;
    }
    return <LoginPage onLogin={handleLogin} onGoRegister={() => setAuthPage("register")} />;
  }

  const handleViewScan = (id: string) => {
    setScanId(id);
    setPage("scanning");
  };

  const handleScanStarted = (id: string) => {
    setScanId(id);
    setPage("scanning");
  };

  const handleBack = () => {
    setPage("history");
  };

  return (
    <>
      {page === "history" && (
        <ScanHistory
          onViewScan={handleViewScan}
          onDownloadAgent={() => setPage("agent")}
          onNewScan={() => setPage("newScan")}
          user={user}
          onLogout={handleLogout}
          onManageUsers={() => setPage("users")}
        />
      )}
      {page === "newScan" && (
        <NewScanForm onScanStarted={handleScanStarted} onBack={handleBack} />
      )}
      {page === "scanning" && (
        <ScanStatusView scanId={scanId} onBack={handleBack} />
      )}
      {page === "agent" && (
        <AgentDownload onBack={handleBack} />
      )}
      {page === "users" && (
        <UserManagement onBack={handleBack} user={user} />
      )}
    </>
  );
}
