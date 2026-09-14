import { useEffect, useLayoutEffect, useState } from "react";
import { getStoredUser, isAuthenticated, logout, setPublicScanAccess } from "./api/client";
import ScanStatusView from "./components/ScanStatus";
import SharedScanView from "./components/SharedScanView";
import type { PublicScanAccess } from "./api/client";
import ScanHistory from "./components/ScanHistory";
import AgentDownload from "./components/AgentDownload";
import AgentConfigPage from "./components/AgentConfigPage";
import NewScanForm from "./components/NewScanForm";
import LoginPage from "./components/LoginPage";
import RegisterPage from "./components/RegisterPage";
import UserManagement from "./components/UserManagement";
import AdminCheckerDashboard from "./components/AdminCheckerDashboard";
import CheckerCatalogPage from "./components/CheckerCatalogPage";
import RuntimeErrorBoundary from "./components/RuntimeErrorBoundary";
import type { User } from "./types";

type Page = "history" | "newScan" | "scanning" | "agent" | "agentConfig" | "users" | "checkerDashboard" | "checkerCatalog";
type AuthPage = "login" | "register";

export function parsePublicScanAccess(hash = window.location.hash || ""): PublicScanAccess | null {
  const match = hash.match(/^#\/(public|shared)-scan\/([^?]*)(?:\?(.*))?$/);
  if (!match) return null;
  const kind = match[1] === "shared" ? "shared" : "integration";
  let scanId = "";
  try {
    scanId = decodeURIComponent(match[2] || "");
  } catch {
    return kind === "shared" ? { scanId: "", token: "", kind } : null;
  }
  const params = new URLSearchParams(match[3] || "");
  const token = params.get("token") || "";
  if ((!scanId || !token) && kind !== "shared") return null;
  return { scanId, token, kind };
}

export default function App() {
  const [user, setUser] = useState<User | null>(getStoredUser);
  const [page, setPage] = useState<Page>("history");
  const [authPage, setAuthPage] = useState<AuthPage>("login");
  const [scanId, setScanId] = useState<string>("");
  const [preferredAgentKey, setPreferredAgentKey] = useState("");
  const [publicAccess, setPublicAccess] = useState<PublicScanAccess | null>(
    parsePublicScanAccess,
  );

  useEffect(() => {
    const handleExpired = () => setUser(null);
    window.addEventListener("auth_expired", handleExpired);
    return () => window.removeEventListener("auth_expired", handleExpired);
  }, []);

  useEffect(() => {
    const syncPublicAccess = () => setPublicAccess(parsePublicScanAccess());
    window.addEventListener("hashchange", syncPublicAccess);
    return () => window.removeEventListener("hashchange", syncPublicAccess);
  }, []);

  useLayoutEffect(() => {
    setPublicScanAccess(publicAccess);
    return () => setPublicScanAccess(null);
  }, [publicAccess]);

  const handleLogin = (u: User) => {
    setUser(u);
    setPage("history");
  };

  const handleLogout = () => {
    logout();
    setUser(null);
  };

  if (publicAccess) {
    const back = () => { window.location.hash = ""; setPublicAccess(null); };
    return (
      <RuntimeErrorBoundary
        name="public-scan-detail"
        resetKey={`${publicAccess.kind}:${publicAccess.scanId}:${publicAccess.token}`}
        fullscreen
      >
        {publicAccess.kind === "shared" ? <SharedScanView
          key={`${publicAccess.scanId}:${publicAccess.token}`} access={publicAccess} onBack={back}
        /> : <ScanStatusView
          key={`${publicAccess.scanId}:${publicAccess.token}`}
          scanId={publicAccess.scanId}
          onBack={back}
        />}
      </RuntimeErrorBoundary>
    );
  }

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
          onAgentConfig={() => {
            setPreferredAgentKey("");
            setPage("agentConfig");
          }}
          onNewScan={() => setPage("newScan")}
          user={user}
          onLogout={handleLogout}
          onManageUsers={() => setPage("users")}
          onCheckerDashboard={() => setPage("checkerDashboard")}
          onCheckerCatalog={() => setPage("checkerCatalog")}
        />
      )}
      {page === "newScan" && (
        <NewScanForm
          onScanStarted={handleScanStarted}
          onBack={handleBack}
          onConfigureAgent={(agentKey) => {
            setPreferredAgentKey(agentKey);
            setPage("agentConfig");
          }}
        />
      )}
      {page === "scanning" && (
        <RuntimeErrorBoundary name="scan-detail" resetKey={scanId} fullscreen>
          <ScanStatusView scanId={scanId} onBack={handleBack} />
        </RuntimeErrorBoundary>
      )}
      {page === "agent" && (
        <AgentDownload onBack={handleBack} />
      )}
      {page === "agentConfig" && (
        <AgentConfigPage onBack={handleBack} initialAgentKey={preferredAgentKey} />
      )}
      {page === "users" && (
        <UserManagement onBack={handleBack} user={user} />
      )}
      {page === "checkerDashboard" && (
        <AdminCheckerDashboard onBack={handleBack} onViewScan={handleViewScan} user={user} />
      )}
      {page === "checkerCatalog" && (
        <CheckerCatalogPage onBack={handleBack} />
      )}
    </>
  );
}
