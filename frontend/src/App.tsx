import { useCallback, useEffect, useLayoutEffect, useMemo, useState } from "react";
import { Navigate, Outlet, Route, Routes, useLocation, useNavigate, useNavigationType, useParams, useSearchParams } from "react-router";
import { getStoredUser, isAuthenticated, logout, setPublicScanAccess } from "./api/client";
import type { PublicScanAccess } from "./api/client";
import { legacyRoute, loginDestination, parsePublicScanAccess, parseScanRoute, scanPath } from "./routing";
import type { ScanRouteState } from "./routing";
import ScanStatusView from "./components/ScanStatus";
import SharedScanView from "./components/SharedScanView";
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

export { parsePublicScanAccess } from "./routing";

function RequireAuth({ user, admin = false }: { user: User | null; admin?: boolean }) {
  const location = useLocation();
  if (!user || !isAuthenticated()) return <Navigate to="/login" replace state={{ returnTo: location.pathname + location.search + location.hash }} />;
  if (admin && user.role !== "admin") return <Navigate to="/" replace />;
  return <Outlet />;
}

function NotFound({ message = "页面不存在" }: { message?: string }) {
  const navigate = useNavigate();
  return <div className="flex min-h-screen items-center justify-center bg-slate-900 p-6 text-slate-200">
    <div className="text-center"><p role="alert" className="text-lg">{message}</p>
      <button type="button" onClick={() => navigate("/")} className="mt-5 rounded-lg border border-slate-600 px-4 py-2 text-sm">返回首页</button>
    </div>
  </div>;
}

function useBack() {
  const navigate = useNavigate();
  return useCallback(() => {
    // BrowserRouter assigns an index within this tab, including after reload.
    if ((window.history.state?.idx ?? 0) > 0) navigate(-1);
    else navigate("/", { replace: true });
  }, [navigate]);
}

function ScanDetailRoute({ access, publicView = false }: { access?: PublicScanAccess | null; publicView?: boolean }) {
  const { scanId = "", section } = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  const action = useNavigationType();
  const onBack = useBack();
  const state = parseScanRoute(section, location.search);
  const onNavigate = useCallback((next: ScanRouteState) => {
    const to = scanPath(scanId, next, access);
    if (to !== location.pathname + location.search) navigate(to);
  }, [scanId, access, location.pathname, location.search, navigate]);
  if (!state) return <NotFound />;
  if (publicView && !access) return <NotFound message="访问链接无效" />;
  if (!section) return <Navigate to={scanPath(scanId, state, access)} replace />;
  const navigation = { state, onNavigate, locationKey: location.key, action };
  const identity = `${access?.kind || "owner"}:${scanId}:${access?.token || ""}`;
  return <RuntimeErrorBoundary name={publicView ? "public-scan-detail" : "scan-detail"} resetKey={identity} fullscreen>
    {access?.kind === "shared" ? <SharedScanView key={identity} access={access} onBack={onBack}
      onHome={() => navigate("/")} navigation={navigation} />
      : <ScanStatusView key={identity} scanId={scanId} onBack={onBack} navigation={navigation} />}
  </RuntimeErrorBoundary>;
}

function AgentConfigRoute() {
  const [params] = useSearchParams();
  return <AgentConfigPage onBack={useBack()} initialAgentKey={params.get("agent") || ""} />;
}

export default function App() {
  const [user, setUser] = useState<User | null>(getStoredUser);
  const location = useLocation();
  const navigate = useNavigate();
  const onBack = useBack();
  const parsedAccess = parsePublicScanAccess(location.pathname + location.search);
  const publicAccess = useMemo(() => parsedAccess, [parsedAccess?.kind, parsedAccess?.scanId, parsedAccess?.token]);

  useEffect(() => {
    const handleExpired = () => setUser(null);
    const handleStorage = (event: StorageEvent) => {
      if (event.key === null || event.key === "auth_token" || event.key === "auth_user") setUser(getStoredUser());
    };
    window.addEventListener("auth_expired", handleExpired);
    window.addEventListener("storage", handleStorage);
    return () => {
      window.removeEventListener("auth_expired", handleExpired);
      window.removeEventListener("storage", handleStorage);
    };
  }, []);

  useLayoutEffect(() => {
    setPublicScanAccess(publicAccess);
    return () => setPublicScanAccess(null);
  }, [publicAccess]);

  const legacy = legacyRoute(location.pathname, location.hash);
  if (legacy) return <Navigate to={legacy} replace />;

  const handleLogin = (next: User) => {
    setUser(next);
    navigate(loginDestination(location.state), { replace: true });
  };
  const handleLogout = () => {
    logout();
    setUser(null);
    navigate("/login", { replace: true });
  };
  const viewScan = (id: string) => navigate(scanPath(id));
  const authPage = (register: boolean) => user && isAuthenticated()
    ? <Navigate to={loginDestination(location.state)} replace />
    : register ? <RegisterPage onRegister={handleLogin} onGoLogin={() => navigate("/login", { state: location.state })} />
      : <LoginPage onLogin={handleLogin} onGoRegister={() => navigate("/register", { state: location.state })} />;

  return <Routes>
    <Route path="login" element={authPage(false)} />
    <Route path="register" element={authPage(true)} />
    <Route path="shared-scan/:scanId/:section?" element={<ScanDetailRoute access={publicAccess} publicView />} />
    <Route path="public-scan/:scanId/:section?" element={<ScanDetailRoute access={publicAccess} publicView />} />
    <Route element={<RequireAuth user={user} />}>
      <Route index element={<ScanHistory user={user!} onViewScan={viewScan} onLogout={handleLogout}
        onDownloadAgent={() => navigate("/agents/download")} onAgentConfig={() => navigate("/agents/config")}
        onNewScan={() => navigate("/scans/new")} onManageUsers={() => navigate("/admin/users")}
        onCheckerDashboard={() => navigate("/dashboard")} onCheckerCatalog={() => navigate("/checkers")} />} />
      <Route path="scans/new" element={<NewScanForm onScanStarted={viewScan} onBack={onBack}
        onConfigureAgent={(agentKey) => navigate(`/agents/config?${new URLSearchParams({ agent: agentKey })}`)} />} />
      <Route path="scans/:scanId/:section?" element={<ScanDetailRoute />} />
      <Route path="agents/download" element={<AgentDownload onBack={onBack} />} />
      <Route path="agents/config" element={<AgentConfigRoute />} />
      <Route path="dashboard" element={<AdminCheckerDashboard user={user!} onBack={onBack} onViewScan={viewScan} />} />
      <Route path="checkers" element={<CheckerCatalogPage onBack={onBack} />} />
      <Route element={<RequireAuth user={user} admin />}>
        <Route path="admin/users" element={<UserManagement user={user!} onBack={onBack} />} />
      </Route>
    </Route>
    <Route path="*" element={<NotFound />} />
  </Routes>;
}
