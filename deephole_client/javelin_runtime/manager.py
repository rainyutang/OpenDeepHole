"""Workspace materialization, cached doctor probe, and on-demand audit-service.mjs manager."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx

from backend.models import JAVELIN_CONTRACT_VERSION
from deephole_client.config import active_opencode_executable
from deephole_client.javelin_runtime.config_bridge import (
    build_javelin_child_env,
    compute_javelin_worker_concurrency,
    select_primary_javelin_model,
    write_javelin_opencode_config,
)

logger = logging.getLogger(__name__)

MIN_NODE_VERSION = (22, 5, 0)
DOCTOR_CACHE_TTL_SECONDS = 600.0
IDLE_SERVICE_SHUTDOWN_SECONDS = 60.0

_SKIP_OPENCODE_DIRS = frozenset({"tests", "node_modules"})
_SKIP_OPENCODE_REL_PREFIXES = (
    "web/dynamic-validation-observatory/public",
)
_SKIP_OPENCODE_FILES = frozenset({"opencode.json"})

_NODE_SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")

_DOCTOR_CACHE: dict[tuple[str, str, str, str], tuple[float, dict[str, Any]]] = {}


def default_runtime_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_javelin_data_root() -> Path:
    env_override = os.environ.get("OPENDEEPHOLE_JAVELIN_DATA_ROOT", "").strip()
    if env_override:
        return Path(env_override).expanduser().resolve()
    return (Path.home() / ".opendeephole" / "javelin").resolve()


def parse_node_semver(raw_version: str) -> tuple[int, int, int] | None:
    """Parse 'v22.5.0' / '22.6.1' into (major, minor, patch)."""
    match = _NODE_SEMVER_RE.match(str(raw_version or "").strip())
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def is_node_version_supported(raw_version: str) -> bool:
    """Strictly check ONLY Node.js >= 22.5.0 without probing experimental sub-features (14-item #9)."""
    parsed = parse_node_semver(raw_version)
    return parsed is not None and parsed >= MIN_NODE_VERSION


def read_javelin_lock(runtime_root: Path | None = None) -> dict[str, Any]:
    root = (runtime_root or default_runtime_root()).resolve()
    lock_file = root / "third_party" / "javelin.lock.json"
    if not lock_file.is_file():
        return {"commit": "", "javelin_contract_version": JAVELIN_CONTRACT_VERSION}
    try:
        return json.loads(lock_file.read_text(encoding="utf-8"))
    except Exception:
        return {"commit": "", "javelin_contract_version": JAVELIN_CONTRACT_VERSION}


def _link_or_copy_node_modules(src_node_modules: Path, dst_node_modules: Path) -> None:
    """Symlink prebuilt node_modules (<1ms, 0 duplicated disk) with copy fallback."""
    resolved_src = src_node_modules.resolve()
    if dst_node_modules.is_symlink():
        try:
            if dst_node_modules.resolve() == resolved_src:
                return
        except OSError:
            pass
        dst_node_modules.unlink(missing_ok=True)
    elif dst_node_modules.exists():
        shutil.rmtree(dst_node_modules, ignore_errors=True)

    try:
        os.symlink(str(resolved_src), str(dst_node_modules), target_is_directory=True)
    except OSError:
        shutil.copytree(resolved_src, dst_node_modules)


def materialize_javelin_workspace(
    workspace_root: Path,
    *,
    runtime_root: Path | None = None,
    force: bool = False,
) -> Path:
    """Materialize Javelin .opencode + AGENTS.md + symlinked node_modules without touching submodule."""
    root = (runtime_root or default_runtime_root()).resolve()
    javelin_src = root / "third_party" / "Javelin"
    opencode_src = javelin_src / ".opencode"
    deps_src = root / "javelin_runtime_deps" / "node_modules"
    if not opencode_src.is_dir():
        raise FileNotFoundError(f"Javelin .opencode directory missing at {opencode_src}")
    if not deps_src.is_dir():
        raise FileNotFoundError(f"Prebuilt Javelin node_modules missing at {deps_src}")

    ws = workspace_root.resolve()
    ws_opencode = ws / ".opencode"
    ws_opencode.mkdir(parents=True, exist_ok=True)

    lock_info = read_javelin_lock(root)
    commit = str(lock_info.get("commit") or "dev")
    try:
        deps_mtime = str(int(deps_src.stat().st_mtime))
    except OSError:
        deps_mtime = "0"
    stamp_value = f"{commit}:{deps_mtime}"
    stamp_path = ws_opencode / ".deephole_materialized_stamp"
    dst_node_modules = ws_opencode / "node_modules"

    if (
        not force
        and stamp_path.is_file()
        and stamp_path.read_text(encoding="utf-8").strip() == stamp_value
        and dst_node_modules.is_dir()
    ):
        return ws

    agents_md = javelin_src / "AGENTS.md"
    if agents_md.is_file():
        shutil.copy2(agents_md, ws / "AGENTS.md")

    for src_dir, dirnames, filenames in os.walk(opencode_src):
        rel_dir = Path(src_dir).relative_to(opencode_src).as_posix()
        if rel_dir == ".":
            rel_dir = ""
        dirnames[:] = [
            d
            for d in dirnames
            if d not in _SKIP_OPENCODE_DIRS
            and f"{rel_dir}/{d}".strip("/") not in _SKIP_OPENCODE_REL_PREFIXES
        ]
        target_dir = ws_opencode / rel_dir if rel_dir else ws_opencode
        target_dir.mkdir(parents=True, exist_ok=True)
        for fname in filenames:
            if fname in _SKIP_OPENCODE_FILES:
                continue
            shutil.copy2(Path(src_dir) / fname, target_dir / fname)

    _link_or_copy_node_modules(deps_src, dst_node_modules)
    stamp_path.write_text(stamp_value + "\n", encoding="utf-8")
    return ws


def clear_javelin_doctor_cache() -> None:
    _DOCTOR_CACHE.clear()


def probe_javelin_doctor(
    config: Any = None,
    *,
    runtime_root: Path | None = None,
    node_executable: str = "node",
    opencode_executable: str | None = None,
    probe_workspace: Path | None = None,
    use_cache: bool = True,
) -> dict[str, Any]:
    """Probe Node >= 22.5.0, offline 5-package ESM import(), and OpenCode executable.

    Cached for 600s so WS heartbeats/reconnects incur zero subprocess overhead.
    """
    root = (runtime_root or default_runtime_root()).resolve()
    lock_info = read_javelin_lock(root)
    commit = str(lock_info.get("commit") or "")
    contract_version = int(lock_info.get("javelin_contract_version") or JAVELIN_CONTRACT_VERSION)

    opencode_cfg = getattr(config, "opencode", None) if config is not None else None
    resolved_opencode_arg = (
        opencode_executable
        if opencode_executable is not None
        else (active_opencode_executable(opencode_cfg) if opencode_cfg is not None else "opencode")
    )
    cache_key = (str(root), node_executable, str(resolved_opencode_arg), commit)
    now_mono = time.monotonic()
    if use_cache:
        cached = _DOCTOR_CACHE.get(cache_key)
        if cached is not None and (now_mono - cached[0]) < DOCTOR_CACHE_TTL_SECONDS:
            return dict(cached[1])

    blockers: list[str] = []
    node_bin = shutil.which(node_executable) or (node_executable if Path(node_executable).is_file() else "")
    node_version = ""
    esm_deps_ok = False

    if not node_bin:
        blockers.append("未找到 Node.js 可执行文件（需 Node.js >= 22.5.0）")
    else:
        try:
            ver_proc = subprocess.run(
                [node_bin, "--version"],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
            node_version = (ver_proc.stdout or ver_proc.stderr or "").strip().splitlines()[0] if (ver_proc.stdout or ver_proc.stderr) else ""
        except Exception as exc:
            blockers.append(f"Node.js 版本探测失败: {type(exc).__name__}")

        if node_version and not is_node_version_supported(node_version):
            blockers.append(f"Node.js 版本过低（当前 {node_version}，要求 >= 22.5.0）")
        elif not node_version and not blockers:
            blockers.append("无法解析 Node.js 版本号（要求 >= 22.5.0）")

    # Offline ESM 5-package import check inside materialized workspace without NODE_PATH
    if node_bin and is_node_version_supported(node_version):
        ws_dir = probe_workspace or (default_javelin_data_root() / "doctor_probe_ws")
        try:
            materialize_javelin_workspace(ws_dir, runtime_root=root)
            probe_script = ws_dir / ".opencode" / ".doctor_esm_probe.mjs"
            probe_script.write_text(
                "await Promise.all([\n"
                "  import('@modelcontextprotocol/sdk/server/mcp.js'),\n"
                "  import('@opencode-ai/plugin'),\n"
                "  import('fflate'),\n"
                "  import('markdown-it'),\n"
                "  import('yaml'),\n"
                "]);\n"
                "process.stdout.write('ESM_OK\\n');\n",
                encoding="utf-8",
            )
            clean_env = dict(os.environ)
            clean_env.pop("NODE_PATH", None)
            esm_proc = subprocess.run(
                [node_bin, str(probe_script)],
                cwd=str(ws_dir),
                env=clean_env,
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
            )
            if esm_proc.returncode == 0 and "ESM_OK" in (esm_proc.stdout or ""):
                esm_deps_ok = True
            else:
                err_tail = ((esm_proc.stderr or esm_proc.stdout or "").strip().splitlines() or ["unknown"])[-1]
                blockers.append(f"Javelin 离线 ESM 依赖解析失败: {err_tail[:180]}")
        except Exception as exc:
            blockers.append(f"Javelin 工作区物化或依赖自检失败: {exc}")

    opencode_bin = shutil.which(resolved_opencode_arg) or (
        resolved_opencode_arg if Path(resolved_opencode_arg).is_file() else ""
    )
    opencode_ok = bool(opencode_bin)
    if not opencode_ok:
        blockers.append(f"未找到 OpenCode 可执行文件: {resolved_opencode_arg}")

    capability = {
        "supported": True,
        "ready": len(blockers) == 0,
        "contract_version": contract_version,
        "submodule_commit": commit,
        "node_version": node_version,
        "esm_deps_ok": esm_deps_ok,
        "opencode_ok": opencode_ok,
        "blockers": blockers,
    }
    if use_cache:
        _DOCTOR_CACHE[cache_key] = (now_mono, dict(capability))
    return capability


async def probe_javelin_doctor_async(config: Any = None, **kwargs: Any) -> dict[str, Any]:
    return await asyncio.to_thread(probe_javelin_doctor, config, **kwargs)


class JavelinAuditServiceManager:
    """On-demand lifecycle controller for unmodified third_party/Javelin audit-service.mjs.

    Starts zero Node processes when idle, reuses a single local service while Java scans
    are active, and automatically stops after 60s of inactivity to reclaim memory.
    """

    def __init__(
        self,
        *,
        runtime_root: Path | None = None,
        data_root: Path | None = None,
        idle_shutdown_seconds: float = IDLE_SERVICE_SHUTDOWN_SECONDS,
    ) -> None:
        self.runtime_root = (runtime_root or default_runtime_root()).resolve()
        self.data_root = (data_root or default_javelin_data_root()).resolve()
        self.idle_shutdown_seconds = idle_shutdown_seconds
        self._lock = asyncio.Lock()
        self._proc: asyncio.subprocess.Process | None = None
        self._origin: str = ""
        self._token: str = ""
        self._http: httpx.AsyncClient | None = None
        self._active_scans: set[str] = set()
        self._idle_task: asyncio.Task | None = None

    @property
    def workspace_root(self) -> Path:
        return self.data_root / "workspace"

    @property
    def state_root(self) -> Path:
        return self.data_root / "state"

    @property
    def service_root(self) -> Path:
        return self.data_root / "service"

    def has_active_work(self) -> bool:
        return bool(self._active_scans)

    def mark_scan_active(self, scan_id: str) -> None:
        self._active_scans.add(scan_id)
        if self._idle_task is not None and not self._idle_task.done():
            self._idle_task.cancel()
            self._idle_task = None

    def mark_scan_finished(self, scan_id: str) -> None:
        self._active_scans.discard(scan_id)
        if not self._active_scans and self._proc is not None and self.idle_shutdown_seconds > 0:
            try:
                loop = asyncio.get_running_loop()
                if self._idle_task is None or self._idle_task.done():
                    self._idle_task = loop.create_task(self._shutdown_when_idle())
            except RuntimeError:
                pass

    async def _shutdown_when_idle(self) -> None:
        try:
            await asyncio.sleep(self.idle_shutdown_seconds)
            if not self._active_scans:
                await self.stop()
        except asyncio.CancelledError:
            return

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        base = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }
        if extra:
            base.update(extra)
        return base

    async def ensure_started(self, config: Any, *, target_project_path: Path | None = None) -> tuple[str, str]:
        async with self._lock:
            ws = await asyncio.to_thread(
                materialize_javelin_workspace,
                self.workspace_root,
                runtime_root=self.runtime_root,
            )
            await asyncio.to_thread(
                write_javelin_opencode_config,
                config,
                workspace_root=ws,
                target_project_path=target_project_path,
                runtime_data_root=self.data_root,
            )
            if self._http is None:
                self._http = httpx.AsyncClient(timeout=30.0, trust_env=False)

            if self._proc is not None and self._proc.returncode is None and self._origin:
                try:
                    resp = await self._http.get(
                        f"{self._origin}/api/v1/runtime/health",
                        headers={"Authorization": f"Bearer {self._token}"},
                        timeout=3.0,
                    )
                    if resp.status_code == 200 and resp.json().get("runtime_service", {}).get("ready"):
                        await self._sync_worker_settings(config)
                        return self._origin, self._token
                except Exception:
                    pass

            await self._terminate_locked()
            self.state_root.mkdir(parents=True, exist_ok=True)
            self.service_root.mkdir(parents=True, exist_ok=True)
            conn_file = self.service_root / "connection.json"
            conn_file.unlink(missing_ok=True)

            child_env = build_javelin_child_env(config)
            script_path = ws / ".opencode" / "scripts" / "audit-service.mjs"
            self._proc = await asyncio.create_subprocess_exec(
                "node",
                str(script_path),
                "serve",
                "--port",
                "0",
                "--state-root",
                str(self.state_root),
                "--service-root",
                str(self.service_root),
                cwd=str(ws),
                env=child_env,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )

            deadline = time.monotonic() + 25.0
            while time.monotonic() < deadline:
                if self._proc.returncode is not None:
                    stderr_bytes = await self._proc.stderr.read() if self._proc.stderr else b""
                    raise RuntimeError(
                        f"audit-service.mjs exited prematurely ({self._proc.returncode}): "
                        f"{stderr_bytes.decode('utf-8', errors='replace')[:400]}"
                    )
                if conn_file.is_file():
                    try:
                        conn = json.loads(conn_file.read_text(encoding="utf-8"))
                        origin = str(conn.get("origin") or "").rstrip("/")
                        token = str(conn.get("token") or "")
                        if origin and token:
                            resp = await self._http.get(
                                f"{origin}/api/v1/runtime/health",
                                headers={"Authorization": f"Bearer {token}"},
                                timeout=3.0,
                            )
                            if resp.status_code == 200 and resp.json().get("runtime_service", {}).get("ready"):
                                self._origin = origin
                                self._token = token
                                await self._sync_worker_settings(config)
                                return self._origin, self._token
                    except Exception:
                        pass
                await asyncio.sleep(0.15)
            await self._terminate_locked()
            raise TimeoutError("Timed out waiting for Javelin audit-service.mjs readiness")

    async def _sync_worker_settings(self, config: Any) -> None:
        assert self._http is not None
        concurrency = compute_javelin_worker_concurrency(config)
        try:
            await self._http.put(
                f"{self._origin}/api/v1/settings/queue",
                headers=self._headers(),
                json={"max_concurrent_audits": concurrency},
                timeout=5.0,
            )
        except Exception:
            pass

    async def create_and_start_audit(
        self,
        *,
        config: Any,
        scan_id: str,
        audit_id: str,
        scan_name: str,
        project_path: Path,
        product_name: str,
        javelin_config: dict[str, Any],
        secret_test_env: str = "",
    ) -> dict[str, Any]:
        await self.ensure_started(config, target_project_path=project_path)
        assert self._http is not None

        # Register or reuse repository under legacy undefined product space
        repos_resp = await self._http.get(
            f"{self._origin}/api/v1/repositories",
            headers={"Authorization": f"Bearer {self._token}"},
        )
        repos_resp.raise_for_status()
        resolved_path = str(project_path.resolve())
        existing_repo = next(
            (
                item
                for item in (repos_resp.json().get("items") or [])
                if str(item.get("path") or "") == resolved_path
            ),
            None,
        )
        if existing_repo is None:
            add_resp = await self._http.post(
                f"{self._origin}/api/v1/repositories",
                headers=self._headers({"Idempotency-Key": f"repo-{scan_id}"}),
                json={"name": scan_name or project_path.name, "path": resolved_path},
            )
            add_resp.raise_for_status()
            repo_id = str(add_resp.json()["id"])
        else:
            repo_id = str(existing_repo["id"])

        selected_model = select_primary_javelin_model(config)
        runtime_testing = javelin_config.get("runtime_testing") if isinstance(javelin_config.get("runtime_testing"), dict) else {}
        rt_enabled = bool(runtime_testing.get("enabled"))
        add_instr = str(javelin_config.get("additional_instructions") or "").strip()

        audit_payload: dict[str, Any] = {
            "audit_id": audit_id,
            "repository_id": repo_id,
            "name": scan_name or project_path.name,
            "model": selected_model,
            "task_protocol": "task-board.v1",
            "mining_strategy": str(javelin_config.get("mining_strategy") or "focus_area"),
            "api_inventory": str(javelin_config.get("api_inventory") or ""),
            "bac_analysis": "auto" if javelin_config.get("bac_enabled", True) else "off",
            "memory_mode": str(javelin_config.get("memory_mode") or "full"),
            "additional_instructions_enabled": bool(add_instr),
            "additional_instructions": add_instr,
            "test_environment_enabled": rt_enabled,
            "test_environment_context": secret_test_env if rt_enabled else "",
        }
        create_resp = await self._http.post(
            f"{self._origin}/api/v1/audits",
            headers=self._headers({"Idempotency-Key": f"create-{scan_id}"}),
            json=audit_payload,
        )
        if create_resp.status_code == 422 and "opencode-model-not-configured" in create_resp.text:
            audit_payload["model"] = "default"
            create_resp = await self._http.post(
                f"{self._origin}/api/v1/audits",
                headers=self._headers({"Idempotency-Key": f"create-default-{scan_id}"}),
                json=audit_payload,
            )
        create_resp.raise_for_status()
        audit = create_resp.json()
        if audit.get("status") == "queued":
            try:
                audit = await self.dispatch_action(audit_id, "dispatch", expected_version=audit.get("version"))
            except Exception:
                pass
        return audit

    async def dispatch_action(
        self,
        audit_id: str,
        action: str,
        *,
        expected_version: int | None = None,
        action_id: str = "",
    ) -> dict[str, Any]:
        assert self._http is not None
        if expected_version is None:
            current = await self.get_audit(audit_id)
            expected_version = int(current.get("version") or 1)
        extra = {"If-Match": f'"{expected_version}"'}
        if action_id:
            extra["Idempotency-Key"] = action_id
        resp = await self._http.post(
            f"{self._origin}/api/v1/audits/{audit_id}/actions",
            headers=self._headers(extra),
            json={"action": action},
        )
        if resp.status_code == 412:
            current = await self.get_audit(audit_id)
            extra["If-Match"] = f'"{int(current.get("version") or 1)}"'
            resp = await self._http.post(
                f"{self._origin}/api/v1/audits/{audit_id}/actions",
                headers=self._headers(extra),
                json={"action": action},
            )
        resp.raise_for_status()
        return resp.json()

    async def get_audit(self, audit_id: str) -> dict[str, Any]:
        assert self._http is not None
        resp = await self._http.get(
            f"{self._origin}/api/v1/audits/{audit_id}?live=1",
            headers={"Authorization": f"Bearer {self._token}"},
        )
        resp.raise_for_status()
        data = resp.json()
        return data["audit"] if isinstance(data, dict) and "audit" in data else data

    async def get_task_board(self, audit_id: str, *, offset: int = 0, limit: int = 500) -> dict[str, Any]:
        assert self._http is not None
        resp = await self._http.get(
            f"{self._origin}/api/v1/audits/{audit_id}/task-board",
            params={"offset": offset, "limit": limit},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        if resp.status_code == 404:
            return {"items": [], "total": 0}
        resp.raise_for_status()
        return resp.json()

    async def get_logs(self, audit_id: str, *, limit: int = 400) -> list[dict[str, Any]]:
        assert self._http is not None
        resp = await self._http.get(
            f"{self._origin}/api/v1/audits/{audit_id}/logs",
            params={"limit": limit},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return list(resp.json().get("items") or [])

    async def get_findings(self, audit_id: str) -> list[dict[str, Any]]:
        assert self._http is not None
        items: list[dict[str, Any]] = []
        page = 1
        while True:
            resp = await self._http.get(
                f"{self._origin}/api/v1/findings",
                params={"audit_id": audit_id, "page": page},
                headers={"Authorization": f"Bearer {self._token}"},
            )
            if resp.status_code == 404:
                break
            resp.raise_for_status()
            payload = resp.json()
            batch = payload.get("items") or []
            items.extend(batch)
            if page >= int(payload.get("total_pages") or 1) or not batch:
                break
            page += 1
        return items

    async def get_http_exchanges(self, audit_id: str) -> list[dict[str, Any]]:
        assert self._http is not None
        resp = await self._http.get(
            f"{self._origin}/api/v1/http-exchanges",
            params={"audit_id": audit_id, "limit": 200},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return list(resp.json().get("items") or [])

    async def get_reports(self, audit_id: str) -> list[dict[str, Any]]:
        assert self._http is not None
        resp = await self._http.get(
            f"{self._origin}/api/v1/reports",
            headers={"Authorization": f"Bearer {self._token}"},
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return [
            item
            for item in (resp.json().get("items") or [])
            if str(item.get("audit_id") or "") == audit_id
        ]

    async def download_report_original_bytes(self, report_id: str) -> bytes:
        assert self._http is not None
        resp = await self._http.get(
            f"{self._origin}/api/v1/reports/{report_id}/download",
            params={"format": "original"},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        resp.raise_for_status()
        return bytes(resp.content)

    def find_source_baseline_file(self, audit: dict[str, Any], audit_id: str) -> Path | None:
        paths = audit.get("paths") if isinstance(audit.get("paths"), dict) else {}
        candidates: list[Path] = []
        for key in ("reports_root", "workspace_root", "audit_dir"):
            val = str(paths.get(key) or "").strip()
            if val:
                base = Path(val)
                candidates.extend([
                    base / f"source-baseline.{audit_id}.json",
                    base / "task-board" / f"source-baseline.{audit_id}.json",
                    base / "scope" / f"source-baseline.{audit_id}.json",
                    base / "reports" / "task-board" / f"source-baseline.{audit_id}.json",
                ])
        if self.state_root.is_dir():
            candidates.extend(self.state_root.rglob(f"source-baseline.{audit_id}.json"))
        for c in candidates:
            if c.is_file():
                return c
        return None

    def open_sse_stream(self, audit_id: str):
        assert self._http is not None
        return self._http.stream(
            "GET",
            f"{self._origin}/api/v1/audits/{audit_id}/events",
            headers={"Authorization": f"Bearer {self._token}", "Accept": "text/event-stream"},
            timeout=httpx.Timeout(connect=5.0, read=65.0, write=10.0, pool=10.0),
        )

    async def stop(self) -> None:
        async with self._lock:
            await self._terminate_locked()
            if self._http is not None:
                await self._http.aclose()
                self._http = None

    async def _terminate_locked(self) -> None:
        if self._proc is None:
            return
        proc = self._proc
        self._proc = None
        if proc.returncode is None:
            if self._http is not None and self._origin and self._token:
                try:
                    await self._http.post(
                        f"{self._origin}/api/internal/service/stop",
                        headers={"Authorization": f"Bearer {self._token}"},
                        timeout=3.0,
                    )
                except Exception:
                    pass
            try:
                proc.terminate()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                await asyncio.gather(proc.wait(), return_exceptions=True)
        self._origin = ""
        self._token = ""


_GLOBAL_JAVELIN_MANAGER: JavelinAuditServiceManager | None = None


def get_javelin_service_manager() -> JavelinAuditServiceManager:
    global _GLOBAL_JAVELIN_MANAGER
    if _GLOBAL_JAVELIN_MANAGER is None:
        _GLOBAL_JAVELIN_MANAGER = JavelinAuditServiceManager()
    return _GLOBAL_JAVELIN_MANAGER
