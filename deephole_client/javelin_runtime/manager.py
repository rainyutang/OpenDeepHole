"""Workspace materialization, cached doctor probe, and on-demand audit-service.mjs manager."""

from __future__ import annotations

import asyncio
from collections import deque
import contextlib
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
    resolve_opencode_binary,
    select_primary_javelin_model,
    write_javelin_opencode_config,
)
from task_agent.output_format import with_local_timestamp

logger = logging.getLogger(__name__)

MIN_NODE_VERSION = (22, 5, 0)
DOCTOR_CACHE_TTL_SECONDS = 600.0
IDLE_SERVICE_SHUTDOWN_SECONDS = 60.0
UNDEFINED_PRODUCT_ID = "product-undefined"

_SKIP_OPENCODE_DIRS = frozenset({"tests", "node_modules"})
_SKIP_OPENCODE_REL_PREFIXES = (
    "web/dynamic-validation-observatory/public",
)
_SKIP_OPENCODE_FILES = frozenset({"opencode.json", "opencode.json.bak"})

_NODE_SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")
_SENSITIVE_CONSOLE_RE = re.compile(
    r"(?i)(\bBearer\s+[A-Za-z0-9._~+/-]+=*|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b)"
)

_DOCTOR_CACHE: dict[tuple[str, str, str, str], tuple[float, dict[str, Any]]] = {}


def javelin_console_log(message: str, *, prefix: str = "[javelin]") -> None:
    """Print a timestamped, secret-scrubbed Javelin lifecycle line to the Agent console."""
    safe_msg = _SENSITIVE_CONSOLE_RE.sub("[REDACTED]", str(message or "").strip())
    if not safe_msg:
        return
    print(with_local_timestamp(safe_msg, prefix=prefix), flush=True)


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


def _is_link_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction):
        with contextlib.suppress(OSError):
            return bool(is_junction())
    return False


def _remove_existing_node_modules_target(dst_node_modules: Path) -> None:
    """Remove an existing symlink, Windows NTFS junction, or copied directory safely."""
    if _is_link_or_junction(dst_node_modules):
        try:
            dst_node_modules.unlink()
            return
        except OSError:
            with contextlib.suppress(OSError):
                os.rmdir(dst_node_modules)
                return
    if dst_node_modules.exists():
        shutil.rmtree(dst_node_modules, ignore_errors=True)


def _link_or_copy_node_modules(src_node_modules: Path, dst_node_modules: Path) -> str:
    """Link prebuilt node_modules via symlink / Windows junction (<1ms) with copy fallback."""
    resolved_src = src_node_modules.resolve()
    if _is_link_or_junction(dst_node_modules):
        with contextlib.suppress(OSError):
            if dst_node_modules.resolve() == resolved_src:
                return "reused"
    _remove_existing_node_modules_target(dst_node_modules)

    try:
        os.symlink(str(resolved_src), str(dst_node_modules), target_is_directory=True)
        return "symlink"
    except OSError:
        pass

    if os.name == "nt":
        try:
            import _winapi  # type: ignore[import-not-found]

            _winapi.CreateJunction(str(resolved_src), str(dst_node_modules))
            return "junction"
        except Exception:
            proc = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(dst_node_modules), str(resolved_src)],
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
            )
            if proc.returncode == 0 and dst_node_modules.is_dir():
                return "junction"

    shutil.copytree(resolved_src, dst_node_modules)
    return "copy"


def materialize_javelin_workspace(
    workspace_root: Path,
    *,
    runtime_root: Path | None = None,
    force: bool = False,
) -> Path:
    """Materialize Javelin .opencode + AGENTS.md + linked node_modules without touching submodule."""
    ws, _meta = materialize_javelin_workspace_with_info(
        workspace_root,
        runtime_root=runtime_root,
        force=force,
    )
    return ws


def materialize_javelin_workspace_with_info(
    workspace_root: Path,
    *,
    runtime_root: Path | None = None,
    force: bool = False,
) -> tuple[Path, dict[str, Any]]:
    """Materialize Javelin workspace and return diagnostic metadata for console output."""
    t0 = time.perf_counter()
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
    stamp_value = f"{commit}:{deps_mtime}:v2"
    stamp_path = ws_opencode / ".deephole_materialized_stamp"
    dst_node_modules = ws_opencode / "node_modules"

    if (
        not force
        and stamp_path.is_file()
        and stamp_path.read_text(encoding="utf-8").strip() == stamp_value
        and dst_node_modules.is_dir()
    ):
        return ws, {
            "cached": True,
            "deps_mode": "cached",
            "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 1),
        }

    agents_md = javelin_src / "AGENTS.md"
    if agents_md.is_file():
        shutil.copy2(agents_md, ws / "AGENTS.md")

    copied_files = 0
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
            copied_files += 1

    deps_mode = _link_or_copy_node_modules(deps_src, dst_node_modules)
    stamp_path.write_text(stamp_value + "\n", encoding="utf-8")
    return ws, {
        "cached": False,
        "deps_mode": deps_mode,
        "copied_files": copied_files,
        "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 1),
    }


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


def _extract_error_detail(resp: httpx.Response) -> tuple[str, str]:
    """Return (error_code, human_message) from a Javelin JSON or text HTTP error response."""
    code = ""
    message = ""
    try:
        payload = resp.json()
        if isinstance(payload, dict):
            code = str(payload.get("error") or payload.get("code") or "").strip()
            raw_msg = payload.get("message") or payload.get("detail") or ""
            message = raw_msg if isinstance(raw_msg, str) else json.dumps(raw_msg, ensure_ascii=False)
    except Exception:
        pass
    if not message:
        message = (resp.text or "").strip()[:400]
    return code, message


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
        self._stderr_task: asyncio.Task | None = None
        self._recent_stderr: deque[str] = deque(maxlen=40)
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
                javelin_console_log("空闲超时已到，自动关闭本地 Javelin audit-service 释放内存")
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

    def _raise_for_javelin_status(self, resp: httpx.Response, context: str) -> None:
        if 200 <= resp.status_code < 300:
            return
        code, message = _extract_error_detail(resp)
        code_part = f" [{code}]" if code else ""
        detail = f"{context}失败 (HTTP {resp.status_code}{code_part}): {message or resp.reason_phrase}"
        if resp.status_code >= 500 and self._recent_stderr:
            stderr_tail = " | ".join(list(self._recent_stderr)[-3:])
            detail += f" (service stderr: {stderr_tail[:240]})"
        raise RuntimeError(detail)

    async def _drain_service_stderr(self, stream: asyncio.StreamReader | None) -> None:
        if stream is None:
            return
        try:
            while True:
                line_bytes = await stream.readline()
                if not line_bytes:
                    return
                line = line_bytes.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                self._recent_stderr.append(line)
                javelin_console_log(line, prefix="[javelin:service]")
        except asyncio.CancelledError:
            return
        except Exception:
            return

    async def ensure_started(self, config: Any, *, target_project_path: Path | None = None) -> tuple[str, str]:
        async with self._lock:
            ws, mat_info = await asyncio.to_thread(
                materialize_javelin_workspace_with_info,
                self.workspace_root,
                runtime_root=self.runtime_root,
            )
            cfg_path = await asyncio.to_thread(
                write_javelin_opencode_config,
                config,
                workspace_root=ws,
                target_project_path=target_project_path,
                runtime_data_root=self.data_root,
            )
            selected_model = select_primary_javelin_model(config)
            concurrency = compute_javelin_worker_concurrency(config)
            opencode_bin = resolve_opencode_binary(config) or "PATH:opencode"
            if not mat_info.get("cached"):
                javelin_console_log(
                    f"工作区已初始化: {ws} (依赖挂载={mat_info.get('deps_mode')}, "
                    f"耗时={mat_info.get('elapsed_ms')}ms)"
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
                        javelin_console_log(
                            f"复用本地审计服务: {self._origin} (pid={self._proc.pid}, "
                            f"模型={selected_model}, 并发={concurrency})"
                        )
                        return self._origin, self._token
                except Exception:
                    pass

            await self._terminate_locked()
            self.state_root.mkdir(parents=True, exist_ok=True)
            self.service_root.mkdir(parents=True, exist_ok=True)
            conn_file = self.service_root / "connection.json"
            conn_file.unlink(missing_ok=True)
            self._recent_stderr.clear()

            child_env = build_javelin_child_env(config)
            node_bin = shutil.which("node") or "node"
            script_path = ws / ".opencode" / "scripts" / "audit-service.mjs"
            t_boot = time.perf_counter()
            javelin_console_log(
                f"正在启动本地审计服务 audit-service.mjs (模型={selected_model}, "
                f"并发={concurrency}, OpenCode={opencode_bin}, 配置={cfg_path.name})..."
            )
            self._proc = await asyncio.create_subprocess_exec(
                node_bin,
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
            self._stderr_task = asyncio.create_task(self._drain_service_stderr(self._proc.stderr))

            deadline = time.monotonic() + 25.0
            while time.monotonic() < deadline:
                if self._proc.returncode is not None:
                    await asyncio.sleep(0.05)
                    stderr_tail = "\n".join(self._recent_stderr)
                    raise RuntimeError(
                        f"audit-service.mjs 启动异常退出 (exit={self._proc.returncode}): "
                        f"{stderr_tail[:400] or '无 stderr 输出'}"
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
                                boot_ms = round((time.perf_counter() - t_boot) * 1000.0)
                                javelin_console_log(
                                    f"本地审计服务已就绪: {self._origin} "
                                    f"(pid={self._proc.pid}, 启动耗时={boot_ms}ms)"
                                )
                                return self._origin, self._token
                    except Exception:
                        pass
                await asyncio.sleep(0.15)
            await self._terminate_locked()
            raise TimeoutError("等待 Javelin audit-service.mjs 就绪超时 (25s)")

    async def _sync_worker_settings(self, config: Any) -> None:
        """Keep Javelin's delayed timer queue disabled and sync worker concurrency."""
        assert self._http is not None
        concurrency = compute_javelin_worker_concurrency(config)
        with contextlib.suppress(Exception):
            q_resp = await self._http.put(
                f"{self._origin}/api/v1/settings/queue",
                headers=self._headers(),
                json={"concurrency": concurrency},
                timeout=5.0,
            )
            if q_resp.status_code == 200 and (q_resp.json().get("queue") or {}).get("enabled") is True:
                await self._http.post(
                    f"{self._origin}/api/v1/settings/queue/deactivate",
                    headers=self._headers(),
                    json={},
                    timeout=5.0,
                )

    async def _ensure_directory_target(self, *, scan_id: str, target_name: str, resolved_path: str) -> str:
        """Register or reuse a v2 directory target under product-undefined (supports non-Git & dirty dirs)."""
        assert self._http is not None
        targets_resp = await self._http.get(
            f"{self._origin}/api/v2/products/{UNDEFINED_PRODUCT_ID}/targets",
            params={"status": "active", "page": 1, "page_size": 100},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        self._raise_for_javelin_status(targets_resp, "查询审计对象列表")
        items = targets_resp.json().get("items") or []
        for item in items:
            scopes = item.get("source_scopes") or []
            if (
                item.get("status") == "active"
                and len(scopes) == 1
                and str(scopes[0].get("path") or "") == resolved_path
                and not scopes[0].get("include_patterns")
                and not scopes[0].get("exclude_patterns")
            ):
                return str(item["id"])

        safe_name = (target_name or Path(resolved_path).name or "java-target").strip()[:120]
        create_target_resp = await self._http.post(
            f"{self._origin}/api/v2/products/{UNDEFINED_PRODUCT_ID}/targets",
            headers=self._headers({"Idempotency-Key": f"target-{scan_id}"}),
            json={
                "name": safe_name,
                "source_scopes": [{"name": "source", "path": resolved_path}],
            },
        )
        self._raise_for_javelin_status(create_target_resp, "注册源码目录审计对象")
        return str(create_target_resp.json()["id"])

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
        _ = product_name
        resolved_project = project_path.resolve()
        if not resolved_project.is_dir():
            raise FileNotFoundError(f"被审计 Java 源码目录不存在或不可访问: {resolved_project}")

        await self.ensure_started(config, target_project_path=resolved_project)
        assert self._http is not None

        resolved_path = str(resolved_project)
        target_id = await self._ensure_directory_target(
            scan_id=scan_id,
            target_name=scan_name or resolved_project.name,
            resolved_path=resolved_path,
        )

        selected_model = select_primary_javelin_model(config)
        runtime_testing_cfg = (
            javelin_config.get("runtime_testing")
            if isinstance(javelin_config.get("runtime_testing"), dict)
            else {}
        )
        rt_enabled = bool(runtime_testing_cfg.get("enabled"))
        add_instr = str(javelin_config.get("additional_instructions") or "").strip()
        add_instr_enabled = bool(javelin_config.get("additional_instructions_enabled", bool(add_instr)) and add_instr)
        mining_strategy = str(javelin_config.get("mining_strategy") or "focus_area")
        api_inventory = str(javelin_config.get("api_inventory") or "")
        if "bac_analysis" in javelin_config and javelin_config.get("bac_analysis") in {"auto", "off"}:
            bac_mode = str(javelin_config["bac_analysis"])
        else:
            bac_mode = "auto" if javelin_config.get("bac_enabled", True) else "off"

        audit_payload: dict[str, Any] = {
            "audit_id": audit_id,
            "target_id": target_id,
            "name": (scan_name or resolved_project.name)[:160],
            "model": selected_model,
            "task_protocol": "task-board.v1",
            "mining_strategy": mining_strategy,
            "api_inventory": api_inventory,
            "bac_analysis": bac_mode,
            "memory_mode": str(javelin_config.get("memory_mode") or "full"),
            "additional_instructions_enabled": add_instr_enabled,
            "additional_instructions": add_instr if add_instr_enabled else "",
            "test_environment_enabled": rt_enabled,
            "test_environment_context": secret_test_env if rt_enabled else "",
        }
        if rt_enabled:
            raw_actions = list(runtime_testing_cfg.get("allowed_actions") or ["navigate", "normal_interaction"])
            allowed_actions = list(dict.fromkeys(["navigate", *raw_actions]))
            budget_minutes = max(10, min(240, int(runtime_testing_cfg.get("budget_minutes") or 60)))
            audit_payload["runtime_testing"] = {
                "protocol": "runtime-testing.v1",
                "mode": str(runtime_testing_cfg.get("mode") or "INTEGRATED_TESTING"),
                "budget_minutes": budget_minutes,
                "allowed_actions": allowed_actions,
                "identity_mode": str(runtime_testing_cfg.get("identity_mode") or "auto"),
                "explicit_authorization": True,
            }

        javelin_console_log(
            f"正在创建目录级审计任务: audit_id={audit_id}, target_id={target_id}, "
            f"策略={mining_strategy}, 越权专项={bac_mode}, 动态测试={'开启' if rt_enabled else '关闭'}"
        )
        create_url = f"{self._origin}/api/v2/products/{UNDEFINED_PRODUCT_ID}/audits"
        create_resp = await self._http.post(
            create_url,
            headers=self._headers({"Idempotency-Key": f"create-{scan_id}"}),
            json=audit_payload,
        )
        if create_resp.status_code == 422:
            err_code, err_msg = _extract_error_detail(create_resp)
            if err_code in {"opencode-model-not-configured", "opencode-model-invalid"} and audit_payload["model"] != "default":
                javelin_console_log(
                    f"所选模型 {audit_payload['model']!r} 未在 OpenCode 清单中登记 ({err_msg})，自动回退为 default 模型"
                )
                audit_payload["model"] = "default"
                create_resp = await self._http.post(
                    create_url,
                    headers=self._headers({"Idempotency-Key": f"create-default-{scan_id}"}),
                    json=audit_payload,
                )

        self._raise_for_javelin_status(create_resp, "创建 Javelin 审计任务")
        audit = create_resp.json()
        if audit.get("status") == "queued":
            with contextlib.suppress(Exception):
                audit = await self.dispatch_action(
                    audit_id,
                    "dispatch",
                    expected_version=audit.get("version"),
                    action_id=f"dispatch-{scan_id}",
                )

        javelin_console_log(
            f"Javelin 审计引擎已启动执行: audit_id={audit_id}, 当前状态={audit.get('status')}, "
            f"模型={audit.get('model') or 'default'}"
        )
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
        norm_action = str(action or "").strip().lower()
        if expected_version is None:
            try:
                current = await self.get_audit(audit_id)
            except FileNotFoundError:
                if norm_action == "cancel":
                    return {"id": audit_id, "status": "cancelled", "already_missing": True}
                raise
            expected_version = int(current.get("version") or 1)

        extra = {"If-Match": f'"{expected_version}"'}
        if action_id:
            extra["Idempotency-Key"] = action_id

        v2_url = f"{self._origin}/api/v2/products/{UNDEFINED_PRODUCT_ID}/audits/{audit_id}/actions"
        resp = await self._http.post(
            v2_url,
            headers=self._headers(extra),
            json={"action": norm_action},
        )
        if resp.status_code == 404:
            resp = await self._http.post(
                f"{self._origin}/api/v1/audits/{audit_id}/actions",
                headers=self._headers(extra),
                json={"action": norm_action},
            )
        if resp.status_code == 412:
            current = await self.get_audit(audit_id)
            extra["If-Match"] = f'"{int(current.get("version") or 1)}"'
            resp = await self._http.post(
                v2_url,
                headers=self._headers(extra),
                json={"action": norm_action},
            )
        if resp.status_code == 404 and norm_action == "cancel":
            return {"id": audit_id, "status": "cancelled", "already_missing": True}
        self._raise_for_javelin_status(resp, f"执行 Javelin 控制动作 '{norm_action}'")
        return resp.json()

    async def get_audit(self, audit_id: str) -> dict[str, Any]:
        assert self._http is not None
        resp = await self._http.get(
            f"{self._origin}/api/v2/products/{UNDEFINED_PRODUCT_ID}/audits/{audit_id}",
            params={"live": "1"},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        if resp.status_code == 404:
            resp = await self._http.get(
                f"{self._origin}/api/v1/audits/{audit_id}",
                params={"live": "1"},
                headers={"Authorization": f"Bearer {self._token}"},
            )
        if resp.status_code == 404:
            raise FileNotFoundError(f"Javelin 本地审计任务不存在: {audit_id}")
        self._raise_for_javelin_status(resp, f"读取审计状态 ({audit_id})")
        data = resp.json()
        return data["audit"] if isinstance(data, dict) and "audit" in data else data

    async def get_task_board(self, audit_id: str, *, offset: int = 0, limit: int = 500) -> dict[str, Any]:
        assert self._http is not None
        resp = await self._http.get(
            f"{self._origin}/api/v2/products/{UNDEFINED_PRODUCT_ID}/audits/{audit_id}/task-board",
            params={"offset": offset, "limit": limit},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        if resp.status_code == 404:
            resp = await self._http.get(
                f"{self._origin}/api/v1/audits/{audit_id}/task-board",
                params={"offset": offset, "limit": limit},
                headers={"Authorization": f"Bearer {self._token}"},
            )
        if resp.status_code == 404:
            return {"items": [], "total": 0}
        self._raise_for_javelin_status(resp, f"读取任务面板 ({audit_id})")
        return resp.json()

    async def get_logs(self, audit_id: str, *, limit: int = 400) -> list[dict[str, Any]]:
        assert self._http is not None
        resp = await self._http.get(
            f"{self._origin}/api/v2/products/{UNDEFINED_PRODUCT_ID}/audits/{audit_id}/logs",
            params={"limit": limit},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        if resp.status_code == 404:
            resp = await self._http.get(
                f"{self._origin}/api/v1/audits/{audit_id}/logs",
                params={"limit": limit},
                headers={"Authorization": f"Bearer {self._token}"},
            )
        if resp.status_code == 404:
            return []
        self._raise_for_javelin_status(resp, f"读取运行日志 ({audit_id})")
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
            self._raise_for_javelin_status(resp, f"读取漏洞发现列表 ({audit_id})")
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
        self._raise_for_javelin_status(resp, f"读取运行测试交互 ({audit_id})")
        return list(resp.json().get("items") or [])

    async def get_reports(self, audit_id: str) -> list[dict[str, Any]]:
        assert self._http is not None
        resp = await self._http.get(
            f"{self._origin}/api/v1/reports",
            headers={"Authorization": f"Bearer {self._token}"},
        )
        if resp.status_code == 404:
            return []
        self._raise_for_javelin_status(resp, f"读取报告列表 ({audit_id})")
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
        self._raise_for_javelin_status(resp, f"下载原始报告 ({report_id})")
        return bytes(resp.content)

    def find_source_baseline_file(self, audit: dict[str, Any], audit_id: str) -> Path | None:
        candidates: list[Path] = []
        sb = audit.get("source_baseline")
        if isinstance(sb, dict) and sb.get("path"):
            candidates.append(Path(str(sb["path"])))
        paths = audit.get("paths") if isinstance(audit.get("paths"), dict) else {}
        for key in ("reports_root", "workspace_root", "audit_dir"):
            val = str(paths.get(key) or "").strip()
            if val:
                base = Path(val)
                candidates.extend([
                    base / "coverage" / f"source-baseline.{audit_id}.json",
                    base / f"source-baseline.{audit_id}.json",
                    base / "task-board" / f"source-baseline.{audit_id}.json",
                    base / "scope" / f"source-baseline.{audit_id}.json",
                    base / "reports" / "coverage" / f"source-baseline.{audit_id}.json",
                    base / "reports" / "task-board" / f"source-baseline.{audit_id}.json",
                ])
        ws_reports = self.workspace_root / "reports" / "repositories"
        if ws_reports.is_dir():
            candidates.extend(ws_reports.rglob(f"source-baseline.{audit_id}.json"))
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
            f"{self._origin}/api/v2/products/{UNDEFINED_PRODUCT_ID}/audits/{audit_id}/events",
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
        stderr_task = self._stderr_task
        self._proc = None
        self._stderr_task = None
        if proc.returncode is None:
            if self._http is not None and self._origin and self._token:
                with contextlib.suppress(Exception):
                    await self._http.post(
                        f"{self._origin}/api/internal/service/stop",
                        headers={"Authorization": f"Bearer {self._token}"},
                        timeout=3.0,
                    )
            with contextlib.suppress(ProcessLookupError):
                proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                await asyncio.gather(proc.wait(), return_exceptions=True)
        if stderr_task is not None and not stderr_task.done():
            stderr_task.cancel()
            await asyncio.gather(stderr_task, return_exceptions=True)
        self._origin = ""
        self._token = ""


_GLOBAL_JAVELIN_MANAGER: JavelinAuditServiceManager | None = None


def get_javelin_service_manager() -> JavelinAuditServiceManager:
    global _GLOBAL_JAVELIN_MANAGER
    if _GLOBAL_JAVELIN_MANAGER is None:
        _GLOBAL_JAVELIN_MANAGER = JavelinAuditServiceManager()
    return _GLOBAL_JAVELIN_MANAGER
