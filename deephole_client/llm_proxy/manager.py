"""Generate and run the local LLM_Proxy used by managed Codex profiles."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

import httpx
import yaml


LLM_PROXY_HOST = "127.0.0.1"
LLM_PROXY_PORT = 31943
LLM_PROXY_BASE_URL = f"http://{LLM_PROXY_HOST}:{LLM_PROXY_PORT}/v1"
LLM_PROXY_PROVIDER_NAME = "codemate"
LLM_PROXY_STARTUP_TIMEOUT_SECONDS = 10.0
_LLM_PROXY_ROOT = Path(__file__).resolve().parent / "LLM_Proxy"
LLM_PROXY_CONFIG_PATH = _LLM_PROXY_ROOT / "config.yaml"
_PROCESS_STATE_PATH = (
    Path.home() / ".opendeephole" / "llm_proxy_process.json"
)
_NO_PROXY_ENV_NAMES = ("NO_PROXY", "no_proxy")
_LOOPBACK_NO_PROXY_ENTRIES = (LLM_PROXY_HOST, "localhost")


@dataclass(frozen=True)
class LLMProxyConfig:
    """Validated deterministic configuration for one proxy process."""

    content: bytes
    fingerprint: str
    upstream_api: str
    model_ids: tuple[str, ...]
    routed_model_ids: tuple[str, ...]


@dataclass(frozen=True)
class LLMProxySyncResult:
    """Outcome of reconciling the process with the selected models."""

    available: bool
    running: bool = False
    restarted: bool = False
    fingerprint: str = ""
    model_ids: tuple[str, ...] = ()
    error: str = ""
    pid: int | None = None
    started_at: float | None = None


def _normalized_model_ids(
    model_ids: Sequence[str] | str,
) -> tuple[str, ...]:
    values: Sequence[str] = (
        (model_ids,) if isinstance(model_ids, str) else model_ids
    )
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_model_id in values:
        model_id = str(raw_model_id or "").strip()
        if not model_id or model_id in seen:
            continue
        seen.add(model_id)
        normalized.append(model_id)
    return tuple(normalized)


def _valid_upstream_base_url(value: object) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text or (text.startswith("{env:") and text.endswith("}")):
        return ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return text.rstrip("/")


def _ensure_loopback_no_proxy() -> None:
    """Keep Codex-to-proxy traffic out of ambient HTTP proxies."""
    for name in _NO_PROXY_ENV_NAMES:
        entries: list[str] = []
        seen: set[str] = set()
        for value in (
            os.environ.get(name, ""),
            ",".join(_LOOPBACK_NO_PROXY_ENTRIES),
        ):
            for item in value.split(","):
                normalized = item.strip()
                if normalized and normalized not in seen:
                    entries.append(normalized)
                    seen.add(normalized)
        os.environ[name] = ",".join(entries)


def build_llm_proxy_config(
    opencode_config: Mapping[str, Any],
    selected_model_ids: Sequence[str] | str,
) -> LLMProxyConfig | None:
    """Map enabled ``codemate/model`` ids to the requested proxy YAML."""
    selected = _normalized_model_ids(selected_model_ids)
    if not selected:
        return None
    if not isinstance(opencode_config, Mapping):
        raise ValueError("effective OpenCode configuration is not an object")

    providers = opencode_config.get("provider")
    if not isinstance(providers, Mapping):
        raise ValueError(
            "effective OpenCode provider configuration is missing or invalid"
        )
    provider = providers.get(LLM_PROXY_PROVIDER_NAME)
    if not isinstance(provider, Mapping):
        raise ValueError(
            "selected Codex models require the codemate OpenCode provider"
        )
    options = provider.get("options")
    if not isinstance(options, Mapping):
        options = {}
    upstream_base_url = _valid_upstream_base_url(options.get("baseURL"))
    if not upstream_base_url:
        raise ValueError(
            "codemate provider options.baseURL is missing or invalid"
        )
    upstream_api = f"{upstream_base_url}/chat/completions"

    configured_models = provider.get("models")
    if not isinstance(configured_models, Mapping):
        raise ValueError("codemate provider models are missing or invalid")

    model_ids: list[str] = []
    routed_model_ids: list[str] = []
    for canonical_id in selected:
        provider_id, separator, model_id = canonical_id.partition("/")
        if (
            not separator
            or provider_id.strip() != LLM_PROXY_PROVIDER_NAME
            or not model_id.strip()
        ):
            raise ValueError(
                "Codex proxy models must use codemate/model identifiers; "
                f"received {canonical_id or '<empty>'}"
            )
        model_id = model_id.strip()
        if not isinstance(configured_models.get(model_id), Mapping):
            raise ValueError(
                "selected model is absent from the effective codemate "
                f"configuration: {canonical_id}"
            )
        model_ids.append(model_id)
        routed_model_ids.append(f"{LLM_PROXY_PROVIDER_NAME}/{model_id}")

    document = {
        "server": {
            "port": LLM_PROXY_PORT,
            "host": LLM_PROXY_HOST,
        },
        "providers": [{
            "name": LLM_PROXY_PROVIDER_NAME,
            "enabled": True,
            "api": upstream_api,
            "source_format": "openai_chat",
            "verify_ssl": False,
            "model_list": model_ids,
            "hook": "codemate_hook.py",
            "proxy_mode": "direct",
        }],
    }
    content = yaml.safe_dump(
        document,
        allow_unicode=True,
        sort_keys=False,
    ).encode("utf-8")
    return LLMProxyConfig(
        content=content,
        fingerprint=hashlib.sha256(content).hexdigest(),
        upstream_api=upstream_api,
        model_ids=tuple(model_ids),
        routed_model_ids=tuple(routed_model_ids),
    )


def _atomic_write(path: Path, content: bytes, *, mode: int = 0o600) -> bool:
    """Replace one owned runtime file and report whether bytes changed."""
    if path.is_symlink():
        raise OSError(f"refused to replace symlinked proxy config {path}")
    if path.exists() and not path.is_file():
        raise OSError(f"proxy config path is not a file: {path}")
    if path.is_file() and path.read_bytes() == content:
        if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) != mode:
            path.chmod(mode)
        return False

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / (
        f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(temporary, mode)
        os.replace(temporary, path)
        return True
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


class LLMProxyManager:
    """Own exactly one proxy child process and serialize reconfiguration."""

    def __init__(
        self,
        *,
        proxy_root: Path | None = None,
        process_state_path: Path | None = None,
        startup_timeout_seconds: float = LLM_PROXY_STARTUP_TIMEOUT_SECONDS,
    ) -> None:
        self.proxy_root = (proxy_root or _LLM_PROXY_ROOT).resolve()
        self.config_path = self.proxy_root / "config.yaml"
        self.process_state_path = process_state_path or _PROCESS_STATE_PATH
        self.startup_timeout_seconds = max(
            0.1,
            float(startup_timeout_seconds),
        )
        self._lock = asyncio.Lock()
        self._process: asyncio.subprocess.Process | None = None
        self._fingerprint = ""
        self._started_at: float | None = None

    async def sync(
        self,
        opencode_config: Mapping[str, Any],
        selected_model_ids: Sequence[str] | str,
    ) -> LLMProxySyncResult:
        """Make config, process and selected proxy routes agree."""
        async with self._lock:
            try:
                desired = build_llm_proxy_config(
                    opencode_config,
                    selected_model_ids,
                )
            except Exception as exc:
                await self._stop_locked()
                return self._error_result(
                    str(exc).strip() or type(exc).__name__,
                )

            if desired is None:
                await self._stop_locked()
                self._remove_generated_config()
                return LLMProxySyncResult(available=True)

            _ensure_loopback_no_proxy()

            process_running = (
                self._process is not None
                and self._process.returncode is None
            )
            same_config = self._config_matches(desired.content)
            if (
                process_running
                and same_config
                and self._fingerprint == desired.fingerprint
                and await self._ready_once(desired.routed_model_ids)
            ):
                return self._success_result(desired, restarted=False)

            restarted = process_running
            if self._process is not None:
                await self._stop_locked()
            try:
                _atomic_write(self.config_path, desired.content)
            except Exception as exc:
                return self._error_result(
                    "could not write LLM proxy config "
                    f"({type(exc).__name__})"
                )

            main_path = self.proxy_root / "main.py"
            if not main_path.is_file():
                return self._error_result(
                    f"LLM proxy entrypoint is missing: {main_path}"
                )
            if await self._port_accepting():
                return self._error_result(
                    f"LLM proxy port {LLM_PROXY_HOST}:{LLM_PROXY_PORT} "
                    "is already occupied by an unowned process"
                )

            try:
                await self._start_locked(desired)
                await self._wait_until_ready(desired.routed_model_ids)
            except asyncio.CancelledError:
                await self._stop_locked()
                raise
            except Exception as exc:
                await self._stop_locked()
                return self._error_result(
                    str(exc).strip() or type(exc).__name__,
                )
            return self._success_result(desired, restarted=restarted)

    async def stop(self) -> None:
        async with self._lock:
            await self._stop_locked()

    def _config_matches(self, content: bytes) -> bool:
        try:
            return (
                not self.config_path.is_symlink()
                and self.config_path.is_file()
                and self.config_path.read_bytes() == content
            )
        except OSError:
            return False

    def _remove_generated_config(self) -> None:
        try:
            if self.config_path.is_symlink():
                return
            if self.config_path.is_file():
                self.config_path.unlink()
        except OSError:
            pass

    async def _start_locked(self, desired: LLMProxyConfig) -> None:
        kwargs: dict[str, Any] = {
            "cwd": str(self.proxy_root),
            "stdout": asyncio.subprocess.DEVNULL,
            "stderr": asyncio.subprocess.DEVNULL,
        }
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        self._process = await asyncio.create_subprocess_exec(
            sys.executable,
            "main.py",
            **kwargs,
        )
        self._fingerprint = desired.fingerprint
        self._started_at = time.time()
        self._write_process_state()

    async def _wait_until_ready(
        self,
        expected_model_ids: tuple[str, ...],
    ) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.startup_timeout_seconds
        while loop.time() < deadline:
            process = self._process
            if process is None:
                raise RuntimeError("LLM proxy process was not created")
            if process.returncode is not None:
                raise RuntimeError(
                    "LLM proxy exited before readiness "
                    f"(exit_code={process.returncode})"
                )
            if await self._ready_once(expected_model_ids):
                return
            await asyncio.sleep(0.1)
        raise RuntimeError(
            "LLM proxy readiness timed out after "
            f"{self.startup_timeout_seconds:g} seconds"
        )

    async def _ready_once(
        self,
        expected_model_ids: tuple[str, ...],
    ) -> bool:
        try:
            async with httpx.AsyncClient(
                timeout=0.5,
                trust_env=False,
            ) as client:
                response = await client.get(f"{LLM_PROXY_BASE_URL}/models")
            if response.status_code != 200:
                return False
            payload = response.json()
            data = payload.get("data") if isinstance(payload, Mapping) else None
            if not isinstance(data, list):
                return False
            available = {
                str(item.get("id") or "")
                for item in data
                if isinstance(item, Mapping)
            }
            return set(expected_model_ids).issubset(available)
        except (httpx.HTTPError, ValueError, TypeError):
            return False

    async def _port_accepting(self) -> bool:
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(LLM_PROXY_HOST, LLM_PROXY_PORT),
                timeout=0.25,
            )
        except (OSError, asyncio.TimeoutError):
            return False
        writer.close()
        await writer.wait_closed()
        return True

    async def _stop_locked(self) -> None:
        process = self._process
        self._process = None
        self._fingerprint = ""
        self._started_at = None
        self._remove_process_state()
        if process is None or process.returncode is not None:
            return

        if os.name == "nt":
            try:
                process.terminate()
            except ProcessLookupError:
                return
        else:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                return
            except OSError:
                try:
                    process.terminate()
                except ProcessLookupError:
                    return
        try:
            await asyncio.wait_for(process.wait(), timeout=5.0)
            return
        except asyncio.TimeoutError:
            pass

        if os.name == "nt":
            try:
                killer = await asyncio.create_subprocess_exec(
                    "taskkill",
                    "/PID",
                    str(process.pid),
                    "/T",
                    "/F",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(killer.wait(), timeout=5.0)
            except (OSError, asyncio.TimeoutError):
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
        try:
            await asyncio.wait_for(process.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            pass

    def _write_process_state(self) -> None:
        process = self._process
        if process is None:
            return
        payload = {
            "pid": process.pid,
            "parent_pid": os.getpid(),
            "created_at": self._started_at,
            "config_fingerprint": self._fingerprint,
            "command": [sys.executable, "main.py"],
            "cwd": str(self.proxy_root),
        }
        try:
            _atomic_write(
                self.process_state_path,
                (
                    json.dumps(payload, ensure_ascii=True, sort_keys=True)
                    + "\n"
                ).encode("utf-8"),
            )
        except OSError:
            pass

    def _remove_process_state(self) -> None:
        try:
            if self.process_state_path.is_symlink():
                return
            if self.process_state_path.is_file():
                self.process_state_path.unlink()
        except OSError:
            pass

    def _success_result(
        self,
        desired: LLMProxyConfig,
        *,
        restarted: bool,
    ) -> LLMProxySyncResult:
        process = self._process
        return LLMProxySyncResult(
            available=True,
            running=process is not None and process.returncode is None,
            restarted=restarted,
            fingerprint=desired.fingerprint,
            model_ids=desired.routed_model_ids,
            pid=process.pid if process is not None else None,
            started_at=self._started_at,
        )

    def _error_result(self, error: str) -> LLMProxySyncResult:
        return LLMProxySyncResult(
            available=False,
            error=error,
        )


_manager: LLMProxyManager | None = None


def get_llm_proxy_manager() -> LLMProxyManager:
    global _manager
    if _manager is None:
        _manager = LLMProxyManager()
    return _manager


async def sync_llm_proxy(
    opencode_config: Mapping[str, Any],
    selected_model_ids: Sequence[str] | str,
) -> LLMProxySyncResult:
    return await get_llm_proxy_manager().sync(
        opencode_config,
        selected_model_ids,
    )


async def stop_llm_proxy() -> None:
    await get_llm_proxy_manager().stop()


def _reset_llm_proxy_manager_for_tests() -> None:
    global _manager
    _manager = None


__all__ = [
    "LLM_PROXY_BASE_URL",
    "LLM_PROXY_CONFIG_PATH",
    "LLM_PROXY_HOST",
    "LLM_PROXY_PORT",
    "LLMProxyConfig",
    "LLMProxyManager",
    "LLMProxySyncResult",
    "build_llm_proxy_config",
    "get_llm_proxy_manager",
    "stop_llm_proxy",
    "sync_llm_proxy",
]
