"""Singleton DeepSeek Harness backend manager implementing RuntimeBackendManager."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import logging
import shutil
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from ..host import OpenCodeSessionRuntime, get_host_bindings
from ..kb_mcp_proxy import KnowledgeBaseMcpProxy
from ..runtime_backend import DEFAULT_DSH_PROFILE, TOOL_DEEPSEEK_HARNESS
from ..serve_client import (
    OpenCodeModelListResult,
    OpenCodePromptResult,
    OpenCodeServeStartupError,
)
from .approval_policy import DshApprovalArbitrator
from .model_catalog import (
    check_dsh_runtime_available,
    extract_llm_providers,
    list_dsh_models,
    resolve_dsh_model,
)
from .patch_composer import (
    DshMcpMountSpec,
    compose_dsh_patch_file,
    sanitize_mcp_server_name,
)
from .session_runner import (
    ActiveDshRunHandle,
    find_persisted_session_jsonl,
    run_dsh_turn,
)

logger = logging.getLogger(__name__)


def _default_dsh_home(
    *,
    backend_options: Mapping[str, Any] | None = None,
    config_workspace: Path | None = None,
) -> Path:
    configured = str((backend_options or {}).get("dsh_home") or "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    if config_workspace is not None:
        return (Path(config_workspace).expanduser().resolve() / ".opendeephole-dsh-home").resolve()
    return (Path.home() / ".opendeephole" / "dsh_home").resolve()


def _extract_permission_write_roots(permissions: Any) -> list[Path]:
    """Extract writable paths from OpenCode-style permission rule dicts."""
    if not isinstance(permissions, Iterable) or isinstance(permissions, (str, bytes, dict)):
        return []
    roots: list[Path] = []
    seen: set[str] = set()
    for rule in permissions:
        if not isinstance(rule, Mapping):
            continue
        if rule.get("permission") != "edit" or rule.get("action") != "allow":
            continue
        pattern = str(rule.get("pattern") or "").strip()
        if not pattern or pattern == "*":
            continue
        if pattern.endswith("/**") or pattern.endswith("\\**"):
            pattern = pattern[:-3]
        elif pattern.endswith("**"):
            pattern = pattern[:-2]
        pattern = pattern.rstrip("/\\") or pattern
        if not pattern or "*" in pattern or "?" in pattern:
            continue
        candidate = Path(pattern).expanduser()
        if not candidate.is_absolute():
            continue
        key = str(candidate)
        if key not in seen:
            seen.add(key)
            roots.append(candidate)
    return roots


def _extract_skill_roots(
    *,
    backend_options: Mapping[str, Any] | None,
    config_workspace: Path | None,
) -> tuple[Path, ...]:
    roots: list[Path] = []
    seen: set[Path] = set()
    raw_roots = (backend_options or {}).get("skill_roots") or ()
    for item in raw_roots:
        text = str(item or "").strip()
        if not text:
            continue
        resolved = Path(text).expanduser().resolve()
        if resolved.is_dir() and resolved not in seen:
            seen.add(resolved)
            roots.append(resolved)
    if not roots and config_workspace is not None:
        candidate = (Path(config_workspace).expanduser().resolve() / ".opencode" / "skills").resolve()
        if candidate.is_dir():
            roots.append(candidate)
    return tuple(roots)


def _session_jsonl_path(dsh_home: Path, session_id: str) -> Path | None:
    return find_persisted_session_jsonl(dsh_home, session_id)


def _read_dsh_session_events(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.is_file():
        return []
    events: list[dict[str, Any]] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            events.append(parsed)
    return events


class DeepSeekHarnessManager:
    """Manages per-turn DeepSeek Harness (`sdk-minimal`) sessions and shared resources."""

    def __init__(
        self,
        *,
        harness_factory: Callable[[Any], Any] | None = None,
    ) -> None:
        self._active_runs: dict[str, ActiveDshRunHandle] = {}
        self._skill_lock = asyncio.Lock()
        self._kb_proxy: KnowledgeBaseMcpProxy | None = None
        self._managed_mcp_specs: dict[str, dict[str, Any]] = {}
        self._cached_limits: dict[str, tuple[int | None, int | None]] = {}
        self._harness_factory = harness_factory

    def is_ready_for_prompt(self) -> bool:
        return True

    def is_preparing(self) -> bool:
        return False

    def config_runtime_status(self) -> dict[str, int | str]:
        return {
            "runtime_state": "active",
            "active_sessions": len(self._active_runs),
        }

    def mark_dirty(self) -> None:
        self._cached_limits.clear()

    def update_managed_mcp_configs(self, specs: dict[str, dict[str, Any]]) -> None:
        self._managed_mcp_specs = dict(specs or {})

    async def refresh_managed_mcp_runtime_status(self) -> dict[str, dict[str, Any]]:
        return {
            target: {
                "name": str(spec.get("name") or target),
                "status": "configured",
            }
            for target, spec in self._managed_mcp_specs.items()
            if isinstance(spec, Mapping)
        }

    def cached_model_limits(
        self,
        *,
        config_content: str = "",
    ) -> dict[str, tuple[int | None, int | None]]:
        if config_content:
            listed = list_dsh_models(config_content=config_content)
            return {
                item.id: (item.limit_context, item.limit_output)
                for item in listed.models
            }
        return dict(self._cached_limits)

    async def update_skill_catalog(
        self,
        needed: Callable[[], bool],
        publish: Callable[[], None],
        *,
        cancel_event: Any = None,
    ) -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise asyncio.CancelledError("Skill catalog sync cancelled")
        async with self._skill_lock:
            if cancel_event is not None and cancel_event.is_set():
                raise asyncio.CancelledError("Skill catalog sync cancelled")
            if needed():
                publish()

    def prepare_runtime(
        self,
        runtime: OpenCodeSessionRuntime,
        context: Any,
    ) -> OpenCodeSessionRuntime:
        """Attach host skill roots and writable boundaries into ``runtime.backend_options``."""
        options = dict(runtime.backend_options)
        skill_roots: list[str] = [
            str(Path(item).expanduser().resolve())
            for item in (options.get("skill_roots") or ())
            if str(item).strip()
        ]
        try:
            bindings = get_host_bindings()
        except RuntimeError:
            bindings = None

        if bindings is not None and bindings.fixed_skill_root is not None:
            fixed = str(Path(bindings.fixed_skill_root()).expanduser().resolve())
            if fixed not in skill_roots:
                skill_roots.append(fixed)
        else:
            for item in getattr(context, "skill_paths", ()) or ():
                resolved = str(Path(item).expanduser().resolve())
                if resolved not in skill_roots:
                    skill_roots.append(resolved)

        writable_roots: list[str] = [
            str(Path(item).expanduser().resolve())
            for item in (options.get("writable_roots") or ())
            if str(item).strip()
        ]
        if bindings is not None:
            for root in bindings.writable_roots() or ():
                resolved = str(Path(root).expanduser().resolve())
                if resolved not in writable_roots:
                    writable_roots.append(resolved)
        work_dir = getattr(context, "work_dir", None)
        if work_dir is not None:
            resolved_work = str(Path(work_dir).expanduser().resolve())
            if resolved_work not in writable_roots:
                writable_roots.append(resolved_work)

        options["skill_roots"] = skill_roots
        options["writable_roots"] = writable_roots
        return dataclasses.replace(runtime, backend_options=options)

    async def prepare_prompt(self, **_kwargs: Any) -> None:
        """Per-turn DSH processes need no shared Serve warm-up permit."""
        return None

    async def list_models(
        self,
        *,
        tool: str = TOOL_DEEPSEEK_HARNESS,
        executable: str = "",
        opencode_version: str = "1",
        directory: Path | None = None,
        config_workspace: Path | None = None,
        config_content: str | None = None,
        env_overrides: dict[str, str] | None = None,
        serve_port_auto: bool = False,
        refresh: bool = False,
        backend_options: Mapping[str, Any] | None = None,
    ) -> OpenCodeModelListResult:
        del tool, opencode_version, directory, serve_port_auto, refresh
        opts = dict(backend_options or {})
        dsh_home = _default_dsh_home(
            backend_options=opts,
            config_workspace=config_workspace,
        )
        llm_providers = opts.get("llm_providers")
        result = list_dsh_models(
            llm_providers=llm_providers if isinstance(llm_providers, Mapping) else None,
            config_content=config_content,
            dsh_home=dsh_home,
            env=env_overrides,
        )
        self._cached_limits = {
            item.id: (item.limit_context, item.limit_output)
            for item in result.models
        }
        return result

    async def reload_runtime(
        self,
        *,
        tool: str = TOOL_DEEPSEEK_HARNESS,
        executable: str = "",
        opencode_version: str = "1",
        directory: Path | None = None,
        config_workspace: Path | None = None,
        config_content: str | None = None,
        env_overrides: dict[str, str] | None = None,
        serve_port_auto: bool = False,
        backend_options: Mapping[str, Any] | None = None,
    ) -> OpenCodeModelListResult:
        opts = dict(backend_options or {})
        dsh_executable = str(opts.get("dsh_executable") or executable or "").strip()
        if dsh_executable == "dsh":
            # Default placeholder means prefer bundled runtime unless explicit path given.
            dsh_executable = ""
        ok, detail = check_dsh_runtime_available(dsh_executable)
        if not ok:
            raise OpenCodeServeStartupError(detail)
        return await self.list_models(
            tool=tool,
            executable=executable,
            opencode_version=opencode_version,
            directory=directory,
            config_workspace=config_workspace,
            config_content=config_content,
            env_overrides=env_overrides,
            serve_port_auto=serve_port_auto,
            refresh=True,
            backend_options=opts,
        )

    async def _build_mcp_mounts(
        self,
        *,
        directory: Path,
        code_graph_mcp: Mapping[str, Any] | None,
        knowledge_base_mcp: Mapping[str, Any] | None,
        disable_all_tools: bool,
    ) -> list[DshMcpMountSpec]:
        if disable_all_tools:
            return []
        mounts: list[DshMcpMountSpec] = []
        used_names: set[str] = set()

        if isinstance(code_graph_mcp, Mapping) and bool(code_graph_mcp.get("enabled")):
            transport = str(code_graph_mcp.get("transport") or "local").strip().lower()
            timeout_ms = max(1, int(code_graph_mcp.get("timeout_seconds") or 300)) * 1000
            server_name = sanitize_mcp_server_name(
                str(code_graph_mcp.get("name") or "codegraph"),
                fallback="codegraph",
                used=used_names,
            )
            if transport == "local":
                local = code_graph_mcp.get("local")
                local_map = local if isinstance(local, Mapping) else {}
                command = str(local_map.get("executable") or "").strip()
                if command:
                    args = tuple(str(item) for item in (local_map.get("args") or ()))
                    env = {
                        str(k): str(v)
                        for k, v in (local_map.get("environment") or {}).items()
                        if str(k)
                    }
                    mounts.append(
                        DshMcpMountSpec(
                            id="mcp-code-graph",
                            server_name=server_name,
                            transport="stdio",
                            timeout_ms=timeout_ms,
                            command=command,
                            args=args,
                            env=env,
                            cwd=str(directory.resolve()),
                        )
                    )
            elif transport == "remote":
                remote = code_graph_mcp.get("remote")
                remote_map = remote if isinstance(remote, Mapping) else {}
                url = str(remote_map.get("url") or "").strip()
                if url:
                    headers = {
                        str(k): str(v)
                        for k, v in (remote_map.get("headers") or {}).items()
                        if str(k)
                    }
                    mounts.append(
                        DshMcpMountSpec(
                            id="mcp-code-graph",
                            server_name=server_name,
                            transport="streamable-http",
                            timeout_ms=timeout_ms,
                            url=url,
                            headers=headers,
                        )
                    )

        if isinstance(knowledge_base_mcp, Mapping) and bool(knowledge_base_mcp.get("enabled")):
            remote = knowledge_base_mcp.get("remote")
            remote_map = remote if isinstance(remote, Mapping) else {}
            upstream_url = str(remote_map.get("url") or "").strip()
            project_id = str(knowledge_base_mcp.get("project_id") or "").strip()
            if upstream_url and project_id:
                timeout_seconds = max(1, int(knowledge_base_mcp.get("timeout_seconds") or 300))
                headers = {
                    str(k): str(v)
                    for k, v in (remote_map.get("headers") or {}).items()
                    if str(k)
                }
                blocked_tools = frozenset(
                    name
                    for name in (
                        str(knowledge_base_mcp.get("projects_tool") or "").strip(),
                        str(knowledge_base_mcp.get("set_project_tool") or "").strip(),
                    )
                    if name
                )
                if self._kb_proxy is None:
                    self._kb_proxy = KnowledgeBaseMcpProxy()
                proxy_url, _route = await self._kb_proxy.ensure_route(
                    upstream_url=upstream_url,
                    headers=headers,
                    project_id=project_id,
                    timeout_seconds=timeout_seconds,
                    blocked_tools=blocked_tools,
                )
                server_name = sanitize_mcp_server_name(
                    str(knowledge_base_mcp.get("name") or "knowledge-base"),
                    fallback="knowledge_base",
                    used=used_names,
                )
                mounts.append(
                    DshMcpMountSpec(
                        id="mcp-knowledge-base",
                        server_name=server_name,
                        transport="streamable-http",
                        timeout_ms=timeout_seconds * 1000,
                        url=proxy_url,
                        headers={},
                    )
                )

        return mounts

    async def run_prompt(
        self,
        *,
        prompt: str,
        directory: Path,
        tool: str = TOOL_DEEPSEEK_HARNESS,
        executable: str = "",
        opencode_version: str = "1",
        model: str = "",
        config_workspace: Path | None = None,
        config_content: str | None = None,
        env_overrides: dict[str, str] | None = None,
        serve_port_auto: bool = False,
        backend_options: Mapping[str, Any] | None = None,
        timeout: float | None = None,
        idle_timeout: float | None = None,
        on_line: Callable[[str], Any] | None = None,
        on_session_id: Callable[[str], Any] | None = None,
        on_model_request_failure: Callable[[str], Any] | None = None,
        on_response_model: Callable[[str], Any] | None = None,
        on_token_usage: Callable[[Any], Any] | None = None,
        on_file_write: Callable[[Any], Any] | None = None,
        on_model_progress: Callable[[], Any] | None = None,
        cancel_event: Any = None,
        session_id: str | None = None,
        session_title: str = "",
        mcp_tools: Any = None,
        disabled_mcp_tools: Any = (),
        scan_id: str = "",
        code_graph_mcp: Mapping[str, Any] | None = None,
        knowledge_base_mcp: Mapping[str, Any] | None = None,
        system_prompt: str = "",
        permissions: Any = None,
        disable_all_tools: bool = False,
        return_details: bool = True,
        show_serve_status: bool = False,
        log_stage: str = "opencode",
        task_id: str = "",
        task_attempt: int = 0,
        allowed_bash_commands: Iterable[str] = (),
        required_bash_commands: Iterable[str] = (),
        bash_command_match_mode: str = "exact",
        required_bash_success_markers: Iterable[tuple[str, str]] = (),
        required_bash_path_prepend: Iterable[str] = (),
        **_ignored_kwargs: Any,
    ) -> OpenCodePromptResult:
        del (
            tool,
            opencode_version,
            serve_port_auto,
            session_title,
            mcp_tools,
            disabled_mcp_tools,
            scan_id,
            return_details,
            show_serve_status,
            task_id,
            task_attempt,
        )
        opts = dict(backend_options or {})
        resolved_dir = Path(directory).resolve()
        dsh_home = _default_dsh_home(
            backend_options=opts,
            config_workspace=config_workspace,
        )
        dsh_executable = str(opts.get("dsh_executable") or executable or "").strip()
        if dsh_executable == "dsh":
            dsh_executable = ""
        dsh_profile = str(opts.get("dsh_profile") or DEFAULT_DSH_PROFILE).strip() or DEFAULT_DSH_PROFILE

        raw_providers = opts.get("llm_providers")
        llm_providers = extract_llm_providers(
            llm_providers=raw_providers if isinstance(raw_providers, Mapping) else None,
            config_content=config_content,
        )
        resolved_model = resolve_dsh_model(
            model,
            llm_providers=llm_providers,
            config_content=config_content,
            env=env_overrides,
        )

        # Combine writable roots from runtime.backend_options and per-task permissions.
        write_roots: list[Path] = []
        seen_write_roots: set[str] = set()
        for item in opts.get("writable_roots") or ():
            text = str(item or "").strip()
            if not text:
                continue
            p = Path(text).expanduser().resolve()
            if str(p) not in seen_write_roots:
                seen_write_roots.add(str(p))
                write_roots.append(p)
        for p in _extract_permission_write_roots(permissions):
            resolved_p = p.resolve()
            if str(resolved_p) not in seen_write_roots:
                seen_write_roots.add(str(resolved_p))
                write_roots.append(resolved_p)

        all_allowed_bash = tuple(
            dict.fromkeys(
                str(cmd).strip()
                for cmd in (*allowed_bash_commands, *required_bash_commands)
                if str(cmd).strip()
            )
        )
        required_bash_tuple = tuple(
            dict.fromkeys(str(cmd).strip() for cmd in required_bash_commands if str(cmd).strip())
        )
        markers_tuple = tuple(
            (str(cmd).strip(), str(marker).strip())
            for cmd, marker in required_bash_success_markers
        )
        skill_roots = _extract_skill_roots(
            backend_options=opts,
            config_workspace=config_workspace,
        )
        mcp_mounts = await self._build_mcp_mounts(
            directory=resolved_dir,
            code_graph_mcp=code_graph_mcp,
            knowledge_base_mcp=knowledge_base_mcp,
            disable_all_tools=disable_all_tools,
        )
        composed_patch = compose_dsh_patch_file(
            resolved_model=resolved_model,
            dsh_home=dsh_home,
            prompt=prompt,
            system_prompt=system_prompt,
            skill_roots=skill_roots,
            write_roots=write_roots,
            allowed_bash_commands=all_allowed_bash,
            required_bash_path_prepend=required_bash_path_prepend,
            disable_all_tools=disable_all_tools,
            mcp_mounts=mcp_mounts,
            extra_env=env_overrides,
        )
        arbitrator = DshApprovalArbitrator(
            cwd=resolved_dir,
            write_roots=write_roots,
            allowed_bash_commands=all_allowed_bash,
            bash_command_match_mode=bash_command_match_mode,
            disable_all_tools=disable_all_tools,
        )

        def register_active(handle: ActiveDshRunHandle) -> None:
            self._active_runs[handle.run_id] = handle

        def unregister_active(run_id: str) -> None:
            self._active_runs.pop(run_id, None)

        return await run_dsh_turn(
            prompt=prompt,
            directory=resolved_dir,
            dsh_home=dsh_home,
            dsh_executable=dsh_executable,
            dsh_profile=dsh_profile,
            resolved_model=resolved_model,
            composed_patch=composed_patch,
            arbitrator=arbitrator,
            session_id=session_id,
            timeout=timeout,
            idle_timeout=idle_timeout,
            cancel_event=cancel_event,
            log_stage=log_stage,
            llm_providers=llm_providers,
            required_bash_commands=required_bash_tuple,
            required_bash_success_markers=markers_tuple,
            on_line=on_line,
            on_session_id=on_session_id,
            on_model_request_failure=on_model_request_failure,
            on_response_model=on_response_model,
            on_token_usage=on_token_usage,
            on_file_write=on_file_write,
            on_model_progress=on_model_progress,
            on_register_active=register_active,
            on_unregister_active=unregister_active,
            harness_factory=self._harness_factory,
        )

    async def get_session(
        self,
        session_id: str,
        *,
        config_workspace: Path | None = None,
        backend_options: Mapping[str, Any] | None = None,
        **_kwargs: Any,
    ) -> dict[str, Any] | None:
        dsh_home = _default_dsh_home(
            backend_options=backend_options,
            config_workspace=config_workspace,
        )
        path = _session_jsonl_path(dsh_home, session_id)
        if path is None or not path.is_file():
            return None
        events = _read_dsh_session_events(path)
        header = events[0] if events else {}
        return {
            "id": session_id,
            "backend": TOOL_DEEPSEEK_HARNESS,
            "path": str(path),
            "event_count": len(events),
            "header": header,
        }

    async def get_session_messages(
        self,
        session_id: str,
        *,
        config_workspace: Path | None = None,
        backend_options: Mapping[str, Any] | None = None,
        **_kwargs: Any,
    ) -> list[dict[str, Any]]:
        dsh_home = _default_dsh_home(
            backend_options=backend_options,
            config_workspace=config_workspace,
        )
        path = _session_jsonl_path(dsh_home, session_id)
        events = _read_dsh_session_events(path)
        messages: list[dict[str, Any]] = []
        for event in events:
            event_type = event.get("type")
            data = event.get("data")
            if not isinstance(data, dict):
                continue
            if event_type == "user/message":
                content = data.get("content") if isinstance(data.get("content"), list) else []
                parts = [
                    {"type": "text", "text": str(block.get("text") or "")}
                    for block in content
                    if isinstance(block, dict) and block.get("type") == "text"
                ]
                messages.append(
                    {
                        "info": {
                            "id": str(data.get("id") or ""),
                            "role": "user",
                        },
                        "parts": parts,
                    }
                )
            elif event_type == "assistant/message":
                msg = data.get("message") if isinstance(data.get("message"), dict) else data
                source = msg.get("source") if isinstance(msg.get("source"), dict) else {}
                content = msg.get("content") if isinstance(msg.get("content"), list) else []
                parts = [
                    {"type": "text", "text": str(block.get("text") or "")}
                    for block in content
                    if isinstance(block, dict) and block.get("type") == "text"
                ]
                messages.append(
                    {
                        "info": {
                            "id": str(msg.get("id") or ""),
                            "role": "assistant",
                            "providerID": str(source.get("provider") or ""),
                            "modelID": str(source.get("model") or ""),
                        },
                        "parts": parts,
                    }
                )
        return messages

    async def delete_session(
        self,
        session_id: str,
        *,
        config_workspace: Path | None = None,
        backend_options: Mapping[str, Any] | None = None,
        **_kwargs: Any,
    ) -> bool:
        for run_id, handle in list(self._active_runs.items()):
            if handle.session_id == session_id:
                handle.abort()
                self._active_runs.pop(run_id, None)
        dsh_home = _default_dsh_home(
            backend_options=backend_options,
            config_workspace=config_workspace,
        )
        path = _session_jsonl_path(dsh_home, session_id)
        deleted = False
        if path is not None and path.is_file():
            if path.parent.name == session_id:
                with contextlib.suppress(OSError):
                    shutil.rmtree(path.parent)
                    deleted = True
            else:
                with contextlib.suppress(OSError):
                    path.unlink()
                    deleted = True
        return deleted

    async def shutdown(self) -> None:
        for handle in list(self._active_runs.values()):
            with contextlib.suppress(Exception):
                handle.abort()
        self._active_runs.clear()
        if self._kb_proxy is not None:
            proxy = self._kb_proxy
            self._kb_proxy = None
            await proxy.close()
        self._cached_limits.clear()


_dsh_manager: DeepSeekHarnessManager | None = None


def get_dsh_manager() -> DeepSeekHarnessManager:
    global _dsh_manager
    if _dsh_manager is None:
        _dsh_manager = DeepSeekHarnessManager()
    return _dsh_manager


async def shutdown_dsh_manager() -> None:
    global _dsh_manager
    manager = _dsh_manager
    _dsh_manager = None
    if manager is not None:
        await manager.shutdown()
