"""Ephemeral Cordis patch composition on top of DeepSeek Harness ``sdk-minimal``."""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from .model_catalog import ResolvedDshModel

_TOOL_GATE_PLUGIN_PATH = (Path(__file__).resolve().parent / "_tool_gate.mjs").resolve()
_API_KEY_ENV_VAR = "OPENDEEPHOLE_DSH_API_KEY"
_MCP_NAME_SANITIZE_RE = re.compile(r"[^A-Za-z0-9_-]+")
_LEADING_SLASH_SKILL_RE = re.compile(r"^\s*/([A-Za-z0-9][A-Za-z0-9._-]{0,127})(?:\s|$)")

_BASE_PERSONA = (
    "You are an expert security researcher and software engineer executing an automated "
    "OpenDeepHole task. Work methodically, rely on direct code/tool evidence, and strictly "
    "follow all output format and file-boundary requirements."
)


@dataclass(frozen=True)
class DshMcpMountSpec:
    """Normalized on-demand MCP server entry for ``@deepseek-ai/dsh-mcp-client``."""

    id: str
    server_name: str
    transport: str  # "stdio" | "streamable-http"
    timeout_ms: int = 300_000
    command: str = ""
    args: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    cwd: str = ""
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ComposedDshPatch:
    """Generated temporary Cordis patch file and matching subprocess environment."""

    patch_path: Path
    patch_document: list[dict[str, Any]]
    env: dict[str, str]
    mounted_mcps: tuple[str, ...] = ()
    mounted_skills: bool = False


def sanitize_mcp_server_name(raw_name: str, *, fallback: str, used: set[str]) -> str:
    """Conform to ``@deepseek-ai/dsh-mcp-client`` ``[A-Za-z0-9_-]{1,32}``."""
    cleaned = _MCP_NAME_SANITIZE_RE.sub("_", str(raw_name or "").strip()).strip("_")
    if not cleaned:
        cleaned = fallback
    base = cleaned[:32]
    candidate = base
    suffix = 2
    while candidate in used:
        tag = f"_{suffix}"
        candidate = f"{base[: 32 - len(tag)]}{tag}"
        suffix += 1
    used.add(candidate)
    return candidate


def detect_leading_skill_name(prompt: str) -> str:
    """Return ``<skill_name>`` when *prompt* begins with ``/<skill_name>``."""
    match = _LEADING_SLASH_SKILL_RE.match(str(prompt or ""))
    return match.group(1) if match else ""


def _build_system_prompt(
    *,
    system_prompt: str,
    prompt: str,
    write_roots: tuple[Path, ...],
    disable_all_tools: bool,
    has_skills: bool,
) -> str:
    sections: list[str] = [_BASE_PERSONA]
    extra = str(system_prompt or "").strip()
    if extra:
        sections.append(extra)
    if has_skills and not disable_all_tools:
        leading_skill = detect_leading_skill_name(prompt)
        if leading_skill:
            sections.append(
                f"The user prompt begins with `/{leading_skill}`. "
                f"First invoke the `skill` tool with `{{\"name\": \"{leading_skill}\"}}` "
                "to load its full instructions before executing the task."
            )
    if not disable_all_tools:
        if write_roots:
            roots_text = ", ".join(str(root) for root in write_roots)
            sections.append(
                "File boundary policy: source code directories are strictly read-only. "
                f"You may only create or modify files inside these writable directories: {roots_text}."
            )
        else:
            sections.append(
                "File boundary policy: this task is strictly read-only; do not attempt to modify files."
            )
    return "\n\n".join(sections)


def _prepend_path_env(
    env: dict[str, str],
    prepend_dirs: Iterable[str],
) -> None:
    entries = [str(item).strip() for item in prepend_dirs if str(item).strip()]
    if not entries:
        return
    sep = os.pathsep
    existing = env.get("PATH") or os.environ.get("PATH") or ""
    existing_parts = [part for part in existing.split(sep) if part]
    normalized_entries = {
        item.lower() if os.name == "nt" else item for item in entries
    }
    retained = [
        part
        for part in existing_parts
        if (part.lower() if os.name == "nt" else part) not in normalized_entries
    ]
    joined = sep.join((*entries, *retained))
    env["PATH"] = joined
    if os.name == "nt":
        env["Path"] = joined


def build_cordis_patch_document(
    *,
    resolved_model: ResolvedDshModel,
    prompt: str = "",
    system_prompt: str = "",
    skill_roots: Iterable[Path] = (),
    write_roots: Iterable[Path] = (),
    allowed_bash_commands: Iterable[str] = (),
    disable_all_tools: bool = False,
    mcp_mounts: Iterable[DshMcpMountSpec] = (),
) -> tuple[list[dict[str, Any]], dict[str, str], bool]:
    """Build the Cordis patch operations and subprocess env overrides.

    Secrets (``apiKey``) are placed exclusively in the returned ``env`` mapping
    and referenced via ``apiKeyEnv`` inside the YAML patch.
    """
    env: dict[str, str] = {}
    insert_rows: list[dict[str, Any]] = []
    override_rows: list[dict[str, Any]] = []

    normalized_write_roots = tuple(dict.fromkeys(Path(root).resolve() for root in write_roots))
    normalized_skill_roots = tuple(
        dict.fromkeys(
            str(Path(root).expanduser().resolve())
            for root in skill_roots
            if str(root).strip()
        )
    )
    has_allowed_bash = any(str(cmd).strip() for cmd in allowed_bash_commands)
    mount_skills = bool(normalized_skill_roots) and not disable_all_tools

    # 1. LLM Provider configuration (pi-ai for arbitrary OpenAI-compatible APIs;
    #    sdk-minimal's built-in llm-deepseek for deepseek-official).
    if resolved_model.is_pi_ai:
        provider_profile: dict[str, Any] = {
            "api": "openai-completions",
            "baseURL": resolved_model.base_url,
            "defaultContextWindow": resolved_model.context_window,
            "defaultMaxTokens": resolved_model.max_tokens,
            "models": [
                {
                    "id": resolved_model.model_id,
                    "name": resolved_model.display_name or resolved_model.model_id,
                    "contextWindow": resolved_model.context_window,
                    "maxTokens": resolved_model.max_tokens,
                }
            ],
        }
        if resolved_model.api_key:
            provider_profile["apiKeyEnv"] = _API_KEY_ENV_VAR
            env[_API_KEY_ENV_VAR] = resolved_model.api_key
        if resolved_model.headers:
            provider_profile["headers"] = dict(resolved_model.headers)
        if resolved_model.timeout_ms:
            provider_profile["timeoutMs"] = int(resolved_model.timeout_ms)
        if resolved_model.stream_idle_timeout_ms:
            provider_profile["streamIdleTimeoutMs"] = int(resolved_model.stream_idle_timeout_ms)
        insert_rows.append(
            {
                "id": "llm-pi-ai",
                "name": "@deepseek-ai/dsh-llm-pi-ai",
                "config": {
                    "providers": {
                        resolved_model.provider_id: provider_profile,
                    }
                },
            }
        )
    elif resolved_model.provider_id == "deepseek-official":
        if resolved_model.api_key:
            env["DEEPSEEK_API_KEY"] = resolved_model.api_key
        if resolved_model.base_url:
            env["DEEPSEEK_BASE_URL"] = resolved_model.base_url

    # 2. System prompt override (explicit personaPrefix, no !!js evaluation needed).
    rendered_system_prompt = _build_system_prompt(
        system_prompt=system_prompt,
        prompt=prompt,
        write_roots=normalized_write_roots,
        disable_all_tools=disable_all_tools,
        has_skills=mount_skills,
    )
    override_rows.append(
        {
            "id": "system-prompt",
            "config": {
                "includeHarnessIdentity": False,
                "includeRuntimeContext": False,
                "personaPrefix": rendered_system_prompt,
            },
        }
    )

    # 3. Native approval service + OpenDeepHole pre-execute tool gate.
    insert_rows.append(
        {
            "id": "approval",
            "name": "@deepseek-ai/dsh-user-approval",
            "config": {"policy": "ask"},
        }
    )

    if disable_all_tools:
        override_rows.extend(
            [
                {"id": "persistent-bash", "disabled": True},
                {"id": "persistent-pwsh", "disabled": True},
                {"id": "tool-fs", "disabled": True},
                {"id": "tool-working-directory", "disabled": True},
            ]
        )
        insert_rows.append(
            {
                "id": "odh-tool-gate",
                "name": _TOOL_GATE_PLUGIN_PATH.as_uri(),
                "config": {"denyAll": True},
            }
        )
    else:
        can_write = bool(normalized_write_roots)
        override_rows.append(
            {
                "id": "tool-fs",
                "config": {
                    "read": True,
                    "readImage": True,
                    "write": can_write,
                    "edit": can_write,
                    "applyPatch": False,
                },
            }
        )
        insert_rows.append(
            {
                "id": "tool-fs-search",
                "name": "@deepseek-ai/dsh-tool-fs-search",
                "config": {"sampleOverCapGlobResults": False},
            }
        )
        if not has_allowed_bash:
            override_rows.append({"id": "persistent-bash", "disabled": True})
            override_rows.append({"id": "persistent-pwsh", "disabled": True})

        ask_tools = ["write", "edit", "apply_patch"]
        if has_allowed_bash:
            ask_tools.extend(["bash", "pwsh"])
        insert_rows.append(
            {
                "id": "odh-tool-gate",
                "name": _TOOL_GATE_PLUGIN_PATH.as_uri(),
                "config": {
                    "denyAll": False,
                    "askTools": ask_tools,
                },
            }
        )

    # 4. Native Skills (A4): mount strictly on OpenDeepHole's managed skill roots.
    if mount_skills:
        insert_rows.extend(
            [
                {"id": "skill", "name": "@deepseek-ai/dsh-skill"},
                {
                    "id": "skill-filesystem",
                    "name": "@deepseek-ai/dsh-skill-filesystem",
                    "config": {
                        "includeDefaultRoots": False,
                        "customSkillDirs": list(normalized_skill_roots),
                        "watch": False,
                    },
                },
                {"id": "tool-skill", "name": "@deepseek-ai/dsh-tool-skill"},
            ]
        )

    # 5. On-demand MCP clients (A3): pure sdk-minimal mounts zero MCP plugins unless requested.
    if not disable_all_tools:
        for mount in mcp_mounts:
            if mount.transport == "stdio":
                mcp_cfg: dict[str, Any] = {
                    "transport": "stdio",
                    "serverName": mount.server_name,
                    "command": mount.command,
                    "args": list(mount.args),
                    "env": dict(mount.env),
                    "toolCallTimeoutMs": int(mount.timeout_ms),
                    "failOnStartupError": False,
                }
                if mount.cwd:
                    mcp_cfg["cwd"] = mount.cwd
            else:
                mcp_cfg = {
                    "transport": "streamable-http",
                    "serverName": mount.server_name,
                    "url": mount.url,
                    "headers": dict(mount.headers),
                    "toolCallTimeoutMs": int(mount.timeout_ms),
                    "failOnStartupError": False,
                }
            insert_rows.append(
                {
                    "id": mount.id,
                    "name": "@deepseek-ai/dsh-mcp-client",
                    "config": mcp_cfg,
                }
            )

    patch_document: list[dict[str, Any]] = []
    if insert_rows:
        patch_document.append({"insert": insert_rows})
    patch_document.extend(override_rows)
    return patch_document, env, mount_skills


def compose_dsh_patch_file(
    *,
    resolved_model: ResolvedDshModel,
    dsh_home: Path,
    prompt: str = "",
    system_prompt: str = "",
    skill_roots: Iterable[Path] = (),
    write_roots: Iterable[Path] = (),
    allowed_bash_commands: Iterable[str] = (),
    required_bash_path_prepend: Iterable[str] = (),
    disable_all_tools: bool = False,
    mcp_mounts: Iterable[DshMcpMountSpec] = (),
    extra_env: Mapping[str, str] | None = None,
) -> ComposedDshPatch:
    """Materialize a private ``0600`` ephemeral Cordis patch YAML file."""
    mounts_tuple = tuple(mcp_mounts)
    patch_document, patch_env, mounted_skills = build_cordis_patch_document(
        resolved_model=resolved_model,
        prompt=prompt,
        system_prompt=system_prompt,
        skill_roots=skill_roots,
        write_roots=write_roots,
        allowed_bash_commands=allowed_bash_commands,
        disable_all_tools=disable_all_tools,
        mcp_mounts=mounts_tuple,
    )
    merged_env = dict(extra_env or {})
    merged_env.update(patch_env)
    _prepend_path_env(merged_env, required_bash_path_prepend)

    patch_dir = Path(dsh_home).expanduser().resolve() / "patches"
    patch_dir.mkdir(parents=True, exist_ok=True)
    fd, raw_path = tempfile.mkstemp(
        prefix="odh-dsh-",
        suffix=".cordis.patch.yml",
        dir=str(patch_dir),
    )
    patch_path = Path(raw_path)
    try:
        rendered = yaml.safe_dump(
            patch_document,
            allow_unicode=True,
            sort_keys=False,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(rendered)
        if os.name != "nt":
            patch_path.chmod(0o600)
    except BaseException:
        try:
            patch_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    return ComposedDshPatch(
        patch_path=patch_path,
        patch_document=patch_document,
        env=merged_env,
        mounted_mcps=tuple(mount.server_name for mount in mounts_tuple),
        mounted_skills=mounted_skills,
    )
