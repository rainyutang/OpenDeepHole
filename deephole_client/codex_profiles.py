"""Safely mirror user-level OpenCode models into Codex profile files."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from task_agent.config_discovery import (
    config_home_candidates,
    deep_merge_opencode_config,
)
from task_agent.config_json import parse_opencode_jsonc

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 Agent compatibility.
    tomllib = None  # type: ignore[assignment]


_MANAGED_MARKER = (
    "# Managed by OpenDeepHole Codex model sync. Do not edit."
)
_PROFILE_GLOB = "opendeephole-*.config.toml"
_ENV_REFERENCE_RE = re.compile(
    r"^\{env:([A-Za-z_][A-Za-z0-9_]*)\}$"
)
_VERSION_RE = re.compile(r"\b(\d+)\.(\d+)(?:\.\d+)?\b")
_SLUG_RE = re.compile(r"[^a-z0-9]+")
_MIN_SEPARATE_PROFILE_VERSION = (0, 134)


@dataclass(frozen=True)
class CodexModelProfile:
    """Secret-free metadata for one generated Codex model profile."""

    id: str
    provider_id: str
    model_id: str
    profile: str

    def engine_value(self, codex_command: tuple[str, ...]) -> dict[str, Any]:
        return {
            "id": self.id,
            "provider_id": self.provider_id,
            "model_id": self.model_id,
            "profile": self.profile,
            "command": [
                *codex_command,
                "--profile",
                self.profile,
            ],
        }


@dataclass(frozen=True)
class CodexProfileSyncResult:
    """Outcome of a best-effort OpenCode-to-Codex profile sync."""

    models: tuple[CodexModelProfile, ...] = ()
    warnings: tuple[str, ...] = ()
    error: str = ""


@dataclass(frozen=True)
class _RenderedProfile:
    model: CodexModelProfile
    content: str


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


def _global_opencode_paths(
    env: Mapping[str, str],
    *,
    platform: str,
) -> tuple[Path, ...]:
    """Return only user-level OpenCode JSON/JSONC paths, low to high."""
    paths: list[Path] = []
    seen: set[str] = set()
    for config_home in config_home_candidates(env, platform=platform):
        config_dir = config_home / "opencode"
        for filename in ("opencode.json", "opencode.jsonc"):
            candidate = config_dir / filename
            key = _path_key(candidate)
            if key in seen:
                continue
            seen.add(key)
            paths.append(candidate)
    return tuple(paths)


def _load_global_opencode_config(
    env: Mapping[str, str],
    *,
    platform: str,
) -> tuple[dict[str, Any], str]:
    merged: dict[str, Any] = {}
    for path in _global_opencode_paths(env, platform=platform):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
            config = parse_opencode_jsonc(text, source=str(path))
        except Exception as exc:
            # Parser messages can contain source details.  Deliberately expose
            # only the path and exception type so malformed secrets are never
            # copied into Agent output.
            return {}, (
                f"could not parse user OpenCode config {path} "
                f"({type(exc).__name__})"
            )
        merged = deep_merge_opencode_config(merged, config)
    return merged, ""


def _codex_home(
    env: Mapping[str, str],
    *,
    platform: str,
) -> Path:
    configured = str(env.get("CODEX_HOME") or "").strip()
    if configured:
        return Path(os.path.expandvars(configured)).expanduser()

    home = str(env.get("HOME") or "").strip()
    if not home and platform == "win32":
        home = str(env.get("USERPROFILE") or "").strip()
    if home:
        return Path(os.path.expandvars(home)).expanduser() / ".codex"
    return Path.home() / ".codex"


def _version_support_error(version: str) -> tuple[str, str]:
    match = _VERSION_RE.search(str(version or ""))
    if match is None:
        return "", (
            "Codex version could not be parsed; using the current separate "
            "profile format"
        )
    current = (int(match.group(1)), int(match.group(2)))
    if current < _MIN_SEPARATE_PROFILE_VERSION:
        return (
            "Codex "
            f"{match.group(0)} is older than 0.134 and does not support "
            "separate profile files; existing managed profiles were kept"
        ), ""
    return "", ""


def _valid_base_url(value: object) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text or _ENV_REFERENCE_RE.fullmatch(text):
        return ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return text


def _slug(value: str, *, fallback: str, limit: int) -> str:
    normalized = _SLUG_RE.sub("-", value.strip().lower()).strip("-")
    return (normalized or fallback)[:limit].rstrip("-") or fallback


def _profile_name(provider_id: str, model_id: str) -> str:
    canonical_id = f"{provider_id}/{model_id}"
    digest = hashlib.sha256(canonical_id.encode("utf-8")).hexdigest()[:12]
    return "-".join((
        "opendeephole",
        _slug(provider_id, fallback="provider", limit=24),
        _slug(model_id, fallback="model", limit=36),
        digest,
    ))


def _provider_key(provider_id: str) -> str:
    digest = hashlib.sha256(provider_id.encode("utf-8")).hexdigest()[:16]
    return f"opendeephole_{digest}"


def _toml_string(value: str) -> str:
    # JSON strings are valid TOML basic strings for the characters emitted by
    # json.dumps with ensure_ascii enabled.
    return json.dumps(value, ensure_ascii=True)


def _context_window(model_config: Mapping[str, Any]) -> int | None:
    limit = model_config.get("limit")
    if not isinstance(limit, Mapping):
        return None
    context = limit.get("context")
    if isinstance(context, bool) or not isinstance(context, int):
        return None
    return context if context > 0 else None


def _render_profile(
    *,
    provider_id: str,
    provider_config: Mapping[str, Any],
    model_id: str,
    model_config: Mapping[str, Any],
) -> tuple[_RenderedProfile | None, tuple[str, ...]]:
    canonical_id = f"{provider_id}/{model_id}"
    options = provider_config.get("options")
    if not isinstance(options, Mapping):
        options = {}
    base_url = _valid_base_url(options.get("baseURL"))
    if not base_url:
        return None, (
            f"Skipped OpenCode model {canonical_id}: provider baseURL is "
            "missing or invalid",
        )

    warnings: list[str] = []
    api_key = options.get("apiKey")
    env_key = ""
    bearer_token = ""
    if isinstance(api_key, str) and api_key:
        env_match = _ENV_REFERENCE_RE.fullmatch(api_key.strip())
        if env_match is not None:
            env_key = env_match.group(1)
        else:
            bearer_token = api_key
    elif api_key is not None:
        warnings.append(
            f"OpenCode model {canonical_id} has a non-string apiKey; "
            "the generated profile has no provider credential"
        )

    profile = CodexModelProfile(
        id=canonical_id,
        provider_id=provider_id,
        model_id=model_id,
        profile=_profile_name(provider_id, model_id),
    )
    provider_key = _provider_key(provider_id)
    provider_name = str(provider_config.get("name") or provider_id).strip()
    context_window = _context_window(model_config)

    lines = [
        _MANAGED_MARKER,
        f"model = {_toml_string(model_id)}",
        f"model_provider = {_toml_string(provider_key)}",
    ]
    if context_window is not None:
        lines.append(f"model_context_window = {context_window}")
    lines.extend((
        "",
        f"[model_providers.{provider_key}]",
        f"name = {_toml_string(provider_name or provider_id)}",
        f"base_url = {_toml_string(base_url)}",
        'wire_api = "responses"',
    ))
    if env_key:
        lines.append(f"env_key = {_toml_string(env_key)}")
    elif bearer_token:
        lines.append(
            "experimental_bearer_token = "
            f"{_toml_string(bearer_token)}"
        )
    content = "\n".join(lines) + "\n"
    # Treat our own serializer as untrusted before any secret-bearing content
    # reaches the user's Codex directory.
    if tomllib is not None:
        tomllib.loads(content)
    return _RenderedProfile(model=profile, content=content), tuple(warnings)


def _render_profiles(
    config: Mapping[str, Any],
) -> tuple[tuple[_RenderedProfile, ...], tuple[str, ...]]:
    providers = config.get("provider")
    if providers is None:
        return (), ()
    if not isinstance(providers, Mapping):
        return (), (
            "Skipped OpenCode models: top-level provider must be an object",
        )

    rendered: list[_RenderedProfile] = []
    warnings: list[str] = []
    for raw_provider_id in sorted(providers, key=lambda item: str(item)):
        provider_id = str(raw_provider_id).strip()
        provider_config = providers[raw_provider_id]
        if not provider_id or not isinstance(provider_config, Mapping):
            warnings.append(
                "Skipped an OpenCode provider with an invalid id or value"
            )
            continue
        models = provider_config.get("models")
        if models is None:
            continue
        if not isinstance(models, Mapping):
            warnings.append(
                f"Skipped OpenCode provider {provider_id}: models must be "
                "an object"
            )
            continue
        for raw_model_id in sorted(models, key=lambda item: str(item)):
            model_id = str(raw_model_id).strip()
            model_config = models[raw_model_id]
            if not model_id or not isinstance(model_config, Mapping):
                warnings.append(
                    f"Skipped an invalid model under OpenCode provider "
                    f"{provider_id}"
                )
                continue
            try:
                item, item_warnings = _render_profile(
                    provider_id=provider_id,
                    provider_config=provider_config,
                    model_id=model_id,
                    model_config=model_config,
                )
            except Exception as exc:
                warnings.append(
                    f"Skipped OpenCode model {provider_id}/{model_id}: "
                    f"profile conversion failed ({type(exc).__name__})"
                )
                continue
            warnings.extend(item_warnings)
            if item is not None:
                rendered.append(item)
    return tuple(rendered), tuple(warnings)


def _is_owned_profile(path: Path) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    try:
        with path.open("r", encoding="utf-8") as handle:
            return handle.readline().rstrip("\r\n") == _MANAGED_MARKER
    except (OSError, UnicodeError):
        return False


def _owned_profiles(codex_home: Path) -> tuple[Path, ...]:
    if not codex_home.is_dir():
        return ()
    return tuple(
        path
        for path in codex_home.glob(_PROFILE_GLOB)
        if _is_owned_profile(path)
    )


def _stage_profile(path: Path, content: str) -> Path:
    temporary = path.parent / (
        f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        return temporary
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _write_and_reconcile(
    codex_home: Path,
    profiles: tuple[_RenderedProfile, ...],
) -> tuple[str, tuple[str, ...]]:
    desired = {
        codex_home / f"{item.model.profile}.config.toml": item.content
        for item in profiles
    }
    try:
        existing_owned = set(_owned_profiles(codex_home))
    except Exception as exc:
        return (
            f"could not inspect Codex profile directory {codex_home} "
            f"({type(exc).__name__})",
            (),
        )

    try:
        foreign_destination = next(
            (
                destination
                for destination in desired
                if (
                    destination.is_symlink()
                    or (
                        destination.exists()
                        and destination not in existing_owned
                    )
                )
            ),
            None,
        )
    except OSError as exc:
        return (
            "could not inspect a target Codex profile "
            f"({type(exc).__name__})",
            (),
        )
    if foreign_destination is not None:
        return (
            f"refused to overwrite non-OpenDeepHole Codex profile "
            f"{foreign_destination}",
            (),
        )

    if desired:
        try:
            codex_home.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as exc:
            return (
                f"could not create Codex profile directory {codex_home} "
                f"({type(exc).__name__})",
                (),
            )

    staged: dict[Path, Path] = {}
    try:
        for destination, content in desired.items():
            staged[destination] = _stage_profile(destination, content)
        for destination, temporary in staged.items():
            os.replace(temporary, destination)
    except Exception as exc:
        for temporary in staged.values():
            try:
                temporary.unlink()
            except OSError:
                pass
        return (
            "could not atomically write managed Codex profiles "
            f"({type(exc).__name__}); existing stale profiles were kept",
            (),
        )

    warnings: list[str] = []
    for stale in sorted(existing_owned - set(desired), key=str):
        try:
            stale.unlink()
        except OSError as exc:
            warnings.append(
                f"Could not remove stale managed Codex profile {stale} "
                f"({type(exc).__name__})"
            )
    return "", tuple(warnings)


def sync_codex_profiles(
    *,
    codex_version: str,
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    codex_home: Path | None = None,
) -> CodexProfileSyncResult:
    """Synchronize global OpenCode models without changing Codex defaults."""
    effective_env = dict(os.environ) if env is None else dict(env)
    active_platform = platform or sys.platform
    version_error, version_warning = _version_support_error(codex_version)
    if version_error:
        return CodexProfileSyncResult(error=version_error)

    config, parse_error = _load_global_opencode_config(
        effective_env,
        platform=active_platform,
    )
    if parse_error:
        return CodexProfileSyncResult(error=parse_error)

    rendered, conversion_warnings = _render_profiles(config)
    destination = codex_home or _codex_home(
        effective_env,
        platform=active_platform,
    )
    write_error, reconciliation_warnings = _write_and_reconcile(
        destination,
        rendered,
    )
    warnings = tuple(
        item
        for item in (
            version_warning,
            *conversion_warnings,
            *reconciliation_warnings,
        )
        if item
    )
    if write_error:
        return CodexProfileSyncResult(
            warnings=warnings,
            error=write_error,
        )
    return CodexProfileSyncResult(
        models=tuple(item.model for item in rendered),
        warnings=warnings,
    )


__all__ = [
    "CodexModelProfile",
    "CodexProfileSyncResult",
    "sync_codex_profiles",
]
