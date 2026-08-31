"""Safely configure Codex defaults and trusted OpenDeepHole paths."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 Agent compatibility.
    import tomli as tomllib


_MANAGED_MARKER = (
    "# Managed by OpenDeepHole Codex model sync. Do not edit."
)
_DEFAULT_CONFIG_BEGIN = (
    "# BEGIN OpenDeepHole managed Codex default model"
)
_DEFAULT_CONFIG_END = (
    "# END OpenDeepHole managed Codex default model"
)
_TRUST_CONFIG_BEGIN = (
    "# BEGIN OpenDeepHole managed Codex trusted projects"
)
_TRUST_CONFIG_END = (
    "# END OpenDeepHole managed Codex trusted projects"
)
_ENV_BEGIN = "# BEGIN OpenDeepHole managed Codex NO_PROXY"
_ENV_END = "# END OpenDeepHole managed Codex NO_PROXY"
_PROFILE_GLOB = "opendeephole-*.config.toml"
_ENV_REFERENCE_RE = re.compile(
    r"^\{env:([A-Za-z_][A-Za-z0-9_]*)\}$"
)
_ENV_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:export\s+)?(NO_PROXY|no_proxy)\s*=\s*(.*?)\s*$"
)


@dataclass(frozen=True)
class CodexModelConfig:
    """Secret-free metadata for the effective Codex default model."""

    id: str
    provider_id: str
    model_id: str

    def engine_value(self, codex_command: tuple[str, ...]) -> dict[str, Any]:
        return {
            "id": self.id,
            "provider_id": self.provider_id,
            "model_id": self.model_id,
            "command": list(codex_command),
        }


@dataclass(frozen=True)
class CodexConfigSyncResult:
    """Outcome of a best-effort Codex default-config synchronization."""

    models: tuple[CodexModelConfig, ...] = ()
    managed_default_model: CodexModelConfig | None = None
    user_default_preserved: bool = False
    warnings: tuple[str, ...] = ()
    error: str = ""


@dataclass(frozen=True)
class CodexTrustSyncResult:
    """Outcome of adding OpenDeepHole-required Codex trust entries."""

    trusted_paths: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    error: str = ""


@dataclass(frozen=True)
class _RenderedModel:
    model: CodexModelConfig
    provider_key: str
    provider_name: str
    base_url: str
    env_key: str = ""
    bearer_token: str = ""
    context_window: int | None = None


@dataclass(frozen=True)
class _DefaultConfigPlan:
    path: Path
    write_content: bytes | None = None
    original_content: bytes | None = None
    original_mode: int = 0o600
    mode: int = 0o600
    effective_model: CodexModelConfig | None = None
    managed_default_model: CodexModelConfig | None = None
    user_default_preserved: bool = False
    error: str = ""


@dataclass(frozen=True)
class _ReconcileResult:
    effective_model: CodexModelConfig | None = None
    managed_default_model: CodexModelConfig | None = None
    user_default_preserved: bool = False
    warnings: tuple[str, ...] = ()
    error: str = ""


class _CodexConfigChangedError(RuntimeError):
    pass


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


def normalize_codex_base_url(value: object) -> str:
    """Normalize an API root so Codex requests ``/v1/responses``."""
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text or _ENV_REFERENCE_RE.fullmatch(text):
        return ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return ""
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.query
        or parsed.fragment
    ):
        return ""
    path = parsed.path.rstrip("/")
    if path.endswith("/responses"):
        path = path[:-len("/responses")].rstrip("/")
    if not path.endswith("/v1"):
        path += "/v1"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


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


def _render_model(
    *,
    provider_id: str,
    provider_config: Mapping[str, Any],
    model_id: str,
    model_config: Mapping[str, Any],
) -> tuple[_RenderedModel | None, tuple[str, ...]]:
    canonical_id = f"{provider_id}/{model_id}"
    options = provider_config.get("options")
    if not isinstance(options, Mapping):
        options = {}
    base_url = normalize_codex_base_url(options.get("baseURL"))
    if not base_url:
        return None, (
            f"Skipped OpenCode model {canonical_id}: provider baseURL is "
            "missing or invalid",
        )

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
        return None, (
            f"OpenCode model {canonical_id} has a non-string apiKey; "
            "Codex configuration was not changed",
        )

    model = CodexModelConfig(
        id=canonical_id,
        provider_id=provider_id,
        model_id=model_id,
    )
    provider_key = _provider_key(provider_id)
    provider_name = str(provider_config.get("name") or provider_id).strip()
    context_window = _context_window(model_config)

    return _RenderedModel(
        model=model,
        provider_key=provider_key,
        provider_name=provider_name or provider_id,
        base_url=base_url,
        env_key=env_key,
        bearer_token=bearer_token,
        context_window=context_window,
    ), ()


def _render_models(
    config: Mapping[str, Any],
    selected_model_ids: Sequence[str],
) -> tuple[tuple[_RenderedModel, ...], tuple[str, ...], str]:
    selected: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for raw_model_id in selected_model_ids:
        canonical_id = str(raw_model_id or "").strip()
        if not canonical_id or canonical_id in seen:
            continue
        provider_id, separator, model_id = canonical_id.partition("/")
        if not separator or not provider_id.strip() or not model_id.strip():
            return (), (), (
                "could not map platform model "
                f"{canonical_id or '<empty>'}: expected provider/model"
            )
        provider_id = provider_id.strip()
        model_id = model_id.strip()
        canonical_id = f"{provider_id}/{model_id}"
        if canonical_id in seen:
            continue
        seen.add(canonical_id)
        selected.append((canonical_id, provider_id, model_id))

    if not selected:
        return (), (), ""

    providers = config.get("provider")
    if not isinstance(providers, Mapping):
        return (), (), (
            "could not map platform models: effective OpenCode provider "
            "configuration is missing or invalid"
        )

    rendered: list[_RenderedModel] = []
    warnings: list[str] = []
    for canonical_id, provider_id, model_id in selected:
        provider_config = providers.get(provider_id)
        if not isinstance(provider_config, Mapping):
            return (), tuple(warnings), (
                f"could not map platform model {canonical_id}: provider "
                "is absent from the effective client OpenCode configuration"
            )
        models = provider_config.get("models")
        if not isinstance(models, Mapping):
            return (), tuple(warnings), (
                f"could not map platform model {canonical_id}: provider "
                "models are missing or invalid"
            )
        model_config = models.get(model_id)
        if not isinstance(model_config, Mapping):
            return (), tuple(warnings), (
                f"could not map platform model {canonical_id}: model is "
                "absent from the effective client OpenCode configuration"
            )
        try:
            item, item_warnings = _render_model(
                provider_id=provider_id,
                provider_config=provider_config,
                model_id=model_id,
                model_config=model_config,
            )
        except Exception as exc:
            return (), tuple(warnings), (
                f"could not map platform model {canonical_id}: configuration "
                f"conversion failed ({type(exc).__name__})"
            )
        warnings.extend(item_warnings)
        if item is None:
            return (), tuple(warnings), (
                f"could not map platform model {canonical_id}; existing "
                "managed Codex configuration was kept"
            )
        rendered.append(item)
    return tuple(rendered), tuple(warnings), ""


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


def _available_provider_key(
    base_key: str,
    configured: Mapping[object, object],
) -> str:
    existing = {str(item) for item in configured}
    if base_key not in existing:
        return base_key
    suffix = 1
    while f"{base_key}_{suffix}" in existing:
        suffix += 1
    return f"{base_key}_{suffix}"


def _user_default_model(
    user_config: Mapping[str, Any],
) -> CodexModelConfig | None:
    raw_model = user_config.get("model")
    if not isinstance(raw_model, str) or not raw_model.strip():
        return None
    model_id = raw_model.strip()
    raw_provider = user_config.get("model_provider")
    provider_id = (
        raw_provider.strip()
        if isinstance(raw_provider, str) and raw_provider.strip()
        else "openai"
    )
    return CodexModelConfig(
        id=f"{provider_id}/{model_id}",
        provider_id=provider_id,
        model_id=model_id,
    )


def _managed_default_block(
    models: tuple[_RenderedModel, ...],
    user_config: Mapping[str, Any],
) -> tuple[str, _RenderedModel | None, str]:
    if not models:
        return "", None, ""

    if "model_provider" in user_config:
        return "", None, (
            "existing model_provider cannot be replaced safely without "
            "rewriting a user-owned value"
        )

    selected = models[0]
    configured_providers = user_config.get("model_providers")
    if isinstance(configured_providers, Mapping):
        provider_key = _available_provider_key(
            selected.provider_key,
            configured_providers,
        )
    elif "model_providers" in user_config:
        return "", None, (
            "existing model_providers cannot be extended safely without "
            "rewriting a user-owned value"
        )
    else:
        provider_key = selected.provider_key

    lines = [
        _DEFAULT_CONFIG_BEGIN,
        f"model = {_toml_string(selected.model.model_id)}",
        f"model_provider = {_toml_string(provider_key)}",
    ]
    if (
        selected.context_window is not None
        and "model_context_window" not in user_config
    ):
        lines.append(f"model_context_window = {selected.context_window}")
    prefix = f"model_providers.{provider_key}"
    lines.extend((
        f"{prefix}.name = {_toml_string(selected.provider_name)}",
        f"{prefix}.base_url = {_toml_string(selected.base_url)}",
        f'{prefix}.wire_api = "responses"',
    ))
    if selected.env_key:
        lines.append(
            f"{prefix}.env_key = {_toml_string(selected.env_key)}"
        )
    elif selected.bearer_token:
        lines.append(
            f"{prefix}.experimental_bearer_token = "
            f"{_toml_string(selected.bearer_token)}"
        )
    lines.extend((_DEFAULT_CONFIG_END, ""))
    return "\n".join(lines), selected, ""


def _split_managed_default(content: str) -> tuple[str, bool, str]:
    prefix = f"{_DEFAULT_CONFIG_BEGIN}\n"
    end_token = f"\n{_DEFAULT_CONFIG_END}\n"
    if not content.startswith(prefix):
        if (
            _DEFAULT_CONFIG_BEGIN in content
            or _DEFAULT_CONFIG_END in content
        ):
            return content, False, (
                "OpenDeepHole managed default markers are malformed or "
                "misplaced"
            )
        return content, False, ""

    end_index = content.find(end_token, len(prefix))
    if end_index < 0:
        return content, False, (
            "OpenDeepHole managed default markers are incomplete"
        )
    remainder_start = end_index + len(end_token)
    if content[remainder_start:remainder_start + 1] == "\n":
        remainder_start += 1
    remainder = content[remainder_start:]
    if (
        _DEFAULT_CONFIG_BEGIN in remainder
        or _DEFAULT_CONFIG_END in remainder
    ):
        return content, False, (
            "OpenDeepHole managed default markers are duplicated"
        )
    return remainder, True, ""


def _split_managed_trust(
    content: str,
) -> tuple[str, tuple[str, ...], bool, str]:
    """Remove and parse the one OpenDeepHole-owned trailing trust block."""
    begin_count = content.count(_TRUST_CONFIG_BEGIN)
    end_count = content.count(_TRUST_CONFIG_END)
    if begin_count == 0 and end_count == 0:
        return content, (), False, ""
    if begin_count != 1 or end_count != 1:
        return content, (), False, (
            "OpenDeepHole managed Codex trust markers are incomplete or "
            "duplicated"
        )

    start = content.find(_TRUST_CONFIG_BEGIN)
    end = content.find(
        _TRUST_CONFIG_END,
        start + len(_TRUST_CONFIG_BEGIN),
    )
    body_start = start + len(_TRUST_CONFIG_BEGIN)
    after = end + len(_TRUST_CONFIG_END)
    if (
        start < 0
        or end < 0
        or (start > 0 and content[start - 1] != "\n")
        or content[body_start:body_start + 1] != "\n"
        or content[end - 1:end] != "\n"
        or content[after:] not in {"", "\n"}
    ):
        return content, (), False, (
            "OpenDeepHole managed Codex trust block is misplaced"
        )

    body = content[body_start + 1:end]
    try:
        parsed = tomllib.loads(body)
    except Exception as exc:
        return content, (), False, (
            "OpenDeepHole managed Codex trust block is invalid "
            f"({type(exc).__name__})"
        )
    projects = parsed.get("projects")
    if set(parsed) != {"projects"} or not isinstance(projects, Mapping):
        return content, (), False, (
            "OpenDeepHole managed Codex trust block has unexpected keys"
        )

    paths: list[str] = []
    for raw_path, raw_config in projects.items():
        if (
            not isinstance(raw_path, str)
            or not raw_path
            or not isinstance(raw_config, Mapping)
            or set(raw_config) != {"trust_level"}
            or raw_config.get("trust_level") != "trusted"
        ):
            return content, (), False, (
                "OpenDeepHole managed Codex trust block has unexpected "
                "project values"
            )
        paths.append(raw_path)

    user_content = "" if start == 0 else content[:start - 1]
    return user_content, tuple(paths), True, ""


def _normalize_trust_paths(
    paths: Sequence[str | os.PathLike[str]],
    *,
    platform: str,
) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    windows = platform == "win32"
    for raw_path in paths:
        value = os.fspath(raw_path)
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError("trusted project paths must be non-empty strings")
        key = value.casefold() if windows else value
        if key in seen:
            continue
        seen.add(key)
        normalized.append(value)
    return tuple(sorted(normalized, key=lambda item: (item.casefold(), item)))


def _render_managed_trust(
    user_content: str,
    paths: Sequence[str],
) -> str:
    if not paths:
        return user_content
    lines = [_TRUST_CONFIG_BEGIN]
    for path in paths:
        lines.extend((
            f"[projects.{_toml_string(path)}]",
            'trust_level = "trusted"',
            "",
        ))
    lines.extend((_TRUST_CONFIG_END, ""))
    block = "\n".join(lines)
    return block if not user_content else user_content + "\n" + block


def sync_codex_trusted_projects(
    paths: Sequence[str | os.PathLike[str]],
    *,
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    codex_home: Path | None = None,
) -> CodexTrustSyncResult:
    """Add trusted projects without rewriting user-owned Codex settings."""
    effective_env = dict(os.environ) if env is None else dict(env)
    active_platform = platform or sys.platform
    destination = codex_home or _codex_home(
        effective_env,
        platform=active_platform,
    )
    config_path = destination / "config.toml"
    try:
        requested = _normalize_trust_paths(paths, platform=active_platform)
    except (TypeError, ValueError) as exc:
        return CodexTrustSyncResult(error=str(exc))
    if not requested:
        return CodexTrustSyncResult()

    try:
        if config_path.is_symlink():
            return CodexTrustSyncResult(
                error=(
                    f"refused to modify symlinked Codex config {config_path}; "
                    "existing configuration was kept"
                ),
            )
        exists = config_path.exists()
        if exists and not config_path.is_file():
            return CodexTrustSyncResult(
                error=(
                    f"refused to modify non-file Codex config {config_path}; "
                    "existing configuration was kept"
                ),
            )
        original_bytes = config_path.read_bytes() if exists else None
        original_text = (
            original_bytes.decode("utf-8")
            if original_bytes is not None
            else ""
        )
        mode = (
            stat.S_IMODE(config_path.stat().st_mode)
            if exists
            else 0o600
        )
    except (OSError, UnicodeError) as exc:
        return CodexTrustSyncResult(
            error=(
                f"could not read existing Codex config {config_path} "
                f"({type(exc).__name__}); existing configuration was kept"
            ),
        )

    remainder, _had_default, default_error = _split_managed_default(
        original_text,
    )
    if default_error:
        return CodexTrustSyncResult(
            error=(
                f"could not update Codex config {config_path}: "
                f"{default_error}; existing configuration was kept"
            ),
        )
    default_prefix_length = len(original_text) - len(remainder)
    default_prefix = original_text[:default_prefix_length]
    user_text, managed_paths, _had_trust, trust_error = (
        _split_managed_trust(remainder)
    )
    if trust_error:
        return CodexTrustSyncResult(
            error=(
                f"could not update Codex config {config_path}: "
                f"{trust_error}; existing configuration was kept"
            ),
        )

    try:
        parsed_user = tomllib.loads(user_text)
    except Exception as exc:
        return CodexTrustSyncResult(
            error=(
                f"could not parse existing Codex config {config_path} "
                f"({type(exc).__name__}); existing configuration was kept"
            ),
        )
    raw_user_projects = parsed_user.get("projects", {})
    if not isinstance(raw_user_projects, Mapping):
        return CodexTrustSyncResult(
            error=(
                f"could not update Codex config {config_path}: existing "
                "projects setting is not a table; existing configuration "
                "was kept"
            ),
        )

    windows = active_platform == "win32"
    user_projects = {
        (str(path).casefold() if windows else str(path)): (str(path), value)
        for path, value in raw_user_projects.items()
    }
    try:
        combined = _normalize_trust_paths(
            (*managed_paths, *requested),
            platform=active_platform,
        )
    except (TypeError, ValueError) as exc:
        return CodexTrustSyncResult(error=str(exc))

    managed_desired: list[str] = []
    effective_paths: list[str] = []
    for path in combined:
        key = path.casefold() if windows else path
        user_project = user_projects.get(key)
        if user_project is None:
            managed_desired.append(path)
            effective_paths.append(path)
            continue
        user_path, raw_config = user_project
        level = (
            raw_config.get("trust_level")
            if isinstance(raw_config, Mapping)
            else None
        )
        if level == "trusted":
            effective_paths.append(user_path)
            continue
        return CodexTrustSyncResult(
            error=(
                f"could not trust Codex project {path}: the user-owned "
                f"configuration for {user_path} is not trusted; existing "
                "configuration was kept"
            ),
        )

    desired_remainder = _render_managed_trust(
        user_text,
        managed_desired,
    )
    desired_text = default_prefix + desired_remainder
    try:
        tomllib.loads(desired_text)
    except Exception as exc:
        return CodexTrustSyncResult(
            error=(
                f"could not safely merge Codex trusted projects into "
                f"{config_path} ({type(exc).__name__}); existing "
                "configuration was kept"
            ),
        )

    desired_bytes = desired_text.encode("utf-8")
    if original_bytes == desired_bytes:
        return CodexTrustSyncResult(
            trusted_paths=tuple(effective_paths),
        )

    plan = _DefaultConfigPlan(
        path=config_path,
        original_content=original_bytes,
        original_mode=mode,
        mode=mode,
    )
    staged: Path | None = None
    try:
        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
        staged = _stage_file(config_path, desired_bytes, mode=mode)
        if not _default_config_is_unchanged(plan):
            raise _CodexConfigChangedError(
                "Codex config changed during trusted-project synchronization"
            )
        os.replace(staged, config_path)
        staged = None
    except Exception as exc:
        if staged is not None:
            _discard_staged((staged,))
        return CodexTrustSyncResult(
            error=(
                "could not atomically write managed Codex trusted projects "
                f"({type(exc).__name__}); existing configuration was kept"
            ),
        )
    return CodexTrustSyncResult(
        trusted_paths=tuple(effective_paths),
    )


def _plan_default_config(
    codex_home: Path,
    models: tuple[_RenderedModel, ...],
) -> _DefaultConfigPlan:
    config_path = codex_home / "config.toml"
    try:
        if config_path.is_symlink():
            return _DefaultConfigPlan(
                path=config_path,
                error=(
                    f"refused to modify symlinked Codex config {config_path}; "
                    "existing configuration was kept"
                ),
            )
        exists = config_path.exists()
        if exists and not config_path.is_file():
            return _DefaultConfigPlan(
                path=config_path,
                error=(
                    f"refused to modify non-file Codex config {config_path}; "
                    "existing configuration was kept"
                ),
            )
        original_bytes = config_path.read_bytes() if exists else None
        original_text = (
            original_bytes.decode("utf-8")
            if original_bytes is not None
            else ""
        )
        mode = (
            stat.S_IMODE(config_path.stat().st_mode)
            if exists
            else 0o600
        )
    except (OSError, UnicodeError) as exc:
        return _DefaultConfigPlan(
            path=config_path,
            error=(
                f"could not read existing Codex config {config_path} "
                f"({type(exc).__name__}); existing configuration was kept"
            ),
        )

    user_text, had_managed_default, marker_error = (
        _split_managed_default(original_text)
    )
    if marker_error:
        return _DefaultConfigPlan(
            path=config_path,
            error=(
                f"could not update Codex config {config_path}: "
                f"{marker_error}; existing configuration was kept"
            ),
        )
    try:
        parsed = tomllib.loads(user_text)
    except Exception as exc:
        return _DefaultConfigPlan(
            path=config_path,
            error=(
                f"could not parse existing Codex config {config_path} "
                f"({type(exc).__name__}); existing configuration was kept"
            ),
        )

    user_default_model = _user_default_model(parsed)
    user_default_preserved = user_default_model is not None
    effective_model = user_default_model
    managed_default_model: CodexModelConfig | None = None
    contains_literal_secret = False
    if user_default_preserved:
        desired_text = user_text
    elif models:
        block, managed_default, block_error = _managed_default_block(
            models,
            parsed,
        )
        if block_error:
            return _DefaultConfigPlan(
                path=config_path,
                error=(
                    f"could not update Codex config {config_path}: "
                    f"{block_error}; existing configuration was kept"
                ),
            )
        assert managed_default is not None
        managed_default_model = managed_default.model
        effective_model = managed_default.model
        contains_literal_secret = (
            ".experimental_bearer_token = " in block
        )
        desired_text = block + ("\n" + user_text if user_text else "")
    else:
        desired_text = user_text

    try:
        tomllib.loads(desired_text)
    except Exception as exc:
        return _DefaultConfigPlan(
            path=config_path,
            error=(
                f"could not safely merge Codex config {config_path} "
                f"({type(exc).__name__}); existing configuration was kept"
            ),
        )

    desired_bytes = desired_text.encode("utf-8")
    write_content = (
        None
        if original_bytes is not None and desired_bytes == original_bytes
        else desired_bytes
    )
    if original_bytes is None and not desired_bytes:
        write_content = None
    if user_default_preserved and not had_managed_default:
        write_content = None

    return _DefaultConfigPlan(
        path=config_path,
        write_content=write_content,
        original_content=original_bytes,
        original_mode=mode,
        mode=0o600 if contains_literal_secret else mode,
        effective_model=effective_model,
        managed_default_model=managed_default_model,
        user_default_preserved=user_default_preserved,
    )


def _stage_file(path: Path, content: bytes, *, mode: int) -> Path:
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
        os.chmod(temporary, mode)
        return temporary
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _split_managed_env(content: str) -> tuple[str, bool, str]:
    """Remove the one OpenDeepHole-owned trailing dotenv block."""
    begin_count = content.count(_ENV_BEGIN)
    end_count = content.count(_ENV_END)
    if begin_count == 0 and end_count == 0:
        return content, False, ""
    if begin_count != 1 or end_count != 1:
        return content, False, (
            "OpenDeepHole managed Codex .env markers are incomplete or "
            "duplicated"
        )

    start = content.find(_ENV_BEGIN)
    end = content.find(_ENV_END, start + len(_ENV_BEGIN))
    if (
        start < 0
        or end < 0
        or (start > 0 and content[start - 1] != "\n")
        or (
            start + len(_ENV_BEGIN) < len(content)
            and content[start + len(_ENV_BEGIN)] != "\n"
        )
    ):
        return content, False, (
            "OpenDeepHole managed Codex .env markers are misplaced"
        )
    after = end + len(_ENV_END)
    if content[after:] not in {"", "\n"}:
        return content, False, (
            "OpenDeepHole managed Codex .env block is not trailing"
        )

    if start == 0:
        return "", True, ""
    # The writer adds exactly one separator newline before its block, so
    # removing that byte restores user-owned content byte-for-byte.
    return content[:start - 1], True, ""


def _dotenv_value(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        text = text[1:-1]
    elif " #" in text:
        text = text.split(" #", 1)[0].rstrip()
    return text


def _user_no_proxy_values(content: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in content.splitlines():
        match = _ENV_ASSIGNMENT_RE.fullmatch(line)
        if match is not None:
            values[match.group(1)] = _dotenv_value(match.group(2))
    return values


def _merge_no_proxy(existing: str, hosts: Sequence[str]) -> str:
    merged: list[str] = []
    seen: set[str] = set()
    for raw in (*existing.split(","), *hosts):
        value = str(raw or "").strip()
        if not value or any(marker in value for marker in ("\r", "\n", ",")):
            continue
        key = value.casefold()
        if key in seen:
            continue
        seen.add(key)
        merged.append(value)
    return ",".join(merged)


def _render_managed_env(user_content: str, hosts: Sequence[str]) -> str:
    normalized_hosts = _merge_no_proxy("", hosts)
    if not normalized_hosts:
        return user_content
    user_values = _user_no_proxy_values(user_content)
    block = "\n".join((
        _ENV_BEGIN,
        "NO_PROXY=" + _merge_no_proxy(
            user_values.get("NO_PROXY", ""),
            normalized_hosts.split(","),
        ),
        "no_proxy=" + _merge_no_proxy(
            user_values.get("no_proxy", ""),
            normalized_hosts.split(","),
        ),
        _ENV_END,
        "",
    ))
    return block if not user_content else user_content + "\n" + block


def _sync_codex_env(codex_home: Path, hosts: Sequence[str]) -> str:
    """Reconcile only OpenDeepHole's trailing CODEX_HOME/.env block."""
    path = codex_home / ".env"
    try:
        if path.is_symlink():
            return f"refused to modify symlinked Codex .env {path}"
        exists = path.exists()
        if exists and not path.is_file():
            return f"refused to modify non-file Codex .env {path}"
        original = path.read_bytes() if exists else None
        original_text = original.decode("utf-8") if original is not None else ""
        mode = stat.S_IMODE(path.stat().st_mode) if exists else 0o600
    except (OSError, UnicodeError) as exc:
        return f"could not read Codex .env {path} ({type(exc).__name__})"

    user_text, _owned, marker_error = _split_managed_env(original_text)
    if marker_error:
        return f"could not update Codex .env {path}: {marker_error}"
    desired = _render_managed_env(user_text, hosts).encode("utf-8")
    if original == desired or (original is None and not desired):
        return ""

    try:
        codex_home.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = _stage_file(path, desired, mode=mode)
        try:
            if path.is_symlink() or (path.exists() and not path.is_file()):
                raise _CodexConfigChangedError(
                    "Codex .env changed during synchronization"
                )
            os.replace(temporary, path)
        except BaseException:
            try:
                temporary.unlink()
            except OSError:
                pass
            raise
    except Exception as exc:
        return (
            "could not atomically write managed Codex .env "
            f"({type(exc).__name__})"
        )
    return ""


def _discard_staged(paths: tuple[Path, ...]) -> None:
    for path in paths:
        try:
            path.unlink()
        except OSError:
            pass


def _default_config_is_unchanged(plan: _DefaultConfigPlan) -> bool:
    try:
        if plan.path.is_symlink():
            return False
        if plan.original_content is None:
            return not plan.path.exists()
        if not plan.path.is_file():
            return False
        return (
            plan.path.read_bytes() == plan.original_content
            and stat.S_IMODE(plan.path.stat().st_mode) == plan.original_mode
        )
    except OSError:
        return False


def _write_and_reconcile(
    codex_home: Path,
    models: tuple[_RenderedModel, ...],
) -> _ReconcileResult:
    default_plan = _plan_default_config(codex_home, models)
    if default_plan.error:
        return _ReconcileResult(error=default_plan.error)

    try:
        existing_owned = set(_owned_profiles(codex_home))
    except Exception as exc:
        return _ReconcileResult(
            error=(
                f"could not inspect Codex configuration directory {codex_home} "
                f"({type(exc).__name__})"
            ),
        )

    if default_plan.write_content is not None:
        try:
            codex_home.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as exc:
            return _ReconcileResult(
                error=(
                    f"could not create Codex configuration directory {codex_home} "
                    f"({type(exc).__name__})"
                ),
            )

    staged_config: Path | None = None
    try:
        if default_plan.write_content is not None:
            staged_config = _stage_file(
                default_plan.path,
                default_plan.write_content,
                mode=default_plan.mode,
            )
            if not _default_config_is_unchanged(default_plan):
                raise _CodexConfigChangedError(
                    "Codex config changed during model synchronization"
                )
        if staged_config is not None:
            if not _default_config_is_unchanged(default_plan):
                raise _CodexConfigChangedError(
                    "Codex config changed during model synchronization"
                )
            os.replace(staged_config, default_plan.path)
    except Exception as exc:
        _discard_staged((staged_config,) if staged_config is not None else ())
        return _ReconcileResult(
            error=(
                "could not atomically write managed Codex configuration "
                f"({type(exc).__name__}); existing configuration and old "
                "managed profiles were kept"
            ),
        )

    warnings: list[str] = []
    for stale in sorted(existing_owned, key=str):
        try:
            if _is_owned_profile(stale):
                stale.unlink()
            elif stale.exists():
                warnings.append(
                    "Could not remove stale Codex profile because its "
                    f"ownership marker changed: {stale}"
                )
        except OSError as exc:
            warnings.append(
                f"Could not remove stale managed Codex profile {stale} "
                f"({type(exc).__name__})"
            )
    return _ReconcileResult(
        effective_model=default_plan.effective_model,
        managed_default_model=default_plan.managed_default_model,
        user_default_preserved=default_plan.user_default_preserved,
        warnings=tuple(warnings),
    )


def inspect_codex_user_default(
    *,
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    codex_home: Path | None = None,
) -> CodexConfigSyncResult:
    """Read a user-owned top-level default without changing any files."""
    effective_env = dict(os.environ) if env is None else dict(env)
    destination = codex_home or _codex_home(
        effective_env,
        platform=platform or sys.platform,
    )
    plan = _plan_default_config(destination, ())
    if plan.error:
        return CodexConfigSyncResult(error=plan.error)
    models = (
        (plan.effective_model,)
        if plan.user_default_preserved and plan.effective_model is not None
        else ()
    )
    return CodexConfigSyncResult(
        models=models,
        user_default_preserved=plan.user_default_preserved,
    )


def sync_codex_config(
    *,
    codex_version: str,
    opencode_config: Mapping[str, Any],
    selected_model_ids: Sequence[str],
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    codex_home: Path | None = None,
    no_proxy_hosts: Sequence[str] = (),
) -> CodexConfigSyncResult:
    """Synchronize one effective default and remove old managed profiles."""
    del codex_version  # Kept in the call contract for existing Agent callers.
    if not isinstance(opencode_config, Mapping):
        return CodexConfigSyncResult(
            error="effective OpenCode configuration is not an object",
        )
    effective_env = dict(os.environ) if env is None else dict(env)
    active_platform = platform or sys.platform

    rendered, conversion_warnings, conversion_error = _render_models(
        opencode_config,
        selected_model_ids,
    )
    warnings = tuple(item for item in conversion_warnings if item)
    if conversion_error:
        return CodexConfigSyncResult(
            warnings=warnings,
            error=conversion_error,
        )

    destination = codex_home or _codex_home(
        effective_env,
        platform=active_platform,
    )
    reconciliation = _write_and_reconcile(
        destination,
        rendered,
    )
    warnings = tuple(
        item
        for item in (
            *warnings,
            *reconciliation.warnings,
        )
        if item
    )
    if reconciliation.error:
        return CodexConfigSyncResult(
            warnings=warnings,
            error=reconciliation.error,
        )
    env_error = _sync_codex_env(destination, no_proxy_hosts)
    if env_error:
        return CodexConfigSyncResult(
            warnings=warnings,
            error=env_error,
        )
    models = (
        (reconciliation.effective_model,)
        if reconciliation.effective_model is not None
        else ()
    )
    return CodexConfigSyncResult(
        models=models,
        managed_default_model=reconciliation.managed_default_model,
        user_default_preserved=reconciliation.user_default_preserved,
        warnings=warnings,
    )


__all__ = [
    "CodexConfigSyncResult",
    "CodexModelConfig",
    "CodexTrustSyncResult",
    "inspect_codex_user_default",
    "normalize_codex_base_url",
    "sync_codex_config",
    "sync_codex_trusted_projects",
]
