"""Safely mirror platform-selected OpenCode models into Codex profiles."""

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
from urllib.parse import urlsplit

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
_ENV_BEGIN = "# BEGIN OpenDeepHole managed Codex NO_PROXY"
_ENV_END = "# END OpenDeepHole managed Codex NO_PROXY"
_PROFILE_GLOB = "opendeephole-*.config.toml"
_ENV_REFERENCE_RE = re.compile(
    r"^\{env:([A-Za-z_][A-Za-z0-9_]*)\}$"
)
_ENV_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:export\s+)?(NO_PROXY|no_proxy)\s*=\s*(.*?)\s*$"
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
    managed_default_model: CodexModelProfile | None = None
    user_default_preserved: bool = False
    warnings: tuple[str, ...] = ()
    error: str = ""


@dataclass(frozen=True)
class _RenderedProfile:
    model: CodexModelProfile
    content: str
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
    managed_default_model: CodexModelProfile | None = None
    user_default_preserved: bool = False
    error: str = ""


@dataclass(frozen=True)
class _ReconcileResult:
    managed_default_model: CodexModelProfile | None = None
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
    tomllib.loads(content)
    return _RenderedProfile(
        model=profile,
        content=content,
        provider_key=provider_key,
        provider_name=provider_name or provider_id,
        base_url=base_url,
        env_key=env_key,
        bearer_token=bearer_token,
        context_window=context_window,
    ), ()


def _render_profiles(
    config: Mapping[str, Any],
    selected_model_ids: Sequence[str],
) -> tuple[tuple[_RenderedProfile, ...], tuple[str, ...], str]:
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

    rendered: list[_RenderedProfile] = []
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
            item, item_warnings = _render_profile(
                provider_id=provider_id,
                provider_config=provider_config,
                model_id=model_id,
                model_config=model_config,
            )
        except Exception as exc:
            return (), tuple(warnings), (
                f"could not map platform model {canonical_id}: profile "
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


def _managed_default_block(
    profiles: tuple[_RenderedProfile, ...],
    user_config: Mapping[str, Any],
) -> tuple[str, _RenderedProfile | None, str]:
    if not profiles:
        return "", None, ""

    selected = profiles[0]
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


def _plan_default_config(
    codex_home: Path,
    profiles: tuple[_RenderedProfile, ...],
) -> _DefaultConfigPlan:
    config_path = codex_home / "config.toml"
    try:
        if config_path.is_symlink():
            return _DefaultConfigPlan(
                path=config_path,
                error=(
                    f"refused to modify symlinked Codex config {config_path}; "
                    "existing config and managed profiles were kept"
                ),
            )
        exists = config_path.exists()
        if exists and not config_path.is_file():
            return _DefaultConfigPlan(
                path=config_path,
                error=(
                    f"refused to modify non-file Codex config {config_path}; "
                    "existing config and managed profiles were kept"
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
                f"({type(exc).__name__}); existing config and managed "
                "profiles were kept"
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
                f"{marker_error}; existing config and managed profiles "
                "were kept"
            ),
        )
    try:
        parsed = tomllib.loads(user_text)
    except Exception as exc:
        return _DefaultConfigPlan(
            path=config_path,
            error=(
                f"could not parse existing Codex config {config_path} "
                f"({type(exc).__name__}); existing config and managed "
                "profiles were kept"
            ),
        )

    user_default_preserved = any(
        key in parsed
        for key in (
            "model",
            "profile",
            "model_provider",
            "openai_base_url",
            "oss_provider",
        )
    )
    managed_default_model: CodexModelProfile | None = None
    contains_literal_secret = False
    if user_default_preserved:
        desired_text = user_text
    elif profiles:
        block, managed_default, block_error = _managed_default_block(
            profiles,
            parsed,
        )
        if block_error:
            return _DefaultConfigPlan(
                path=config_path,
                error=(
                    f"could not update Codex config {config_path}: "
                    f"{block_error}; existing config and managed profiles "
                    "were kept"
                ),
            )
        assert managed_default is not None
        managed_default_model = managed_default.model
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
                f"({type(exc).__name__}); existing config and managed "
                "profiles were kept"
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
    profiles: tuple[_RenderedProfile, ...],
) -> _ReconcileResult:
    default_plan = _plan_default_config(codex_home, profiles)
    if default_plan.error:
        return _ReconcileResult(error=default_plan.error)

    desired = {
        codex_home / f"{item.model.profile}.config.toml": item.content
        for item in profiles
    }
    try:
        existing_owned = set(_owned_profiles(codex_home))
    except Exception as exc:
        return _ReconcileResult(
            error=(
                f"could not inspect Codex profile directory {codex_home} "
                f"({type(exc).__name__})"
            ),
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
        return _ReconcileResult(
            error=(
                "could not inspect a target Codex profile "
                f"({type(exc).__name__})"
            ),
        )
    if foreign_destination is not None:
        return _ReconcileResult(
            error=(
                "refused to overwrite non-OpenDeepHole Codex profile "
                f"{foreign_destination}"
            ),
        )

    changed_desired: dict[Path, str] = {}
    try:
        for destination, content in desired.items():
            if destination not in existing_owned:
                changed_desired[destination] = content
                continue
            if (
                destination.read_bytes() != content.encode("utf-8")
                or stat.S_IMODE(destination.stat().st_mode) != 0o600
            ):
                changed_desired[destination] = content
    except OSError as exc:
        return _ReconcileResult(
            error=(
                "could not inspect an existing managed Codex profile "
                f"({type(exc).__name__})"
            ),
        )

    if changed_desired or default_plan.write_content is not None:
        try:
            codex_home.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as exc:
            return _ReconcileResult(
                error=(
                    f"could not create Codex profile directory {codex_home} "
                    f"({type(exc).__name__})"
                ),
            )

    staged: dict[Path, Path] = {}
    staged_config: Path | None = None
    try:
        for destination, content in changed_desired.items():
            staged[destination] = _stage_file(
                destination,
                content.encode("utf-8"),
                mode=0o600,
            )
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
        for destination, temporary in staged.items():
            if destination.exists() and not _is_owned_profile(destination):
                raise _CodexConfigChangedError(
                    "Codex profile ownership changed during synchronization"
                )
            os.replace(temporary, destination)
        if staged_config is not None:
            if not _default_config_is_unchanged(default_plan):
                raise _CodexConfigChangedError(
                    "Codex config changed during model synchronization"
                )
            os.replace(staged_config, default_plan.path)
    except Exception as exc:
        _discard_staged(tuple(staged.values()) + (
            (staged_config,) if staged_config is not None else ()
        ))
        return _ReconcileResult(
            error=(
                "could not atomically write managed Codex configuration "
                f"({type(exc).__name__}); existing config and stale profiles "
                "were kept"
            ),
        )

    warnings: list[str] = []
    for stale in sorted(existing_owned - set(desired), key=str):
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
        managed_default_model=default_plan.managed_default_model,
        user_default_preserved=default_plan.user_default_preserved,
        warnings=tuple(warnings),
    )


def sync_codex_profiles(
    *,
    codex_version: str,
    opencode_config: Mapping[str, Any],
    selected_model_ids: Sequence[str],
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    codex_home: Path | None = None,
    no_proxy_hosts: Sequence[str] = (),
) -> CodexProfileSyncResult:
    """Synchronize selected client models and fill a missing default safely."""
    if not isinstance(opencode_config, Mapping):
        return CodexProfileSyncResult(
            error="effective OpenCode configuration is not an object",
        )
    effective_env = dict(os.environ) if env is None else dict(env)
    active_platform = platform or sys.platform
    version_error, version_warning = _version_support_error(codex_version)
    if version_error:
        return CodexProfileSyncResult(error=version_error)

    rendered, conversion_warnings, conversion_error = _render_profiles(
        opencode_config,
        selected_model_ids,
    )
    warnings = tuple(
        item
        for item in (version_warning, *conversion_warnings)
        if item
    )
    if conversion_error:
        return CodexProfileSyncResult(
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
        return CodexProfileSyncResult(
            warnings=warnings,
            error=reconciliation.error,
        )
    env_error = _sync_codex_env(destination, no_proxy_hosts)
    if env_error:
        return CodexProfileSyncResult(
            warnings=warnings,
            error=env_error,
        )
    return CodexProfileSyncResult(
        models=tuple(item.model for item in rendered),
        managed_default_model=reconciliation.managed_default_model,
        user_default_preserved=reconciliation.user_default_preserved,
        warnings=warnings,
    )


__all__ = [
    "CodexModelProfile",
    "CodexProfileSyncResult",
    "sync_codex_profiles",
]
