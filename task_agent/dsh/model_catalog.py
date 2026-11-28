"""Model resolution, catalog discovery, and runtime availability checks for DSH."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from ..config_json import parse_opencode_jsonc
from ..llm_config import normalize_llm_providers
from ..serve_client import OpenCodeModelInfo, OpenCodeModelListResult

DEEPSEEK_OFFICIAL_PROVIDER = "deepseek-official"
DEFAULT_DSH_CONTEXT_WINDOW = 200_000
DEFAULT_DSH_MAX_OUTPUT_TOKENS = 32_768
OFFICIAL_DSH_CONTEXT_WINDOW = 1_048_576
OFFICIAL_DSH_MAX_OUTPUT_TOKENS = 256_000

_OFFICIAL_BUILTIN_MODELS: tuple[tuple[str, str, int, int], ...] = (
    (
        "deepseek-flash",
        "DeepSeek-V4.1-Flash",
        OFFICIAL_DSH_CONTEXT_WINDOW,
        OFFICIAL_DSH_MAX_OUTPUT_TOKENS,
    ),
    (
        "deepseek-v4-pro",
        "DeepSeek-V4-Pro",
        OFFICIAL_DSH_CONTEXT_WINDOW,
        OFFICIAL_DSH_MAX_OUTPUT_TOKENS,
    ),
)


@dataclass(frozen=True)
class ResolvedDshModel:
    """Resolved provider/model target for one DeepSeek Harness turn."""

    full_id: str
    provider_id: str
    model_id: str
    is_pi_ai: bool
    base_url: str = ""
    api_key: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    timeout_ms: int | None = None
    stream_idle_timeout_ms: int | None = None
    context_window: int = DEFAULT_DSH_CONTEXT_WINDOW
    max_tokens: int = DEFAULT_DSH_MAX_OUTPUT_TOKENS
    display_name: str = ""


def resolve_dsh_binary(dsh_executable: str = "") -> str | None:
    """Resolve an explicit ``dsh`` binary path, bundled SDK runtime, or PATH ``dsh``.

    Returns:
        - Explicit resolved path when ``dsh_executable`` is provided.
        - ``None`` when using ``deepseek-harness-sdk``'s bundled runtime.
        - Fallback ``shutil.which("dsh")`` if bundled wheel is absent but CLI is installed.

    Raises:
        FileNotFoundError: when neither an explicit binary, bundled runtime, nor PATH ``dsh`` exists.
    """
    configured = str(dsh_executable or "").strip()
    if configured:
        expanded = Path(configured).expanduser()
        if expanded.is_file():
            return str(expanded.resolve())
        located = shutil.which(configured)
        if located:
            return located
        raise FileNotFoundError(f"Configured dsh executable not found: {configured}")

    try:
        from deepseek_harness_runtime import resolve_bundled_launch_args

        resolve_bundled_launch_args()
        return None  # Let DeepSeekHarness use its bundled runtime directly.
    except Exception:
        located = shutil.which("dsh")
        if located:
            return located
        raise FileNotFoundError(
            "Unable to locate bundled deepseek-harness-runtime-bin or `dsh` on PATH"
        )


def check_dsh_runtime_available(dsh_executable: str = "") -> tuple[bool, str]:
    """Verify that the Python SDK and a runnable ``dsh`` runtime are available."""
    try:
        import deepseek_harness  # noqa: F401
    except ImportError as exc:
        return (
            False,
            f"未安装 deepseek-harness-sdk（{exc}），请先执行 `pip install deepseek-harness-sdk`。",
        )
    try:
        resolved = resolve_dsh_binary(dsh_executable)
    except FileNotFoundError as exc:
        return False, str(exc)
    return True, resolved or "bundled:deepseek-harness-runtime-bin"


def extract_llm_providers(
    *,
    llm_providers: Mapping[str, Any] | None = None,
    config_content: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Extract normalized OpenAI-compatible provider entries from explicit map or config JSON."""
    raw: dict[str, Any] = {}
    if config_content:
        try:
            parsed = parse_opencode_jsonc(
                config_content,
                source="DeepSeek Harness runtime config",
            )
            providers_section = parsed.get("provider")
            if isinstance(providers_section, dict):
                raw.update(providers_section)
        except Exception:
            pass
    if isinstance(llm_providers, Mapping):
        for key, value in llm_providers.items():
            if isinstance(value, Mapping):
                raw[str(key)] = dict(value)
    if not raw:
        return {}
    normalized: dict[str, dict[str, Any]] = {}
    for provider_id, provider_cfg in raw.items():
        if not isinstance(provider_cfg, Mapping):
            continue
        options = provider_cfg.get("options")
        models = provider_cfg.get("models")
        if not isinstance(options, Mapping) or not isinstance(models, Mapping) or not models:
            continue
        if not str(options.get("baseURL") or "").strip():
            continue
        try:
            single = normalize_llm_providers({provider_id: dict(provider_cfg)})
            normalized.update(single)
        except ValueError:
            # Keep lenient fallback for standalone / external opencode.json providers
            # that may carry additional provider options not in managed Web schema.
            normalized[str(provider_id)] = {
                "name": str(provider_cfg.get("name") or provider_id),
                "options": {
                    "baseURL": str(options.get("baseURL") or "").strip(),
                    **(
                        {"apiKey": str(options["apiKey"])}
                        if isinstance(options.get("apiKey"), str)
                        else {}
                    ),
                    **(
                        {"headers": {str(k): str(v) for k, v in options["headers"].items()}}
                        if isinstance(options.get("headers"), Mapping)
                        else {}
                    ),
                    **(
                        {"timeout": int(options["timeout"])}
                        if isinstance(options.get("timeout"), int)
                        and not isinstance(options.get("timeout"), bool)
                        and options["timeout"] > 0
                        else {}
                    ),
                    **(
                        {"chunkTimeout": int(options["chunkTimeout"])}
                        if isinstance(options.get("chunkTimeout"), int)
                        and not isinstance(options.get("chunkTimeout"), bool)
                        and options["chunkTimeout"] > 0
                        else {}
                    ),
                },
                "models": {
                    str(mid): dict(mcfg) if isinstance(mcfg, Mapping) else {}
                    for mid, mcfg in models.items()
                    if str(mid).strip()
                },
            }
    return normalized


def _positive_int(value: object, default: int) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return default


def _split_provider_and_model(
    model_spec: str,
    known_providers: Mapping[str, Any],
) -> tuple[str, str]:
    raw = str(model_spec or "").strip()
    if not raw:
        return "", ""
    # Prefer longest matching configured provider prefix so model IDs containing '/'
    # (e.g. openrouter/anthropic/claude-3.7-sonnet) split accurately.
    for provider_id in sorted(known_providers, key=len, reverse=True):
        prefix = f"{provider_id}/"
        if raw.startswith(prefix) and len(raw) > len(prefix):
            return provider_id, raw[len(prefix):]
    if "/" in raw:
        provider_id, model_id = raw.split("/", 1)
        return provider_id.strip(), model_id.strip()
    return DEEPSEEK_OFFICIAL_PROVIDER, raw


def resolve_dsh_model(
    model_spec: str,
    *,
    llm_providers: Mapping[str, Any] | None = None,
    config_content: str | None = None,
    env: Mapping[str, str] | None = None,
) -> ResolvedDshModel:
    """Resolve a ``provider/model`` spec into DeepSeek Harness routing parameters."""
    providers = extract_llm_providers(
        llm_providers=llm_providers,
        config_content=config_content,
    )
    effective_env = {**os.environ, **(dict(env) if env else {})}
    raw_spec = str(model_spec or "").strip()
    if not raw_spec:
        # Default fallback when no explicit model is specified.
        if providers:
            first_provider_id = next(iter(providers))
            first_model_id = next(iter(providers[first_provider_id]["models"]))
            raw_spec = f"{first_provider_id}/{first_model_id}"
        else:
            raw_spec = f"{DEEPSEEK_OFFICIAL_PROVIDER}/{_OFFICIAL_BUILTIN_MODELS[0][0]}"

    provider_id, model_id = _split_provider_and_model(raw_spec, providers)
    if not provider_id or not model_id:
        raise ValueError(f"Invalid DeepSeek Harness model specification: {model_spec!r}")

    if provider_id in providers:
        provider_cfg = providers[provider_id]
        options = provider_cfg.get("options") or {}
        model_cfg = (provider_cfg.get("models") or {}).get(model_id) or {}
        limits = model_cfg.get("limit") if isinstance(model_cfg.get("limit"), Mapping) else {}
        merged_headers: dict[str, str] = {}
        if isinstance(options.get("headers"), Mapping):
            merged_headers.update({str(k): str(v) for k, v in options["headers"].items()})
        if isinstance(model_cfg.get("headers"), Mapping):
            merged_headers.update({str(k): str(v) for k, v in model_cfg["headers"].items()})
        return ResolvedDshModel(
            full_id=f"{provider_id}/{model_id}",
            provider_id=provider_id,
            model_id=model_id,
            is_pi_ai=True,
            base_url=str(options.get("baseURL") or "").strip(),
            api_key=str(options.get("apiKey") or ""),
            headers=merged_headers,
            timeout_ms=(
                _positive_int(options.get("timeout"), 0) or None
            ),
            stream_idle_timeout_ms=(
                _positive_int(options.get("chunkTimeout"), 0) or None
            ),
            context_window=_positive_int(limits.get("context"), DEFAULT_DSH_CONTEXT_WINDOW),
            max_tokens=_positive_int(limits.get("output"), DEFAULT_DSH_MAX_OUTPUT_TOKENS),
            display_name=str(model_cfg.get("name") or model_id),
        )

    if provider_id == DEEPSEEK_OFFICIAL_PROVIDER:
        return ResolvedDshModel(
            full_id=f"{DEEPSEEK_OFFICIAL_PROVIDER}/{model_id}",
            provider_id=DEEPSEEK_OFFICIAL_PROVIDER,
            model_id=model_id,
            is_pi_ai=False,
            base_url=str(effective_env.get("DEEPSEEK_BASE_URL") or "").strip(),
            api_key=str(effective_env.get("DEEPSEEK_API_KEY") or ""),
            context_window=OFFICIAL_DSH_CONTEXT_WINDOW,
            max_tokens=OFFICIAL_DSH_MAX_OUTPUT_TOKENS,
            display_name=model_id,
        )

    # Provider might live in user's local $DSH_HOME cordis patch / settings.
    return ResolvedDshModel(
        full_id=f"{provider_id}/{model_id}",
        provider_id=provider_id,
        model_id=model_id,
        is_pi_ai=False,
        context_window=DEFAULT_DSH_CONTEXT_WINDOW,
        max_tokens=DEFAULT_DSH_MAX_OUTPUT_TOKENS,
        display_name=model_id,
    )


def _discover_local_dsh_patch_models(dsh_home: Path | None) -> list[OpenCodeModelInfo]:
    """Read optional ``llm-pi-ai`` provider entries from local DSH home patch files."""
    if dsh_home is None:
        return []
    candidates = (
        dsh_home / "cordis.patch.yml",
        dsh_home / "profiles" / "sdk-minimal" / "cordis.patch.yml",
        dsh_home / "settings.yml",
    )
    discovered: list[OpenCodeModelInfo] = []
    seen: set[str] = set()
    for path in candidates:
        if not path.is_file():
            continue
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        provider_dicts: list[dict[str, Any]] = []
        if isinstance(loaded, dict):
            pi_ai = loaded.get("llm-pi-ai")
            if isinstance(pi_ai, dict) and isinstance(pi_ai.get("providers"), dict):
                provider_dicts.append(pi_ai["providers"])
        elif isinstance(loaded, list):
            for entry in loaded:
                if not isinstance(entry, dict):
                    continue
                rows = entry.get("insert") if isinstance(entry.get("insert"), list) else [entry]
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    if row.get("id") == "llm-pi-ai" or row.get("name") == "@deepseek-ai/dsh-llm-pi-ai":
                        cfg = row.get("config")
                        if isinstance(cfg, dict) and isinstance(cfg.get("providers"), dict):
                            provider_dicts.append(cfg["providers"])
        for providers_map in provider_dicts:
            for provider_id, profile in providers_map.items():
                if not isinstance(profile, dict):
                    continue
                default_ctx = _positive_int(
                    profile.get("defaultContextWindow"),
                    DEFAULT_DSH_CONTEXT_WINDOW,
                )
                default_out = _positive_int(
                    profile.get("defaultMaxTokens"),
                    DEFAULT_DSH_MAX_OUTPUT_TOKENS,
                )
                models = profile.get("models")
                if not isinstance(models, list):
                    continue
                for item in models:
                    if not isinstance(item, dict):
                        continue
                    model_id = str(item.get("id") or "").strip()
                    if not model_id:
                        continue
                    full_id = f"{provider_id}/{model_id}"
                    if full_id in seen:
                        continue
                    seen.add(full_id)
                    discovered.append(
                        OpenCodeModelInfo(
                            id=full_id,
                            provider_id=str(provider_id),
                            model_id=model_id,
                            name=str(item.get("name") or model_id),
                            limit_context=_positive_int(item.get("contextWindow"), default_ctx),
                            limit_output=_positive_int(item.get("maxTokens"), default_out),
                        )
                    )
    return discovered


def list_dsh_models(
    *,
    llm_providers: Mapping[str, Any] | None = None,
    config_content: str | None = None,
    dsh_home: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> OpenCodeModelListResult:
    """List available DeepSeek Harness models from Web APIs, local DSH home, and env."""
    models: list[OpenCodeModelInfo] = []
    seen: set[str] = set()

    providers = extract_llm_providers(
        llm_providers=llm_providers,
        config_content=config_content,
    )
    for provider_id, provider_cfg in providers.items():
        raw_models = provider_cfg.get("models") or {}
        for model_id, model_cfg in raw_models.items():
            full_id = f"{provider_id}/{model_id}"
            if full_id in seen:
                continue
            seen.add(full_id)
            limits = (
                model_cfg.get("limit")
                if isinstance(model_cfg, Mapping) and isinstance(model_cfg.get("limit"), Mapping)
                else {}
            )
            models.append(
                OpenCodeModelInfo(
                    id=full_id,
                    provider_id=provider_id,
                    model_id=model_id,
                    name=str(
                        (model_cfg.get("name") if isinstance(model_cfg, Mapping) else "")
                        or model_id
                    ),
                    limit_context=_positive_int(limits.get("context"), DEFAULT_DSH_CONTEXT_WINDOW),
                    limit_output=_positive_int(limits.get("output"), DEFAULT_DSH_MAX_OUTPUT_TOKENS),
                )
            )

    for item in _discover_local_dsh_patch_models(dsh_home):
        if item.id not in seen:
            seen.add(item.id)
            models.append(item)

    effective_env = {**os.environ, **(dict(env) if env else {})}
    if str(effective_env.get("DEEPSEEK_API_KEY") or "").strip():
        for model_id, display_name, ctx_limit, out_limit in _OFFICIAL_BUILTIN_MODELS:
            full_id = f"{DEEPSEEK_OFFICIAL_PROVIDER}/{model_id}"
            if full_id in seen:
                continue
            seen.add(full_id)
            models.append(
                OpenCodeModelInfo(
                    id=full_id,
                    provider_id=DEEPSEEK_OFFICIAL_PROVIDER,
                    model_id=model_id,
                    name=display_name,
                    limit_context=ctx_limit,
                    limit_output=out_limit,
                )
            )

    message = (
        ""
        if models
        else "未检测到可用 DeepSeek Harness 模型：请在上方“添加 LLM API”或配置环境变量 DEEPSEEK_API_KEY。"
    )
    return OpenCodeModelListResult(models=models, message=message)
