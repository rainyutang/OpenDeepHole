"""Validated, provider-only OpenCode configuration and write-only secrets."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from urllib.parse import urlsplit

OPENAI_COMPATIBLE_NPM = "@ai-sdk/openai-compatible"
_PROVIDER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


def _mapping(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{label}必须是对象")
    return value


def _keys(value: dict, allowed: set[str], label: str) -> None:
    if set(value) - allowed:
        raise ValueError(f"{label}包含不支持的字段")


def _positive(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label}必须是正整数")
    return value


def _headers(value: object) -> dict[str, str]:
    headers = _mapping(value, "Headers")
    result: dict[str, str] = {}
    names: set[str] = set()
    for key, item in headers.items():
        if not isinstance(key, str) or not _HEADER_NAME.fullmatch(key):
            raise ValueError("Header 名称无效")
        if key.lower() in names:
            raise ValueError("Header 名称不能重复")
        if not isinstance(item, str) or "\r" in item or "\n" in item:
            raise ValueError("Header 值必须是无换行的字符串")
        names.add(key.lower())
        result[key] = item
    return result


def normalize_llm_providers(value: object) -> dict:
    """Validate native provider shapes; never put secret values in errors."""
    providers = _mapping(value, "LLM API 配置")
    result = {}
    for provider_id, raw in providers.items():
        if not isinstance(provider_id, str) or not _PROVIDER_ID.fullmatch(provider_id):
            raise ValueError("Provider ID 只能包含字母、数字、点、下划线和短横线")
        provider = copy.deepcopy(_mapping(raw, "Provider"))
        _keys(provider, {"name", "npm", "options", "models"}, "Provider")
        if provider.get("npm", OPENAI_COMPATIBLE_NPM) != OPENAI_COMPATIBLE_NPM:
            raise ValueError("LLM API 仅支持 OpenAI Chat Completions 兼容协议")
        provider["npm"] = OPENAI_COMPATIBLE_NPM
        if "name" in provider and not isinstance(provider["name"], str):
            raise ValueError("API 名称必须是字符串")
        options = _mapping(provider.get("options"), "API options")
        _keys(options, {"baseURL", "apiKey", "headers", "timeout", "chunkTimeout"}, "API options")
        url = options.get("baseURL")
        if not isinstance(url, str):
            raise ValueError("API URL 必须是 HTTP 或 HTTPS 地址")
        try:
            parsed = urlsplit(url.strip())
            valid = parsed.scheme in {"http", "https"} and bool(parsed.hostname)
            valid = valid and parsed.username is None and parsed.password is None and not parsed.fragment
            _ = parsed.port
        except ValueError:
            valid = False
        if not valid or any(character.isspace() for character in url.strip()):
            raise ValueError("API URL 必须是无用户名、密码或片段的 HTTP 或 HTTPS 地址")
        options["baseURL"] = url.strip()
        if "apiKey" in options and not isinstance(options["apiKey"], str):
            raise ValueError("API Key 必须是字符串")
        for key in ("timeout", "chunkTimeout"):
            if key in options:
                _positive(options[key], "API 超时（毫秒）")
        if "headers" in options:
            options["headers"] = _headers(options["headers"])
        models = _mapping(provider.get("models"), "API 模型")
        if not models:
            raise ValueError("每个 API 至少需要一个模型")
        for model_id, raw_model in models.items():
            if not isinstance(model_id, str) or not model_id or len(model_id) > 256 or any(c.isspace() or ord(c) < 32 for c in model_id):
                raise ValueError("模型 ID 不能为空或包含空白字符")
            model = _mapping(raw_model, "模型")
            _keys(model, {"name", "limit", "headers"}, "模型")
            if "name" in model and not isinstance(model["name"], str):
                raise ValueError("模型名称必须是字符串")
            if "headers" in model:
                model["headers"] = _headers(model["headers"])
            if "limit" in model:
                limits = _mapping(model["limit"], "模型 limit")
                _keys(limits, {"context", "output", "input"}, "模型 limit")
                for key in ("context", "output"):
                    _positive(limits.get(key), f"模型 limit.{key}")
                if "input" in limits:
                    _positive(limits["input"], "模型 limit.input")
        result[provider_id] = provider
    return result


def llm_provider_revision(providers: object) -> str:
    payload = json.dumps(normalize_llm_providers(providers), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def redact_llm_providers(providers: dict) -> dict:
    """Return browser-safe values; all headers are treated as credentials."""
    result = copy.deepcopy(providers)
    for provider in result.values():
        options = provider.get("options", {})
        options["apiKey_set"] = bool(options.pop("apiKey", ""))
        for owner in (options, *provider.get("models", {}).values()):
            if "headers" in owner:
                owner["headers"] = {name: None for name in owner["headers"]}
    return result


def _merge_headers(incoming: dict, previous: dict) -> None:
    if "headers" not in incoming:
        if "headers" in previous:
            incoming["headers"] = copy.deepcopy(previous["headers"])
        return
    headers = _mapping(incoming["headers"], "Headers")
    old_headers = {name.lower(): value for name, value in previous.get("headers", {}).items()}
    for name, value in headers.items():
        if value is None:
            if not isinstance(name, str) or name.lower() not in old_headers:
                raise ValueError("新 Header 必须填写值")
            headers[name] = old_headers[name.lower()]


def merge_llm_provider_secrets(incoming: object, previous: dict) -> dict:
    """Resolve browser secret markers and input-only original IDs before validation."""
    result = copy.deepcopy(_mapping(incoming, "LLM API 配置"))
    for provider_id, raw in result.items():
        provider = _mapping(raw, "Provider")
        previous_id = provider.pop("previous_id", provider_id)
        if not isinstance(previous_id, str):
            raise ValueError("原 Provider ID 无效")
        old = previous.get(previous_id, {})
        options = _mapping(provider.get("options"), "API options")
        old_options = old.get("options", {})
        options.pop("apiKey_set", None)
        if "apiKey" not in options and "apiKey" in old_options:
            options["apiKey"] = old_options["apiKey"]
        elif options.get("apiKey", False) is None:
            options.pop("apiKey")
        _merge_headers(options, old_options)
        models = _mapping(provider.get("models"), "API 模型")
        for model_id, raw_model in models.items():
            model = _mapping(raw_model, "模型")
            previous_model_id = model.pop("previous_id", model_id)
            if not isinstance(previous_model_id, str):
                raise ValueError("原模型 ID 无效")
            _merge_headers(model, old.get("models", {}).get(previous_model_id, {}))
    return normalize_llm_providers(result)


def redact_llm_error(message: object, providers: dict) -> str:
    """Remove configured credentials from a runtime error returned to browsers."""
    result = str(message or "")
    secrets = []
    for provider in providers.values():
        options = provider.get("options", {})
        secrets.append(options.get("apiKey", ""))
        for owner in (options, *provider.get("models", {}).values()):
            secrets.extend(owner.get("headers", {}).values())
    for secret in sorted({value for value in secrets if isinstance(value, str) and value}, key=len, reverse=True):
        result = result.replace(secret, "[REDACTED]")
    return result[:4000]
