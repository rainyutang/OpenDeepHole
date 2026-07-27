"""Shared OpenCode token-usage value objects and aggregation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class TokenCounters:
    input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return (
            self.input_tokens
            + self.output_tokens
            + self.reasoning_tokens
            + self.cache_read_tokens
            + self.cache_write_tokens
        )

    def __add__(self, other: "TokenCounters") -> "TokenCounters":
        return TokenCounters(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            reasoning_tokens=self.reasoning_tokens + other.reasoning_tokens,
            cache_read_tokens=self.cache_read_tokens + other.cache_read_tokens,
            cache_write_tokens=self.cache_write_tokens + other.cache_write_tokens,
        )

    def as_dict(self) -> dict[str, int]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "reasoning_tokens": self.reasoning_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
            "total_tokens": self.total_tokens,
        }


@dataclass(frozen=True)
class ModelTokenUsage:
    model: str
    counters: TokenCounters

    def as_dict(self) -> dict[str, Any]:
        return {"model": self.model, **self.counters.as_dict()}


@dataclass(frozen=True)
class OpenCodeTokenUsage:
    counters: TokenCounters
    by_model: tuple[ModelTokenUsage, ...] = ()
    complete: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            **self.counters.as_dict(),
            "complete": self.complete,
            "by_model": [item.as_dict() for item in self.by_model],
        }


def _non_negative_int(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def parse_token_counters(value: object) -> TokenCounters | None:
    if not isinstance(value, dict):
        return None
    cache = value.get("cache")
    cache = cache if isinstance(cache, dict) else {}
    keys_present = any(
        key in value for key in ("input", "output", "reasoning", "input_tokens", "output_tokens")
    ) or bool(cache) or any(
        key in value for key in ("cache_read_tokens", "cache_write_tokens")
    )
    if not keys_present:
        return None
    return TokenCounters(
        input_tokens=_non_negative_int(value.get("input_tokens", value.get("input"))),
        output_tokens=_non_negative_int(value.get("output_tokens", value.get("output"))),
        reasoning_tokens=_non_negative_int(
            value.get("reasoning_tokens", value.get("reasoning"))
        ),
        cache_read_tokens=_non_negative_int(
            value.get("cache_read_tokens", cache.get("read"))
        ),
        cache_write_tokens=_non_negative_int(
            value.get("cache_write_tokens", cache.get("write"))
        ),
    )


def token_usage_from_models(
    models: dict[str, TokenCounters],
    *,
    complete: bool = True,
) -> OpenCodeTokenUsage:
    normalized = {
        str(model or "unknown"): counters for model, counters in models.items()
    }
    total = TokenCounters()
    for counters in normalized.values():
        total += counters
    return OpenCodeTokenUsage(
        counters=total,
        by_model=tuple(
            ModelTokenUsage(model=model, counters=counters)
            for model, counters in sorted(normalized.items())
        ),
        complete=complete,
    )


def token_usage_from_dict(value: object) -> OpenCodeTokenUsage | None:
    if isinstance(value, OpenCodeTokenUsage):
        return value
    if not isinstance(value, dict):
        return None
    total = parse_token_counters(value) or TokenCounters()
    models: dict[str, TokenCounters] = {}
    raw_models = value.get("by_model")
    if isinstance(raw_models, list):
        for item in raw_models:
            if not isinstance(item, dict):
                continue
            model = str(item.get("model") or "unknown")
            counters = parse_token_counters(item)
            if counters is not None:
                models[model] = models.get(model, TokenCounters()) + counters
    if not models and total.total_tokens:
        models["unknown"] = total
    if models:
        rebuilt = token_usage_from_models(models, complete=bool(value.get("complete", True)))
        if rebuilt.counters == total or total.total_tokens == 0:
            return rebuilt
    return OpenCodeTokenUsage(
        counters=total,
        by_model=tuple(
            ModelTokenUsage(model=model, counters=counters)
            for model, counters in sorted(models.items())
        ),
        complete=bool(value.get("complete", True)),
    )


def merge_token_usages(
    values: Iterable[OpenCodeTokenUsage | dict[str, Any] | None],
) -> OpenCodeTokenUsage | None:
    models: dict[str, TokenCounters] = {}
    total_without_models = TokenCounters()
    complete = True
    found = False
    for raw in values:
        usage = token_usage_from_dict(raw)
        if usage is None:
            continue
        found = True
        complete = complete and usage.complete
        if usage.by_model:
            for item in usage.by_model:
                models[item.model] = models.get(item.model, TokenCounters()) + item.counters
        else:
            total_without_models += usage.counters
    if not found:
        return None
    if total_without_models.total_tokens or not models:
        models["unknown"] = models.get("unknown", TokenCounters()) + total_without_models
    return token_usage_from_models(models, complete=complete)
