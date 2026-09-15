"""Shared OpenCode token-usage value objects and aggregation helpers."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Iterable

from .token_categories import CATEGORY_LABELS


TOKEN_COUNTER_FIELDS = (
    "input_tokens", "output_tokens", "reasoning_tokens", "cache_read_tokens", "cache_write_tokens",
)


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
class CategoryTokenUsage:
    category: str
    counters: TokenCounters
    label: str = ""
    complete: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "label", CATEGORY_LABELS.get(self.category) or self.label or self.category)

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "label": CATEGORY_LABELS.get(self.category) or self.label or self.category,
            "complete": self.complete,
            **self.counters.as_dict(),
        }


@dataclass(frozen=True)
class OpenCodeTokenUsage:
    counters: TokenCounters
    by_model: tuple[ModelTokenUsage, ...] = ()
    complete: bool = True
    by_category: tuple[CategoryTokenUsage, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            **self.counters.as_dict(),
            "complete": self.complete,
            "by_model": [item.as_dict() for item in self.by_model],
            "by_category": [item.as_dict() for item in self.by_category],
        }


def reconcile_token_categories(
    total: TokenCounters,
    categories: Iterable[CategoryTokenUsage],
    *,
    complete: bool = True,
) -> tuple[CategoryTokenUsage, ...]:
    """Keep the original total authoritative; never scale conflicting history."""
    grouped: dict[str, CategoryTokenUsage] = {}
    used = TokenCounters()
    for item in categories:
        previous = grouped.get(item.category)
        grouped[item.category] = replace(
            item,
            counters=item.counters + (previous.counters if previous else TokenCounters()),
            complete=item.complete and (previous.complete if previous else True),
        )
        used += item.counters
    if any(getattr(used, key) > getattr(total, key) for key in TOKEN_COUNTER_FIELDS):
        return (CategoryTokenUsage("uncategorized", total, complete=complete),)
    remainder = TokenCounters(**{key: getattr(total, key) - getattr(used, key) for key in TOKEN_COUNTER_FIELDS})
    if remainder.total_tokens:
        previous = grouped.get("uncategorized")
        grouped["uncategorized"] = CategoryTokenUsage(
            "uncategorized", remainder + (previous.counters if previous else TokenCounters()),
            complete=complete and (previous.complete if previous else True),
        )
    return tuple(grouped[key] for key in sorted(grouped))


def attribute_token_usage(usage: OpenCodeTokenUsage, category: str, label: str = "") -> OpenCodeTokenUsage:
    """Attribute one deduplicated prompt delta, including its child sessions."""
    return replace(usage, by_category=(CategoryTokenUsage(category, usage.counters, label, usage.complete),))


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
    categories = tuple(
        CategoryTokenUsage(
            str(item.get("category") or "uncategorized"),
            parse_token_counters(item) or TokenCounters(),
            str(item.get("label") or ""), bool(item.get("complete", True)),
        )
        for item in (value.get("by_category") or []) if isinstance(item, dict)
    ) if isinstance(value.get("by_category"), list) else ()
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
            return replace(rebuilt, by_category=categories)
    return OpenCodeTokenUsage(
        counters=total,
        by_model=tuple(
            ModelTokenUsage(model=model, counters=counters)
            for model, counters in sorted(models.items())
        ),
        complete=bool(value.get("complete", True)),
        by_category=categories,
    )


def merge_token_usages(
    values: Iterable[OpenCodeTokenUsage | dict[str, Any] | None],
) -> OpenCodeTokenUsage | None:
    models: dict[str, TokenCounters] = {}
    total_without_models = TokenCounters()
    complete = True
    found = False
    categories: list[CategoryTokenUsage] = []
    has_categories = False
    for raw in values:
        usage = token_usage_from_dict(raw)
        if usage is None:
            continue
        found = True
        complete = complete and usage.complete
        has_categories = has_categories or bool(usage.by_category)
        categories.extend(reconcile_token_categories(usage.counters, usage.by_category, complete=usage.complete))
        if usage.by_model:
            for item in usage.by_model:
                models[item.model] = models.get(item.model, TokenCounters()) + item.counters
        else:
            total_without_models += usage.counters
    if not found:
        return None
    if total_without_models.total_tokens or not models:
        models["unknown"] = models.get("unknown", TokenCounters()) + total_without_models
    merged = token_usage_from_models(models, complete=complete)
    return replace(merged, by_category=reconcile_token_categories(merged.counters, categories, complete=complete)) if has_categories else merged
