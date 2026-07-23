"""Server-side view of validation targets reported by connected clients."""

from __future__ import annotations

import json

from backend.models import ValidationTarget
from backend.store import get_scan_store


def refresh_validation_catalog() -> list[ValidationTarget]:
    """Aggregate normalized product/environment pairs from client metadata."""
    targets: dict[tuple[str, str], ValidationTarget] = {}
    for record in get_scan_store().list_agent_records():
        try:
            catalog = json.loads(
                str(record.get("validator_catalog_json") or "{}"),
            )
        except (TypeError, ValueError):
            continue
        for registration in catalog.get("registrations") or []:
            if not isinstance(registration, dict):
                continue
            product = str(registration.get("product") or "").strip()
            environment = str(registration.get("environment") or "").strip()
            if not product or not environment:
                continue
            targets.setdefault(
                (product, environment),
                ValidationTarget(
                    validator_id=str(
                        registration.get("method_id")
                        or registration.get("registration_key")
                        or ""
                    ),
                    product=product,
                    validation_environment=environment,
                    timeout_seconds=registration.get("timeout_seconds"),
                ),
            )
    return sorted(
        targets.values(),
        key=lambda item: (
            item.product,
            item.validation_environment,
            item.validator_id,
        ),
    )


def get_validation_catalog() -> list[ValidationTarget]:
    return refresh_validation_catalog()


def find_validation_target(
    product: str,
    validation_environment: str,
) -> ValidationTarget | None:
    key = (
        str(product or "").strip(),
        str(validation_environment or "").strip(),
    )
    return next(
        (
            item
            for item in get_validation_catalog()
            if (item.product, item.validation_environment) == key
        ),
        None,
    )
