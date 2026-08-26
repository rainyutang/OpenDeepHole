"""Validate Codex artifacts against this method's private JSON Schemas."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any


class ArtifactValidationError(ValueError):
    """A generated artifact does not satisfy the threat-analysis contract."""


def validate_artifacts(
    *,
    value_asset_path: Path,
    high_risk_modules_path: Path,
    attack_tree_path: Path,
    value_asset_schema_path: Path,
    high_risk_modules_schema_path: Path,
    attack_tree_schema_path: Path,
) -> None:
    artifacts = (
        (value_asset_path, value_asset_schema_path),
        (high_risk_modules_path, high_risk_modules_schema_path),
        (attack_tree_path, attack_tree_schema_path),
    )
    for path, schema_path in artifacts:
        schema = _read_json(schema_path, label="schema")
        if not isinstance(schema, Mapping):
            raise ArtifactValidationError(
                f"schema must contain a JSON object: {schema_path}"
            )
        value = _read_json(path, label="artifact")
        _validate(value, schema, path="$")


def _read_json(path: Path, *, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ArtifactValidationError(f"required {label} is missing: {path}") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArtifactValidationError(
            f"{label} is not readable UTF-8 JSON: {path}"
        ) from exc


def _validate(value: Any, schema: Mapping[str, Any], *, path: str) -> None:
    if "enum" in schema and value not in schema["enum"]:
        raise ArtifactValidationError(f"{path}: value is outside the allowed enum")

    expected_type = schema.get("type")
    if expected_type is not None and not _matches_type(value, expected_type):
        raise ArtifactValidationError(f"{path}: expected {expected_type!r}")

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                raise ArtifactValidationError(
                    f"{path}: missing required property {key!r}"
                )
        if schema.get("additionalProperties") is False:
            extras = sorted(set(value) - set(properties))
            if extras:
                raise ArtifactValidationError(f"{path}: unexpected properties {extras!r}")
        for key, child_schema in properties.items():
            if key in value:
                _validate(value[key], child_schema, path=f"{path}.{key}")
        return

    if isinstance(value, list):
        minimum = schema.get("minItems")
        if minimum is not None and len(value) < int(minimum):
            raise ArtifactValidationError(f"{path}: expected at least {minimum} items")
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                _validate(item, item_schema, path=f"{path}[{index}]")
        return

    if isinstance(value, str):
        minimum = schema.get("minLength")
        if minimum is not None and len(value) < int(minimum):
            raise ArtifactValidationError(f"{path}: string must not be empty")


def _matches_type(value: Any, expected: str | list[str]) -> bool:
    if isinstance(expected, list):
        return any(_matches_type(value, item) for item in expected)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    raise ArtifactValidationError(f"unsupported schema type: {expected!r}")
