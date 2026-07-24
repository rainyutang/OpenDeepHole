"""Validate persisted threat-analysis outputs against their task schemas."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from threat_analysis_harness.errors import OutputSchemaValidationError


def validate_json_schema(
    value: Any,
    schema: Mapping[str, Any],
    path: str = "$",
) -> None:
    """Validate the JSON Schema subset used by threat-analysis task outputs."""

    if "enum" in schema and value not in schema["enum"]:
        raise OutputSchemaValidationError(
            f"{path}: value {value!r} not in enum {schema['enum']!r}"
        )

    if "const" in schema and value != schema["const"]:
        raise OutputSchemaValidationError(
            f"{path}: value {value!r} does not equal const {schema['const']!r}"
        )

    expected_type = schema.get("type")
    if expected_type is not None and not _matches_type(value, expected_type):
        raise OutputSchemaValidationError(
            f"{path}: expected type {expected_type!r}, got {type(value).__name__}"
        )

    if isinstance(value, dict):
        _validate_object(value, schema, path)
    elif isinstance(value, list):
        _validate_array(value, schema, path)
    elif isinstance(value, str):
        _validate_string(value, schema, path)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        _validate_number(value, schema, path)


def _validate_object(
    value: dict[str, Any],
    schema: Mapping[str, Any],
    path: str,
) -> None:
    required = schema.get("required", [])
    for key in required:
        if key not in value:
            raise OutputSchemaValidationError(
                f"{path}: missing required property {key!r}"
            )

    properties = schema.get("properties", {})
    for key, property_schema in properties.items():
        if key in value:
            validate_json_schema(value[key], property_schema, f"{path}.{key}")

    additional = schema.get("additionalProperties", True)
    if additional is False:
        extras = sorted(set(value) - set(properties))
        if extras:
            raise OutputSchemaValidationError(
                f"{path}: additional properties not allowed: {extras!r}"
            )
    elif isinstance(additional, Mapping):
        for key in set(value) - set(properties):
            validate_json_schema(value[key], additional, f"{path}.{key}")


def _validate_array(
    value: list[Any],
    schema: Mapping[str, Any],
    path: str,
) -> None:
    if "minItems" in schema and len(value) < int(schema["minItems"]):
        raise OutputSchemaValidationError(
            f"{path}: expected at least {schema['minItems']} items"
        )
    if "maxItems" in schema and len(value) > int(schema["maxItems"]):
        raise OutputSchemaValidationError(
            f"{path}: expected at most {schema['maxItems']} items"
        )

    item_schema = schema.get("items")
    if isinstance(item_schema, Mapping):
        for index, item in enumerate(value):
            validate_json_schema(item, item_schema, f"{path}[{index}]")


def _validate_string(
    value: str,
    schema: Mapping[str, Any],
    path: str,
) -> None:
    if "minLength" in schema and len(value) < int(schema["minLength"]):
        raise OutputSchemaValidationError(
            f"{path}: string is shorter than minLength={schema['minLength']}"
        )
    if "maxLength" in schema and len(value) > int(schema["maxLength"]):
        raise OutputSchemaValidationError(
            f"{path}: string is longer than maxLength={schema['maxLength']}"
        )


def _validate_number(
    value: int | float,
    schema: Mapping[str, Any],
    path: str,
) -> None:
    if "minimum" in schema and value < schema["minimum"]:
        raise OutputSchemaValidationError(
            f"{path}: number is smaller than minimum={schema['minimum']}"
        )
    if "maximum" in schema and value > schema["maximum"]:
        raise OutputSchemaValidationError(
            f"{path}: number is larger than maximum={schema['maximum']}"
        )


def _matches_type(value: Any, expected_type: str | list[str]) -> bool:
    if isinstance(expected_type, list):
        return any(_matches_type(value, item) for item in expected_type)
    if expected_type == "object":
        return isinstance(value, dict)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "null":
        return value is None
    raise OutputSchemaValidationError(
        f"Unsupported JSON schema type: {expected_type!r}"
    )
