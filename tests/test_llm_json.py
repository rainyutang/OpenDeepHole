import pytest

from task_agent.llm_json import (
    LLMJsonParseError,
    parse_llm_json,
    parse_llm_json_schema,
)


def test_parse_llm_json_extracts_fenced_object_matching_schema() -> None:
    text = """analysis first
```json
{"confirmed": true, "severity": "high", "line": 12}
```
"""
    schema = {"confirmed": bool, "severity": str, "line": int}

    assert parse_llm_json(text, schema) == {
        "confirmed": True,
        "severity": "high",
        "line": 12,
    }


def test_parse_llm_json_prefers_longest_then_latest_match() -> None:
    text = (
        '{"confirmed": false, "severity": "low"}\n'
        'later {"confirmed": true, "severity": "high", "description": "full"}'
    )
    schema = {"confirmed": bool, "severity": str}

    assert parse_llm_json(text, schema)["description"] == "full"


def test_parse_llm_json_validates_nested_array_schema() -> None:
    text = '{"results": [{"line": 1, "confirmed": false}, {"line": 2, "confirmed": true}]}'
    schema = {"results": [{"line": int, "confirmed": bool}]}

    assert len(parse_llm_json(text, schema)["results"]) == 2


def test_parse_llm_json_rejects_non_matching_schema() -> None:
    with pytest.raises(LLMJsonParseError):
        parse_llm_json('{"line": "not-int"}', {"line": int})


def test_parse_llm_json_can_disallow_extra_keys() -> None:
    with pytest.raises(LLMJsonParseError):
        parse_llm_json('{"line": 1, "extra": true}', {"line": int}, allow_extra_keys=False)


def test_parse_llm_json_schema_extracts_plain_text_json() -> None:
    schema = {
        "type": "object",
        "properties": {
            "results": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "properties": {
                        "role": {"type": "string", "enum": ["alloc", "free"]},
                        "line": {"type": "integer"},
                    },
                    "required": ["role", "line"],
                    "additionalProperties": False,
                },
            }
        },
        "required": ["results"],
        "additionalProperties": False,
    }

    assert parse_llm_json_schema(
        'answer:\n```json\n{"results":[{"role":"alloc","line":7}]}\n```',
        schema,
    ) == {"results": [{"role": "alloc", "line": 7}]}


def test_parse_llm_json_schema_rejects_invalid_shape() -> None:
    schema = {
        "type": "object",
        "properties": {"line": {"type": "integer"}},
        "required": ["line"],
        "additionalProperties": False,
    }

    with pytest.raises(LLMJsonParseError):
        parse_llm_json_schema('{"line":"7","extra":true}', schema)


def test_parse_llm_json_schema_does_not_promote_nested_empty_array() -> None:
    schema = {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "call_chain": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string"},
                },
            },
            "required": ["call_chain"],
            "additionalProperties": False,
        },
    }

    with pytest.raises(LLMJsonParseError):
        parse_llm_json_schema('[{"call_chain":[]}]', schema)


def test_parse_llm_json_schema_enforces_string_and_number_bounds() -> None:
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string", "minLength": 1, "maxLength": 4},
            "line": {"type": "integer", "minimum": 1, "maximum": 10},
        },
        "required": ["name", "line"],
        "additionalProperties": False,
    }

    assert parse_llm_json_schema('{"name":"ok","line":7}', schema) == {
        "name": "ok",
        "line": 7,
    }
    for text in (
        '{"name":"","line":7}',
        '{"name":"longer","line":7}',
        '{"name":"ok","line":0}',
        '{"name":"ok","line":11}',
    ):
        with pytest.raises(LLMJsonParseError):
            parse_llm_json_schema(text, schema)
