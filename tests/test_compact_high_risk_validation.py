from __future__ import annotations

import asyncio
import importlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from deephole_client.threat_analysis_runner import _load_implementation
from test_deephole_compact_threat_analysis import _module


@pytest.fixture
def validator():
    native = _load_implementation("deephole_compact_threat_analysis")
    yield importlib.import_module(native.__name__ + ".validate_high_risk_modules")
    _load_implementation()


def _write(path: Path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


@pytest.mark.parametrize("values", [[], [_module()], [_module(), _module()]])
def test_original_module_array_format_including_empty_array_is_accepted(validator, tmp_path, values):
    output = tmp_path / "modules.json"
    _write(output, values)
    original = output.read_bytes()
    assert validator.validate_file(output) == values
    assert output.read_bytes() == original


@pytest.mark.parametrize("paths", ["src/parser", ["src/parser", "src/shared"], "", []])
def test_code_paths_keep_original_schema_semantics(validator, tmp_path, paths):
    output = tmp_path / "modules.json"
    values = [{**_module(), "代码目录": paths}]
    _write(output, values)
    assert validator.validate_file(output) == values


@pytest.mark.parametrize("defect, expected", [
    ("missing", "cannot read UTF-8 JSON"),
    ("directory", "cannot read UTF-8 JSON"),
    ("empty", "JSON 第 1 行"),
    ("syntax", "JSON 第 2 行"),
    ("encoding", "cannot read UTF-8 JSON"),
    ("object", "expected type 'array'"),
    ("null", "expected type 'array'"),
    ("missing_field", "missing required property '模块名称'"),
    ("extra_field", "additional properties not allowed"),
    ("boolean_flag", "not in enum"),
    ("unknown_flag", "not in enum"),
    ("number_path", "expected type"),
])
def test_invalid_files_report_filename_and_schema_or_json_location(validator, tmp_path, defect, expected):
    output = tmp_path / "高风险模块.json"
    if defect == "missing":
        pass
    elif defect == "directory":
        output.mkdir()
    elif defect == "empty":
        output.write_bytes(b"")
    elif defect == "syntax":
        output.write_text('[\ninvalid]', encoding="utf-8")
    elif defect == "encoding":
        output.write_bytes(b"\xff")
    elif defect in {"object", "null"}:
        _write(output, {} if defect == "object" else None)
    else:
        module = _module()
        if defect == "missing_field":
            del module["模块名称"]
        elif defect == "extra_field":
            module["unexpected"] = "value"
        elif defect == "boolean_flag":
            module["是否外部暴露面"] = True
        elif defect == "unknown_flag":
            module["是否外部暴露面"] = "unknown"
        else:
            module["代码目录"] = 123
        _write(output, [module])
    with pytest.raises(ValueError, match=expected) as error:
        validator.validate_file(output)
    assert str(output) in str(error.value)
    if defect in {"missing_field", "extra_field", "boolean_flag", "unknown_flag", "number_path"}:
        assert "$[0]" in str(error.value)


@pytest.mark.parametrize("values", [[], [_module()]])
def test_standalone_cli_uses_fixed_schema_from_unrelated_cwd(validator, tmp_path, values):
    isolated = tmp_path / "isolated validator"
    isolated.mkdir()
    source = validator.VALIDATOR_PATH.parent
    for name in ("validate_high_risk_modules.py", "artifact_validation.py", "schemas.py",
                 "output_validation.py", "errors.py"):
        shutil.copy2(source / name, isolated / name)
    output = tmp_path / "高风险 modules.json"
    _write(output, values)
    working_dir = tmp_path / "scanned source"
    working_dir.mkdir()
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    argv = [sys.executable, str(isolated / "validate_high_risk_modules.py"), "--output", str(output)]
    result = subprocess.run(argv, cwd=working_dir, env=env, capture_output=True,
                            encoding="utf-8", timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("VALID:")
    output.write_text("invalid JSON", encoding="utf-8")
    failed = subprocess.run(argv, cwd=working_dir, env=env, capture_output=True,
                            encoding="utf-8", timeout=10)
    assert failed.returncode == 1
    assert "INVALID:" in failed.stderr and "JSON 第 1 行" in failed.stderr
    assert str(output) in failed.stderr


def test_async_validation_checks_same_file_and_accepts_empty_array(validator, tmp_path):
    output = tmp_path / "modules.json"
    _write(output, [])
    asyncio.run(validator.validate_file_async(output))
    _write(output, [_module()])
    asyncio.run(validator.validate_file_async(output))
    _write(output, [{"模块名称": "incomplete"}])
    with pytest.raises(ValueError, match="missing required property"):
        asyncio.run(validator.validate_file_async(output))


def test_self_check_command_binds_only_the_output_path(validator, tmp_path, monkeypatch):
    output = tmp_path / "模块 output.json"
    expected = (sys.executable, str(validator.VALIDATOR_PATH), "--output", str(output))
    assert validator.validation_argv(output) == expected
    monkeypatch.setattr(validator.sys, "platform", "linux")
    assert tuple(shlex.split(validator.validation_command(output))) == expected
    monkeypatch.setattr(validator.sys, "platform", "win32")
    assert validator.validation_command(output) == (
        f'python "{validator.VALIDATOR_PATH}" "--output" "{output}"'
    )


def test_windows_command_rejects_unquotable_path(validator, tmp_path, monkeypatch):
    monkeypatch.setattr(validator.sys, "platform", "win32")
    with pytest.raises(ValueError, match="cannot contain quotes"):
        validator.validation_command(tmp_path / 'bad"path.json')
