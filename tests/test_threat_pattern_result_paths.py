"""The copied audit validator checks the on-disk result, never chat output."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from deephole_client.vulnerability_mining.engines.threat_pattern_audit import validate_result
from deephole_client.vulnerability_mining.engines.threat_pattern_audit.prompt import (
    THREAT_PATTERN_VULNERABILITY_LIST_SCHEMA,
)
from test_threat_pattern_audit import _finding


@pytest.fixture
def source(tmp_path):
    project = tmp_path / "项目 with spaces"
    for name in ("src/auth/session.c", "src/shared/session.c", "src/single.c", "src/other.c"):
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    return project


def check(value, project):
    validate_result.validate_paths(
        value, project_path=project,
        scan_directories=(project / "src/auth",), scan_files=(project / "src/single.c",),
    )


@pytest.mark.parametrize("file", ["src/auth/session.c", "src/single.c", r"src\auth\session.c"])
def test_selected_files_and_directory_descendants_are_valid(source, file):
    value = [{**_finding(), "file": file}]
    before = json.dumps(value)
    check(value, source)
    assert json.dumps(value) == before


@pytest.mark.parametrize("file,reason", [
    ("src/shared/session.c", "outside_scan_paths"),
    ("src/other.c", "outside_scan_paths"),
    ("auth/session.c", "outside_scan_paths"),
    ("src/auth/missing.c", "missing_file"),
    ("src/auth", "missing_file"),
    ("../session.c", "not_project_relative"),
    ("/project/src/auth/session.c", "not_project_relative"),
    (r"C:\project\src\auth\session.c", "not_project_relative"),
    (r"C:src\auth\session.c", "not_project_relative"),
    (r"\\server\project\src\auth\session.c", "not_project_relative"),
])
def test_invalid_location_reports_field_raw_path_and_scope_without_mutation(source, file, reason):
    value = [{**_finding(), "file": file}]
    before = json.dumps(value)
    with pytest.raises(validate_result.FindingPathError) as caught:
        check(value, source)
    message = str(caught.value)
    assert "$[0].file" in message and reason in message
    assert repr(file) in message and str(source) in message
    assert str(source / "src/auth") in message and str(source / "src/single.c") in message
    assert json.dumps(value) == before


def test_symlinks_cannot_escape_the_selected_paths(source):
    link = source / "src/auth/link.c"
    link.symlink_to(source / "src/shared/session.c")
    with pytest.raises(validate_result.FindingPathError, match="outside_scan_paths"):
        check([{**_finding(), "file": "src/auth/link.c"}], source)


def test_empty_result_is_valid_but_never_created_by_validator(source):
    check([], source)
    with pytest.raises(ValueError, match="at least one selected"):
        validate_result.validate_paths([], project_path=source)


def test_standalone_script_revalidates_the_same_file_after_model_correction(source, tmp_path):
    copied_script = tmp_path / "validate_result.py"
    copied_script.write_bytes(Path(validate_result.__file__).read_bytes())
    schema = tmp_path / "schema.json"
    schema.write_text(json.dumps(THREAT_PATTERN_VULNERABILITY_LIST_SCHEMA), encoding="utf-8")
    result = tmp_path / "task result.json"
    command = [sys.executable, "-I", str(copied_script), str(schema), str(result),
               "--project-path", str(source), "--scan-directory", str(source / "src/auth"),
               "--scan-file", str(source / "src/single.c")]

    def run_file(value):
        result.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
        original = result.read_bytes()
        run = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True, check=False)
        assert result.read_bytes() == original
        return run

    failed = run_file([{**_finding(), "file": "src/shared/session.c"}])
    assert failed.returncode != 0
    assert str(result) in failed.stderr and "outside_scan_paths" in failed.stderr
    assert run_file([_finding()]).returncode == 0
    assert run_file([]).returncode == 0
    invalid_schema = run_file([{"file": "src/auth/session.c"}])
    assert invalid_schema.returncode != 0 and "missing required" in invalid_schema.stderr
    result.write_text("This chat reply is not a JSON artifact", encoding="utf-8")
    assert subprocess.run(command, capture_output=True, check=False).returncode != 0
