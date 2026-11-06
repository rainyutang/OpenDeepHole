from __future__ import annotations

import asyncio
import copy
import importlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from deephole_client.threat_analysis_runner import _load_implementation
from test_deephole_compact_threat_analysis import _assets, _attack_tree, _module


@pytest.fixture
def validation_case(tmp_path):
    native = _load_implementation("deephole_compact_threat_analysis")
    validator = importlib.import_module(native.__name__ + ".validate_attack_tree")
    trees = importlib.import_module(native.__name__ + ".stages.attack_trees")
    module = _module()
    schema = trees._attack_tree_task_schema(trees._high_risk_module_references([module]))
    modes = json.loads(validator.CATALOG_PATH.read_text(encoding="utf-8"))
    patterns = [{"pattern_id": "、".join(mode["攻击模式编号"]),
                 "pattern_name": mode["攻击模式名称"], "association_description": "外部输入影响资产。"}
                for mode in modes]
    data = _attack_tree("tree", _assets()[0], module, trees._stable_high_risk_module_id(module), patterns)
    output = tmp_path / "攻击树 output.json"
    schema_path = tmp_path / "task schema.json"
    schema_path.write_text(json.dumps(schema, ensure_ascii=False), encoding="utf-8")
    case = SimpleNamespace(validator=validator, data=data, schema=schema, output=output, schema_path=schema_path)
    case.write = lambda: output.write_text(json.dumps(case.data, ensure_ascii=False), encoding="utf-8")
    case.write()
    yield case
    _load_implementation()


def test_all_51_patterns_validate_without_rewriting_file(validation_case):
    case = validation_case
    before = case.output.read_bytes()
    assert case.validator.validate_file(case.output, case.schema) == case.data
    assert case.validator.validate_file(case.output, case.schema_path) == case.data
    assert case.output.read_bytes() == before


@pytest.mark.parametrize("change, expected", [
    ({"pattern_id": "OUTSIDE-51"}, "pattern_id='OUTSIDE-51'"),
    ({"pattern_name": "库中不存在的名称"}, "expected pattern_name="),
    ({"pattern_id": " ODH-NATIVE-01"}, "pattern_id=' ODH-NATIVE-01'"),
    ({"pattern_name": " "}, "pattern_name=' '"),
    ({"pattern_id": ""}, "pattern_id=''"),
])
def test_invalid_pattern_identity_reports_file_and_field(validation_case, change, expected):
    case = validation_case
    case.data["attack_trees"][0]["attack_paths"][0]["attack_patterns"][0].update(change)
    case.write()
    with pytest.raises(ValueError) as error:
        case.validator.validate_file(case.output, case.schema)
    assert str(case.output) in str(error.value)
    assert "$.attack_trees[0].attack_paths[0].attack_patterns[0]" in str(error.value)
    assert expected in str(error.value)


def test_duplicates_rejected_per_path_but_reuse_between_paths_allowed(validation_case):
    case = validation_case
    tree = case.data["attack_trees"][0]
    tree["attack_paths"].append(copy.deepcopy(tree["attack_paths"][0]))
    case.write()
    case.validator.validate_file(case.output, case.schema)
    patterns = tree["attack_paths"][0]["attack_patterns"]
    patterns.append(copy.deepcopy(patterns[0]))
    case.write()
    with pytest.raises(ValueError, match="duplicate attack pattern"):
        case.validator.validate_file(case.output, case.schema)


def test_empty_pattern_arrays_are_valid(validation_case):
    case = validation_case
    case.data["attack_trees"][0]["attack_paths"][0]["attack_patterns"] = []
    case.write()
    case.validator.validate_file(case.output, case.schema)
    case.validator.validate_patterns({"attack_trees": [], "unassigned_module_pattern_baselines": []})


@pytest.mark.parametrize("unassigned", [False, True])
def test_fixed_baseline_patterns_are_checked(validation_case, unassigned):
    case = validation_case
    record = {"module_name": "module", "source": "compact_baseline",
              "attack_patterns": [copy.deepcopy(case.data["attack_trees"][0]["attack_paths"][0]["attack_patterns"][0])]}
    if unassigned:
        data = {"attack_trees": [], "unassigned_module_pattern_baselines": [record]}
    else:
        data = {"attack_trees": [{"module_pattern_baselines": [record]}]}
    case.validator.validate_patterns(data)
    record["attack_patterns"][0]["pattern_id"] = "INVALID"
    with pytest.raises(ValueError, match="module_pattern_baselines.*pattern_id='INVALID'"):
        case.validator.validate_patterns(data)


@pytest.mark.parametrize("defect, expected", [
    ("missing", "cannot read UTF-8 JSON"),
    ("directory", "cannot read UTF-8 JSON"),
    ("syntax", "JSON 第 2 行"),
    ("encoding", "cannot read UTF-8 JSON"),
    ("missing_property", "missing required property 'nodes'"),
    ("module_id", "not in enum"),
    ("one_of", "oneOf"),
])
def test_file_and_dynamic_schema_failures_are_value_errors(validation_case, defect, expected):
    case = validation_case
    if defect in {"missing", "directory"}:
        case.output.unlink()
        if defect == "directory":
            case.output.mkdir()
    elif defect == "syntax":
        case.output.write_text('{\ninvalid}', encoding="utf-8")
    elif defect == "encoding":
        case.output.write_bytes(b"\xff")
    else:
        tree = case.data["attack_trees"][0]
        if defect == "missing_property":
            del tree["nodes"]
        elif defect == "module_id":
            tree["attack_paths"][0]["related_high_risk_modules"][0]["module_id"] = "unknown"
        else:
            tree["nodes"][0]["module_id"] = tree["nodes"][1]["module_id"]
        case.write()
    with pytest.raises(ValueError, match=expected):
        case.validator.validate_file(case.output, case.schema)


def test_cli_is_standalone_from_an_unrelated_working_directory(validation_case, tmp_path):
    case = validation_case
    standalone = tmp_path / "standalone validator"
    standalone.mkdir()
    source = case.validator.VALIDATOR_PATH.parent
    for name in ("validate_attack_tree.py", "output_validation.py", "errors.py"):
        shutil.copy2(source / name, standalone / name)
    catalog = standalone / case.validator.CATALOG_PATH.relative_to(source)
    catalog.parent.mkdir(parents=True)
    shutil.copy2(case.validator.CATALOG_PATH, catalog)
    other_cwd = tmp_path / "unrelated"
    other_cwd.mkdir()
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    argv = [sys.executable, str(standalone / "validate_attack_tree.py"),
            "--output", str(case.output), "--schema", str(case.schema_path)]
    success = subprocess.run(argv, cwd=other_cwd, env=env, capture_output=True, encoding="utf-8", timeout=10)
    assert success.returncode == 0, success.stderr
    assert success.stdout.startswith("VALID:")
    case.data["attack_trees"][0]["attack_paths"][0]["attack_patterns"][0]["pattern_id"] = "UNKNOWN"
    case.write()
    failure = subprocess.run(argv, cwd=other_cwd, env=env, capture_output=True, encoding="utf-8", timeout=10)
    assert failure.returncode == 1
    assert "INVALID:" in failure.stderr and "UNKNOWN" in failure.stderr
    assert str(case.output) in failure.stderr


def test_async_host_validation_uses_same_script(validation_case):
    case = validation_case
    asyncio.run(case.validator.validate_file_async(case.output, case.schema_path))
    case.output.write_text("not JSON", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON 第 1 行"):
        asyncio.run(case.validator.validate_file_async(case.output, case.schema_path))


def test_command_arguments_bind_exact_paths_on_posix_and_windows(validation_case, monkeypatch):
    case = validation_case
    monkeypatch.setattr(case.validator.sys, "platform", "linux")
    command = case.validator.validation_command(case.output, case.schema_path)
    assert tuple(shlex.split(command)) == case.validator.validation_argv(case.output, case.schema_path)
    monkeypatch.setattr(case.validator.sys, "platform", "win32")
    command = case.validator.validation_command(case.output, case.schema_path)
    assert command.startswith('python "')
    assert f'"{case.output}"' in command and f'"{case.schema_path}"' in command


@pytest.mark.parametrize("cancel", [False, True])
def test_async_timeout_and_cancellation_reap_validator(validation_case, monkeypatch, cancel):
    case = validation_case

    async def run():
        entered = asyncio.Event()
        stopped = asyncio.Event()

        class Process:
            returncode = None
            terminated = False
            killed = False

            async def wait(self):
                entered.set()
                await stopped.wait()
                return self.returncode

            def terminate(self):
                self.terminated = True

            def kill(self):
                self.killed = True
                self.returncode = -9
                stopped.set()

        process = Process()

        async def spawn(*args, **kwargs):
            assert args == case.validator.validation_argv(case.output, case.schema_path)
            assert "shell" not in kwargs
            return process

        monkeypatch.setattr(case.validator.asyncio, "create_subprocess_exec", spawn)
        monkeypatch.setattr(case.validator, "ARTIFACT_VALIDATION_TIMEOUT_SECONDS", 0.01)
        monkeypatch.setattr(case.validator, "_VALIDATION_STOP_TIMEOUT_SECONDS", 0.04)
        task = asyncio.create_task(case.validator.validate_file_async(case.output, case.schema_path))
        await entered.wait()
        if cancel:
            task.cancel()
        with pytest.raises(asyncio.CancelledError if cancel else ValueError):
            await asyncio.wait_for(task, timeout=1)
        assert process.terminated and process.killed and process.returncode == -9

    asyncio.run(run())
