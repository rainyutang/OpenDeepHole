import asyncio
import json
import shlex
import subprocess
import sys
from functools import partial
from pathlib import Path
from unittest.mock import patch

import pytest

from task_agent import run_opencode_task
from task_agent.bash_commands import command_binding_metadata
from task_agent.serve_client import (
    _managed_file_write_plugin_path,
    _validate_required_command_audit,
    _write_command_binding,
)
from task_agent.task_service import OpenCodeTaskService, OpenCodeTaskSpec


def _run_hook(runtime: Path, script: str, data: dict) -> str:
    plugin = _managed_file_write_plugin_path(runtime)
    completed = subprocess.run(
        ["node", "--input-type=module", "-e", script, str(plugin), json.dumps(data)],
        capture_output=True, text=True, timeout=15, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout


@pytest.mark.parametrize("platform", ["posix", "win32"])
def test_bound_python_script_rewrites_before_permissions_and_audits(
    tmp_path: Path, platform: str,
) -> None:
    windows = platform == "win32"
    script_path = r"C:\Agent install\schema_validation.py" if windows else "/agent install/schema_validation.py"
    host_python = r"C:\Python install\python.exe" if windows else "/venv/bin/python"
    path_arg = '"' + script_path + '"'
    command_a = "python " + path_arg + ' --input "task-a.json"'
    command_b = "python " + path_arg + ' --input "task-b.json"'
    metadata = partial(
        command_binding_metadata, platform=platform, python_executable=host_python,
    )
    with patch("task_agent.serve_client.command_binding_metadata", metadata):
        _, audit_a = _write_command_binding(
            tmp_path, session_id="task-a", required_commands=(command_a,),
            bash_command_match_mode="bound_python_script",
        )
        _, audit_b = _write_command_binding(
            tmp_path, session_id="task-b", required_commands=(command_b,),
            bash_command_match_mode="bound_python_script",
        )
        legacy_binding, _ = _write_command_binding(
            tmp_path, session_id="exact", required_commands=(command_a,),
        )
    assert "bash_command_match_mode" not in json.loads(legacy_binding.read_text())
    accepted = [
        command_a,
        "python3 " + path_arg,
        "python\t  " + path_arg + ' --unknown "discarded value"',
        "python '" + script_path + "' --input other-task.json",
        "python.exe " + path_arg + ' --references-root "/wrong" --input "/wrong"',
        "python3.exe " + path_arg + " --input=wrong.json",
        '"' + host_python + '" ' + path_arg,
        "python " + path_arg + " --input ''",
    ]
    if windows:
        accepted.append('PYTHON3 "' + script_path.replace("\\", "/").lower() + '"')
    else:
        accepted.append("python /agent\\ install/./schema_validation.py")
    prefix = "python " + path_arg
    rejected = [
        "echo " + prefix,
        "python -c " + path_arg,
        "python -m " + path_arg,
        "python schema_validation.py",
        'python "' + script_path.replace("schema_validation", "other/schema_validation") + '"',
        'python "' + script_path + '.other.py"',
        'python "' + script_path,
        "/unbound/python " + path_arg,
        "PYTHONPATH=/tmp " + prefix,
        prefix + " && echo injected",
        prefix + "; echo injected",
        prefix + " | echo injected",
        prefix + " > output.txt",
        prefix + " 2>&1",
        prefix + "\necho injected",
        prefix + " $(echo injected)",
        prefix + " " + chr(96) + "echo injected" + chr(96),
        prefix + " --input $OTHER",
        prefix + ' --input "$OTHER"',
        prefix + " --input *.json",
        prefix + " &",
    ]
    if windows:
        rejected.extend([prefix + " %OTHER%", prefix + " !OTHER!"])
    data = dict(accepted=accepted, rejected=rejected, command_a=command_a, command_b=command_b)
    _run_hook(tmp_path, r'''
import assert from "node:assert/strict"
import { pathToFileURL } from "node:url"
const plugin = await import(pathToFileURL(process.argv[1]).href)
const hooks = await plugin.OpenDeepHoleFileWriteHook({ directory: process.cwd() })
const data = JSON.parse(process.argv[2])
const before = hooks["tool.execute.before"], after = hooks["tool.execute.after"]
await hooks.event({ event: {
  type: "session.created", properties: { info: { id: "child", parentID: "task-a" } },
}})
for (const sessionID of ["task-a", "child", "task-b"]) {
  const canonical = sessionID === "task-b" ? data.command_b : data.command_a
  for (const [index, requested] of data.accepted.entries()) {
    const args = { command: requested }
    const output = { args }
    const input = { sessionID, tool: "bash", callID: "call-" + index }
    await before(input, output)
    assert.equal(output.args, args)
    // Native permission evaluation happens after the Hook and sees only this.
    assert.equal(args.command, canonical)
    await after({ ...input, args }, { metadata: { exitCode: 0 }, output: "VALID" })
  }
  for (const command of data.rejected) {
    await assert.rejects(before({ sessionID, tool: "bash" }, { args: { command } }), /not bound.*before/)
  }
}
const shellArgs = { cmd: data.accepted[1] }
await before({ sessionID: "child", tool: "shell" }, { args: shellArgs })
assert.equal(shellArgs.cmd, data.command_a)
await assert.rejects(
  after({ sessionID: "task-a", tool: "bash", args: { command: data.accepted[1] } }, { metadata: { exitCode: 0 } }),
  /not bound.*after/,
)
await before({ sessionID: "exact", tool: "bash" }, { args: { command: data.command_a } })
await assert.rejects(
  before({ sessionID: "exact", tool: "bash" }, { args: { command: data.accepted[1] } }),
  /not bound/,
)
// Concurrent calls to different task bindings must retain their own parameters.
await Promise.all(["task-a", "task-b"].map(async (sessionID) => {
  const args = { command: data.accepted[1] }
  await before({ sessionID, tool: "bash" }, { args })
  assert.equal(args.command, sessionID === "task-a" ? data.command_a : data.command_b)
}))
''', data)
    for audit, command, sessions in [
        (audit_a, command_a, {"task-a", "child"}),
        (audit_b, command_b, {"task-b"}),
    ]:
        _validate_required_command_audit(audit, (command,))
        events = [json.loads(line) for line in audit.read_text().splitlines()]
        assert {event["command"] for event in events} == {command}
        assert {event["session_id"] for event in events} == sessions
        assert all(event["success"] for event in events)


@pytest.mark.skipif(sys.platform == "win32", reason="executes a POSIX shell locally")
def test_hook_executes_only_the_bound_interpreter_and_arguments(tmp_path: Path) -> None:
    script_path = tmp_path / "validator's directory" / "schema_validation.py"
    script_path.parent.mkdir()
    script_path.write_text("import json, sys\nprint(json.dumps(sys.argv[1:]))\n")
    expected = [
        "--value-assets", str(tmp_path / "task" / "value-assets.json"),
        "--high-risk-modules", str(tmp_path / "task" / "high-risk-modules.json"),
        "--attack-trees", str(tmp_path / "task" / "attack-trees.json"),
        "--references-root", str(tmp_path / "references"),
    ]
    command = shlex.join([sys.executable, str(script_path), *expected])
    _, audit = _write_command_binding(
        tmp_path, session_id="run", required_commands=(command,),
        bash_command_match_mode="bound_python_script",
    )
    _run_hook(tmp_path, r'''
import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import { pathToFileURL } from "node:url"
const plugin = await import(pathToFileURL(process.argv[1]).href)
const hooks = await plugin.OpenDeepHoleFileWriteHook({ directory: process.cwd() })
const data = JSON.parse(process.argv[2])
const args = { command: data.requested }
const input = { sessionID: "run", tool: "bash", callID: "actual-execution" }
await hooks["tool.execute.before"](input, { args })
assert.equal(args.command, data.command)
const result = spawnSync(args.command, { shell: true, encoding: "utf8" })
assert.equal(result.status, 0, result.stderr)
assert.deepEqual(JSON.parse(result.stdout), data.expected)
await hooks["tool.execute.after"]({ ...input, args }, {
  metadata: { exitCode: result.status }, output: result.stdout,
})
''', {
        "command": command, "expected": expected,
        "requested": 'python3 "' + str(script_path) + '" --value-assets "/another-task.json"',
    })
    _validate_required_command_audit(audit, (command,))
    assert json.loads(audit.read_text())["command"] == command


@pytest.mark.skipif(sys.platform == "win32", reason="executes a POSIX shell locally")
def test_real_lightweight_validator_runs_after_command_rewrite(tmp_path: Path) -> None:
    from deephole_client.threat_analysis import lightweight_contract

    guidance, _ = lightweight_contract.reference_paths()
    paths = {
        "value_asset_path": tmp_path / "value-assets.json",
        "high_risk_modules_path": tmp_path / "high-risk-modules.json",
        "attack_tree_path": tmp_path / "attack-trees.json",
    }
    for path in paths.values():
        path.write_text("{}\n")
    command = lightweight_contract.opencode_validation_command(
        guidance_path=guidance, paths=paths,
    )
    argv = lightweight_contract.validation_argv(guidance_path=guidance, paths=paths)
    assert shlex.split(command) == list(argv)
    # Compare the actual script diagnostic with the independent host validator.
    host = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    assert host.returncode == 1
    assert host.stderr.startswith("INVALID:")
    _, audit = _write_command_binding(
        tmp_path, session_id="real-validator", required_commands=(command,),
        bash_command_match_mode="bound_python_script",
    )
    _run_hook(tmp_path, r'''
import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import { pathToFileURL } from "node:url"
const plugin = await import(pathToFileURL(process.argv[1]).href)
const hooks = await plugin.OpenDeepHoleFileWriteHook({ directory: process.cwd() })
const data = JSON.parse(process.argv[2])
const args = { command: data.requested }
const input = { sessionID: "real-validator", tool: "bash", callID: "validate" }
await hooks["tool.execute.before"](input, { args })
assert.equal(args.command, data.command)
const result = spawnSync(args.command, { shell: true, encoding: "utf8" })
assert.equal(result.status, 1)
assert.equal(result.stderr, data.diagnostic)
await hooks["tool.execute.after"]({ ...input, args }, {
  metadata: { exitCode: result.status }, output: result.stderr,
})
''', {
        "command": command, "diagnostic": host.stderr,
        "requested": 'python3 "' + argv[1] + '" --value-assets "/another-task.json"',
    })
    event = json.loads(audit.read_text())
    assert event["command"] == command
    assert event["exit_code"] == 1
    assert event["success"] is False
    assert event["output_tail"] == host.stderr


@pytest.mark.parametrize(("mode", "commands", "error"), [
    ("contains_python", ("python /validator.py",), "bash_command_match_mode"),
    ("bound_python_script", (), "requires bound bash commands"),
    ("bound_python_script", ("python validator.py",), "absolute Python script path"),
    ("bound_python_script", ("echo python /validator.py",), "direct literal Python"),
    ("bound_python_script", ('python -c "print(1)"',), "absolute Python script path"),
    ("bound_python_script", ("python /validator.py && echo injected",), "direct literal Python"),
    ("bound_python_script", ("python /validator.py --a", "python /validator.py --b"), "multiple commands"),
])
def test_invalid_script_binding_is_rejected_before_task_submission(
    tmp_path: Path, mode: str, commands: tuple[str, ...], error: str,
) -> None:
    with pytest.raises(ValueError, match=error):
        asyncio.run(run_opencode_task(
            task_name="invalid binding", task_type="threat_analysis", prompt="test",
            required_capability="high", allowed_bash_commands=commands,
            bash_command_match_mode=mode,
        ))
    service = OpenCodeTaskService()
    with pytest.raises(ValueError, match=error):
        service._normalize_spec(OpenCodeTaskSpec(
            task_name="invalid binding", prompt="test", directory=tmp_path,
            allowed_bash_commands=commands, bash_command_match_mode=mode,
        ))
