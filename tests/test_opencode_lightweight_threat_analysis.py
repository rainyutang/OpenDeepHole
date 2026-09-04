from __future__ import annotations

import asyncio
import importlib
import json
import subprocess
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, patch

from deephole_client.codex_scan_config import codex_runtime_reference_root
from deephole_client.threat_analysis import lightweight_contract
from deephole_client.threat_analysis.lightweight_contract import (
    validation_command,
)
from deephole_client.threat_analysis.runtime import (
    load_threat_analysis_method_package,
    resolve_threat_analysis_method,
)


METHOD_ID = "opencode_lightweight_threat_analysis"


def _implementation(method_id: str = METHOD_ID) -> ModuleType:
    manifest = resolve_threat_analysis_method(method_id)
    load_threat_analysis_method_package(manifest)
    return importlib.import_module("threat_analysis_harness.threat_analysis")


def _write_dummy_artifacts(paths: dict[str, Path]) -> None:
    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")


def test_codex_and_opencode_share_core_prompt_but_assign_validation_differently(
    tmp_path: Path,
) -> None:
    code_root = tmp_path / "source"
    artifact_root = tmp_path / "artifacts"
    code_root.mkdir()
    artifact_root.mkdir()
    context_path = artifact_root / "scan-context.json"

    codex = _implementation("codex_goal_threat_analysis")
    codex_paths = codex._artifact_paths(artifact_root)
    guidance_path, schema_paths = codex._reference_paths()
    codex_prompt = codex.build_goal_prompt(
        code_root=code_root,
        context_path=context_path,
        guidance_path=guidance_path,
        schema_paths=schema_paths,
        paths=codex_paths,
    )

    opencode = _implementation()
    opencode_paths = opencode._artifact_paths(artifact_root)
    opencode_prompt = opencode.build_task_prompt(
        code_root=code_root,
        context_path=context_path,
        guidance_path=guidance_path,
        schema_paths=schema_paths,
        paths=opencode_paths,
    )

    assert opencode_paths == codex_paths
    assert opencode_prompt != codex_prompt
    assert opencode_prompt.split("##完成条件:", 1)[0] == codex_prompt.split(
        "##完成条件:", 1
    )[0]
    assert "是否执行该命令不作为 Session 完成条件" in opencode_prompt
    assert "宿主会在本次回复结束后独立校验产物" in opencode_prompt
    assert "必须在本 Goal 内执行以下校验命令" in codex_prompt
    assert "命令退出码为0才允许结束 Goal" in codex_prompt
    assert "\npython " in opencode_prompt
    assert "\npython " in codex_prompt


def test_all_prompt_references_are_inside_the_agent_readable_root() -> None:
    reference_root = codex_runtime_reference_root().resolve()
    guidance_path, schema_paths = lightweight_contract.reference_paths()
    reference_paths = (
        guidance_path,
        guidance_path.parent / lightweight_contract.ATTACK_MODE_FILE,
        *schema_paths.values(),
        reference_root / "schema_validation.py",
    )

    assert {path.name for path in reference_paths} == {
        "analysis-guidance.json",
        "attack_mode.json",
        "value-assets.schema.json",
        "high-risk-modules.schema.json",
        "attack-trees.schema.json",
        "schema_validation.py",
    }
    for path in reference_paths:
        assert path.is_file()
        assert path.resolve().is_relative_to(reference_root)


def test_method_runs_one_task_with_read_only_references_and_exact_command(
    tmp_path: Path,
    monkeypatch,
) -> None:
    implementation = _implementation()
    code_root = tmp_path / "source"
    artifact_root = tmp_path / "artifacts"
    code_root.mkdir()
    calls: list[dict] = []

    async def fake_run_task(**kwargs):
        calls.append(kwargs)
        _write_dummy_artifacts(implementation._artifact_paths(artifact_root))
        return SimpleNamespace(
            session_id="ses-opencode-lightweight",
            status="success",
            text="completed",
        )

    monkeypatch.setattr(implementation, "_run_task", fake_run_task)
    monkeypatch.setattr(implementation, "validate_artifacts_locally", lambda **_: None)

    result = implementation.run_threat_analysis(
        code_root,
        artifact_root,
        product_mcp="product-info",
        attack_modes={"protocol": True},
    )

    assert result["result"] is True
    assert len(calls) == 1
    guidance_path, _ = implementation._reference_paths()
    paths = implementation._artifact_paths(artifact_root)
    assert calls[0]["reference_root"] == codex_runtime_reference_root()
    assert calls[0]["guidance_path"] == guidance_path
    assert calls[0]["paths"] == paths
    assert calls[0]["validation_command_value"] == validation_command(
        guidance_path=guidance_path,
        paths=paths,
    )
    assert calls[0]["session_id"] is None
    context = json.loads(
        (artifact_root / "scan-context.json").read_text(encoding="utf-8")
    )
    assert context["source"] == {
        "root": str(code_root.resolve()),
        "access": "read_only",
    }
    assert context["optional_inputs"] == {
        "product_mcp": "product-info",
        "attack_modes": {"protocol": True},
    }
    state = json.loads(
        (artifact_root / "opencode-task-state.json").read_text(encoding="utf-8")
    )
    assert state["session_id"] == "ses-opencode-lightweight"
    assert state["status"] == "complete"


def test_task_adapter_allows_optional_command_and_uses_post_session_validator(
    tmp_path: Path,
) -> None:
    implementation = _implementation()
    runner = AsyncMock(return_value=SimpleNamespace(status="success"))
    reference_root = codex_runtime_reference_root()
    command = "python validate.py"
    guidance_path, _ = implementation._reference_paths()
    paths = implementation._artifact_paths(tmp_path)

    with (
        patch("task_agent.run_opencode_task", new=runner),
        patch.object(implementation, "validate_artifacts_locally") as validate,
    ):
        asyncio.run(implementation._run_task(
            prompt="strict shared prompt",
            reference_root=reference_root,
            validation_command_value=command,
            guidance_path=guidance_path,
            paths=paths,
            session_id="ses-existing",
        ))
        validator = runner.await_args.kwargs["post_session_validator"]
        assert validator() is None

    runner.assert_awaited_once()
    kwargs = dict(runner.await_args.kwargs)
    kwargs.pop("post_session_validator")
    assert kwargs == {
        "task_name": "opencode-lightweight-threat-analysis",
        "task_type": "threat_analysis",
        "prompt": "strict shared prompt",
        "required_capability": "high",
        "output_schema": None,
        "readable_paths": (reference_root,),
        "allowed_bash_commands": (command,),
        "post_session_validation_retry_count": 1,
        "session_id": "ses-existing",
    }
    validate.assert_called_once_with(guidance_path=guidance_path, paths=paths)


def test_windows_validation_command_uses_cmd_safe_double_quotes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    method_root = tmp_path / "method with spaces"
    method_root.mkdir()
    (method_root / "schema_validation.py").write_text("", encoding="utf-8")
    guidance_path = method_root / "references" / "guidance with spaces.md"
    guidance_path.parent.mkdir()
    paths = {
        "value_asset_path": tmp_path / "output with spaces" / "value-assets.json",
        "high_risk_modules_path": tmp_path / "output with spaces" / "high-risk.json",
        "attack_tree_path": tmp_path / "output with spaces" / "attack-trees.json",
    }
    monkeypatch.setattr(lightweight_contract, "reference_root", lambda: method_root)
    monkeypatch.setattr(lightweight_contract.sys, "platform", "win32")
    monkeypatch.setattr(
        lightweight_contract.sys,
        "executable",
        r"C:\Program Files\Python\python.exe",
    )

    command = validation_command(guidance_path=guidance_path, paths=paths)

    assert command.startswith('python "')
    assert r"C:\Program Files\Python\python.exe" not in command
    assert "'" not in command
    assert f'"{method_root / "schema_validation.py"}"' in command
    assert f'"{paths["value_asset_path"]}"' in command


def test_local_validation_executes_an_argv_without_a_shell(
    tmp_path: Path,
    monkeypatch,
) -> None:
    method_root = tmp_path / "method"
    method_root.mkdir()
    (method_root / "schema_validation.py").write_text("", encoding="utf-8")
    guidance_path = method_root / "references" / "guidance.md"
    paths = {
        "value_asset_path": tmp_path / "value-assets.json",
        "high_risk_modules_path": tmp_path / "high-risk.json",
        "attack_tree_path": tmp_path / "attack-trees.json",
    }
    calls: list[tuple[str, ...]] = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        assert kwargs == {
            "check": False,
            "capture_output": True,
            "text": True,
        }
        return subprocess.CompletedProcess(argv, 0, "valid\n", "")

    monkeypatch.setattr(lightweight_contract, "reference_root", lambda: method_root)
    monkeypatch.setattr(lightweight_contract.subprocess, "run", fake_run)

    lightweight_contract.validate_artifacts_locally(
        guidance_path=guidance_path,
        paths=paths,
    )

    assert len(calls) == 1
    assert isinstance(calls[0], tuple)
    assert calls[0][0] == lightweight_contract.sys.executable


def test_post_session_validation_feedback_returns_diagnostics(
    tmp_path: Path,
) -> None:
    implementation = _implementation()
    guidance_path, _ = implementation._reference_paths()
    paths = implementation._artifact_paths(tmp_path)

    with patch.object(
        implementation,
        "validate_artifacts_locally",
        side_effect=ValueError("invalid\nattack tree"),
    ):
        assert implementation._artifact_validation_feedback(
            guidance_path=guidance_path,
            paths=paths,
        ) == "invalid attack tree"


def test_resume_reuses_valid_completed_outputs_without_new_task(
    tmp_path: Path,
    monkeypatch,
) -> None:
    implementation = _implementation()
    code_root = tmp_path / "source"
    artifact_root = tmp_path / "artifacts"
    code_root.mkdir()
    paths = implementation._artifact_paths(artifact_root)
    _write_dummy_artifacts(paths)
    (artifact_root / "opencode-task-state.json").write_text(
        json.dumps({
            "session_id": "ses-complete",
            "status": "complete",
            "validation_policy_version": 1,
        }),
        encoding="utf-8",
    )
    runner = AsyncMock()
    monkeypatch.setattr(implementation, "_run_task", runner)
    monkeypatch.setattr(implementation, "validate_artifacts_locally", lambda **_: None)

    result = implementation.run_threat_analysis(
        code_root,
        artifact_root,
        is_resume=True,
    )

    assert result["result"] is True
    runner.assert_not_awaited()


def test_failed_task_persists_session_for_diagnostics(
    tmp_path: Path,
    monkeypatch,
) -> None:
    implementation = _implementation()
    code_root = tmp_path / "source"
    artifact_root = tmp_path / "artifacts"
    code_root.mkdir()

    async def fake_run_task(**_kwargs):
        return SimpleNamespace(
            session_id="ses-failed",
            status="failure",
            text="validation command missing after retries",
        )

    monkeypatch.setattr(implementation, "_run_task", fake_run_task)

    result = implementation.run_threat_analysis(code_root, artifact_root)

    assert result == {
        "result": False,
        "reason": "validation command missing after retries",
    }
    state = json.loads(
        (artifact_root / "opencode-task-state.json").read_text(encoding="utf-8")
    )
    assert state["session_id"] == "ses-failed"
    assert state["status"] == "failure"


def test_resume_after_failure_starts_fresh_session_and_clears_partial_outputs(
    tmp_path: Path,
    monkeypatch,
) -> None:
    implementation = _implementation()
    code_root = tmp_path / "source"
    artifact_root = tmp_path / "artifacts"
    code_root.mkdir()
    paths = implementation._artifact_paths(artifact_root)
    _write_dummy_artifacts(paths)
    (artifact_root / "opencode-task-state.json").write_text(
        json.dumps({
            "session_id": "ses-failed",
            "status": "failure",
            "validation_policy_version": 1,
        }),
        encoding="utf-8",
    )
    calls: list[dict] = []

    async def fake_run_task(**kwargs):
        calls.append(kwargs)
        assert all(not path.exists() for path in paths.values())
        _write_dummy_artifacts(paths)
        return SimpleNamespace(
            session_id="ses-fresh",
            status="success",
            text="completed",
        )

    monkeypatch.setattr(implementation, "_run_task", fake_run_task)
    monkeypatch.setattr(
        implementation,
        "validate_artifacts_locally",
        lambda **_: None,
    )

    result = implementation.run_threat_analysis(
        code_root,
        artifact_root,
        is_resume=True,
    )

    assert result["result"] is True
    assert len(calls) == 1
    assert calls[0]["session_id"] is None
