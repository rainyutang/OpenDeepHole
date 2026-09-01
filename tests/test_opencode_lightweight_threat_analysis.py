from __future__ import annotations

import asyncio
import importlib
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, patch

from deephole_client.codex_scan_config import codex_runtime_reference_root
from deephole_client.threat_analysis.lightweight_contract import validation_command
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


def test_codex_and_opencode_lightweight_methods_build_identical_prompt(
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
    assert opencode_prompt == codex_prompt


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


def test_task_adapter_calls_public_run_opencode_task_once() -> None:
    implementation = _implementation()
    runner = AsyncMock(return_value=SimpleNamespace(status="success"))
    reference_root = codex_runtime_reference_root()
    command = "python validate.py"

    with patch("task_agent.run_opencode_task", new=runner):
        asyncio.run(implementation._run_task(
            prompt="strict shared prompt",
            reference_root=reference_root,
            validation_command_value=command,
            session_id="ses-existing",
        ))

    runner.assert_awaited_once_with(
        task_name="opencode-lightweight-threat-analysis",
        task_type="threat_analysis",
        prompt="strict shared prompt",
        required_capability="high",
        output_schema=None,
        readable_paths=(reference_root,),
        required_bash_commands=(command,),
        session_id="ses-existing",
    )


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


def test_failed_task_persists_session_for_resume(
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
