from __future__ import annotations

import importlib
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

from deephole_client.threat_analysis.runtime import (
    load_threat_analysis_method_package,
    resolve_threat_analysis_method,
)


METHOD_ID = "codex_goal_threat_analysis"


def _implementation() -> ModuleType:
    manifest = resolve_threat_analysis_method(METHOD_ID)
    load_threat_analysis_method_package(manifest)
    return importlib.import_module("threat_analysis_harness.threat_analysis")


def _valid_artifacts() -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    value_assets = [{
        "资产名": "认证服务",
        "资产类别": "服务资产",
        "资产描述": "处理外部用户身份认证",
        "攻击损失": "认证绕过导致未授权访问",
        "判断为价值资产的原因": "位于系统安全边界",
    }]
    high_risk_modules = [{
        "模块名称": "认证入口",
        "代码目录": "src/auth",
        "面临威胁": "凭据填充和认证绕过",
        "是否涉及设备或系统对外提供管理和控制接口相关的代码": "否",
        "是否涉及对不可信来源数据进行解析或处理的代码": "是",
        "是否涉及安全相关类代码(如，认证、授权、接入控制、加解密、密钥管理、日志审计、软件完整性保护等模块)": "是",
        "是否涉及个人数据或者敏感数据的代码": "是",
        "是否涉及web相关处理": "是",
        "是否外部暴露面": "是",
        "判断为高风险模块的原因": "直接处理外部凭据并作出认证决策",
    }]
    attack_trees = {
        "attack_trees": [{
            "tree_id": "tree-auth",
            "value_asset": {
                "asset_name": "认证服务",
                "asset_category": "服务资产",
                "asset_description": "处理外部用户身份认证",
                "attack_loss": "认证绕过导致未授权访问",
            },
            "nodes": [
                {
                    "node_id": "root",
                    "node_type": "根节点",
                    "node_name": "认证服务",
                    "description": "认证服务被绕过后会导致未授权访问",
                    "module_name": None,
                    "is_high_risk_module": False,
                    "external_exposure": False,
                    "external_interface_description": None,
                },
                {
                    "node_id": "leaf",
                    "node_type": "叶子节点",
                    "node_name": "认证入口",
                    "description": "构造输入触发认证缺陷",
                    "module_name": "认证入口",
                    "is_high_risk_module": True,
                    "external_exposure": True,
                    "external_interface_description": "HTTP 登录接口",
                },
            ],
            "edges": [{
                "edge_id": "edge-1",
                "source_node_id": "leaf",
                "target_node_id": "root",
                "influence_type": "直接影响",
                "description": "恶意认证请求直接影响认证结果",
            }],
            "attack_paths": [{
                "path_id": "path-1",
                "path_name": "外部认证绕过",
                "node_ids": ["leaf", "root"],
                "edge_ids": ["edge-1"],
                "path_description": "从登录接口到认证服务的攻击路径",
                "related_high_risk_modules": [{
                    "module_name": "认证入口",
                    "node_id": "leaf",
                    "external_exposure": True,
                    "path_role": "外部攻击入口",
                    "association_description": "负责接收不可信认证请求",
                }],
                "attack_patterns": [{
                    "pattern_id": "CAPEC-1",
                    "pattern_name": "访问功能未正确地约束访问控制列表",
                    "association_description": "外部认证入口的访问控制缺失会直接影响认证服务。",
                }],
            }],
        }],
    }
    return value_assets, high_risk_modules, attack_trees


def _write_valid_artifacts(root: Path) -> None:
    value_assets, high_risk_modules, attack_trees = _valid_artifacts()
    final = root / "final"
    final.mkdir(parents=True, exist_ok=True)
    for name, value in (
        ("value-assets.json", value_assets),
        ("high-risk-modules.json", high_risk_modules),
        ("attack-trees.json", attack_trees),
    ):
        (final / name).write_text(
            json.dumps(value, ensure_ascii=False),
            encoding="utf-8",
        )


def _run_artifact_validator(
    implementation: ModuleType,
    artifact_root: Path,
) -> subprocess.CompletedProcess[str]:
    method_root = Path(implementation.__file__).resolve().parent
    return subprocess.run(
        [
            sys.executable,
            str(method_root / "schema_validation.py"),
            "--value-assets",
            str(artifact_root / "final" / "value-assets.json"),
            "--high-risk-modules",
            str(artifact_root / "final" / "high-risk-modules.json"),
            "--attack-trees",
            str(artifact_root / "final" / "attack-trees.json"),
            "--references-root",
            str(method_root / "references"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_goal_prompt_is_short_and_uses_reference_paths(tmp_path: Path) -> None:
    implementation = _implementation()
    code_root = tmp_path / "source"
    artifact_root = tmp_path / "artifacts"
    code_root.mkdir()
    artifact_root.mkdir()
    paths = implementation._artifact_paths(artifact_root)
    guidance_path, schema_paths = implementation._reference_paths()

    prompt = implementation.build_goal_prompt(
        code_root=code_root,
        context_path=artifact_root / "scan-context.json",
        guidance_path=guidance_path,
        schema_paths=schema_paths,
        paths=paths,
    )

    assert len(prompt) < 4000
    assert str(guidance_path) in prompt
    assert all(str(path) in prompt for path in schema_paths.values())
    assert str(code_root) in prompt
    assert all(str(path) in prompt for path in paths.values())
    assert "deephole_threat_analysis" not in prompt
    assert str(artifact_root / "scan-context.json") in prompt
    assert str(guidance_path.parent / "attack_mode.json") in prompt
    assert "先识别项目架构、信任边界、外部入口" in prompt
    assert "三类产物必须保持来源一致" in prompt
    assert "内部节点只能是路径中的真实内部源码模块" in prompt
    assert "有足够适用模式时至少输出10个" in prompt
    assert "schema_validation.py" in prompt
    assert "--value-assets" in prompt
    assert "命令退出码为0才允许结束 Goal" in prompt
    assert "如果失败，必须根据错误修正产物并反复执行" in prompt


def test_analysis_guidance_and_schemas_are_private_json_files() -> None:
    implementation = _implementation()
    guidance_path, schema_paths = implementation._reference_paths()
    references_root = Path(implementation.__file__).resolve().parent / "references"

    assert guidance_path.parent == references_root
    attack_mode_path = references_root / "attack_mode.json"
    assert attack_mode_path.is_file()
    assert set(schema_paths) == {
        "value_asset_path",
        "high_risk_modules_path",
        "attack_tree_path",
    }
    guidance = json.loads(guidance_path.read_text(encoding="utf-8"))
    assert [step["step"] for step in guidance["workflow"]] == [
        "project_reconnaissance",
        "value_assets",
        "high_risk_modules",
        "attack_trees",
    ]
    assert len(guidance["outputs"]) == 3
    assert guidance["cross_artifact_invariants"]
    assert guidance["attack_tree_method"]["internal_node"]
    assert guidance["attack_tree_method"]["attack_pattern_matching"]
    assert guidance["completion_checks"]
    attack_modes = json.loads(attack_mode_path.read_text(encoding="utf-8"))
    assert len(attack_modes) > 1000
    assert all("攻击模式名称" in mode for mode in attack_modes)
    for schema_path in schema_paths.values():
        assert schema_path.parent == references_root
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_method_runs_one_goal_and_returns_schema_valid_artifacts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    implementation = _implementation()
    code_root = tmp_path / "source"
    artifact_root = tmp_path / "artifacts"
    (code_root / "src" / "auth").mkdir(parents=True)
    calls: list[dict[str, Any]] = []

    def fake_run_goal(**kwargs: Any) -> str:
        calls.append(kwargs)
        _write_valid_artifacts(kwargs["artifact_root"])
        return "complete"

    monkeypatch.setattr(implementation, "_run_goal", fake_run_goal)

    result = implementation.run_threat_analysis(
        code_root,
        artifact_root,
        product_mcp="product-knowledge",
        attack_modes={"network": True},
    )

    assert result["result"] is True
    assert len(calls) == 1
    assert len(calls[0]["prompt"]) < 4000
    context = json.loads(
        (artifact_root / "scan-context.json").read_text(encoding="utf-8")
    )
    assert context["source"] == {
        "root": str(code_root.resolve()),
        "access": "read_only",
    }
    assert context["optional_inputs"] == {
        "product_mcp": "product-knowledge",
        "attack_modes": {"network": True},
    }
    assert set(result) == {
        "result",
        "value_asset_path",
        "attack_tree_path",
        "high_risk_modules_path",
    }


def test_method_does_not_revalidate_goal_output_after_completion(
    tmp_path: Path,
    monkeypatch,
) -> None:
    implementation = _implementation()
    code_root = tmp_path / "source"
    artifact_root = tmp_path / "artifacts"
    code_root.mkdir()

    def fake_run_goal(**kwargs: Any) -> str:
        _write_valid_artifacts(kwargs["artifact_root"])
        value_path = kwargs["artifact_root"] / "final" / "value-assets.json"
        value_path.write_text('[{"资产名": "缺少其它字段"}]', encoding="utf-8")
        return "complete"

    monkeypatch.setattr(implementation, "_run_goal", fake_run_goal)

    result = implementation.run_threat_analysis(code_root, artifact_root)

    assert result["result"] is True


def test_goal_validator_command_accepts_valid_artifacts(tmp_path: Path) -> None:
    implementation = _implementation()
    _write_valid_artifacts(tmp_path)

    completed = _run_artifact_validator(implementation, tmp_path)

    assert completed.returncode == 0
    assert completed.stdout.startswith("VALID:")


def test_goal_validator_command_rejects_schema_error(tmp_path: Path) -> None:
    implementation = _implementation()
    _write_valid_artifacts(tmp_path)
    value_path = tmp_path / "final" / "value-assets.json"
    value_path.write_text('[{"资产名": "缺少其它字段"}]', encoding="utf-8")

    completed = _run_artifact_validator(implementation, tmp_path)

    assert completed.returncode == 1
    assert "missing required property" in completed.stderr


def test_goal_validator_rejects_root_name_that_differs_from_its_value_asset(
    tmp_path: Path,
) -> None:
    implementation = _implementation()
    _write_valid_artifacts(tmp_path)
    attack_tree_path = tmp_path / "final" / "attack-trees.json"
    attack_trees = json.loads(attack_tree_path.read_text(encoding="utf-8"))
    attack_trees["attack_trees"][0]["nodes"][0]["node_name"] = (
        "攻击价值资产：认证服务"
    )
    attack_tree_path.write_text(
        json.dumps(attack_trees, ensure_ascii=False),
        encoding="utf-8",
    )

    completed = _run_artifact_validator(implementation, tmp_path)

    assert completed.returncode == 1
    assert "must exactly equal value asset name" in completed.stderr


def test_goal_validator_rejects_leaf_that_is_not_the_external_module(
    tmp_path: Path,
) -> None:
    implementation = _implementation()
    _write_valid_artifacts(tmp_path)
    attack_tree_path = tmp_path / "final" / "attack-trees.json"
    attack_trees = json.loads(attack_tree_path.read_text(encoding="utf-8"))
    attack_trees["attack_trees"][0]["nodes"][1]["node_name"] = "恶意认证请求"
    attack_tree_path.write_text(
        json.dumps(attack_trees, ensure_ascii=False),
        encoding="utf-8",
    )

    completed = _run_artifact_validator(implementation, tmp_path)

    assert completed.returncode == 1
    assert "leaf node_name and module_name must be exactly identical" in completed.stderr


def test_goal_validator_allows_path_without_a_reasonable_attack_pattern(
    tmp_path: Path,
) -> None:
    implementation = _implementation()
    _write_valid_artifacts(tmp_path)
    attack_tree_path = tmp_path / "final" / "attack-trees.json"
    attack_trees = json.loads(attack_tree_path.read_text(encoding="utf-8"))
    attack_trees["attack_trees"][0]["attack_paths"][0]["attack_patterns"] = []
    attack_tree_path.write_text(
        json.dumps(attack_trees, ensure_ascii=False),
        encoding="utf-8",
    )

    completed = _run_artifact_validator(implementation, tmp_path)

    assert completed.returncode == 0


def test_goal_validator_allows_more_than_ten_applicable_attack_patterns(
    tmp_path: Path,
) -> None:
    implementation = _implementation()
    attack_mode_path = (
        Path(implementation.__file__).resolve().parent
        / "references"
        / "attack_mode.json"
    )
    attack_modes = json.loads(attack_mode_path.read_text(encoding="utf-8"))[:11]

    _write_valid_artifacts(tmp_path)
    attack_tree_path = tmp_path / "final" / "attack-trees.json"
    attack_trees = json.loads(attack_tree_path.read_text(encoding="utf-8"))
    attack_trees["attack_trees"][0]["attack_paths"][0]["attack_patterns"] = [
        {
            "pattern_id": "、".join(mode.get("攻击模式编号") or []),
            "pattern_name": mode["攻击模式名称"],
            "association_description": "候选攻击模式关联说明",
        }
        for mode in attack_modes
    ]
    attack_tree_path.write_text(
        json.dumps(attack_trees, ensure_ascii=False),
        encoding="utf-8",
    )

    completed = _run_artifact_validator(implementation, tmp_path)

    assert completed.returncode == 0


def test_goal_validator_rejects_attack_pattern_not_in_reference_library(
    tmp_path: Path,
) -> None:
    implementation = _implementation()
    _write_valid_artifacts(tmp_path)
    attack_tree_path = tmp_path / "final" / "attack-trees.json"
    attack_trees = json.loads(attack_tree_path.read_text(encoding="utf-8"))
    pattern = attack_trees["attack_trees"][0]["attack_paths"][0][
        "attack_patterns"
    ][0]
    pattern["pattern_id"] = "MADE-UP-1"
    attack_tree_path.write_text(
        json.dumps(attack_trees, ensure_ascii=False),
        encoding="utf-8",
    )

    completed = _run_artifact_validator(implementation, tmp_path)

    assert completed.returncode == 1
    assert "must exactly match attack_mode.json" in completed.stderr


def test_goal_uses_persisted_thread_and_workspace_write_sandbox(
    tmp_path: Path,
    monkeypatch,
) -> None:
    implementation = _implementation()
    captured: dict[str, Any] = {}
    from deephole_client import codex_runtime

    model = SimpleNamespace(
        id="codemate/threat-model",
        model_id="threat-model",
        profile="opendeephole-codemate-threat-model",
    )

    monkeypatch.setattr(
        codex_runtime,
        "get_codex_runtime_state",
        lambda: SimpleNamespace(
            available=True,
            command=("/opt/codex",),
            error="",
            models=(model,),
            model_config_error="",
        ),
    )

    class FakeController:
        def __init__(self, **kwargs: Any) -> None:
            captured["controller"] = kwargs
            self.thread_id = kwargs.get("thread_id") or "thread-new"

        def __enter__(self):
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def start_thread(self, **options: Any) -> str:
            captured["thread_options"] = options
            return self.thread_id

        def goal(self, prompt: str, *, model: str | None = None):
            captured["prompt"] = prompt
            captured["model"] = model
            return SimpleNamespace(goal=SimpleNamespace(status="complete"))

    fake_sdk = ModuleType("codex_sdk")
    fake_sdk.ApprovalMode = SimpleNamespace(deny_all="deny_all")
    fake_sdk.CodexConfig = lambda **kwargs: SimpleNamespace(**kwargs)
    fake_sdk.CodexController = FakeController
    fake_sdk.OutputMode = SimpleNamespace(HUMAN="human")
    fake_sdk.ResumePolicy = lambda **kwargs: SimpleNamespace(**kwargs)
    fake_sdk.Sandbox = SimpleNamespace(workspace_write="workspace-write")
    monkeypatch.setitem(sys.modules, "codex_sdk", fake_sdk)

    status = implementation._run_goal(
        prompt="analyze",
        artifact_root=tmp_path,
        is_resume=False,
    )

    assert status == "complete"
    codex_config = captured["controller"]["codex_config"]
    assert codex_config.cwd == str(tmp_path)
    assert codex_config.launch_args_override == (
        "/opt/codex",
        "--profile",
        "opendeephole-codemate-threat-model",
        "app-server",
        "--listen",
        "stdio://",
    )
    assert codex_config.env == {
        "CODEX_SQLITE_HOME": str(tmp_path / ".codex-state"),
    }
    assert (tmp_path / ".codex-state").is_dir()
    assert captured["thread_options"]["sandbox"] == "workspace-write"
    assert captured["thread_options"]["approval_mode"] == "deny_all"
    assert captured["thread_options"]["model"] == "codemate/threat-model"
    assert captured["model"] == "codemate/threat-model"
    assert captured["thread_options"]["config"] == {
        "sandbox_workspace_write": {
            "network_access": False,
            "writable_roots": [str(tmp_path)],
        }
    }
    assert json.loads(
        (tmp_path / "codex-goal-state.json").read_text(encoding="utf-8")
    ) == {
        "thread_id": "thread-new",
        "goal_status": "complete",
        "model_id": "codemate/threat-model",
        "profile": "opendeephole-codemate-threat-model",
        "validation_policy_version": 1,
    }
    assert "Codex managed model: codemate/threat-model" in (
        tmp_path / "codex-goal.log"
    ).read_text(encoding="utf-8")


def test_goal_requires_ready_managed_profile_and_proxy(
    tmp_path: Path,
    monkeypatch,
) -> None:
    implementation = _implementation()
    from deephole_client import codex_runtime

    monkeypatch.setattr(
        codex_runtime,
        "get_codex_runtime_state",
        lambda: SimpleNamespace(
            available=True,
            command=("codex",),
            error="",
            models=(),
            model_config_error="LLM proxy entrypoint is missing",
        ),
    )

    result = implementation.run_threat_analysis(
        tmp_path,
        tmp_path / "artifacts",
    )

    assert result["result"] is False
    assert "local LLM proxy" in result["reason"]
    assert "Bare Codex fallback is disabled" in result["reason"]
    assert "LLM proxy entrypoint is missing" in result["reason"]


def test_resume_keeps_saved_managed_model_profile(
    tmp_path: Path,
    monkeypatch,
) -> None:
    implementation = _implementation()
    captured: dict[str, Any] = {}
    from deephole_client import codex_runtime

    models = (
        SimpleNamespace(
            id="codemate/first",
            model_id="first",
            profile="profile-first",
        ),
        SimpleNamespace(
            id="codemate/saved",
            model_id="saved",
            profile="profile-saved",
        ),
    )
    monkeypatch.setattr(
        codex_runtime,
        "get_codex_runtime_state",
        lambda: SimpleNamespace(
            available=True,
            command=("codex",),
            error="",
            models=models,
            model_config_error="",
        ),
    )
    (tmp_path / "codex-goal-state.json").write_text(
        json.dumps({
            "thread_id": "thread-saved",
            "goal_status": "paused",
            "model_id": "codemate/saved",
            "profile": "profile-saved",
            "validation_policy_version": 1,
        }),
        encoding="utf-8",
    )

    class FakeController:
        def __init__(self, **kwargs: Any) -> None:
            captured["controller"] = kwargs
            self.thread_id = kwargs["thread_id"]

        def __enter__(self):
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def resume_thread(self, thread_id: str, **options: Any) -> str:
            captured["resumed"] = (thread_id, options)
            return thread_id

        def get_goal(self):
            return SimpleNamespace(status="paused")

        def resume_goal(self, *, model: str | None = None):
            captured["resume_goal"] = model
            return SimpleNamespace(goal=SimpleNamespace(status="complete"))

    fake_sdk = ModuleType("codex_sdk")
    fake_sdk.ApprovalMode = SimpleNamespace(deny_all="deny_all")
    fake_sdk.CodexConfig = lambda **kwargs: SimpleNamespace(**kwargs)
    fake_sdk.CodexController = FakeController
    fake_sdk.OutputMode = SimpleNamespace(HUMAN="human")
    fake_sdk.ResumePolicy = lambda **kwargs: SimpleNamespace(**kwargs)
    fake_sdk.Sandbox = SimpleNamespace(workspace_write="workspace-write")
    monkeypatch.setitem(sys.modules, "codex_sdk", fake_sdk)

    status = implementation._run_goal(
        prompt="continue",
        artifact_root=tmp_path,
        is_resume=True,
    )

    assert status == "complete"
    assert captured["resume_goal"] == "codemate/saved"
    assert captured["resumed"][1]["model"] == "codemate/saved"
    assert captured["controller"]["codex_config"].launch_args_override == (
        "codex",
        "--profile",
        "profile-saved",
        "app-server",
        "--listen",
        "stdio://",
    )


def test_transport_closed_reason_keeps_bounded_stderr_diagnostic() -> None:
    implementation = _implementation()

    class TransportClosedError(RuntimeError):
        pass

    result = implementation._safe_reason(
        TransportClosedError(
            "Codex process closed stdout.\n"
            "stderr_tail=failed to initialize sqlite state runtime"
        )
    )

    assert result == (
        "Codex Goal runtime closed unexpectedly: Codex process closed stdout. "
        "stderr_tail=failed to initialize sqlite state runtime"
    )


def test_type_error_reason_keeps_parameter_diagnostic() -> None:
    implementation = _implementation()

    result = implementation._safe_reason(
        TypeError(
            "controller.goal() got an unexpected keyword argument 'model'"
        )
    )

    assert result == (
        "Codex Goal type error: controller.goal() got an unexpected keyword "
        "argument 'model'"
    )
