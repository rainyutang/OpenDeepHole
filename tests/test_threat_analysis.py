from __future__ import annotations

import asyncio
import json
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

import deephole_client.threat_analysis_runner as threat_analysis_runner
from backend.models import ScanItemStatus, ScanMeta, ScanStatus, ThreatAuditTask
from backend.store.sqlite import SqliteScanStore
from backend.threat_data import parse_threat_analysis_data
from deephole_client.process_artifacts import collect_json_artifacts
from deephole_client.threat_analysis_runner import run_threat_analysis
from deephole_client.vulnerability_mining.engines.threat_audit.engine import (
    _legacy_non_leaf_tasks,
    _supersede_legacy_non_leaf_tasks,
)
from deephole_client.vulnerability_mining.engines.threat_audit.runner import (
    _tasks,
    _threat_prompt,
    run_threat_audit,
)
from task_agent import (
    OpenCodeResult,
    opencode_task_context,
    run_opencode_task,
    run_sync_component,
)
from task_agent.task_service import get_opencode_execution_context


def _artifact_bundle() -> dict:
    return {
        "entrypoint_result": {
            "result": True,
            "value_asset_path": "final/value-assets.json",
            "attack_tree_path": "final/attack-trees.json",
            "high_risk_modules_path": "final/high-risk-modules.json",
        },
        "artifacts": {
            "value_asset_path": {
                "path": "final/value-assets.json",
                "content": [{"资产名": "凭据"}],
            },
            "attack_tree_path": {
                "path": "final/attack-trees.json",
                "content": {"attack_trees": []},
            },
            "high_risk_modules_path": {
                "path": "final/high-risk-modules.json",
                "content": [],
            },
        },
    }


def _scan(scan_id: str) -> tuple[ScanStatus, ScanMeta]:
    scan = ScanStatus(
        scan_id=scan_id,
        project_id="project",
        scan_items=["npd"],
        created_at="2026-01-01T00:00:00+00:00",
        status=ScanItemStatus.COMPLETE,
        progress=1.0,
        total_candidates=0,
        processed_candidates=0,
        vulnerabilities=[],
    )
    meta = ScanMeta(
        scan_items=["npd"],
        created_at=scan.created_at,
        project_path="/tmp/project",
        scan_name="project",
        user_id="user-1",
    )
    return scan, meta


def test_builtin_method_contains_native_files_and_private_skills() -> None:
    root = (
        Path(__file__).resolve().parents[1]
        / "deephole_client"
        / "threat_analysis"
        / "methods"
        / "deephole_threat_analysis"
    )
    expected = {
        "__init__.py",
        "method.yaml",
        "artifacts.py",
        "errors.py",
        "main.py",
        "output_validation.py",
        "pipeline.py",
        "schemas.py",
        "skills/attack-trees/attack-tree-by-asset/SKILL.md",
        (
            "skills/attack-trees/attack-tree-by-asset/references/"
            "attack_mode.json"
        ),
        "skills/high-risk-modules/high-risk-module-map/SKILL.md",
        "skills/high-risk-modules/high-risk-module-merge/SKILL.md",
        "skills/value-assets/value-asset-map/SKILL.md",
        "stages/__init__.py",
        "stages/attack_trees.py",
        "stages/base.py",
        "stages/high_risk_modules.py",
        "stages/value_assets.py",
        "task_agent_submitter.py",
        "threat_analysis.py",
    }
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }

    assert actual == expected


def test_adapter_loads_selected_method_under_native_package_name() -> None:
    module = threat_analysis_runner._load_implementation()
    expected = (
        Path(__file__).resolve().parents[1]
        / "deephole_client"
        / "threat_analysis"
        / "methods"
        / "deephole_threat_analysis"
        / "__init__.py"
    )

    assert Path(module.__file__).resolve() == expected
    assert callable(module.run_threat_analysis)


@pytest.mark.parametrize("use_standalone_config", [False, True])
def test_async_facade_calls_sync_native_entry_and_preserves_native_result(
    tmp_path: Path,
    use_standalone_config: bool,
) -> None:
    project = tmp_path / "project"
    output_path = tmp_path / "output"
    project.mkdir()
    events: list[dict] = []
    captured: dict = {}
    native_result = {
        "result": True,
        "value_asset_path": str(output_path / "value-assets.json"),
        "attack_tree_path": str(output_path / "attack-trees.json"),
        "high_risk_modules_path": str(output_path / "high-risk-modules.json"),
    }

    def native_entry(**kwargs):
        context = get_opencode_execution_context()
        captured.update({
            "kwargs": kwargs,
            "project_dir": context.project_dir,
            "work_dir": context.work_dir,
            "config_path": context.config_path,
            "skill_paths": context.skill_paths,
        })
        return native_result

    async def scenario() -> dict:
        task_agent_config = (
            tmp_path / "task-agent.yaml"
            if use_standalone_config
            else None
        )
        with patch(
            "deephole_client.threat_analysis_runner._load_implementation",
            return_value=SimpleNamespace(run_threat_analysis=native_entry),
        ):
            return await run_threat_analysis(
                code_path=project,
                output_path=output_path,
                is_resume=True,
                product_mcp="product-info",
                attack_modes={"network": True},
                task_agent_config=task_agent_config,
                output=events.append,
            )

    result = asyncio.run(scenario())

    assert result is native_result
    assert captured["kwargs"] == {
        "code_path": project.resolve(),
        "output_path": output_path.resolve(),
        "is_resume": True,
        "product_mcp": "product-info",
        "attack_modes": {"network": True},
    }
    assert captured["project_dir"] == project.resolve()
    assert captured["work_dir"] == output_path.resolve()
    assert captured["config_path"] == (
        (tmp_path / "task-agent.yaml").resolve()
        if use_standalone_config
        else None
    )
    assert {
        path.name for path in captured["skill_paths"]
    } == {"attack-trees", "high-risk-modules", "value-assets"}
    assert events[0]["process"] == "threat_analysis"
    assert events[-1]["kind"] == "artifact"


def test_async_facade_scopes_opencode_to_scan_path_and_rebases_module_paths(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scan_path = project / "services" / "api"
    output_path = tmp_path / "output"
    outer_work_path = tmp_path / "outer-work"
    scan_path.mkdir(parents=True)
    outer_work_path.mkdir()
    (scan_path / "src" / "auth").mkdir(parents=True)
    (scan_path / "absolute.py").touch()
    raw_modules = [
        {
            "模块名称": "认证模块",
            "代码目录": "src/auth",
            "面临威胁": "认证绕过",
        },
        {
            "模块名称": "解析模块",
            "代码目录": [
                "services/api/src/already-project-relative",
                str(scan_path / "absolute.py"),
                r"lib\parser",
            ],
            "面临威胁": "恶意输入",
        },
    ]
    captured: dict[str, Any] = {
        "outer_project_dirs": [],
        "project_dirs": [],
        "native_calls": [],
    }

    async def fake_local(**kwargs):
        context = get_opencode_execution_context()
        captured["project_dirs"].append(context.project_dir)
        return OpenCodeResult(
            session_id="session-scan-path",
            status="success",
            text="[]",
            structured=[],
            model="test/model",
        )

    def native_entry(**kwargs):
        captured["native_calls"].append(kwargs)
        asyncio.run(run_opencode_task(
            task_name="native-scan-scope",
            task_type="threat_analysis",
            prompt="inspect scan scope",
            required_capability="high",
        ))
        output_path.mkdir(parents=True, exist_ok=True)
        value_asset_path = output_path / "value-assets.json"
        attack_tree_path = output_path / "attack-trees.json"
        high_risk_modules_path = output_path / "native-high-risk-modules.json"
        value_asset_path.write_text("[]", encoding="utf-8")
        attack_tree_path.write_text(
            '{"attack_trees": []}',
            encoding="utf-8",
        )
        high_risk_modules_path.write_text(
            json.dumps(raw_modules, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return {
            "result": True,
            "value_asset_path": str(value_asset_path),
            "attack_tree_path": str(attack_tree_path),
            "high_risk_modules_path": str(high_risk_modules_path),
            "native_marker": "preserved",
        }

    async def scenario() -> tuple[dict, dict]:
        with opencode_task_context(
            project_dir=project,
            work_dir=outer_work_path,
        ):
            with (
                patch(
                    "deephole_client.threat_analysis_runner._load_implementation",
                    return_value=SimpleNamespace(
                        run_threat_analysis=native_entry,
                    ),
                ),
                patch("task_agent.api._run_opencode_task_local", new=fake_local),
            ):
                first = await run_threat_analysis(
                    project_path=project,
                    code_path=scan_path,
                    output_path=output_path,
                )
                captured["outer_project_dirs"].append(
                    get_opencode_execution_context().project_dir
                )
                second = await run_threat_analysis(
                    project_path=project,
                    code_path=scan_path,
                    output_path=output_path,
                    is_resume=True,
                )
                captured["outer_project_dirs"].append(
                    get_opencode_execution_context().project_dir
                )
        return first, second

    first, second = asyncio.run(scenario())

    expected_platform_path = (
        output_path / "platform" / "high-risk-modules.json"
    ).resolve()
    expected_modules = [
        {
            **raw_modules[0],
            "代码目录": "services/api/src/auth",
        },
        {
            **raw_modules[1],
            "代码目录": [
                "services/api/src/already-project-relative",
                "services/api/absolute.py",
                "services/api/lib/parser",
            ],
        },
    ]
    assert Path(first["high_risk_modules_path"]) == expected_platform_path
    assert Path(second["high_risk_modules_path"]) == expected_platform_path
    assert first["native_marker"] == "preserved"
    artifact_bundle = collect_json_artifacts(first, output_root=output_path)
    assert artifact_bundle["artifacts"]["high_risk_modules_path"]["content"] == (
        expected_modules
    )
    assert json.loads(expected_platform_path.read_text(encoding="utf-8")) == (
        expected_modules
    )
    assert json.loads(
        (output_path / "native-high-risk-modules.json").read_text(
            encoding="utf-8",
        )
    ) == raw_modules
    assert captured["outer_project_dirs"] == [
        project.resolve(),
        project.resolve(),
    ]
    assert captured["project_dirs"] == [scan_path.resolve(), scan_path.resolve()]
    assert [call["code_path"] for call in captured["native_calls"]] == [
        scan_path.resolve(),
        scan_path.resolve(),
    ]
    assert [call["is_resume"] for call in captured["native_calls"]] == [
        False,
        True,
    ]


@pytest.mark.parametrize("module_path", ["../outside", 1])
def test_module_path_normalization_rejects_invalid_values(
    tmp_path: Path,
    module_path: Any,
) -> None:
    project = (tmp_path / "project").resolve()
    scan_path = (project / "scan").resolve()
    scan_path.mkdir(parents=True)

    with pytest.raises((TypeError, ValueError)):
        threat_analysis_runner._normalize_module_code_paths(
            module_path,
            project_path=project,
            code_path=scan_path,
        )


def test_module_path_normalization_rejects_absolute_path_outside_scan(
    tmp_path: Path,
) -> None:
    project = (tmp_path / "project").resolve()
    scan_path = (project / "scan").resolve()
    outside_path = (project / "outside" / "module.py").resolve()
    scan_path.mkdir(parents=True)

    with pytest.raises(ValueError, match="escapes code_path"):
        threat_analysis_runner._normalize_module_code_paths(
            str(outside_path),
            project_path=project,
            code_path=scan_path,
        )


def test_async_facade_rejects_code_path_outside_project(tmp_path: Path) -> None:
    project = tmp_path / "project"
    scan_path = tmp_path / "other"
    output_path = tmp_path / "output"
    project.mkdir()
    scan_path.mkdir()

    with pytest.raises(ValueError, match="code_path must be inside project_path"):
        asyncio.run(run_threat_analysis(
            project_path=project,
            code_path=scan_path,
            output_path=output_path,
        ))


def test_sync_component_can_call_async_task_agent_on_owner_loop() -> None:
    async def scenario() -> None:
        owner_loop = asyncio.get_running_loop()
        owner_thread = threading.get_ident()
        observed: dict = {}

        async def fake_local(**kwargs):
            observed["loop"] = asyncio.get_running_loop()
            observed["task_name"] = kwargs["task_name"]
            return OpenCodeResult(
                session_id="session-1",
                status="success",
                text="ok",
                structured=None,
                model="test/model",
            )

        def sync_entry() -> OpenCodeResult:
            observed["worker_thread"] = threading.get_ident()
            return asyncio.run(run_opencode_task(
                task_name="native-sync-task",
                task_type="threat_analysis",
                prompt="inspect",
                required_capability="high",
            ))

        with patch("task_agent.api._run_opencode_task_local", new=fake_local):
            result = await run_sync_component(sync_entry)

        assert result.status == "success"
        assert observed["loop"] is owner_loop
        assert observed["worker_thread"] != owner_thread
        assert observed["task_name"] == "native-sync-task"

    asyncio.run(scenario())


def test_collect_json_artifacts_keeps_native_result_and_loads_content(
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "output"
    output_root.mkdir()
    files = {
        "value_asset_path": ("value-assets.json", [{"资产名": "凭据"}]),
        "attack_tree_path": ("attack-trees.json", {"attack_trees": []}),
        "high_risk_modules_path": ("high-risk-modules.json", []),
    }
    native_result: dict = {"result": True}
    for key, (filename, content) in files.items():
        path = output_root / filename
        path.write_text(json.dumps(content, ensure_ascii=False), encoding="utf-8")
        native_result[key] = str(path)

    bundle = collect_json_artifacts(native_result, output_root=output_root)

    assert bundle["entrypoint_result"]["result"] is True
    assert bundle["entrypoint_result"]["value_asset_path"] == "value-assets.json"
    assert bundle["artifacts"]["value_asset_path"]["content"][0]["资产名"] == "凭据"


def test_collect_json_artifacts_rejects_output_root_escape(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    output_root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="escapes output root"):
        collect_json_artifacts(
            {"result": True, "attack_tree_path": str(outside)},
            output_root=output_root,
        )


def test_opaque_artifact_bundle_round_trips_without_schema_conversion() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = SqliteScanStore(Path(tmp) / "scan.db")
        store.save_scan(*_scan("scan-1"))
        bundle = _artifact_bundle()
        parsed = parse_threat_analysis_data(bundle)

        stored = store.replace_threat_analysis("scan-1", parsed)
        loaded = store.get_threat_analysis("scan-1")
        scan, _meta = store.load_scan("scan-1")  # type: ignore[misc]

        assert stored == bundle
        assert loaded == bundle
        assert scan.threat_analysis == bundle


def test_threat_audit_creates_one_task_for_each_leaf_pattern_pair() -> None:
    attack_tree_data = {
        "attack_trees": [{
            "tree_id": "TREE-1",
            "value_asset": {
                "asset_name": "管理权限",
                "asset_category": "服务资产",
                "asset_description": "系统管理和配置能力",
                "attack_loss": "攻击者可接管系统",
            },
            "nodes": [
                {
                    "node_id": "NODE-1",
                    "node_type": "叶子节点",
                    "node_name": "管理接口",
                    "description": "接收远程管理请求",
                    "module_name": "管理接口",
                    "is_high_risk_module": True,
                    "external_exposure": True,
                    "external_interface_description": "HTTPS 管理接口",
                },
                {
                    "node_id": "NODE-2",
                    "node_type": "内部节点",
                    "node_name": "认证模块",
                    "description": "验证管理凭据",
                    "module_name": "认证模块",
                    "is_high_risk_module": True,
                    "external_exposure": False,
                    "external_interface_description": None,
                },
                {
                    "node_id": "NODE-3",
                    "node_type": "根节点",
                    "node_name": "攻击价值资产：管理权限",
                    "description": "管理权限受到攻击",
                    "module_name": None,
                    "is_high_risk_module": False,
                    "external_exposure": False,
                    "external_interface_description": None,
                },
            ],
            "edges": [
                {
                    "edge_id": "EDGE-1",
                    "source_node_id": "NODE-1",
                    "target_node_id": "NODE-2",
                    "influence_type": "调用",
                    "description": "管理接口调用认证模块",
                },
                {
                    "edge_id": "EDGE-2",
                    "source_node_id": "NODE-2",
                    "target_node_id": "NODE-3",
                    "influence_type": "直接影响",
                    "description": "认证结果决定管理权限",
                },
            ],
            "attack_paths": [{
                "path_id": "PATH-1",
                "path_name": "绕过认证",
                "node_ids": ["NODE-1", "NODE-2", "NODE-3"],
                "edge_ids": ["EDGE-1", "EDGE-2"],
                "path_description": "从管理入口到权限资产",
                "related_high_risk_modules": [
                    {
                        "module_name": "管理接口",
                        "node_id": "NODE-1",
                        "external_exposure": True,
                        "path_role": "外部攻击入口",
                        "association_description": "外部输入入口",
                    },
                    {
                        "module_name": "认证模块",
                        "node_id": "NODE-2",
                        "external_exposure": False,
                        "path_role": "直接资产影响模块",
                        "association_description": "验证凭据",
                    },
                ],
                "attack_patterns": [
                    {
                        "pattern_id": "PATTERN-1",
                        "pattern_name": "弱口令",
                        "association_description": "猜测凭据",
                    },
                    {
                        "pattern_id": "PATTERN-2",
                        "pattern_name": "会话伪造",
                        "association_description": "伪造会话",
                    },
                ],
            }],
        }],
    }
    high_risk_modules = [
        {
            "模块名称": "管理接口",
            "代码目录": [" ./src/api/ ", "src\\common", "src/shared/"],
            "面临威胁": "未授权访问",
            "是否外部暴露面": "是",
            "判断为高风险模块的原因": "处理外部管理请求",
        },
        {
            "模块名称": "认证模块",
            "代码目录": ["src/auth", "src/shared"],
            "面临威胁": "认证绕过",
            "是否外部暴露面": "否",
            "判断为高风险模块的原因": "决定管理权限",
        },
    ]

    tasks = _tasks("scan-1", attack_tree_data, high_risk_modules)

    assert [
        (task["native_node_id"], task["method_node_id"])
        for task in tasks
    ] == [
        ("NODE-1", "PATTERN-1"),
        ("NODE-1", "PATTERN-2"),
    ]
    assert len({task["task_id"] for task in tasks}) == 2
    assert [path["path"] for path in tasks[0]["code_paths"]] == [
        "src/api",
        "src/common",
        "src/shared",
        "src/auth",
    ]
    assert [
        context["module_name"]
        for context in tasks[0]["code_path_contexts"]
    ] == ["管理接口", "管理接口", "管理接口", "认证模块"]
    assert all(task["attack_path_id"] == "PATH-1" for task in tasks)
    prompt = _threat_prompt(tasks[1])
    assert "- 攻击模式：会话伪造（PATTERN-2）" in prompt
    assert (
        "- 攻击路径：管理接口 -> 认证模块 -> 攻击价值资产：管理权限"
        in prompt
    )
    assert "- 管理接口 : src/api，处理外部管理请求" in prompt
    assert "- 认证模块 : src/auth，决定管理权限" in prompt
    assert "- 目标资产：管理权限，系统管理和配置能力" in prompt
    assert "HTTPS 管理接口" not in prompt
    assert "攻击者可接管系统" not in prompt
    assert "管理接口 --调用--> 认证模块" not in prompt
    assert "模式关联说明" not in prompt
    assert "模块关联说明" not in prompt
    assert "对外暴露面" not in prompt
    assert "只作为审计线索，不需要严格遵循" in prompt
    assert "外部输入或对外入口到漏洞触发点" in prompt
    assert tasks[1]["task_id"] not in prompt
    assert '"confirmed":' not in prompt


def test_threat_audit_temporarily_merges_duplicate_leaf_paths() -> None:
    nodes = [
        {
            "node_id": node_id,
            "node_type": node_type,
            "node_name": module_name,
            "description": f"{module_name}说明",
            "module_name": None if node_type == "根节点" else module_name,
            "is_high_risk_module": high_risk,
            "external_exposure": node_type == "叶子节点",
            "external_interface_description": None,
        }
        for node_id, module_name, node_type, high_risk in [
            ("NODE-A", "入口A", "叶子节点", True),
            ("NODE-B", "处理模块B", "内部节点", True),
            ("NODE-C", "普通内部模块C", "内部节点", False),
            ("NODE-R", "攻击价值资产：关键服务", "根节点", False),
        ]
    ]
    pattern = {
        "pattern_id": "PATTERN-SHARED",
        "pattern_name": "恶意输入",
        "association_description": "外部输入可到达处理模块",
    }

    def attack_path(
        path_id: str,
        internal_id: str,
        internal_name: str,
    ) -> dict:
        related = [{
            "module_name": "入口A",
            "node_id": "NODE-A",
            "external_exposure": True,
            "path_role": "外部攻击入口",
            "association_description": "入口A接收输入",
        }]
        if internal_id == "NODE-B":
            related.append({
                "module_name": internal_name,
                "node_id": internal_id,
                "external_exposure": False,
                "path_role": "直接资产影响模块",
                "association_description": "处理不可信数据",
            })
        return {
            "path_id": path_id,
            "path_name": f"经{internal_name}攻击关键服务",
            "node_ids": ["NODE-A", internal_id, "NODE-R"],
            "edge_ids": [],
            "path_description": f"入口A经{internal_name}到关键服务",
            "related_high_risk_modules": related,
            "attack_patterns": [pattern],
        }

    paths = [
        attack_path("PATH-B", "NODE-B", "处理模块B"),
        attack_path("PATH-C", "NODE-C", "普通内部模块C"),
    ]
    paths[1]["attack_patterns"].append({
        "pattern_id": "PATTERN-C",
        "pattern_name": "路径C专用攻击",
        "association_description": "仅与路径C关联",
    })
    attack_tree_data = {
        "attack_trees": [{
            "tree_id": "TREE-1",
            "value_asset": {
                "asset_name": "关键服务",
                "asset_description": "对外提供核心业务",
            },
            "nodes": nodes,
            "edges": [],
            "attack_paths": paths,
        }],
    }
    high_risk_modules = [
        {
            "模块名称": module_name,
            "代码目录": code_path,
            "面临威胁": "恶意输入",
            "是否外部暴露面": "是" if exposed else "否",
            "判断为高风险模块的原因": f"{module_name}风险",
        }
        for module_name, code_path, exposed in [
            ("入口A", ["src/entry", "src/shared/"], True),
            ("处理模块B", ["src/b", "src\\shared"], False),
        ]
    ]

    tasks = _tasks("scan-1", attack_tree_data, high_risk_modules)

    assert {
        (task["native_node_id"], task["method_node_id"])
        for task in tasks
    } == {
        ("NODE-A", "PATTERN-SHARED"),
        ("NODE-A", "PATTERN-C"),
    }
    shared = next(
        task
        for task in tasks
        if task["method_node_id"] == "PATTERN-SHARED"
    )
    assert [item["path_id"] for item in shared["attack_path_contexts"]] == [
        "PATH-B",
        "PATH-C",
    ]
    assert [item["path"] for item in shared["code_paths"]] == [
        "src/entry",
        "src/shared",
        "src/b",
    ]
    assert shared["legacy_multiple_paths"] is True
    assert shared["legacy_path_count"] == 2
    prompt = _threat_prompt(shared)
    assert "- 攻击路径：\n" in prompt
    assert (
        "- 入口A -> 处理模块B -> 攻击价值资产：关键服务" in prompt
    )
    assert (
        "- 入口A -> 普通内部模块C -> 攻击价值资产：关键服务" in prompt
    )
    assert "普通内部模块C :" not in prompt
    assert prompt.count("src/shared") == 1

    reversed_tasks = _tasks(
        "scan-1",
        {
            "attack_trees": [{
                **attack_tree_data["attack_trees"][0],
                "attack_paths": list(reversed(paths)),
            }],
        },
        high_risk_modules,
    )
    reversed_shared = next(
        task
        for task in reversed_tasks
        if task["method_node_id"] == "PATTERN-SHARED"
    )
    assert reversed_shared["task_id"] == shared["task_id"]
    assert (
        reversed_shared["attack_path_fingerprint"]
        == shared["attack_path_fingerprint"]
    )


def test_run_threat_audit_warns_once_for_legacy_duplicate_leaf_paths(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    attack_tree_path = tmp_path / "attack-trees.json"
    high_risk_modules_path = tmp_path / "high-risk-modules.json"
    attack_tree_path.write_text(json.dumps({
        "attack_trees": [{
            "tree_id": "TREE-LEGACY",
            "value_asset": {
                "asset_name": "关键服务",
                "asset_description": "核心业务能力",
            },
            "nodes": [
                {
                    "node_id": "LEAF",
                    "node_type": "叶子节点",
                    "node_name": "网络入口",
                    "module_name": "网络入口",
                    "is_high_risk_module": True,
                },
                {
                    "node_id": "INTERNAL-A",
                    "node_type": "内部节点",
                    "node_name": "处理器A",
                    "module_name": "处理器A",
                    "is_high_risk_module": False,
                },
                {
                    "node_id": "INTERNAL-B",
                    "node_type": "内部节点",
                    "node_name": "处理器B",
                    "module_name": "处理器B",
                    "is_high_risk_module": False,
                },
                {
                    "node_id": "ROOT",
                    "node_type": "根节点",
                    "node_name": "攻击价值资产：关键服务",
                    "module_name": None,
                    "is_high_risk_module": False,
                },
            ],
            "attack_paths": [
                {
                    "path_id": "PATH-A",
                    "path_name": "路径A",
                    "node_ids": ["LEAF", "INTERNAL-A", "ROOT"],
                    "related_high_risk_modules": [{
                        "node_id": "LEAF",
                        "module_name": "网络入口",
                    }],
                    "attack_patterns": [{
                        "pattern_id": "PATTERN-1",
                        "pattern_name": "恶意输入",
                    }],
                },
                {
                    "path_id": "PATH-B",
                    "path_name": "路径B",
                    "node_ids": ["LEAF", "INTERNAL-B", "ROOT"],
                    "related_high_risk_modules": [{
                        "node_id": "LEAF",
                        "module_name": "网络入口",
                    }],
                    "attack_patterns": [{
                        "pattern_id": "PATTERN-1",
                        "pattern_name": "恶意输入",
                    }],
                },
            ],
        }],
    }), encoding="utf-8")
    high_risk_modules_path.write_text(json.dumps([{
        "模块名称": "网络入口",
        "代码目录": "src/network",
        "面临威胁": "恶意输入",
    }]), encoding="utf-8")
    events: list[dict] = []

    with patch(
        "deephole_client.vulnerability_mining.engines.threat_audit.runner.run_opencode_task",
        return_value=SimpleNamespace(
            status="success",
            structured=[],
            text="[]",
            output_source={},
        ),
    ):
        result = asyncio.run(run_threat_audit(
            project_path=project,
            work_dir=tmp_path / "audit",
            scan_id="scan-legacy-paths",
            attack_tree_path=attack_tree_path,
            high_risk_modules_path=high_risk_modules_path,
            output=events.append,
        ))

    assert len(result["tasks"]) == 1
    warnings = [
        event
        for event in events
        if event["kind"] == "log" and event["message"].startswith("Warning:")
    ]
    assert len(warnings) == 1
    assert warnings[0]["data"] == {
        "surface_node_id": "TREE-LEGACY:LEAF",
        "path_count": 2,
    }


def test_legacy_non_leaf_tasks_are_superseded_without_touching_unknowns(
    tmp_path: Path,
) -> None:
    attack_tree_data = {
        "attack_trees": [{
            "tree_id": "TREE-1",
            "nodes": [
                {"node_id": "LEAF", "node_type": "叶子节点"},
                {"node_id": "INTERNAL", "node_type": "内部节点"},
                {"node_id": "ROOT", "node_type": "根节点"},
            ],
        }],
    }
    tasks = [
        ThreatAuditTask(
            task_id="legacy-internal",
            status="timeout",
            surface_node_id="TREE-1:INTERNAL",
        ),
        ThreatAuditTask(
            task_id="legacy-root",
            status="pending",
            surface_node_id="ROOT",
        ),
        ThreatAuditTask(
            task_id="current-leaf",
            status="timeout",
            surface_node_id="TREE-1:LEAF",
        ),
        ThreatAuditTask(
            task_id="completed-internal",
            status="completed",
            surface_node_id="TREE-1:INTERNAL",
        ),
        ThreatAuditTask(
            task_id="unknown-history",
            status="failed",
            surface_node_id="UNKNOWN",
        ),
    ]
    assert [
        task.task_id
        for task in _legacy_non_leaf_tasks(tasks, attack_tree_data)
    ] == ["legacy-internal", "legacy-root"]

    attack_tree_path = tmp_path / "attack-trees.json"
    attack_tree_path.write_text(
        json.dumps(attack_tree_data),
        encoding="utf-8",
    )
    pushed: list[ThreatAuditTask] = []
    events: list[dict] = []

    class Reporter:
        async def push_threat_audit_task(
            self,
            _scan_id: str,
            task: ThreatAuditTask,
        ) -> None:
            pushed.append(task)

    async def output(event: dict) -> None:
        events.append(event)

    reconciled = asyncio.run(_supersede_legacy_non_leaf_tasks(
        scan_id="scan-1",
        existing=tasks,
        attack_tree_path=attack_tree_path,
        reporter=Reporter(),
        output=output,
    ))

    assert [(task.task_id, task.status) for task in pushed] == [
        ("legacy-internal", "superseded"),
        ("legacy-root", "superseded"),
    ]
    assert {
        task.task_id: task.status
        for task in reconciled
    } == {
        "legacy-internal": "superseded",
        "legacy-root": "superseded",
        "current-leaf": "timeout",
        "completed-internal": "completed",
        "unknown-history": "failed",
    }
    assert events[0]["data"]["task_ids"] == [
        "legacy-internal",
        "legacy-root",
    ]


def test_threat_audit_task_storage_namespaces_nodes_by_tree(
    tmp_path: Path,
) -> None:
    def tree(tree_id: str, asset_name: str) -> dict:
        return {
            "tree_id": tree_id,
            "value_asset": {"asset_name": asset_name},
            "nodes": [{
                "node_id": "NODE-1",
                "node_type": "叶子节点",
                "node_name": "共享入口",
                "description": "接收外部输入",
                "module_name": "共享入口",
                "is_high_risk_module": True,
                "external_exposure": True,
                "external_interface_description": "网络接口",
            }],
            "edges": [],
            "attack_paths": [{
                "path_id": "PATH-1",
                "path_name": "共享路径",
                "node_ids": ["NODE-1"],
                "edge_ids": [],
                "path_description": "外部输入进入共享入口",
                "related_high_risk_modules": [{
                    "module_name": "共享入口",
                    "node_id": "NODE-1",
                    "external_exposure": True,
                    "path_role": "外部攻击入口",
                    "association_description": "接收外部输入",
                }],
                "attack_patterns": [{
                    "pattern_id": "PATTERN-1",
                    "pattern_name": "恶意输入",
                    "association_description": "输入可触发异常",
                }],
            }],
        }

    tasks = _tasks(
        "scan-1",
        {"attack_trees": [
            tree("TREE-A", "资产A"),
            tree("TREE-B", "资产B"),
        ]},
        [{
            "模块名称": "共享入口",
            "代码目录": "src/shared",
            "面临威胁": "恶意输入",
        }],
    )

    assert {task["surface_node_id"] for task in tasks} == {
        "TREE-A:NODE-1",
        "TREE-B:NODE-1",
    }
    store = SqliteScanStore(tmp_path / "scan.db")
    store.save_scan(*_scan("scan-1"))
    for task in tasks:
        store.upsert_threat_audit_task(
            "scan-1",
            ThreatAuditTask.model_validate(task),
        )
    assert len(store.list_threat_audit_tasks("scan-1")) == 2
