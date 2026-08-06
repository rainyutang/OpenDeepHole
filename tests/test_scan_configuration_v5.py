import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from backend.api import agent as agent_api
from backend.api import scan as scan_api
from backend.models import (
    AgentMcpConfig,
    AgentMcpRemoteConfig,
    AgentRemoteConfig,
    AgentVulnerabilityValidationUpdate,
    AgentValidatorCatalog,
    AgentValidatorField,
    AgentValidatorMethod,
    ScanItemStatus,
    ScanKnowledgeBaseRequest,
    ScanMeta,
    ScanStatus,
    ScanVulnerabilityValidationRequest,
    UpdateScanValidationTargetRequest,
    User,
)
from backend.store.sqlite import SqliteScanStore
from deephole_client.vulnerability_mining.engines.static_candidate import (
    engine as static_candidate_engine,
)


def _catalog() -> AgentValidatorCatalog:
    return AgentValidatorCatalog(methods=[AgentValidatorMethod(
        method_id="demo",
        method_label="Demo 验证方法",
        description="Demo 验证方法",
        products=["LTE", "NR"],
        fields=[AgentValidatorField(
            key="target_ip",
            label="验证目标 IP",
            type="string",
            required=False,
            default="",
            help="留空时由验证方法自行发现目标",
        )],
    )])


def test_v4_migration_resets_only_old_validation_shape() -> None:
    config = AgentRemoteConfig.model_validate({
        "schema_version": 4,
        "vulnerability_mining": {
            "required_capability": "low",
            "timeout_seconds": 901,
            "max_retries": 7,
        },
        "vulnerability_validation": {
            "environments": {
                "lab": {
                    "concurrency": 8,
                    "methods": {"demo:LTE:lab": {"target_ip": "10.0.0.8"}},
                },
            },
        },
        "product_info": {
            "enabled": True,
            "transport": "remote",
            "remote": {"url": "http://old-product.test/mcp"},
        },
    })

    assert config.schema_version == 6
    assert config.vulnerability_mining.required_capability == "low"
    assert config.vulnerability_mining.timeout_seconds == 901
    assert config.vulnerability_mining.max_retries == 7
    assert config.vulnerability_validation.concurrency == 1
    assert config.vulnerability_validation.supported_vulnerability_types == ["*"]
    assert config.checker_selection.disabled_checkers == []
    assert "product_info" not in config.model_dump(mode="json")


def test_scan_validation_snapshots_global_policy_and_typed_method_values() -> None:
    global_config = AgentRemoteConfig().vulnerability_validation
    global_config.concurrency = 3
    global_config.validation_max_retries = 2
    resolved = scan_api._resolve_scan_validation(
        ScanVulnerabilityValidationRequest(
            enabled=True,
            method_id="demo",
            values={"target_ip": "10.0.0.8"},
        ),
        product="LTE",
        catalog=_catalog(),
        policy=global_config,
    )

    assert resolved is not None
    assert resolved.method_id == "demo"
    assert resolved.method_label == "Demo 验证方法"
    assert resolved.values == {"target_ip": "10.0.0.8"}
    assert resolved.policy.concurrency == 3
    global_config.concurrency = 9
    assert resolved.policy.concurrency == 3


def test_agent_validation_progress_preserves_method_snapshot() -> None:
    captured = None

    async def direct_store_call(_store, operation, *args, **_kwargs):
        nonlocal captured
        assert operation == "upsert_vulnerability_validation"
        captured = args[1]
        return captured

    async def scenario() -> None:
        with (
            patch.object(agent_api, "get_scan_store", return_value=object()),
            patch.object(agent_api, "run_store_call", side_effect=direct_store_call),
            patch.object(agent_api, "_ensure_running_scan", new=AsyncMock(return_value=None)),
            patch("backend.sse.publish"),
        ):
            await agent_api.agent_report_vulnerability_validation(
                "scan-1",
                AgentVulnerabilityValidationUpdate(
                    vuln_index=0,
                    status="running",
                    running=True,
                    product="LTE",
                    validation_method_id="demo",
                    validation_method_label="扫描时方法名称",
                ),
            )

    asyncio.run(scenario())
    assert captured is not None
    assert captured.validation_method_id == "demo"
    assert captured.validation_method_label == "扫描时方法名称"


def test_scan_validation_rejects_incompatible_method_and_unknown_field() -> None:
    with pytest.raises(HTTPException, match="没有适用于产品"):
        scan_api._resolve_scan_validation(
            ScanVulnerabilityValidationRequest(enabled=True, method_id="demo"),
            product="WiFi",
            catalog=_catalog(),
            policy=AgentRemoteConfig().vulnerability_validation,
        )
    with pytest.raises(HTTPException, match="未知字段"):
        scan_api._resolve_scan_validation(
            ScanVulnerabilityValidationRequest(
                enabled=True,
                method_id="demo",
                values={"legacy_environment": "lab"},
            ),
            product="LTE",
            catalog=_catalog(),
            policy=AgentRemoteConfig().vulnerability_validation,
        )


def test_checker_exclusion_policy_enables_new_checkers_by_default(monkeypatch) -> None:
    registry = {
        "builtin": SimpleNamespace(visibility="public"),
        "disabled": SimpleNamespace(visibility="public"),
        "new-user-checker": SimpleNamespace(visibility="public"),
        "admin-only": SimpleNamespace(visibility="admin"),
    }
    monkeypatch.setattr(scan_api, "refresh_registry", lambda: registry)
    config = AgentRemoteConfig(
        schema_version=6,
        checker_selection={"disabled_checkers": ["disabled"]},
    )

    assert scan_api._globally_enabled_checker_names(
        config,
        User(user_id="user-1", username="alice", role="user"),
    ) == ["builtin", "new-user-checker"]
    assert scan_api._globally_enabled_checker_names(
        config,
        User(user_id="admin", username="admin", role="admin"),
    ) == ["builtin", "new-user-checker", "admin-only"]


def test_static_candidate_with_all_checkers_disabled_is_a_noop(tmp_path: Path) -> None:
    reporter = SimpleNamespace(
        report_candidates=AsyncMock(),
        send_static_progress=AsyncMock(),
    )
    output = AsyncMock()
    result = asyncio.run(static_candidate_engine.run(
        project_path=tmp_path,
        code_scan_path=tmp_path,
        scan_dir=tmp_path,
        work_dir=tmp_path,
        index_db_path=tmp_path / "unused.db",
        scan_id="scan-empty-checkers",
        config=SimpleNamespace(),
        reporter=reporter,
        checker_names=[],
        checker_packages=[],
        product="",
        feedback_entries=[],
        is_resume=False,
        retry_candidates=None,
        retry_total_candidates=None,
        retry_processed_offset=0,
        output=output,
        cancel_event=SimpleNamespace(is_set=lambda: False),
        report_vulnerabilities=AsyncMock(),
    ))

    assert result == {
        "status": "success",
        "vulnerabilities": [],
        "total_candidates": 0,
        "processed_candidates": 0,
    }
    reporter.report_candidates.assert_awaited_once_with(
        "scan-empty-checkers",
        [],
    )
    reporter.send_static_progress.assert_awaited_once_with(
        "scan-empty-checkers",
        0,
        0,
        done=True,
    )


def test_scan_code_graph_accepts_only_mode_and_remote_connection_values() -> None:
    local = scan_api._scan_code_graph_mcp(AgentMcpConfig(
        enabled=True,
        name="caller-controlled",
        transport="local",
        timeout_seconds=17,
        local={
            "executable": "unsafe-custom-command",
            "args": ["--custom"],
            "environment": {"CUSTOM": "value"},
        },
    ))
    assert local is not None
    assert local.name == "codegraph"
    assert local.timeout_seconds == 300
    assert local.local.executable == "codegraph"
    assert local.local.args == ["serve", "--mcp"]
    assert "CUSTOM" not in local.local.environment

    remote = scan_api._scan_code_graph_mcp(AgentMcpConfig(
        enabled=True,
        name="caller-controlled",
        transport="remote",
        timeout_seconds=17,
        remote={
            "url": " http://graph.test/mcp ",
            "headers": {"Authorization": "Bearer graph-secret"},
        },
    ))
    assert remote is not None
    assert remote.name == "codegraph"
    assert remote.timeout_seconds == 300
    assert remote.remote.url == "http://graph.test/mcp"
    assert remote.remote.headers == {"Authorization": "Bearer graph-secret"}
    assert remote.local.executable == ""


def test_scan_private_snapshots_and_memory_round_trip(tmp_path: Path) -> None:
    store = SqliteScanStore(tmp_path / "scan.db")
    knowledge = scan_api._knowledge_base_mcp(ScanKnowledgeBaseRequest(
        enabled=True,
        url="http://knowledge.test/mcp",
        headers={"Authorization": "Bearer scan-secret"},
    ))
    validation = scan_api._resolve_scan_validation(
        ScanVulnerabilityValidationRequest(
            enabled=True,
            method_id="demo",
            values={"target_ip": "10.0.0.8"},
        ),
        product="LTE",
        catalog=_catalog(),
        policy=AgentRemoteConfig().vulnerability_validation,
    )
    scan = ScanStatus(
        scan_id="scan-a",
        project_id="project",
        product="LTE",
        knowledge_base_enabled=True,
        vulnerability_validation_enabled=True,
        validation_method_id="demo",
        validation_method_label="Demo 验证方法",
        status=ScanItemStatus.PENDING,
        progress=0,
        total_candidates=0,
        processed_candidates=0,
        vulnerabilities=[],
    )
    meta = ScanMeta(
        scan_items=[],
        created_at="2026-08-05T00:00:00+00:00",
        product="LTE",
        knowledge_base_enabled=True,
        vulnerability_validation_enabled=True,
        validation_method_id="demo",
        validation_method_label="Demo 验证方法",
        knowledge_base_mcp=knowledge,
        vulnerability_validation=validation,
    )

    store.save_scan(scan, meta)
    loaded_scan, loaded_meta = store.load_scan("scan-a")
    assert loaded_scan.knowledge_base_enabled is True
    assert loaded_scan.vulnerability_validation_enabled is True
    assert loaded_meta.knowledge_base_mcp == knowledge
    assert loaded_meta.vulnerability_validation == validation
    assert "knowledge_base_mcp" not in loaded_meta.model_dump()
    assert "vulnerability_validation" not in loaded_meta.model_dump()

    memory = {
        "knowledge_base": {
            "url": knowledge.remote.url,
            "headers": knowledge.remote.headers,
        },
        "validation_by_product": {
            "LTE": {
                "last_method_id": "demo",
                "values_by_method": {"demo": {"target_ip": "10.0.0.8"}},
            },
        },
    }
    store.upsert_scan_config_memory("user-1", "agent-a", memory)
    assert store.get_scan_config_memory("user-1", "agent-a") == memory
    assert store.get_scan_config_memory("user-2", "agent-a") is None
    assert store.get_scan_config_memory("user-1", "agent-b") is None


def test_scan_memory_never_leaks_through_public_models() -> None:
    config = AgentMcpConfig(
        enabled=True,
        name="product-info",
        transport="remote",
        remote=AgentMcpRemoteConfig(
            url="http://knowledge.test/mcp",
            headers={"Authorization": "Bearer secret"},
        ),
    )
    meta = ScanMeta(
        scan_items=[],
        created_at="now",
        knowledge_base_mcp=config,
    )
    dumped = meta.model_dump(mode="json")
    assert "knowledge_base_mcp" not in dumped
    assert "Bearer secret" not in str(dumped)


def test_legacy_validation_target_edit_is_read_only(monkeypatch) -> None:
    monkeypatch.setattr(scan_api, "_check_scan_owner", AsyncMock())

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(scan_api.update_scan_validation_target(
            "legacy-scan",
            UpdateScanValidationTargetRequest(
                product="LTE",
                validation_environment="lab",
            ),
            User(user_id="user-1", username="owner", role="user"),
        ))

    assert excinfo.value.status_code == 410
