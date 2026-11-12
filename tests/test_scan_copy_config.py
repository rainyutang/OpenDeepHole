from fastapi import FastAPI
from types import SimpleNamespace
import asyncio
import httpx
import os
import pytest
import uuid
from backend import application
from backend.api import integration, scan as api, sharing
from backend.application import get_runtime
from backend.auth import get_current_user
from backend.models import (
    AgentMcpConfig,
    CreateScanRequest,
    MiningEngineSelection,
    MultiVersionTarget,
    ScanMeta,
    ScanStatus,
    ScanVulnerabilityValidationConfig,
    User,
)
from backend.store.sqlite import SqliteScanStore
"""Copy only saved, owner-private creation inputs into a new scan form."""


@pytest.fixture(params=["sqlite", "postgres"])
def env(request, tmp_path, monkeypatch):
    if request.param == "postgres":
        dsn = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN")
        if not dsn:
            pytest.skip("PostgreSQL test DSN not configured")
        from backend.store.postgres import PostgresScanStore
        store = PostgresScanStore(dsn, pool_min_size=1, pool_max_size=2)
    else:
        store = SqliteScanStore(tmp_path / "copy.db")
    owner_id = "copy-owner-" + uuid.uuid4().hex
    scan_id = "copy-" + uuid.uuid4().hex
    status = ScanStatus(
        scan_id=scan_id, project_id="original", status="complete", progress=1,
        total_candidates=0, processed_candidates=0, vulnerabilities=[],
    )
    meta = ScanMeta(
        scan_items=["historical-checker"], created_at="2026-11-09T00:00:00Z",
        user_id=owner_id, scan_name="Original name", product="Current product",
        execution_product="Original product", agent_key="stable-agent",
        agent_id="old-connection", agent_name="Original client",
        project_path="/project", code_scan_path="/project/src",
        code_scan_paths=["/project/src/a.c", "/project/src/lib"],
        scan_mode="custom", threat_analysis_enabled=True,
        threat_analysis_method="deephole_compact_threat_analysis",
        auto_fp_review=False, fp_review_method="adversarial",
        mining_engines=[
            MiningEngineSelection(engine_id="static_candidate", engine_label="Static"),
            MiningEngineSelection(engine_id="threat_pattern_audit", engine_label="Patterns", enabled=False),
        ],
        feedback_ids=["old-feedback"], public_access_token="private-scan-token",
        code_graph_mcp=AgentMcpConfig(enabled=True, name="custom-graph", transport="remote",
                                     remote={"url": "http://graph.test/mcp"}),
        knowledge_base_enabled=True,
        knowledge_base_mcp=AgentMcpConfig(enabled=True, name="knowledge",
                                        project_id="kb-id", project_name="Saved KB"),
        vulnerability_validation_enabled=True,
        vulnerability_validation=ScanVulnerabilityValidationConfig(
            method_id="validator", values={"host": "10.2.3.4", "port": 12, "tls": False},
        ),
    )
    store.save_scan(status, meta)
    note = store.create_review_note(owner_id, "Saved note", "Original content")
    store.set_scan_review_notes(scan_id, owner_id, True, [note["id"]])

    async def direct_call(target, operation, *args, **kwargs):
        return (getattr(target, operation) if isinstance(operation, str) else operation)(*args, **kwargs)

    monkeypatch.setattr(application, "default_store_factory", lambda: store)
    monkeypatch.setattr(application, "default_store_runner", direct_call)
    monkeypatch.setattr(get_runtime().scans, 'running_scans', {})
    monkeypatch.setattr(get_runtime().scans, 'scan_owners', {})

    def get(path=None, *, user_id=owner_id, role="user", authenticated=True, params=None):
        app = FastAPI()
        app.include_router(api.router)
        app.include_router(integration.router)
        app.include_router(sharing.router)
        if authenticated:
            async def current_user():
                return User(user_id=user_id, username="copy", role=role)
            app.dependency_overrides[get_current_user] = current_user

        async def run():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                return await client.get(path or f"/api/scan/{scan_id}/copy-config", params=params)
        return asyncio.run(run())

    yield SimpleNamespace(store=store, scan_id=scan_id, status=status, meta=meta,
                          owner_id=owner_id, note_id=note["id"], get=get)
    with store._lock:
        store._conn.execute("DELETE FROM scan_shares WHERE scan_id = ?", (scan_id,))
        store._conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        store._conn.execute("DELETE FROM review_notes WHERE user_id = ?", (owner_id,))
        store._conn.commit()
    store.close()


def test_copy_reads_all_saved_form_inputs_without_results_or_credentials(env):
    response = env.get()
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    payload = response.json()
    assert set(payload) == {
        "agent_key", "project_path", "code_scan_path", "code_scan_paths", "scan_name",
        "scan_mode", "product", "knowledge_base", "vulnerability_validation",
        "code_graph_mcp", "review_notes_enabled", "review_note_ids", "multi_versions",
        "threat_analysis_enabled", "threat_analysis_method", "mining_engines",
        "auto_fp_review", "fp_review_method",
    }
    assert payload["agent_key"] == "stable-agent"
    assert payload["scan_name"] == ""
    assert payload["product"] == "Current product"
    assert payload["project_path"] == "/project"
    assert payload["code_scan_paths"] == ["/project/src/a.c", "/project/src/lib"]
    assert payload["threat_analysis_enabled"] is True
    assert payload["threat_analysis_method"] == "deephole_compact_threat_analysis"
    assert payload["mining_engines"] == [{"engine_id": "static_candidate"}]
    assert payload["auto_fp_review"] is False
    assert payload["fp_review_method"] == "adversarial"
    assert payload["knowledge_base"] == {"enabled": True, "project_id": "kb-id", "project_name": "Saved KB"}
    assert payload["vulnerability_validation"] == {
        "enabled": True, "method_id": "validator", "values": {"host": "10.2.3.4", "port": 12, "tls": False},
    }
    assert payload["code_graph_mcp"] == env.meta.code_graph_mcp.model_dump(mode="json")
    assert payload["review_notes_enabled"] is True
    assert payload["review_note_ids"] == [env.note_id]
    assert "private-scan-token" not in response.text
    assert CreateScanRequest.model_validate(payload).scan_name == ""
    assert env.store.get_scan_meta(env.scan_id).scan_name == "Original name"
    assert env.store.load_scan(env.scan_id)[0].status == "complete"


def test_copy_uses_latest_saved_metadata_and_note_selection(env):
    env.store.update_scan_metadata(env.scan_id, product="Renamed product", scan_name="Renamed scan")
    env.store.set_scan_review_notes(env.scan_id, env.owner_id, False, [env.note_id])
    get_runtime().scans.running_scans[env.scan_id] = env.status
    payload = env.get().json()
    assert payload["product"] == "Renamed product"
    assert payload["scan_name"] == ""
    assert payload["review_notes_enabled"] is False
    assert payload["review_note_ids"] == [env.note_id]


def test_disabled_threat_analysis_preserves_an_empty_method(env):
    env.meta.threat_analysis_enabled = False
    env.meta.threat_analysis_method = ""
    env.meta.code_graph_mcp.enabled = False
    env.meta.code_scan_paths = []
    env.store.save_scan(env.status, env.meta)
    response = env.get()
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["threat_analysis_enabled"] is False
    assert payload["threat_analysis_method"] == ""
    assert payload["code_graph_mcp"]["enabled"] is False
    assert payload["code_graph_mcp"]["remote"]["url"] == "http://graph.test/mcp"
    assert payload["code_scan_paths"] == ["/project/src"]


@pytest.mark.parametrize("mode,expected", [
    ("standard", "standard"), ("quick", "quick"), ("full", "custom"),
    ("threat_analysis_only", "custom"),
])
def test_copy_modes_use_current_profiles_or_preserve_custom_inputs(env, mode, expected):
    env.meta.scan_mode = mode
    env.store.save_scan(env.status, env.meta)
    response = env.get()
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["scan_mode"] == expected
    if expected == "custom":
        assert payload["mining_engines"] == [{"engine_id": "static_candidate"}]
        assert payload["auto_fp_review"] is False
    else:
        assert all(payload[key] is None for key in (
            "mining_engines", "threat_analysis_enabled", "threat_analysis_method", "auto_fp_review", "fp_review_method",
        ))


def test_copy_preserves_multiversion_baseline_and_legacy_scope(env):
    env.meta.scan_mode = "multi_version"
    env.meta.multi_versions = [
        MultiVersionTarget(version_name="Baseline", project_path="C:\\base", code_scan_path="C:\\base\\src"),
        MultiVersionTarget(version_name="Comparison", project_path="C:\\next",
                           code_scan_paths=["C:\\next\\lib", "C:\\next\\one.c"]),
    ]
    env.meta.knowledge_base_enabled = False
    env.meta.knowledge_base_mcp = None
    env.meta.code_graph_mcp = None
    env.store.save_scan(env.status, env.meta)
    response = env.get()
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["scan_mode"] == "multi_version"
    assert [item["version_name"] for item in payload["multi_versions"]] == ["Baseline", "Comparison"]
    assert payload["multi_versions"][0]["code_scan_paths"] == ["C:\\base\\src"]
    assert payload["multi_versions"][1]["code_scan_paths"] == ["C:\\next\\lib", "C:\\next\\one.c"]
    assert payload["knowledge_base"]["enabled"] is False
    assert payload["code_graph_mcp"] is None


@pytest.mark.parametrize("changes,missing", [
    ({"agent_key": ""}, "客户端标识"),
    ({"project_path": ""}, "项目总路径"),
    ({"product": ""}, "产品"),
    ({"knowledge_base_mcp": None}, "知识库项目配置"),
    ({"vulnerability_validation": None}, "漏洞验证配置"),
    ({"scan_mode": "multi_version", "multi_versions": []}, "多版本配置"),
    ({"validation_environment": "old target"}, "旧版验证环境"),
    ({"scan_mode": "unknown"}, "模式"),
])
def test_incomplete_sources_do_not_silently_receive_defaults(env, changes, missing):
    env.meta = env.meta.model_copy(update=changes)
    env.store.save_scan(env.status, env.meta)
    response = env.get()
    assert response.status_code == 409, response.text
    assert missing in response.json()["detail"]


def test_copy_permissions_and_status_capability_are_owner_specific(env):
    assert env.get(authenticated=False).status_code == 401
    assert env.get(user_id="other").status_code == 403
    assert env.get(user_id="other", role="admin").status_code == 403
    assert env.get(role="admin").status_code == 200
    assert env.get("/api/scan/missing/copy-config").status_code == 404
    for path in (f"/api/scan/{env.scan_id}", f"/api/v2/scans/{env.scan_id}/overview"):
        assert env.get(path).json()["can_copy_scan"] is True
        assert env.get(path, user_id="other", role="admin").json()["can_copy_scan"] is False
        assert env.get(path).json()["can_copy_scan"] is True
    share = env.store.get_or_create_scan_share(env.scan_id)
    for prefix, token in (("public", env.meta.public_access_token), ("shared", share["token"])):
        path = f"/api/{prefix}/scans/{env.scan_id}"
        response = env.get(path + "/overview", authenticated=False, params={"token": token})
        assert response.status_code == 200, response.text
        assert response.json()["can_copy_scan"] is False
        assert env.get(path + "/copy-config", authenticated=False, params={"token": token}).status_code == 404
    response = env.get(f"/api/public/scans/{env.scan_id}", authenticated=False,
                       params={"token": env.meta.public_access_token})
    assert response.status_code == 200, response.text
    assert response.json()["can_copy_scan"] is False
