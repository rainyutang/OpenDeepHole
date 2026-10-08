from __future__ import annotations

import asyncio
import copy
import os
import threading
import uuid
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI
from pydantic import ValidationError

from backend import auth, report_routes, sse
from backend.api import agent, integration, scan, sharing
from backend.file_inventory import FileInventoryUpload, ScanFileInventory
from backend.models import ScanItemStatus, ScanMeta, ScanStatus
from backend.store.sqlite import SqliteScanStore
from backend.threat_coverage import analysis_targets, build_threat_coverage
from deephole_client import file_inventory as collector, scanner
from deephole_client.config import AgentConfig
from deephole_client.codex_runtime import ScanCodexConfigResult
from deephole_client.reporter import Reporter
from deephole_client.vulnerability_mining.engines.threat_pattern_audit.engine import _build_targets


def inventory(**changes):
    return {
        "schema_version": 1, "snapshot_id": "snapshot-1", "status": "complete",
        "project_path": "/project", "scan_root": "/project/src",
        "captured_at": "2026-10-08T01:00:00+00:00",
        "entries": [{"path": ".", "kind": "directory"},
                    {"path": "auth", "kind": "directory"},
                    {"path": "auth/a.c", "kind": "file"},
                    {"path": "authentication.c", "kind": "file"},
                    {"path": "README", "kind": "file"}],
        "issues": [], "issue_count": 0, "excluded_paths": [], "error_message": "", **changes,
    }


def analysis():
    return {
        "entrypoint_result": {"result": True, "value_asset_path": "assets.json", "high_risk_modules_path": "risk.json", "attack_tree_path": "trees.json"},
        "artifacts": {
            "value_asset_path": {"path": "assets.json", "content": []},
            "high_risk_modules_path": {"path": "risk.json", "content": [
                {"模块名称": "认证", "代码目录": ["src/auth", "src/auth/a.c"]},
                {"模块名称": "其它", "代码目录": "src/authentication.c"},
            ]},
            "attack_tree_path": {"path": "trees.json", "content": {"attack_trees": [{
                "tree_id": "tree-1", "nodes": [{"node_id": "auth", "module_name": "认证", "is_high_risk_module": True}],
                "attack_paths": [{"path_id": "p1", "path_name": "登录", "node_ids": ["auth"],
                                  "related_high_risk_modules": [{"module_name": "认证"}],
                                  "attack_patterns": [{"pattern_id": "AUTH-1", "pattern_name": "认证绕过", "association_description": "外部登录入口"}]}],
            }]}},
        },
    }


def test_target_derivation_matches_existing_engine_without_changing_it():
    bundle = analysis()
    trees = bundle["artifacts"]["attack_tree_path"]["content"]
    modules = bundle["artifacts"]["high_risk_modules_path"]["content"]
    paths = trees["attack_trees"][0]["attack_paths"]
    paths.extend([copy.deepcopy(paths[0]), {**copy.deepcopy(paths[0]), "related_high_risk_modules": []},
                  {**copy.deepcopy(paths[0]), "related_high_risk_modules": [{"module_name": "缺失模块"}]}])
    paths[1]["attack_patterns"].append({"pattern_name": "无编号模式"})
    fields = ("module_name", "code_paths", "pattern_id", "pattern_name")
    expected = [{key: target[key] for key in fields} for target in _build_targets(trees, modules, fallback_code_path=Path("/project/src"))]
    actual = analysis_targets(trees, modules, "/project/src")
    assert [{"module_name": target["module_name"], "code_paths": target["paths"], "pattern_id": target["pattern_id"], "pattern_name": target["pattern_name"]} for target in actual] == expected
    assert actual[-1]["fallback"] is True
    assert len(actual[0]["sources"]) == 1


@pytest.mark.parametrize("project,root,module_path", [
    ("/project", "/project/src", "src/auth"),
    ("/project", "/project/src", "/project/src/auth"),
    ("C:\\Project", "C:\\Project\\src", "c:\\PROJECT\\SRC\\auth"),
    ("\\\\server\\share\\project", "\\\\server\\share\\project\\src", "\\\\server\\share\\project\\src\\auth"),
])
def test_paths_match_exact_inventory_entries_across_agent_operating_systems(project, root, module_path):
    bundle = analysis()
    bundle["artifacts"]["high_risk_modules_path"]["content"][0]["代码目录"] = module_path
    data = build_threat_coverage(inventory(project_path=project, scan_root=root), bundle)
    assert data["modules"][0]["mapped_paths"] == ["auth"]
    assert data["targets"][0]["mapped_paths"] == ["auth"]
    assert "authentication.c" not in data["targets"][0]["mapped_paths"]


def test_unmapped_paths_do_not_invent_coverage_and_either_input_can_arrive_first():
    tree_only = build_threat_coverage(inventory(), None)
    assert tree_only["inventory"]["entries"] and not tree_only["analysis_ready"]
    assert tree_only["modules"] == tree_only["targets"] == []
    annotations_only = build_threat_coverage(None, analysis())
    assert annotations_only["analysis_ready"] and annotations_only["inventory"] is None
    assert annotations_only["targets"][0]["mapped_paths"] == []
    bundle = analysis()
    bundle["artifacts"]["high_risk_modules_path"]["content"][0]["代码目录"] = ["/outside/auth", "src/missing", "src/auth*"]
    data = build_threat_coverage(inventory(), bundle)
    assert data["targets"][0]["mapped_paths"] == []
    assert len(data["unmapped"]) == 6


@pytest.mark.parametrize("bundle", [None, {}, {"artifacts": ["legacy"]}, {"entrypoint_result": [], "artifacts": {"high_risk_modules_path": []}}])
def test_unavailable_or_legacy_analysis_preserves_the_independent_tree(bundle):
    data = build_threat_coverage(inventory(), bundle)
    assert data["inventory"]["entries"]
    assert not data["analysis_ready"]
    assert data["modules"] == data["targets"] == []


def test_posix_literal_backslash_filename_does_not_match_a_directory_scope():
    snapshot = inventory(entries=[{"path": ".", "kind": "directory"}, {"path": "auth\\a.c", "kind": "file"}])
    ScanFileInventory.model_validate(snapshot)
    bundle = analysis()
    bundle["artifacts"]["high_risk_modules_path"]["content"][0]["代码目录"] = "src/auth/a.c"
    assert build_threat_coverage(snapshot, bundle)["targets"][0]["mapped_paths"] == []


@pytest.mark.parametrize("entries", [
    [{"path": "../escape", "kind": "file"}],
    [{"path": ".", "kind": "directory"}, {"path": "missing/file", "kind": "file"}],
    [{"path": ".", "kind": "directory"}, {"path": ".", "kind": "directory"}],
])
def test_invalid_inventory_is_rejected(entries):
    with pytest.raises(ValidationError):
        ScanFileInventory.model_validate(inventory(entries=entries))


def test_filesystem_inventory_includes_hidden_files_and_reports_omissions(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".hidden").write_text("secret", encoding="utf-8")
    (root / "README").write_text("text", encoding="utf-8")
    (root / "src").mkdir()
    (root / "src/a.c").write_text("code", encoding="utf-8")
    work = root / "work"
    work.mkdir()
    (work / "generated.json").write_text("{}", encoding="utf-8")
    (root / "loop").symlink_to(root, target_is_directory=True)
    result = collector.collect_file_inventory(inventory(project_path=str(root), scan_root=str(root)),
        excluded=(work,), cancel_event=threading.Event(), stop_event=threading.Event())
    ScanFileInventory.model_validate(result)
    assert {entry["path"] for entry in result["entries"]} == {".", ".hidden", "README", "src", "src/a.c"}
    assert result["status"] == "partial"
    assert result["issues"] == [{"path": "loop", "reason": "symlink"}]
    assert result["excluded_paths"] == ["work"]
    limited = collector.collect_file_inventory(inventory(project_path=str(root), scan_root=str(root)),
        excluded=(work,), cancel_event=threading.Event(), stop_event=threading.Event(), max_entries=2)
    assert limited["status"] == "partial" and any(issue["reason"] == "entry_limit" for issue in limited["issues"])
    stopped = threading.Event()
    stopped.set()
    cancelled = collector.collect_file_inventory(inventory(project_path=str(root), scan_root=str(root)),
        excluded=(), cancel_event=stopped, stop_event=threading.Event())
    assert cancelled["status"] == "cancelled"


@pytest.fixture(params=["sqlite", "postgres"])
def coverage_env(request, tmp_path, monkeypatch):
    if request.param == "postgres":
        dsn = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN")
        if not dsn:
            pytest.skip("OPENDEEPHOLE_TEST_POSTGRES_DSN is not configured")
        from backend.store.postgres import PostgresScanStore
        store = PostgresScanStore(dsn, pool_min_size=1, pool_max_size=4)
    else:
        store = SqliteScanStore(tmp_path / "inventory.db")
    scan_id = "coverage-" + uuid.uuid4().hex
    owner = "owner-" + scan_id
    store.create_user(owner, owner, "unused", "user", owner)
    status = ScanStatus(scan_id=scan_id, project_id="project", scan_items=[], created_at="2026-10-08T00:00:00+00:00", status=ScanItemStatus.COMPLETE,
                        progress=1.0, total_candidates=0, processed_candidates=0, vulnerabilities=[])
    meta = ScanMeta(user_id=owner, scan_items=[], created_at=status.created_at, project_path="/project", code_scan_path="/project/src", public_access_token="integration-token")
    store.save_scan(status, meta)
    revision = store.begin_scan_execution(scan_id, agent_id="agent-1", agent_session_id="session-1")
    async def store_call(store, operation, *args, **kwargs):
        return (getattr(store, operation) if isinstance(operation, str) else operation)(*args, **kwargs)
    for module in (auth, scan, sharing, integration, agent, report_routes):
        monkeypatch.setattr(module, "get_scan_store", lambda: store)
        monkeypatch.setattr(module, "run_store_call", store_call)
    monkeypatch.setattr(sse, "_distributed_store", None)
    monkeypatch.setattr(scan, "_running_scans", {})
    app = FastAPI()
    for router in (scan.router, integration.router, sharing.router, agent.router):
        app.include_router(router)
    headers = {"Authorization": "Bearer " + auth.create_token(owner, owner, "user")}
    yield SimpleNamespace(store=store, scan_id=scan_id, revision=revision, app=app, headers=headers)
    store.close()


def test_independent_inventory_round_trip_auth_idempotency_and_deletion(coverage_env):
    env = coverage_env
    async def run():
        notifications = sse.subscribe(env.scan_id)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=env.app), base_url="http://test") as client:
            path = f"/api/scan/{env.scan_id}/threat-coverage"
            upload = f"/api/agent/scan/{env.scan_id}/file-inventory"
            body = {"execution_revision": env.revision, "agent_session_id": "session-1", "inventory": inventory()}
            assert (await client.get(path)).status_code == 401
            assert (await client.post(upload, json={**body, "execution_revision": 999})).status_code == 409
            assert (await client.post(upload, json=body)).json() == {"ok": True, "changed": True}
            notice = notifications.get_nowait()
            assert notice["event"] == "resource_changed"
            assert notice["data"] == {"resource": "file-inventory", "index": None}
            assert env.store.get_threat_analysis(env.scan_id) is None
            first = (await client.get(path, headers=env.headers)).json()
            assert first["inventory"]["status"] == "complete" and first["analysis_ready"] is False
            assert (await client.post(upload, json=body)).json()["changed"] is False
            assert notifications.empty()
            assert (await client.post(upload, json={**body, "inventory": inventory(status="collecting", entries=[])})).json()["changed"] is False
            env.store.replace_threat_analysis(env.scan_id, analysis())
            annotated = (await client.get(path, headers=env.headers)).json()
            assert annotated["analysis_ready"] and annotated["targets"][0]["mapped_paths"] == ["auth", "auth/a.c"]
            assert "scan_inventory" not in env.store.get_threat_analysis(env.scan_id)
            token = (await client.post(f"/api/scan/{env.scan_id}/share", headers=env.headers)).json()["token"]
            for route, credential in (("shared", token), ("public", "integration-token")):
                public_path = f"/api/{route}/scans/{env.scan_id}/threat-coverage"
                assert (await client.get(public_path, params={"token": "bad"})).status_code == 403
                assert (await client.get(public_path, params={"token": credential})).json() == annotated
            env.store.request_scan_deletion(env.scan_id)
            for _ in range(10):
                env.store.process_scan_deletions(scan_id=env.scan_id)
            assert env.store.get_file_inventory(env.scan_id) is None
            assert (await client.post(upload, json=body)).json()["discarded"] == "scan_deleted"
        sse.unsubscribe(env.scan_id, notifications)
    asyncio.run(run())


def test_analysis_can_arrive_before_inventory_and_old_execution_cannot_overwrite(coverage_env):
    env = coverage_env
    env.store.replace_threat_analysis(env.scan_id, analysis())
    assert env.store.get_threat_coverage(env.scan_id)["inventory"] is None
    partial = inventory(status="partial", issue_count=1, issues=[{"path": "other", "reason": "unreadable"}])
    def report(data, revision=env.revision):
        return FileInventoryUpload(inventory=data, execution_revision=revision, agent_session_id="session-1")
    env.store.replace_file_inventory(env.scan_id, report(partial))
    new_revision = env.store.begin_scan_execution(env.scan_id, agent_id="agent-1", agent_session_id="session-1")
    with pytest.raises(ValueError, match="stale scan execution"):
        env.store.replace_file_inventory(env.scan_id, report(inventory()))
    env.store.replace_file_inventory(env.scan_id, report(inventory(snapshot_id="retry"), new_revision))
    assert env.store.get_threat_coverage(env.scan_id)["inventory"]["status"] == "complete"
    assert env.store.list_threat_audit_tasks(env.scan_id) == []


@pytest.mark.parametrize("inventory_first,failure", [(True, None), (False, None), (True, "analysis"), (True, "inventory")])
def test_scanner_uploads_inventory_independently_of_model_completion(tmp_path, monkeypatch, inventory_first, failure):
    async def run():
        project = tmp_path / "project"
        project.mkdir()
        (project / "a.c").write_text("code", encoding="utf-8")
        posted = asyncio.Event()
        analysis_started = asyncio.Event()
        release_analysis = asyncio.Event()
        release_inventory = threading.Event()
        reports = []
        reporter = SimpleNamespace(
            agent_session_id="session-1", scan_execution_revision=lambda _id: 1,
            send_event=AsyncMock(), finish_scan=AsyncMock(), send_index_status=AsyncMock(),
            publish_opencode_pool_until=AsyncMock(), send_static_progress=AsyncMock(),
            report_threat_analysis_run=AsyncMock(), report_mining_engine_run=AsyncMock(),
            get_threat_analysis=AsyncMock(return_value=None), push_threat_analysis=AsyncMock(),
        )
        async def upload(_id, value, **_kwargs):
            reports.append(value)
            if value["status"] != "collecting": posted.set()
        reporter.push_file_inventory = upload
        async def analyze(**_kwargs):
            analysis_started.set()
            await release_analysis.wait()
            return {"result": failure != "analysis", "reason": "model failed" if failure == "analysis" else ""}
        real_collect = collector.collect_file_inventory
        def collect(*args, **kwargs):
            assert release_inventory.wait(5), "inventory gate timed out"
            if failure == "inventory":
                raise PermissionError("unreadable scan directory")
            return real_collect(*args, **kwargs)
        monkeypatch.setattr(scanner.Path, "home", lambda: tmp_path)
        monkeypatch.setattr(scanner, "configure_platform_runtime", lambda *_args: None)
        codex_config = ScanCodexConfigResult()
        monkeypatch.setattr(scanner, "prepare_scan_codex_access_async", AsyncMock(return_value=codex_config))
        monkeypatch.setattr(scanner, "sync_scan_codex_mcp_async", AsyncMock(return_value=codex_config))
        monkeypatch.setattr(scanner, "opencode_task_context", lambda **_kwargs: nullcontext())
        monkeypatch.setattr(scanner, "run_threat_analysis", AsyncMock(side_effect=analyze))
        monkeypatch.setattr(scanner, "collect_json_artifacts", lambda *_args, **_kwargs: analysis())
        monkeypatch.setattr(collector, "collect_file_inventory", collect)
        task = asyncio.create_task(scanner.run_scan(
            config=AgentConfig(), project_path=project, code_scan_path=project, reporter=reporter, scan_name="coverage",
            product="", validation_environment="", checker_names=[], scan_id="s",
            cancel_event=threading.Event(), threat_analysis_enabled=True,
            threat_analysis_method="custom_threat_analysis", mining_engines=[],
        ))
        try:
            await asyncio.wait_for(analysis_started.wait(), 5)
            if inventory_first:
                release_inventory.set()
                await asyncio.wait_for(posted.wait(), 5)
                reporter.push_threat_analysis.assert_not_awaited()
                assert not task.done()
                release_analysis.set()
            else:
                release_analysis.set()
                for _ in range(100):
                    if reporter.push_threat_analysis.await_count: break
                    await asyncio.sleep(.01)
                reporter.push_threat_analysis.assert_awaited_once()
                assert not posted.is_set()
                release_inventory.set()
            await asyncio.wait_for(task, 5)
            scanner.run_threat_analysis.assert_awaited_once()
            assert reports[-1]["status"] == ("failed" if failure == "inventory" else "complete")
            if failure != "inventory":
                assert any(entry["path"] == "a.c" for entry in reports[-1]["entries"])
                assert (tmp_path / ".opendeephole/scans/s/coverage/file-inventory.json").is_file()
            if failure != "analysis":
                assert "scan_inventory" not in reporter.push_threat_analysis.await_args.args[1]
            else:
                reporter.push_threat_analysis.assert_not_awaited()
            assert reporter.finish_scan.await_args.args[2] == ("error" if failure == "analysis" else "complete")
        finally:
            release_analysis.set()
            release_inventory.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    asyncio.run(run())


def test_resume_inventory_is_frozen_and_transport_does_not_queue_behind_analysis(tmp_path, monkeypatch):
    async def run():
        reporter = Reporter("http://server", outbox_path=tmp_path / "outbox.db")
        reporter.set_scan_execution("s", 1)
        reporter._outbox.enqueue(target_url=reporter.server_url, stream_key="scan:s", dedupe_key="analysis",
                                 path="/api/agent/scan/s/threat-analysis", payload={}, timeout_seconds=30)
        posted = []
        async def post(url, **kwargs):
            posted.append((url, kwargs["json"]))
            return httpx.Response(200, request=httpx.Request("POST", url), json={"ok": True})
        monkeypatch.setattr(reporter._client, "post", post)
        project = tmp_path / "project"
        project.mkdir()
        (project / "first.c").write_text("code", encoding="utf-8")
        kwargs = dict(project=project, scan_root=project, scan_dir=tmp_path / "work", scan_id="s", reporter=reporter, cancel_event=threading.Event())
        try:
            await collector.collect_and_report_file_inventory(**kwargs, is_resume=False)
            assert len(posted) == 2 and all(url.endswith("file-inventory") for url, _body in posted)
            assert reporter._outbox.pending_count() == 1
            first = posted[-1][1]["inventory"]
            (project / "later.c").write_text("code", encoding="utf-8")
            await collector.collect_and_report_file_inventory(**kwargs, is_resume=True)
            assert posted[-1][1]["inventory"] == first
        finally:
            await reporter.close()
    asyncio.run(run())
