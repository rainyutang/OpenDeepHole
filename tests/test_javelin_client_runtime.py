"""Tests for Javelin client runtime: Node semver, doctor cache, config bridge, observer dedup & /finish closure."""

from __future__ import annotations

import asyncio
from pathlib import Path
import subprocess
import time
from typing import Any

import httpx
import pytest

from backend.application import use_runtime
from backend.config import AppConfig
from backend.main import app
from backend.models import ScanItemStatus
from deephole_client.config import AgentConfig, OpenCodeModelConfig
from deephole_client.javelin_runtime.config_bridge import (
    compute_javelin_worker_concurrency,
    write_javelin_opencode_config,
)
from deephole_client.javelin_runtime.manager import (
    clear_javelin_doctor_cache,
    is_node_version_supported,
    materialize_javelin_workspace,
    probe_javelin_doctor,
)
from deephole_client.javelin_runtime.runner import (
    run_javelin_scan,
    set_javelin_service_factory_for_testing,
)
from deephole_client.reporter import Reporter
from deephole_client.task_manager import TaskManager
from tests.test_javelin_store_and_ingestion import _seed_javelin_scan, _setup_env


def test_node_semver_check_only_requires_22_5_plus_and_doctor_cache(tmp_path: Path) -> None:
    assert is_node_version_supported("v22.5.0") is True
    assert is_node_version_supported("v22.6.0") is True
    assert is_node_version_supported("24.1.0") is True
    assert is_node_version_supported("v22.4.9") is False
    assert is_node_version_supported("v20.18.0") is False
    assert is_node_version_supported("invalid") is False

    # Create a fake opencode executable to test full offline ESM + Node doctor probe
    fake_bin = tmp_path / "opencode"
    fake_bin.write_text("#!/bin/sh\necho 'opencode 1.0'\n", encoding="utf-8")
    fake_bin.chmod(0o755)

    clear_javelin_doctor_cache()
    probe_ws = tmp_path / "probe_ws"
    cap1 = probe_javelin_doctor(
        opencode_executable=str(fake_bin),
        probe_workspace=probe_ws,
        use_cache=True,
    )
    assert cap1["supported"] is True
    assert cap1["esm_deps_ok"] is True
    assert cap1["opencode_ok"] is True
    assert cap1["ready"] is True
    assert cap1["contract_version"] == 1

    # Second call hits 600s cache in < 1ms without spawning subprocesses
    t0 = time.perf_counter()
    cap2 = probe_javelin_doctor(
        opencode_executable=str(fake_bin),
        probe_workspace=probe_ws,
        use_cache=True,
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    assert cap2 == cap1
    assert elapsed_ms < 5.0


def test_config_bridge_concurrency_cap_and_clean_submodule(tmp_path: Path) -> None:
    agent_cfg = AgentConfig()
    assert compute_javelin_worker_concurrency(agent_cfg) == 1

    agent_cfg.opencode.models = [
        OpenCodeModelConfig(id="m1", model="openai/gpt-5", max_concurrency=3, enabled=True),
        OpenCodeModelConfig(id="m2", model="openai/gpt-5-mini", max_concurrency=5, enabled=True),
    ]
    assert compute_javelin_worker_concurrency(agent_cfg) == 4

    ws = materialize_javelin_workspace(tmp_path / "mat_ws")
    target_java = tmp_path / "java_repo"
    target_java.mkdir()
    cfg_file = write_javelin_opencode_config(
        agent_cfg,
        workspace_root=ws,
        target_project_path=target_java,
        runtime_data_root=tmp_path / "data",
    )
    assert cfg_file.is_file()
    assert (cfg_file.stat().st_mode & 0o777) == 0o600
    mtime1 = cfg_file.stat().st_mtime_ns
    # Writing identical config again skips disk rewrite
    write_javelin_opencode_config(
        agent_cfg,
        workspace_root=ws,
        target_project_path=target_java,
        runtime_data_root=tmp_path / "data",
    )
    assert cfg_file.stat().st_mtime_ns == mtime1

    # Submodule working tree must remain 100% clean
    git_status = subprocess.run(
        ["git", "-C", "third_party/Javelin", "status", "-s"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert git_status.stdout.strip() == ""


class _DeterministicMockJavelinService:
    """In-memory mock of audit-service.mjs verifying 5-channel observer + /finish convergence."""

    def __init__(self, tmp_dir: Path) -> None:
        self.tmp_dir = tmp_dir
        self._polls = 0
        self.baseline_path = tmp_dir / "source-baseline.dh-scan-e2e.json"
        self.baseline_path.write_text(
            '{"files":[{"id":"f-1","path":"src/main/java/App.java","size":512,"eligible":true}]}',
            encoding="utf-8",
        )

    def mark_scan_active(self, scan_id: str) -> None:
        pass

    def mark_scan_finished(self, scan_id: str) -> None:
        pass

    async def ensure_started(self, config: Any, **kwargs: Any) -> tuple[str, str]:
        return ("http://127.0.0.1:0", "tok")

    async def create_and_start_audit(self, **kwargs: Any) -> dict[str, Any]:
        return {"id": kwargs["audit_id"], "status": "running", "version": 1}

    async def get_audit(self, audit_id: str) -> dict[str, Any]:
        self._polls += 1
        done = self._polls >= 2
        return {
            "id": audit_id,
            "status": "completed" if done else "running",
            "version": 2 if done else 1,
            "stage": "报告封存" if done else "任务执行与报告收集",
            "progress": 100.0 if done else 50.0,
            "task_board": {"total": 1, "reported": 1 if done else 0, "running": 0 if done else 1},
        }

    async def get_logs(self, audit_id: str, limit: int = 400) -> list[dict[str, Any]]:
        return [
            {"sequence": 1, "event_type": "audit.started", "body": "Scope frozen"},
            {"sequence": 2, "event_type": "audit.completed", "body": "Report sealed"},
        ]

    async def get_task_board(self, audit_id: str, **kwargs: Any) -> dict[str, Any]:
        return {
            "items": [{
                "task_id": "T-001",
                "title": "Audit App.java",
                "domain": "java",
                "status": "REPORTED",
                "file_ids": ["f-1"],
                "finding_count": 1,
            }],
            "total": 1,
        }

    async def get_findings(self, audit_id: str) -> list[dict[str, Any]]:
        return [{
            "id": "F-001",
            "resource_id": "res-f-001",
            "title": "SpEL Expression Injection",
            "severity": "CRITICAL",
            "cwe": "CWE-917",
            "location": {"path": "src/main/java/App.java", "line": 28, "symbol": "evalExpr"},
            "description": "Untrusted input passed to SpelExpressionParser.parseExpression.",
            "adjudication_verdict": "TRUE_POSITIVE",
        }]

    async def get_http_exchanges(self, audit_id: str) -> list[dict[str, Any]]:
        return [{
            "exchange_id": "http_001",
            "finding_id": "F-001",
            "method": "POST",
            "url": "http://127.0.0.1:8080/api/eval?token=secret123",
            "request": {"headers": {"Authorization": "Bearer live-secret"}, "body": '{"expr":"1+1"}'},
            "response": {"status": 200, "headers": {"Content-Type": "application/json"}, "body": '{"result":2}'},
        }]

    async def get_reports(self, audit_id: str) -> list[dict[str, Any]]:
        return [{"id": "final-dh-scan-e2e", "audit_id": audit_id, "report_kind": "final", "name": "Java 安全审计报告.md"}]

    async def download_report_original_bytes(self, report_id: str) -> bytes:
        return "# Java 安全审计报告\n\n发现 1 处高危 SpEL 注入漏洞。\n".encode("utf-8")

    def find_source_baseline_file(self, audit: dict[str, Any], audit_id: str) -> Path | None:
        return self.baseline_path


@pytest.mark.anyio
async def test_p0_5_e2e_runner_outbox_finish_convergence_and_offline_db_view(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENDEEPHOLE_JAVELIN_DATA_ROOT", str(tmp_path / "jdata"))
    monkeypatch.setattr("deephole_client.javelin_runtime.observer.FALLBACK_POLL_SECONDS", 0.05)
    monkeypatch.setattr("deephole_client.javelin_runtime.observer.DEBOUNCE_SECONDS", 0.01)
    monkeypatch.setattr("deephole_client.javelin_runtime.runner.FALLBACK_POLL_SECONDS", 0.05)
    monkeypatch.setattr("deephole_client.javelin_runtime.runner.DEBOUNCE_SECONDS", 0.01)

    cfg, store, runtime, uid, jwt = _setup_env(tmp_path, javelin_enabled=True)
    _seed_javelin_scan(store, "scan-e2e", user_id=uid, agent_key="ag-key-1", agent_id="ag-live-1", session_id="sess-e2e")

    # Regression check before runner finishes: without /finish, scans.status is still AUDITING!
    assert store.load_scan_runtime("scan-e2e")[0].status == ScanItemStatus.AUDITING

    mock_service = _DeterministicMockJavelinService(tmp_path)
    set_javelin_service_factory_for_testing(lambda: mock_service)

    try:
        with use_runtime(runtime):
            transport = httpx.ASGITransport(app=app)
            reporter = Reporter("http://testserver", outbox_path=tmp_path / "outbox.sqlite3")
            reporter._client = httpx.AsyncClient(transport=transport, base_url="http://testserver")
            reporter.agent_id = "ag-live-1"
            reporter._agent_session_id = "sess-e2e"
            reporter.set_protocol_version(2)
            reporter.set_scan_execution("scan-e2e", 1)
            reporter.start_outbox_worker()

            tm = TaskManager()
            task = tm.create(
                scan_id="scan-e2e",
                project_path=str(tmp_path),
                code_scan_path=str(tmp_path),
                checkers=[],
                scan_name="demo-java",
                product="Mall",
                mining_engines=[{"engine_id": "javelin", "enabled": True}],
                execution_revision=1,
                language="java",
                javelin_audit_id="dh-scan-e2e",
            )

            await run_javelin_scan(config=AgentConfig(), task=task, reporter=reporter)
            await reporter.flush_for_restart(timeout=10.0)
            await reporter.close()

            # Client is now COMPLETELY OFFLINE (reporter closed, zero live WS connections)!
            # Verify P0 #5: scans.status converged to COMPLETE via /api/agent/v2/scan/{id}/finish!
            persisted_scan, _ = store.load_scan_runtime("scan-e2e")
            assert persisted_scan.status == ScanItemStatus.COMPLETE
            assert persisted_scan.progress == 1.0

            # Verify 100% of Javelin workbench endpoints serve full data from DB while client is offline!
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ui_client:
                headers = {"Authorization": f"Bearer {jwt}"}
                ws_resp = await ui_client.get("/api/v2/scans/scan-e2e/javelin/api/v1/workspace", headers=headers)
                assert ws_resp.status_code == 200
                ws_json = ws_resp.json()
                assert ws_json["audits"][0]["status"] == "completed"
                assert ws_json["summary"]["finding_count"] == 1

                board_resp = await ui_client.get("/api/v2/scans/scan-e2e/javelin/api/v2/products/product-undefined/audits/dh-scan-e2e/task-board", headers=headers)
                assert board_resp.json()["total"] == 1
                assert board_resp.json()["items"][0]["task_id"] == "T-001"

                findings_resp = await ui_client.get("/api/v2/scans/scan-e2e/javelin/api/v1/findings", headers=headers)
                assert findings_resp.json()["count"] == 1
                assert findings_resp.json()["items"][0]["title"] == "SpEL Expression Injection"

                cov_resp = await ui_client.get("/api/v2/scans/scan-e2e/javelin/file-coverage", headers=headers)
                assert cov_resp.json()["summary"]["covered_files"] == 1

                rep_resp = await ui_client.get("/api/v2/scans/scan-e2e/javelin/api/v1/reports/final-dh-scan-e2e", headers=headers)
                assert rep_resp.status_code == 200
                assert "SpEL" in rep_resp.json()["rendered_html"]

                ex_resp = await ui_client.get("/api/v2/scans/scan-e2e/javelin/api/v1/http-exchanges", headers=headers)
                ex_item = ex_resp.json()["items"][0]
                assert "secret123" not in ex_item["request"]["url"]
                assert "live-secret" not in str(ex_item["request"]["headers"])
    finally:
        set_javelin_service_factory_for_testing(None)
        store.close()


@pytest.mark.anyio
async def test_real_audit_service_non_git_directory_target_and_graceful_404_cancel(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Spawn REAL unmodified audit-service.mjs against a plain non-Git Java folder (regression for 422 & 404)."""
    from deephole_client.javelin_runtime.manager import JavelinAuditServiceManager

    # Plain Java directory WITHOUT .git (previously triggered HTTP 422 on legacy /api/v1/audits)
    plain_java = tmp_path / "plain_java_service"
    java_src = plain_java / "src" / "main" / "java" / "com" / "demo"
    java_src.mkdir(parents=True)
    (java_src / "DemoController.java").write_text(
        "package com.demo;\npublic class DemoController { public String ping(String q) { return q; } }\n",
        encoding="utf-8",
    )

    fake_bin_dir = tmp_path / "bin"
    fake_bin_dir.mkdir()
    fake_opencode = fake_bin_dir / "opencode"
    fake_opencode.write_text(
        "#!/bin/sh\n"
        "if [ \"$2\" = \"--help\" ]; then\n"
        "  echo 'usage: opencode run --format --session'\n"
        "  exit 0\n"
        "fi\n"
        "sleep 2\n"
        "exit 0\n",
        encoding="utf-8",
    )
    fake_opencode.chmod(0o755)

    agent_cfg = AgentConfig()
    agent_cfg.opencode.executable = str(fake_opencode)
    # Unconfigured provider/model exercises automatic fallback to 'default' without 422!
    agent_cfg.opencode.models = [
        OpenCodeModelConfig(id="m-unregistered", model="unregistered-provider/demo-model", enabled=True)
    ]

    mgr = JavelinAuditServiceManager(
        runtime_root=Path(__file__).resolve().parents[1],
        data_root=tmp_path / "javelin_data",
        idle_shutdown_seconds=0,
    )
    try:
        # Cancel on a non-existent audit_id must NOT raise 404 Not Found
        await mgr.ensure_started(agent_cfg, target_project_path=plain_java)
        missing_cancel = await mgr.dispatch_action("dh-never-created", "cancel")
        assert missing_cancel["status"] == "cancelled"
        assert missing_cancel.get("already_missing") is True

        created = await mgr.create_and_start_audit(
            config=agent_cfg,
            scan_id="scan-real-nongit",
            audit_id="dh-scan-real-nongit",
            scan_name="plain-java-app",
            project_path=plain_java,
            product_name="Mall",
            javelin_config={
                "mining_strategy": "focus_area",
                "bac_analysis": "auto",
                "runtime_testing": {
                    "enabled": True,
                    "mode": "CONTACT_ONLY",
                    "budget_minutes": 15,
                    "allowed_actions": ["normal_interaction"],
                },
            },
            secret_test_env="http://127.0.0.1:18080\ntest_token=secret-abc",
        )
        assert created["id"] == "dh-scan-real-nongit"
        assert created["source_kind"] == "directory"

        # Poll briefly until runner generates source-baseline.<audit_id>.json
        baseline_found = None
        for _ in range(30):
            live_audit = await mgr.get_audit("dh-scan-real-nongit")
            baseline_found = mgr.find_source_baseline_file(live_audit, "dh-scan-real-nongit")
            if baseline_found is not None:
                break
            await asyncio.sleep(0.1)
        assert baseline_found is not None and baseline_found.is_file()

        board = await mgr.get_task_board("dh-scan-real-nongit")
        assert "items" in board

        await mgr.dispatch_action("dh-scan-real-nongit", "cancel", action_id="cancel-real-1")

        console_out = capsys.readouterr().out
        assert "[javelin]" in console_out
        assert "本地审计服务已就绪" in console_out
        assert "Javelin 审计引擎已启动执行" in console_out
        assert "secret-abc" not in console_out
    finally:
        await mgr.stop()


def test_terminal_scan_never_displays_queued_and_workbench_routes(tmp_path: Path) -> None:
    """Verify initial state is 'preparing' (not 'queued') and terminal scans converge out of active states."""
    from fastapi.testclient import TestClient

    _cfg, store, runtime, uid, jwt = _setup_env(tmp_path, javelin_enabled=True)
    try:
        _seed_javelin_scan(store, "scan-conv", user_id=uid, agent_key="ag-key-1", agent_id="ag-live-1")
        init_state = store.get_javelin_audit_state("scan-conv")
        assert init_state is not None
        assert init_state["status"] == "preparing"

        # Simulate legacy/stuck 'queued' row while scans.status transitions to ERROR
        store.upsert_javelin_state_snapshot("scan-conv", execution_revision=1, snapshot={"status": "queued"})
        store.update_scan_progress("scan-conv", status=ScanItemStatus.ERROR, error_message="startup failure")

        with use_runtime(runtime):
            client = TestClient(app)
            headers = {"Authorization": f"Bearer {jwt}"}
            state_resp = client.get("/api/v2/scans/scan-conv/javelin/state", headers=headers)
            assert state_resp.status_code == 200
            assert state_resp.json()["audit"]["status"] == "failed"
            assert state_resp.json()["brief"]["status"] == "failed"

            audits_col = client.get(
                "/api/v2/scans/scan-conv/javelin/api/v2/products/product-undefined/audits?tab=all&page=1&page_size=20",
                headers=headers,
            )
            assert audits_col.status_code == 200
            assert audits_col.json()["items"][0]["status"] == "failed"

        # Store-level convergence helper also updates persisted row
        assert store.converge_javelin_state_on_scan_terminal(
            "scan-conv", scan_status="error", error_message="startup failure"
        ) is True
        assert store.get_javelin_audit_state("scan-conv")["status"] == "failed"
    finally:
        store.close()
