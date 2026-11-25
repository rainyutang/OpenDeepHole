"""Integration tests for Javelin 6+1 DB tables, P0/P1 invariants, quotas, chunked upload, LRU cache & DB perf."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import time
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.agents.artifacts import _iter_agent_runtime_files as iter_agent_runtime_files, get_cached_agent_runtime_hash
from backend.application import BackendRuntime, use_runtime
from backend.auth import create_token, hash_password
import backend.config as backend_config
from backend.config import AppConfig
from backend.main import app
from backend.models import (
    JAVELIN_CONTRACT_VERSION,
    JAVELIN_ENGINE_ID,
    JAVELIN_ENGINE_LABEL,
    JavelinAgentCapability,
    JavelinScanConfig,
    MiningEngineSelection,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
)
from backend.scans.javelin_queries import invalidate_javelin_coverage_cache
import backend.store as backend_store
from backend.store.maintenance import cleanup_stale_javelin_upload_staging
from backend.store.sqlite import SqliteScanStore
from deephole_client.updater import _iter_runtime_files, compute_runtime_hash, runtime_root


def _setup_env(tmp_path: Path, *, javelin_enabled: bool = True):
    cfg = AppConfig()
    cfg.storage.scans_dir = str(tmp_path / "scans")
    cfg.storage.projects_dir = str(tmp_path / "projects")
    cfg.storage.user_skills_dir = str(tmp_path / "skills")
    cfg.auth.secret_key = "test-jwt-secret-for-javelin-store-suite"
    cfg.javelin.enabled = javelin_enabled

    Path(cfg.storage.scans_dir).mkdir(parents=True, exist_ok=True)
    Path(cfg.storage.projects_dir).mkdir(parents=True, exist_ok=True)
    Path(cfg.storage.user_skills_dir).mkdir(parents=True, exist_ok=True)

    store = SqliteScanStore(Path(cfg.storage.scans_dir) / "scans.db")
    user_id = "user-1"
    store.create_user(user_id, "tester", hash_password("pw123456"), "admin", "agent-tok-1")

    backend_config._config = cfg
    backend_config._auth_secret = cfg.auth.secret_key
    backend_store._store = store

    runtime = BackendRuntime(store=store, config_factory=lambda: cfg)
    app.state.backend_runtime = runtime
    with use_runtime(runtime):
        jwt_token = create_token(user_id, "tester", "admin")
    return cfg, store, runtime, user_id, jwt_token


def _seed_javelin_scan(
    store: SqliteScanStore,
    scan_id: str = "scan-jav-1",
    *,
    user_id: str = "user-1",
    agent_key: str = "ag-key-1",
    agent_id: str = "ag-live-1",
    session_id: str = "sess-1",
    secret_ciphertext: bytes | None = None,
    secret_meta: dict | None = None,
) -> tuple[ScanStatus, ScanMeta]:
    now = datetime.now(timezone.utc).isoformat()
    store.upsert_agent_record(
        agent_key=agent_key,
        user_id=user_id,
        ip="127.0.0.1",
        machine_name="java-worker",
        display_name="java-worker",
        agent_id=agent_id,
        last_seen=now,
        initial_config_json="{}",
        validator_catalog_json="{}",
    )
    store.set_agent_javelin_capability(
        agent_key,
        JavelinAgentCapability(
            supported=True,
            ready=True,
            contract_version=JAVELIN_CONTRACT_VERSION,
            node_version="v22.6.0",
            esm_deps_ok=True,
            opencode_ok=True,
        ),
    )
    sel = MiningEngineSelection(engine_id=JAVELIN_ENGINE_ID, engine_label=JAVELIN_ENGINE_LABEL, enabled=True)
    pub_token = "pub-token-xyz"
    scan = ScanStatus(
        scan_id=scan_id,
        project_id="demo-java",
        scan_name=f"demo-java-{scan_id}",
        project_path="/srv/demo-java",
        code_scan_path="/srv/demo-java",
        code_scan_paths=["/srv/demo-java"],
        scan_mode="custom",
        product="Mall",
        mining_engines=[sel],
        created_at=now,
        status=ScanItemStatus.AUDITING,
        progress=0.0,
        total_candidates=0,
        processed_candidates=0,
        vulnerabilities=[],
        agent_name="java-worker",
        agent_key=agent_key,
        language="java",
        has_javelin=True,
        javelin_config=JavelinScanConfig(),
    )
    meta = ScanMeta(
        scan_items=[],
        created_at=now,
        scan_mode="custom",
        mining_engines=[sel],
        agent_id=agent_id,
        agent_key=agent_key,
        agent_name="java-worker",
        project_path="/srv/demo-java",
        code_scan_path="/srv/demo-java",
        code_scan_paths=["/srv/demo-java"],
        scan_name=f"demo-java-{scan_id}",
        product="Mall",
        user_id=user_id,
        public_access_token=pub_token,
        language="java",
        javelin_config=JavelinScanConfig(),
    )
    store.save_scan(scan, meta)
    rev = store.begin_scan_execution(scan_id, agent_id=agent_id, agent_session_id=session_id)
    store.init_javelin_audit_state(
        scan_id=scan_id,
        audit_id=f"dh-{scan_id}",
        product_id="product-undefined",
        product_name="Mall",
        target_id="target-1",
        target_name="demo-java",
        repository_id="repo-1",
        repository_name="demo-java",
        mining_strategy="focus_area",
        execution_revision=rev,
        secret_ciphertext=secret_ciphertext,
        secret_meta=secret_meta,
    )
    return scan, meta


def test_p0_1_single_column_raw_bytes_and_exact_bom_crlf_original_download(tmp_path: Path) -> None:
    cfg, store, runtime, _uid, jwt = _setup_env(tmp_path)
    try:
        _seed_javelin_scan(store, "scan-blob")

        # Verify schema has NO utf8_text column on javelin_report_blobs
        cols = {r[1] for r in store._conn.execute("PRAGMA table_info(javelin_report_blobs)").fetchall()}
        assert "raw_bytes" in cols
        assert "utf8_text" not in cols

        # 3 MiB report with UTF-8 BOM + CRLF line endings
        bom_crlf_report = b"\xef\xbb\xbf# Javelin Sealed Report\r\n\r\n" + (b"Line with CRLF ending 0123456789abcdef\r\n" * 82_000)
        expected_sha = hashlib.sha256(bom_crlf_report).hexdigest()
        assert len(bom_crlf_report) > 3 * 1024 * 1024

        store.store_javelin_report(
            "scan-blob",
            execution_revision=1,
            report_id="final-r1",
            report_kind="final",
            name="security-audit-report.md",
            format="markdown",
            raw_bytes=bom_crlf_report,
            expected_sha256=expected_sha,
        )
        stored_row = store._conn.execute(
            "SELECT OCTET_LENGTH(raw_bytes) AS b_len FROM javelin_report_blobs WHERE blob_sha256 = ?",
            (expected_sha,),
        ).fetchone()
        assert int(stored_row["b_len"]) == len(bom_crlf_report)

        with use_runtime(runtime):
            client = TestClient(app)
            dl = client.get(
                "/api/v2/scans/scan-blob/javelin/api/v1/reports/final-r1/download?format=original",
                headers={"Authorization": f"Bearer {jwt}"},
            )
            assert dl.status_code == 200
            assert hashlib.sha256(dl.content).hexdigest() == expected_sha
            assert dl.content == bom_crlf_report
    finally:
        store.close()


def test_p0_2_secret_context_never_leaks_to_state_shared_or_public_endpoints(tmp_path: Path) -> None:
    from backend.scans.javelin_sanitizer import encrypt_secret_context

    cfg, store, runtime, _uid, jwt = _setup_env(tmp_path)
    try:
        ct, meta = encrypt_secret_context(
            {"test_environment_context": "TOP_SECRET_COOKIE=xyz987"},
            scan_id="scan-sec",
            expires_at="2099-01-01T00:00:00+00:00",
            config=cfg,
        )
        _seed_javelin_scan(store, "scan-sec", secret_ciphertext=ct, secret_meta=meta)
        share = store.get_or_create_scan_share("scan-sec")
        assert share is not None
        share_tok = share["token"]

        with use_runtime(runtime):
            client = TestClient(app)
            r_auth = client.get("/api/v2/scans/scan-sec/javelin/state", headers={"Authorization": f"Bearer {jwt}"})
            r_shared = client.get(f"/api/shared/scans/scan-sec/javelin/state?token={share_tok}")
            r_public = client.get("/api/public/scans/scan-sec/javelin/state?token=pub-token-xyz")
            for resp in (r_auth, r_shared, r_public):
                assert resp.status_code == 200, resp.text
                raw_text = resp.text
                for forbidden in (
                    "secret_context_ciphertext",
                    "secret_context_meta_json",
                    "TOP_SECRET_COOKIE",
                    "nonce_b64",
                    "nonce_hex",
                    "ciphertext",
                ):
                    assert forbidden not in raw_text
    finally:
        store.close()


def test_p0_3_and_p0_4_feature_gate_and_contract_version_rejection(tmp_path: Path) -> None:
    cfg, store, runtime, _uid, jwt = _setup_env(tmp_path, javelin_enabled=False)
    try:
        _seed_javelin_scan(store, "scan-hist")

        with use_runtime(runtime):
            client = TestClient(app)
            headers = {"Authorization": f"Bearer {jwt}"}
            # Feature flag disabled -> /api/mining-engines omits javelin
            cat = client.get("/api/mining-engines", headers=headers)
            assert cat.status_code == 200
            assert all(item["engine_id"] != "javelin" for item in cat.json()["engines"])

            # Feature flag disabled -> POST /api/scan for Java rejected with 422
            create_resp = client.post(
                "/api/scan",
                headers=headers,
                json={
                    "agent_key": "ag-key-1",
                    "project_path": "/srv/java-app",
                    "scan_name": "blocked-java",
                    "product": "Mall",
                    "language": "java",
                },
            )
            assert create_resp.status_code == 422

            # Historical scan remains viewable read-only while control actions return 404
            hist = client.get("/api/v2/scans/scan-hist/javelin/state", headers=headers)
            assert hist.status_code == 200
            assert hist.json()["allowed_actions"] == []
            act = client.post("/api/v2/scans/scan-hist/javelin/actions", headers=headers, json={"action": "cancel"})
            assert act.status_code == 404

            # Enable feature flag, then test contract_version=999 rejection (P0 #4)
            cfg.javelin.enabled = True
            bad_ingest = client.post(
                "/api/agent/scan/scan-hist/javelin/state",
                headers={"X-Agent-Id": "ag-live-1"},
                json={"contract_version": 999, "execution_revision": 1, "state": {"status": "running"}},
            )
            assert bad_ingest.status_code == 409
    finally:
        store.close()


def test_p1_6_and_p1_7_quotas_429_and_chunked_upload_staging_and_gc(tmp_path: Path) -> None:
    cfg, store, runtime, _uid, jwt = _setup_env(tmp_path, javelin_enabled=True)
    try:
        cfg.javelin.hard_quota_events_per_scan = 5
        _seed_javelin_scan(store, "scan-quota")

        with use_runtime(runtime):
            client = TestClient(app)
            # Exceed hard_quota_events_per_scan -> 429 with retry_after_ms
            events_ok = client.post(
                "/api/agent/scan/scan-quota/javelin/events",
                headers={"X-Agent-Id": "ag-live-1"},
                json={
                    "contract_version": 1,
                    "execution_revision": 1,
                    "agent_session_id": "sess-1",
                    "events": [{"sequence": i, "body": f"log {i}"} for i in range(1, 6)],
                },
            )
            assert events_ok.status_code == 200

            events_429 = client.post(
                "/api/agent/scan/scan-quota/javelin/events",
                headers={"X-Agent-Id": "ag-live-1"},
                json={
                    "contract_version": 1,
                    "execution_revision": 1,
                    "agent_session_id": "sess-1",
                    "events": [{"sequence": 6, "body": "overflow"}],
                },
            )
            assert events_429.status_code == 429
            assert events_429.json()["detail"]["retry_after_ms"] == cfg.javelin.quota_retry_after_ms

            # Chunked > 4 MiB report upload (3 chunks) + resume check + SHA mismatch cleanup
            big_report = b"# Multi-chunk report\n" + (b"0123456789abcdef" * 280_000)
            sha = hashlib.sha256(big_report).hexdigest()
            chunk_size = 2 * 1024 * 1024
            pieces = [big_report[i : i + chunk_size] for i in range(0, len(big_report), chunk_size)]
            assert len(pieces) == 3

            for idx in (0, 2):
                c_resp = client.post(
                    "/api/agent/scan/scan-quota/javelin/report/chunk",
                    headers={"X-Agent-Id": "ag-live-1"},
                    json={
                        "contract_version": 1,
                        "execution_revision": 1,
                        "agent_session_id": "sess-1",
                        "blob_sha256": sha,
                        "chunk_index": idx,
                        "total_chunks": 3,
                        "data_b64": base64.b64encode(pieces[idx]).decode("ascii"),
                    },
                )
                assert c_resp.status_code == 200

            # Commit before chunk 1 arrives -> returns missing_chunks=[1]
            incomplete = client.post(
                "/api/agent/scan/scan-quota/javelin/report",
                headers={"X-Agent-Id": "ag-live-1"},
                json={
                    "contract_version": 1,
                    "execution_revision": 1,
                    "agent_session_id": "sess-1",
                    "report_id": "rep-big",
                    "report_kind": "final",
                    "name": "big.md",
                    "staged": True,
                    "blob_sha256": sha,
                    "total_chunks": 3,
                },
            )
            assert incomplete.status_code == 200
            assert incomplete.json()["missing_chunks"] == [1]

            # Upload missing chunk 1 and commit -> success & staging dir removed
            client.post(
                "/api/agent/scan/scan-quota/javelin/report/chunk",
                headers={"X-Agent-Id": "ag-live-1"},
                json={
                    "contract_version": 1,
                    "execution_revision": 1,
                    "agent_session_id": "sess-1",
                    "blob_sha256": sha,
                    "chunk_index": 1,
                    "total_chunks": 3,
                    "data_b64": base64.b64encode(pieces[1]).decode("ascii"),
                },
            )
            complete = client.post(
                "/api/agent/scan/scan-quota/javelin/report",
                headers={"X-Agent-Id": "ag-live-1"},
                json={
                    "contract_version": 1,
                    "execution_revision": 1,
                    "agent_session_id": "sess-1",
                    "report_id": "rep-big",
                    "report_kind": "final",
                    "name": "big.md",
                    "staged": True,
                    "blob_sha256": sha,
                    "total_chunks": 3,
                },
            )
            assert complete.status_code == 200
            assert complete.json()["ok"] is True

            # Tampered chunk SHA mismatch -> 422 + immediate cleanup
            fake_sha = "a" * 64
            client.post(
                "/api/agent/scan/scan-quota/javelin/report/chunk",
                headers={"X-Agent-Id": "ag-live-1"},
                json={
                    "contract_version": 1,
                    "execution_revision": 1,
                    "agent_session_id": "sess-1",
                    "blob_sha256": fake_sha,
                    "chunk_index": 0,
                    "total_chunks": 1,
                    "data_b64": base64.b64encode(b"tampered").decode("ascii"),
                },
            )
            bad_commit = client.post(
                "/api/agent/scan/scan-quota/javelin/report",
                headers={"X-Agent-Id": "ag-live-1"},
                json={
                    "contract_version": 1,
                    "execution_revision": 1,
                    "agent_session_id": "sess-1",
                    "report_id": "rep-bad",
                    "report_kind": "final",
                    "name": "bad.md",
                    "staged": True,
                    "blob_sha256": fake_sha,
                    "total_chunks": 1,
                },
            )
            assert bad_commit.status_code == 422
            staging_root = tmp_path / "tmp" / "javelin-upload"
            assert not (staging_root / "scan-quota" / fake_sha).exists()

            # 72h stale upload directory GC
            stale_dir = staging_root / "scan-abandoned" / ("b" * 64)
            stale_dir.mkdir(parents=True, exist_ok=True)
            (stale_dir / "0000").write_bytes(b"part")
            cleaned = cleanup_stale_javelin_upload_staging(
                staging_root,
                max_age_seconds=72 * 3600,
                now_ts=time.time() + 73 * 3600,
            )
            assert cleaned == 1
            assert not stale_dir.exists()
    finally:
        store.close()


def test_p1_9_p1_10_p1_11_migration_deletion_compaction_findings_and_coverage_lru(tmp_path: Path) -> None:
    invalidate_javelin_coverage_cache()
    cfg, store, runtime, _uid, jwt = _setup_env(tmp_path, javelin_enabled=True)
    try:
        _seed_javelin_scan(store, "scan-a")
        _seed_javelin_scan(store, "scan-b")

        # P1 #9: Exact JSON engine_id == "javelin" backfill (javelin_v2 must stay c_cpp!)
        now = datetime.now(timezone.utc).isoformat()
        store._conn.execute(
            """
            INSERT INTO scans (scan_id, project_id, scan_name, scan_items, created_at, status, language, mining_engines_json)
            VALUES ('scan-fake-jav', 'p', 'fake-jav', '[]', ?, 'complete', 'c_cpp', '[{"engine_id":"javelin_v2","enabled":true}]')
            """,
            (now,),
        )
        store._conn.execute(
            """
            INSERT INTO scans (scan_id, project_id, scan_name, scan_items, created_at, status, language, mining_engines_json)
            VALUES ('scan-real-jav', 'p', 'real-jav', '[]', ?, 'complete', 'c_cpp', '[{"engine_id":"javelin","enabled":true}]')
            """,
            (now,),
        )
        store._conn.commit()
        updated_count = store.backfill_javelin_scan_language()
        assert updated_count == 1
        fake_lang = store._conn.execute("SELECT language FROM scans WHERE scan_id = 'scan-fake-jav'").fetchone()["language"]
        real_lang = store._conn.execute("SELECT language FROM scans WHERE scan_id = 'scan-real-jav'").fetchone()["language"]
        assert fake_lang == "c_cpp"
        assert real_lang == "java"

        # Event compaction (compacted=1) + late duplicate sequence idempotency
        store.append_javelin_events(
            "scan-a",
            execution_revision=1,
            events=[{"sequence": i, "event_type": "audit.runner_output", "body": f"line {i}"} for i in range(1, 45)],
            max_events_before_compact=20,
        )
        active_events = store.list_javelin_events("scan-a", limit=200, include_compacted=False)
        all_events = store.list_javelin_events("scan-a", limit=200, include_compacted=True)
        assert any(e["event_type"] == "audit.logs.compacted" for e in active_events)
        assert len(all_events) > len(active_events)
        # Re-sending compacted sequence=1 must NOT re-insert!
        dup_res = store.append_javelin_events(
            "scan-a",
            execution_revision=1,
            events=[{"sequence": 1, "event_type": "audit.runner_output", "body": "line 1"}],
            max_events_before_compact=20,
        )
        assert dup_res["inserted"] == 0

        # Single-tx javelin_findings + vulnerabilities + SQL trigger summary consistency + workflow sync
        store.upsert_javelin_artifacts(
            "scan-a",
            execution_revision=1,
            findings=[{
                "resource_id": "res-sqli-1",
                "finding_id": "F-001",
                "title": "MyBatis OrderBy SQL Injection",
                "severity": "HIGH",
                "cwe": "CWE-89",
                "primary_location": {"path": "src/main/java/com/mall/OrderDao.java", "line": 42, "symbol": "listOrders"},
                "summary": "Unvalidated sort column concatenated into SQL.",
                "adjudication_verdict": "TRUE_POSITIVE",
            }],
        )
        totals = store.get_scan_totals(["scan-a"])["scan-a"]
        assert int(totals["llm_issue_count"]) == 1
        assert int(totals["accuracy_basis_count"]) == 1
        store.update_javelin_finding_workflow("scan-a", "res-sqli-1", status="confirmed", note="Verified in OrderDao")
        totals_after = store.get_scan_totals(["scan-a"])["scan-a"]
        assert int(totals_after["human_confirmed_count"]) == 1

        # P1 #11: 20,000-file source-baseline /file-coverage 100 consecutive queries p95 < 300ms
        files_20k = {
            "files": [
                {"id": f"f-{i}", "path": f"src/main/java/com/mall/mod{i % 50}/Service{i}.java", "size": 1200, "eligible": True}
                for i in range(20_000)
            ]
        }
        baseline_bytes = json.dumps(files_20k).encode("utf-8")
        store.store_javelin_report(
            "scan-a",
            execution_revision=1,
            report_id="baseline-dh-scan-a",
            report_kind="source_baseline",
            name="source-baseline.dh-scan-a.json",
            format="json",
            raw_bytes=baseline_bytes,
        )
        store.upsert_javelin_tasks(
            "scan-a",
            execution_revision=1,
            tasks=[{
                "task_id": "T-1",
                "title": "Audit mod0",
                "status": "REPORTED",
                "file_ids": ["f-0", "f-1", "f-2"],
            }],
        )

        with use_runtime(runtime):
            client = TestClient(app)
            headers = {"Authorization": f"Bearer {jwt}"}
            first_cov = client.get("/api/v2/scans/scan-a/javelin/file-coverage?limit=100", headers=headers)
            assert first_cov.status_code == 200
            assert first_cov.json()["summary"]["total_files"] == 20_000

            durations_ms: list[float] = []
            for idx in range(100):
                t0 = time.perf_counter()
                r = client.get(
                    f"/api/v2/scans/scan-a/javelin/file-coverage?offset={(idx * 100) % 19000}&limit=100",
                    headers=headers,
                )
                durations_ms.append((time.perf_counter() - t0) * 1000.0)
                assert r.status_code == 200
            durations_ms.sort()
            p95_ms = durations_ms[94]
            assert p95_ms < 300.0, f"Expected p95 < 300ms, got {p95_ms:.2f}ms"

        # P1 #10: Shared blob deduplication, FK-safe scan deletion, and 1h grace blob GC
        shared_bytes = b"# Shared report content"
        shared_sha = hashlib.sha256(shared_bytes).hexdigest()
        for sid in ("scan-a", "scan-b"):
            store.store_javelin_report(
                sid,
                execution_revision=1,
                report_id="shared-rep",
                report_kind="task",
                name="shared.md",
                format="markdown",
                raw_bytes=shared_bytes,
            )
            store.update_scan_progress(sid, status=ScanItemStatus.COMPLETE, progress=1.0)

        # Delete scan-a -> shared blob MUST survive because scan-b still references it!
        store.request_scan_deletion("scan-a")
        store.process_scan_deletions(limit=100)
        assert store.get_javelin_blob_bytes(shared_sha) == shared_bytes

        # Delete scan-b -> within 1h grace period, blob still survives concurrent-upload window
        store.request_scan_deletion("scan-b")
        store.process_scan_deletions(limit=100)
        store.run_storage_maintenance("owner-1", {"enabled": True, "javelin_blob_gc_grace_seconds": 3600})
        assert store.get_javelin_blob_bytes(shared_sha) == shared_bytes

        # Backdate last_referenced_at past 1h grace -> maintenance GC reclaims unreferenced blob!
        old_ts = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        store._conn.execute(
            "UPDATE javelin_report_blobs SET last_referenced_at = ?",
            (old_ts,),
        )
        store._conn.execute("DELETE FROM storage_maintenance_jobs")
        store._conn.commit()
        gc_res = store.run_storage_maintenance("owner-1", {"enabled": True, "javelin_blob_gc_grace_seconds": 3600})
        assert gc_res["counts"].get("javelin_report_blobs", 0) >= 1
        assert store.get_javelin_blob_bytes(shared_sha) is None
    finally:
        store.close()


def test_db_overhead_zero_javelin_queries_on_cpp_scans_and_batched_for_java(tmp_path: Path) -> None:
    _cfg, store, runtime, uid, jwt = _setup_env(tmp_path, javelin_enabled=True)
    try:
        now = datetime.now(timezone.utc).isoformat()
        cpp_sel = MiningEngineSelection(engine_id="static_candidate", engine_label="Static", enabled=True)
        for i in range(5):
            sid = f"cpp-{i}"
            store.save_scan(
                ScanStatus(
                    scan_id=sid,
                    project_id="cpp",
                    scan_name=f"cpp-scan-{i}",
                    project_path="/srv/cpp",
                    code_scan_path="/srv/cpp",
                    scan_mode="standard",
                    product="Core",
                    mining_engines=[cpp_sel],
                    created_at=now,
                    status=ScanItemStatus.COMPLETE,
                    progress=1.0,
                    total_candidates=0,
                    processed_candidates=0,
                    vulnerabilities=[],
                ),
                ScanMeta(
                    scan_items=[],
                    created_at=now,
                    scan_mode="standard",
                    mining_engines=[cpp_sel],
                    project_path="/srv/cpp",
                    code_scan_path="/srv/cpp",
                    scan_name=f"cpp-scan-{i}",
                    product="Core",
                    user_id=uid,
                ),
            )

        with (
            use_runtime(runtime),
            patch.object(store, "get_javelin_audit_states_by_scans", wraps=store.get_javelin_audit_states_by_scans) as spy_states,
            patch.object(store, "get_agents_javelin_metadata_batch", wraps=store.get_agents_javelin_metadata_batch) as spy_agents,
        ):
            client = TestClient(app)
            headers = {"Authorization": f"Bearer {jwt}"}
            r_cpp = client.get("/api/v2/scans?limit=20", headers=headers)
            assert r_cpp.status_code == 200
            assert len(r_cpp.json()["items"]) == 5
            # Pure C/C++ scan page MUST issue 0 Javelin DB queries!
            assert spy_states.call_count == 0
            assert spy_agents.call_count == 0

            # Now add 6 Javelin scans across 2 agents -> still at most 1 batched call each (zero N+1)!
            for j in range(6):
                _seed_javelin_scan(
                    store,
                    f"jav-batch-{j}",
                    user_id=uid,
                    agent_key=f"ag-k-{j % 2}",
                    agent_id=f"ag-id-{j % 2}",
                )
            r_mixed = client.get("/api/v2/scans?limit=30", headers=headers)
            assert r_mixed.status_code == 200
            assert len(r_mixed.json()["items"]) == 11
            assert spy_states.call_count == 1
            assert spy_agents.call_count == 1
    finally:
        store.close()


def test_agent_runtime_packaging_hash_symmetry() -> None:
    server_files = [rel for rel, _ in iter_agent_runtime_files()]
    client_files = [rel for rel, _ in _iter_runtime_files(runtime_root())]
    assert server_files == client_files
    assert any(rel.startswith("third_party/Javelin/.opencode/") for rel in server_files)
    assert any(rel.startswith("javelin_runtime_deps/node_modules/") for rel in server_files)
    assert not any("dynamic-validation-observatory/public/" in rel for rel in server_files)
    assert get_cached_agent_runtime_hash(check_stat=True) == compute_runtime_hash()
