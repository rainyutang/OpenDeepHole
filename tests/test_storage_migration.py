import json
import sqlite3

import pytest

from backend.store.sqlite import SqliteScanStore
from scripts.migrate_scan_storage import main
from test_storage_history import make_store, task
from backend.models import Vulnerability, FpReviewResult


def test_migration_reopens_cursor_and_verifies_all_task_content(tmp_path):
    store = make_store(tmp_path)
    original = {"total_tasks": 7, "completed_task_count": 7,
                "completed_tasks": [task(index) for index in range(7)],
                "unknown_recovery_checkpoint": {"cursor": 999, "scope": "keep"}}
    raw = json.dumps(original, ensure_ascii=False)
    store._conn.execute("UPDATE scans SET opencode_pool = ?, history_version = 0", (raw,))
    store._conn.commit()
    first = store.backfill_storage_batch(batch_rows=2)
    assert first["processed"] == 2
    assert first["cursor"]["offset"] == 2
    # Before cutover legacy APIs still expose all seven historical tasks.
    assert len(store.load_scan("s")[0].opencode_pool.completed_tasks) == 7
    store.close()
    store = SqliteScanStore(tmp_path / "history.db")
    try:
        second = store.backfill_storage_batch(batch_rows=2)
        assert second["cursor"]["offset"] == 4
        while not store.backfill_storage_batch(batch_rows=2)["complete"]:
            pass
        assert store.verify_scan_history("s")["ok"]
        assert len(store.load_scan("s")[0].opencode_pool.completed_tasks) == 7
        assert store._conn.execute("SELECT payload_json FROM scan_legacy_payloads").fetchone()[0] == raw
        assert store.storage_migration_status()["remaining_scans"] == 0
        assert store.cleanup_verified_receipts() == 0
    finally:
        store.close()


def test_bad_legacy_json_and_oversize_snapshot_never_destroy_source(tmp_path):
    store = make_store(tmp_path)
    try:
        store._conn.execute("UPDATE scans SET opencode_pool = 'broken', history_version = 0")
        store._conn.commit()
        with pytest.raises(ValueError):
            store.backfill_storage_batch()
        assert store._conn.execute("SELECT opencode_pool FROM scans").fetchone()[0] == "broken"
        assert next(item for item in store.storage_migration_status()["migrations"] if item["name"] == "scan-history-v1")["status"] == "error"
        raw = json.dumps({"completed_tasks": [task()]})
        store._conn.execute("UPDATE scans SET opencode_pool = ?", (raw,))
        store._conn.commit()
        with pytest.raises(ValueError, match="byte limit"):
            store.backfill_storage_batch(batch_bytes=10)
        assert store._conn.execute("SELECT opencode_pool FROM scans").fetchone()[0] == raw
    finally:
        store.close()


def test_cli_check_is_read_only_and_requires_explicit_target(tmp_path, capsys):
    store = make_store(tmp_path)
    path = tmp_path / "history.db"
    store.close()
    before = path.read_bytes()
    assert main(["--sqlite", str(path), "check"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["rows"]["scans"] == 1
    assert path.read_bytes() == before
    connection = sqlite3.connect(path)
    count = connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
    connection.close()
    assert count == 2
    with pytest.raises(SystemExit):
        main(["check"])


def test_corrupted_destination_fails_verification_and_retains_archive(tmp_path):
    store = make_store(tmp_path)
    raw = json.dumps({"completed_tasks": [task()], "completed_task_count": 1})
    store._conn.execute("UPDATE scans SET opencode_pool = ?, history_version = 0", (raw,))
    store._conn.commit()
    try:
        store.backfill_storage_batch()
        store._conn.execute("UPDATE scan_task_versions SET task_json = '{}' WHERE scan_id = 's'")
        store._conn.commit()
        assert store.verify_scan_history("s")["ok"] is False
        assert store._conn.execute("SELECT payload_json FROM scan_legacy_payloads").fetchone()[0] == raw
        assert store._conn.execute("SELECT verified_at FROM scan_legacy_payloads").fetchone()[0] == ""
    finally:
        store.close()


def test_receipt_cleanup_compares_json_content_instead_of_formatting(tmp_path):
    from test_storage_history import receipt
    store = make_store(tmp_path)
    value = task()
    receipt(store, value)
    store._conn.execute("UPDATE opencode_task_reports SET task_json = ?", (json.dumps(value, indent=2, ensure_ascii=False),))
    store._conn.commit()
    assert store.verify_scan_history("s")["ok"]
    assert store.cleanup_verified_receipts() == 0
    store._conn.execute("UPDATE scan_migration_checks SET checked_at = '2000-01-01' WHERE kind = 'receipts'")
    store._conn.commit()
    assert store.cleanup_verified_receipts() == 1
    assert store.get_task_detail("s", value["task_id"]) == value
    store.close()


def test_body_backfill_and_explicit_cleanup_preserve_original_information(tmp_path):
    store = make_store(tmp_path)
    finding = Vulnerability(file="a.c", line=7, function="f", vuln_type="npd", severity="high", description="old",
                            vulnerability_report="完整历史报告", function_source="source", ai_analysis="analysis",
                            confirmed=True, ai_verdict="confirmed", user_verdict="confirmed", user_verdict_reason="人工确认")
    store.add_vulnerability("s", finding)
    store._conn.execute("UPDATE vulnerabilities SET audit_body_id = NULL, vulnerability_report = ?, function_source = ?, ai_analysis = ?", (finding.vulnerability_report, finding.function_source, finding.ai_analysis))
    store.create_fp_review_job("r", "s", 1, "2026-01-01")
    store._conn.execute("INSERT INTO fp_review_stage_outputs (review_id, vuln_index, stage, markdown, created_at, updated_at) VALUES ('r', 0, 'proof', '历史阶段正文', '2026-01-01', '2026-01-01')")
    store._conn.execute("INSERT INTO fp_review_results (review_id, vuln_index, verdict, reason, stage_outputs, created_at) VALUES ('r', 0, 'tp', 'old reason', ?, '2026-01-01')", (json.dumps({"proof": "历史阶段正文"}),))
    store._conn.commit()
    while not store.backfill_bodies_batch(batch_rows=1)["complete"]:
        pass
    assert store.verify_scan_history("s")["ok"]
    assert store.cleanup_verified_archives() == 0
    store._conn.execute("UPDATE scan_legacy_payloads SET verified_at = '2000-01-01'")
    store._conn.commit()
    assert store.cleanup_verified_archives() == 3
    assert store.verify_scan_history("s")["ok"]
    actual = store.get_vulnerabilities("s")[0]
    assert actual.vulnerability_report == finding.vulnerability_report
    assert actual.user_verdict_reason == finding.user_verdict_reason
    assert store.get_fp_review_job("r").results[0].stage_outputs == {"proof": "历史阶段正文"}
    # Only duplicates were removed; old records still reconstruct exactly in
    # terms of fields and content, including manual decisions.
    archives = store._conn.execute("SELECT payload_json FROM scan_legacy_payloads WHERE payload_format = 1").fetchall()
    assert any(store._restore_archive_manifest(json.loads(row[0])).get("user_verdict_reason") == "人工确认" for row in archives)
    store.restore_legacy_scan_fields("s")
    assert store._conn.execute("SELECT vulnerability_report FROM vulnerabilities").fetchone()[0] == "完整历史报告"
    assert store._conn.execute("SELECT markdown FROM fp_review_stage_outputs").fetchone()[0] == "历史阶段正文"
    assert store.get_vulnerabilities("s")[0].user_verdict_reason == "人工确认"
    while not store.backfill_storage_batch()["complete"]:
        pass
    while not store.backfill_bodies_batch()["complete"]:
        pass
    assert store.verify_scan_history("s")["ok"]
    store.close()
