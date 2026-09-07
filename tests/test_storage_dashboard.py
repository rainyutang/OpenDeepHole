from unittest.mock import patch
from types import SimpleNamespace

from backend.api.admin import _build_checker_dashboard, _build_checker_dashboard_v2
from backend.models import ScanStatus, ScanMeta, Vulnerability, OpenCodePoolStatus, OpenCodeTokenUsage
from test_storage_history import make_store


def test_sql_dashboard_matches_legacy_with_sparse_indexes_and_scope(tmp_path):
    store = make_store(tmp_path)
    store._conn.execute("UPDATE scans SET scan_items = '[\"npd\"]', user_id = 'alice', product = 'A'")
    store._conn.commit()
    finding = Vulnerability(file="a", line=1, function="f", vuln_type="npd", description="report", severity="high", ai_verdict="confirmed", confirmed=True)
    store.add_vulnerability("s", finding)
    store._conn.execute("UPDATE vulnerabilities SET idx = 42")
    store._conn.commit()
    store.rebuild_scan_summary("s")
    for scan_id, owner, product in (("s2", "alice", "B"), ("s3", "bob", "A")):
        store.save_scan(ScanStatus(scan_id=scan_id, project_id=scan_id, scan_items=["npd"], created_at="2026-01-01", status="complete", progress=1,
                                  total_candidates=0, processed_candidates=0, vulnerabilities=[]),
                        ScanMeta(scan_items=["npd"], created_at="2026-01-01", user_id=owner, product=product, scan_name=scan_id))
    for scan_id in ("s", "s2", "s3"):
        store.upsert_scan_opencode_token_usage(scan_id=scan_id, agent_session_id="session", status=OpenCodePoolStatus(token_usage=OpenCodeTokenUsage(input_tokens=10, total_tokens=10)))
    registry = {"npd": SimpleNamespace(label="NPD", description="", user_created=False)}
    with patch("backend.api.admin.refresh_registry", return_value=registry):
        before = _build_checker_dashboard(store, "A", "alice")
        after = _build_checker_dashboard_v2(store, "A", "alice")
        assert before.summary == after.summary
        assert after.token_usage.scan_count == 2
        assert after.token_usage.usage.total_tokens == 20
        assert after.products == ["A", "B"]
        assert after.checkers[0].scans == []
        assert [row["scan_id"] for row in store.list_checker_scans_page("npd", user_id="alice", product="A")] == ["s"]
        # Both paths work during online backfill, without full ScanStatus reads.
        store._conn.execute("UPDATE scan_summary_state SET ready = 0")
        store._conn.commit()
        assert _build_checker_dashboard_v2(store, "A", "alice").summary == before.summary
    store.close()
