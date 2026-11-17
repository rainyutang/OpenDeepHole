from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

import backend.auth as auth_module
from backend.api import auth as auth_api
from backend.auth import create_token, hash_password
from backend.models import FpReviewResult, ScanMeta, ScanStatus, Vulnerability
from backend.store.postgres import (
    PostgresScanStore,
    _Connection,
    _PG_CREATE_TRIGGER,
    _PG_TRIGGER_FN,
    _sqlite_schema,
)
from backend.store.sqlite import SqliteScanStore
from backend.store.summaries import summary_triggers


def _finding(index: int, vuln_type: str = "npd") -> Vulnerability:
    return Vulnerability(
        file=f"src/f{index}.c",
        line=index + 1,
        function="parse",
        vuln_type=vuln_type,
        severity="high",
        description="issue",
        confirmed=True,
        ai_verdict="confirmed",
    )


def _save_scan(
    store: SqliteScanStore,
    scan_id: str,
    user_id: str,
    *,
    scan_items: list[str] | None = None,
    created_at: str = "2026-11-01T00:00:00+00:00",
) -> None:
    items = ["npd", "oob"] if scan_items is None else scan_items
    store.save_scan(
        ScanStatus(
            scan_id=scan_id,
            project_id=f"proj-{scan_id}",
            created_at=created_at,
            status="complete",
            progress=1.0,
            total_candidates=0,
            processed_candidates=0,
            vulnerabilities=[],
        ),
        ScanMeta(
            scan_items=items,
            created_at=created_at,
            scan_name=f"name-{scan_id}",
            user_id=user_id,
        ),
    )


def test_legacy_users_table_upgrades_and_postgres_schema_exports_departments(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "legacy_users.db"
    raw = sqlite3.connect(str(db_path))
    raw.execute(
        """
        CREATE TABLE users (
            user_id       TEXT PRIMARY KEY,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'user',
            agent_token   TEXT NOT NULL,
            created_at    TEXT NOT NULL
        )
        """
    )
    raw.execute(
        """
        INSERT INTO users (user_id, username, password_hash, role, agent_token, created_at)
        VALUES ('u-legacy', 'legacy_user', 'hash', 'user', 'tok', '2026-01-01T00:00:00+00:00')
        """
    )
    raw.commit()
    raw.close()

    store = SqliteScanStore(db_path)
    try:
        migrated = store.get_user_by_id("u-legacy")
        assert migrated is not None
        assert migrated.employee_id == ""
        assert migrated.department_id == ""
        assert migrated.department_name == ""

        summaries = store.list_admin_users()
        assert len(summaries) == 1
        assert summaries[0].username == "legacy_user"
        assert summaries[0].scan_count == 0
        assert summaries[0].suspected_issue_count == 0
        sqlite_indexes = {
            str(r[0])
            for r in store._conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            ).fetchall()
        }
        assert "storage_idx_checker_totals_suspected" in sqlite_indexes
        assert "idx_scan_checker_totals_suspected" not in sqlite_indexes
    finally:
        store.close()

    portable_ddl = "\n".join(_sqlite_schema())
    assert "CREATE TABLE IF NOT EXISTS departments" in portable_ddl
    assert "idx_departments_name" not in portable_ddl
    assert "employee_id" in portable_ddl
    assert "department_id" in portable_ddl
    assert "idx_users_department" in portable_ddl
    # Deferred to empty-table check / prepare_storage_online_indexes(CONCURRENTLY)
    assert "storage_idx_checker_totals_suspected" not in portable_ddl
    assert "idx_scan_checker_totals_suspected" not in portable_ddl


def test_postgres_connection_releases_readonly_cte_and_retains_modifying_cte() -> None:
    class FakeCursor:
        rowcount = 1

        def fetchone(self):
            return {"ok": 1}

        def fetchall(self):
            return [{"ok": 1}]

    class FakeRawConn:
        closed = False
        broken = False

        def __init__(self) -> None:
            self.rollbacks = 0
            self.commits = 0

        def execute(self, _sql, _params=()):
            return FakeCursor()

        def rollback(self) -> None:
            self.rollbacks += 1

        def commit(self) -> None:
            self.commits += 1

    class SingleSlotPool:
        def __init__(self) -> None:
            self.raw = FakeRawConn()
            self.available = [self.raw]

        def getconn(self):
            if not self.available:
                raise TimeoutError("PoolTimeout: connection leaked in transaction")
            return self.available.pop()

        def putconn(self, conn) -> None:
            self.available.append(conn)

    pool = SingleSlotPool()
    pg_conn = _Connection(pool)

    readonly_ctes = [
        "WITH scan_counts AS (SELECT user_id, COUNT(*) FROM scans GROUP BY user_id) SELECT * FROM scan_counts",
        "WITH RECURSIVE t(n) AS (VALUES (1) UNION ALL SELECT n + 1 FROM t WHERE n < 3) SELECT * FROM t",
        "WITH scoped AS MATERIALIZED (SELECT 'UPDATE' AS txt FROM users) SELECT * FROM scoped",
        "/* leading comment */ -- line comment\nWITH a AS (SELECT $$ ) DELETE $$ AS s), b AS (SELECT 1) (SELECT * FROM a UNION ALL SELECT 'x' FROM b)",
        "EXPLAIN (ANALYZE, BUFFERS) WITH x AS (SELECT 1) SELECT * FROM x",
    ]
    for query in readonly_ctes:
        assert _Connection._is_write(query) is False, query
        rows = pg_conn.execute(query).fetchall()
        assert rows == [{"ok": 1}]
        # Must have rolled back read snapshot and returned the single slot immediately!
        assert len(pool.available) == 1

    modifying_ctes = [
        "WITH claimed AS (SELECT id FROM agent_commands FOR UPDATE SKIP LOCKED) UPDATE agent_commands SET status = 'delivering' FROM claimed WHERE agent_commands.id = claimed.id RETURNING *",
        "WITH deleted AS (DELETE FROM scans WHERE scan_id = ? RETURNING scan_id) SELECT * FROM deleted",
        "WITH src AS (SELECT 1) INSERT INTO departments VALUES ('d', 'n', 't', 't')",
        "SELECT 1; UPDATE users SET employee_id = 'x'",
    ]
    for query in modifying_ctes:
        assert _Connection._is_write(query) is True, query

    # Verify a modifying CTE holds the connection dirty until commit()
    pg_conn.execute(modifying_ctes[0], ()).fetchall()
    assert len(pool.available) == 0
    pg_conn.commit()
    assert len(pool.available) == 1


def test_postgres_bootstrap_preserves_ready_summaries_when_triggers_unchanged() -> None:
    summary_stmts = summary_triggers(postgres=True)
    fn_map = {}
    trig_names = set()
    for stmt in summary_stmts:
        m_fn = _PG_TRIGGER_FN.match(stmt.strip())
        if m_fn:
            fn_map[m_fn.group(1).lower()] = m_fn.group(2).strip()
        m_tr = _PG_CREATE_TRIGGER.match(stmt.strip())
        if m_tr:
            trig_names.add(m_tr.group(1).lower())

    def run_bootstrap(*, has_expand_marker: bool, trigger_marker_sig: str | None, tamper_pg_proc: bool, totals_populated: bool):
        executed_sql: list[str] = []

        class MockBootResult:
            def __init__(self, rows):
                self._rows = rows

            def fetchone(self):
                return self._rows[0] if self._rows else None

            def fetchall(self):
                return list(self._rows)

        class MockBootConn:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def execute(self, sql: str, params=()):
                executed_sql.append(sql.strip())
                s = sql.strip()
                if "to_regclass('schema_migrations')" in s:
                    return MockBootResult([{"name": "schema_migrations" if has_expand_marker or trigger_marker_sig else None}])
                if "WHERE name = 'scan-storage-expand-v1'" in s:
                    return MockBootResult([{"cursor_json": '{"signature":"old-schema","fingerprint":"old-fp"}'}] if has_expand_marker else [])
                if "WHERE name = 'scan-storage-triggers-v1'" in s:
                    return MockBootResult([{"cursor_json": f'{{"signature":"{trigger_marker_sig}"}}'}] if trigger_marker_sig else [])
                if "AS fingerprint" in s:
                    return MockBootResult([{"fingerprint": "new-fp"}])
                if "information_schema.columns" in s:
                    return MockBootResult([
                        {"table_name": "scans", "column_name": "mining_engine_runs_json"},
                        {"table_name": "scans", "column_name": "user_id"},
                        {"table_name": "scan_candidates", "column_name": "audit_state"},
                    ])
                if "SELECT 1 FROM scan_checker_totals LIMIT 1" in s:
                    return MockBootResult([{"1": 1}] if totals_populated else [])
                if "FROM pg_proc p" in s:
                    rows = [
                        {"proname": k, "prosrc": ("CHANGED" if tamper_pg_proc else v)}
                        for k, v in fn_map.items()
                    ]
                    return MockBootResult(rows)
                if "FROM pg_trigger t" in s:
                    return MockBootResult([{"tgname": k} for k in trig_names])
                return MockBootResult([{"acquired": True}])

            def commit(self):
                pass

        class MockPool:
            def connection(self):
                return MockBootConn()

        dummy = object.__new__(PostgresScanStore)
        dummy._pool = MockPool()
        dummy._conn = type("DummyConn", (), {"commit": lambda self: None})()
        dummy._bootstrap()
        return executed_sql

    # 1. Existing DB upgrading from scan-storage-expand-v1 (triggers unchanged in pg_proc, populated scan_checker_totals)
    sql_upgrade = run_bootstrap(
        has_expand_marker=True,
        trigger_marker_sig=None,
        tamper_pg_proc=False,
        totals_populated=True,
    )
    assert "UPDATE scan_summary_state SET ready = 0" not in sql_upgrade
    assert not any("CREATE INDEX IF NOT EXISTS storage_idx_checker_totals_suspected" in s for s in sql_upgrade)
    assert any("scan-storage-triggers-v1" in s for s in sql_upgrade)

    # 2. Empty DB builds storage_idx_checker_totals_suspected immediately and resets ready = 0 on initial bootstrap
    sql_fresh = run_bootstrap(
        has_expand_marker=False,
        trigger_marker_sig=None,
        tamper_pg_proc=False,
        totals_populated=False,
    )
    assert "UPDATE scan_summary_state SET ready = 0" in sql_fresh
    assert any("CREATE INDEX IF NOT EXISTS storage_idx_checker_totals_suspected" in s for s in sql_fresh)

    # 3. Existing DB where summary trigger function changed -> MUST reset ready = 0
    sql_trig_changed = run_bootstrap(
        has_expand_marker=True,
        trigger_marker_sig="stale-trigger-sig",
        tamper_pg_proc=True,
        totals_populated=True,
    )
    assert "UPDATE scan_summary_state SET ready = 0" in sql_trig_changed


def test_hot_path_auth_avoids_join_and_steady_state_skips_vulnerability_tables(
    tmp_path: Path,
) -> None:
    store = SqliteScanStore(tmp_path / "perf_plan.db")
    try:
        dept = store.create_department("安全研究部")
        store.create_user(
            "u-1",
            "alice",
            "pw",
            "user",
            "tok-1",
            employee_id="E001",
            department_id=dept.department_id,
        )
        _save_scan(store, "s-1", "u-1", scan_items=["npd"])
        store.add_vulnerability("s-1", _finding(0, "npd"))
        now = "2026-11-02T00:00:00+00:00"
        store.create_fp_review_job("r-1", "s-1", 1, now)
        store.add_fp_review_result(
            "r-1", FpReviewResult(vuln_index=0, verdict="tp", reason="confirmed tp", created_at=now)
        )
        store._conn.execute(
            "INSERT INTO schema_migrations (name, status) VALUES ('scan-summaries-v1', 'complete') "
            "ON CONFLICT(name) DO UPDATE SET status = 'complete'"
        )
        store._conn.commit()

        executed: list[str] = []
        store._conn.set_trace_callback(executed.append)
        try:
            user = store.get_user_by_id("u-1")
            assert user is not None and user.employee_id == "E001"
            assert not any("departments" in sql for sql in executed)

            executed.clear()
            rows = store.list_admin_users()
            assert len(rows) == 1
            assert rows[0].scan_count == 1
            assert rows[0].suspected_issue_count == 1
            assert rows[0].department_name == "安全研究部"
            assert not any("vulnerabilities" in sql or "fp_review_results" in sql for sql in executed)
        finally:
            store._conn.set_trace_callback(None)
    finally:
        store.close()


def test_user_scan_and_suspected_issue_aggregates_filter_and_sort(
    tmp_path: Path,
) -> None:
    store = SqliteScanStore(tmp_path / "stats.db")
    try:
        sec_dept = store.create_department("  安全研究部  ")
        dev_dept = store.create_department("平台研发部")
        assert sec_dept.name == "安全研究部"

        store.create_user(
            "u-alice",
            "alice",
            "pw",
            "user",
            "tok-a",
            employee_id=" E1001 ",
            department_id=sec_dept.department_id,
        )
        store.create_user(
            "u-bob",
            "bob",
            "pw",
            "user",
            "tok-b",
            employee_id="E1001",  # 允许同工号多账号备注
            department_id=dev_dept.department_id,
        )
        store.create_user(
            "u-carol",
            "carol",
            "pw",
            "user",
            "tok-c",
        )

        # Alice: 3 scans created, 1 deleted -> 2 active scans.
        # Scan a1: multi-checker scan with 2 TP and 1 FP across two checkers (must NOT double count).
        _save_scan(store, "a1", "u-alice", scan_items=["npd", "oob"])
        store.add_vulnerability("a1", _finding(0, "npd"))
        store.add_vulnerability("a1", _finding(1, "oob"))
        store.add_vulnerability("a1", _finding(2, "npd"))
        now = "2026-11-02T00:00:00+00:00"
        store.create_fp_review_job("rev-a1", "a1", 3, now)
        store.add_fp_review_result(
            "rev-a1", FpReviewResult(vuln_index=0, verdict="tp", reason="real bug", created_at=now)
        )
        store.add_fp_review_result(
            "rev-a1", FpReviewResult(vuln_index=1, verdict="tp", reason="real oob", created_at=now)
        )
        store.add_fp_review_result(
            "rev-a1", FpReviewResult(vuln_index=2, verdict="fp", reason="benign", created_at=now)
        )

        # Scan a2: empty threat-only scan (scan_items=[]), counts toward scan_count.
        _save_scan(store, "a2", "u-alice", scan_items=[])

        # Scan a3: deleted scan with 1 TP -> must be excluded from both counts!
        _save_scan(store, "a3", "u-alice", scan_items=["npd"])
        store.add_vulnerability("a3", _finding(0, "npd"))
        store.create_fp_review_job("rev-a3", "a3", 1, now)
        store.add_fp_review_result(
            "rev-a3", FpReviewResult(vuln_index=0, verdict="tp", reason="deleted", created_at=now)
        )
        store._conn.execute("UPDATE fp_review_jobs SET status = 'complete' WHERE review_id = 'rev-a3'")
        store._conn.commit()
        assert store.request_scan_deletion("a3") is not None

        # Bob: 1 legacy un-backfilled scan (ready = 0) with 4 TP findings!
        _save_scan(store, "b1", "u-bob", scan_items=["npd"])
        for idx in range(4):
            store.add_vulnerability("b1", _finding(idx, "npd"))
        store.create_fp_review_job("rev-b1", "b1", 4, now)
        for idx in range(4):
            store.add_fp_review_result(
                "rev-b1", FpReviewResult(vuln_index=idx, verdict="tp", reason="legacy tp", created_at=now)
            )
        store._conn.execute("UPDATE scan_summary_state SET ready = 0 WHERE scan_id = 'b1'")
        store._conn.execute("DELETE FROM scan_checker_totals WHERE scan_id = 'b1'")
        store._conn.execute("DELETE FROM scan_issue_facts WHERE scan_id = 'b1'")
        store._conn.commit()

        by_scan_desc = store.list_admin_users(sort_by="scan_count", sort_order="desc")
        assert [(u.username, u.scan_count, u.suspected_issue_count) for u in by_scan_desc] == [
            ("alice", 2, 2),
            ("bob", 1, 4),
            ("carol", 0, 0),
        ]
        assert by_scan_desc[0].employee_id == "E1001"
        assert by_scan_desc[0].department_name == "安全研究部"

        by_issue_desc = store.list_admin_users(sort_by="suspected_issue_count", sort_order="desc")
        assert [u.username for u in by_issue_desc] == ["bob", "alice", "carol"]

        by_issue_asc = store.list_admin_users(sort_by="suspected_issue_count", sort_order="asc")
        assert [u.username for u in by_issue_asc] == ["carol", "alice", "bob"]

        sec_only = store.list_admin_users(department_id=sec_dept.department_id)
        assert [u.username for u in sec_only] == ["alice"]

        unassigned = store.list_admin_users(department_id="__unassigned__")
        assert [u.username for u in unassigned] == ["carol"]
    finally:
        store.close()


def test_admin_user_and_department_pool_api_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = SqliteScanStore(tmp_path / "api.db")
    monkeypatch.setattr(auth_module, "get_scan_store", lambda: store)
    monkeypatch.setattr(auth_api, "get_scan_store", lambda: store)

    admin_hash = hash_password("admin123")
    user_hash = hash_password("user123")
    store.create_user("admin-1", "root_admin", admin_hash, "admin", "tok-admin")
    store.create_user("user-1", "normal_user", user_hash, "user", "tok-user")

    admin_headers = {"Authorization": f"Bearer {create_token('admin-1', 'root_admin', 'admin')}"}
    user_headers = {"Authorization": f"Bearer {create_token('user-1', 'normal_user', 'user')}"}

    app = FastAPI()
    app.include_router(auth_api.router)

    async def exercise() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            # Non-admin receives 403 on all user/department admin endpoints
            for method, url in [
                ("GET", "/api/auth/users"),
                ("GET", "/api/auth/departments"),
                ("POST", "/api/auth/departments"),
                ("PUT", "/api/auth/users/user-1/profile"),
            ]:
                resp = await client.request(method, url, headers=user_headers, json={"name": "X"})
                assert resp.status_code == 403

            # Department Pool CRUD + validation
            empty_resp = await client.post(
                "/api/auth/departments", headers=admin_headers, json={"name": "   "}
            )
            assert empty_resp.status_code == 400

            create_sec = await client.post(
                "/api/auth/departments", headers=admin_headers, json={"name": " 安全部 "}
            )
            assert create_sec.status_code == 200
            sec = create_sec.json()
            assert sec["name"] == "安全部"
            assert sec["user_count"] == 0

            dup_resp = await client.post(
                "/api/auth/departments", headers=admin_headers, json={"name": "安全部"}
            )
            assert dup_resp.status_code == 409

            create_ops = await client.post(
                "/api/auth/departments", headers=admin_headers, json={"name": "运维部"}
            )
            assert create_ops.status_code == 200
            ops = create_ops.json()

            # Update existing user's employee_id and department_id (including admin self)
            upd_admin = await client.put(
                "/api/auth/users/admin-1/profile",
                headers=admin_headers,
                json={"employee_id": " A001 ", "department_id": sec["department_id"]},
            )
            assert upd_admin.status_code == 200
            assert upd_admin.json()["employee_id"] == "A001"
            assert upd_admin.json()["department_name"] == "安全部"

            # Create new user with employee_id & department_id
            created_user = await client.post(
                "/api/auth/users",
                headers=admin_headers,
                json={
                    "username": "auditor",
                    "password": "secret",
                    "role": "user",
                    "employee_id": "A001",  # non-unique employee_id allowed
                    "department_id": sec["department_id"],
                },
            )
            assert created_user.status_code == 200
            auditor = created_user.json()
            assert auditor["employee_id"] == "A001"
            assert auditor["department_id"] == sec["department_id"]
            assert auditor["department_name"] == "安全部"
            assert auditor["scan_count"] == 0
            assert auditor["suspected_issue_count"] == 0

            # Invalid department and overly long employee_id rejected with 400
            bad_dept = await client.put(
                f"/api/auth/users/{auditor['user_id']}/profile",
                headers=admin_headers,
                json={"employee_id": "A002", "department_id": "missing-dept"},
            )
            assert bad_dept.status_code == 400

            too_long_emp = await client.put(
                f"/api/auth/users/{auditor['user_id']}/profile",
                headers=admin_headers,
                json={"employee_id": "X" * 65, "department_id": ""},
            )
            assert too_long_emp.status_code == 400

            # Department list reflects user_count = 2
            depts = (await client.get("/api/auth/departments", headers=admin_headers)).json()
            assert [(d["name"], d["user_count"]) for d in depts] == [
                ("安全部", 2),
                ("运维部", 0),
            ]

            # Rename department propagates to users in /api/auth/users and store
            renamed = await client.put(
                f"/api/auth/departments/{sec['department_id']}",
                headers=admin_headers,
                json={"name": "产品安全部"},
            )
            assert renamed.status_code == 200
            assert renamed.json()["name"] == "产品安全部"
            assert renamed.json()["user_count"] == 2

            users_after_rename = (await client.get("/api/auth/users", headers=admin_headers)).json()
            admin_entry = next(u for u in users_after_rename if u["username"] == "root_admin")
            assert admin_entry["department_name"] == "产品安全部"
            assert admin_entry["employee_id"] == "A001"

            # Rename collision rejected with 409
            collision = await client.put(
                f"/api/auth/departments/{ops['department_id']}",
                headers=admin_headers,
                json={"name": "产品安全部"},
            )
            assert collision.status_code == 409

            # Filter users via API query params
            filtered = await client.get(
                "/api/auth/users",
                headers=admin_headers,
                params={"department_id": sec["department_id"]},
            )
            assert filtered.status_code == 200
            assert {u["username"] for u in filtered.json()} == {"root_admin", "auditor"}

            # Delete department with 2 linked users -> clears both users to unassigned
            deleted = await client.delete(
                f"/api/auth/departments/{sec['department_id']}",
                headers=admin_headers,
            )
            assert deleted.status_code == 200
            assert deleted.json()["cleared_user_count"] == 2

            all_users = (await client.get("/api/auth/users", headers=admin_headers)).json()
            for item in all_users:
                assert item["department_id"] == ""
                assert item["department_name"] == ""
                if item["username"] in {"root_admin", "auditor"}:
                    assert item["employee_id"] == "A001"

    try:
        asyncio.run(exercise())
    finally:
        store.close()
