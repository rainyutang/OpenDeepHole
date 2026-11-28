"""Department pool and admin user management persistence & SQL aggregations."""

from __future__ import annotations

import sqlite3
import uuid

from backend.models import AdminUserSummary, Department, UserInDB

from .base import DepartmentNotFoundError, DuplicateDepartmentError
from .history import utc_now

UNASSIGNED_DEPARTMENT_FILTER = "__unassigned__"

# `name TEXT NOT NULL UNIQUE` already creates an implicit unique B-tree index in
# both SQLite and PostgreSQL; avoid adding a redundant duplicate index on `name`.
USER_MANAGEMENT_SCHEMA = """
CREATE TABLE IF NOT EXISTS departments (
    department_id TEXT PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
"""

USER_MANAGEMENT_COLUMNS = {
    "users": {
        "employee_id": "TEXT NOT NULL DEFAULT ''",
        "department_id": "TEXT NOT NULL DEFAULT ''",
    },
}

# Partial indexes keep storage overhead minimal: unassigned users ('') and
# zero-TP checker rows (0) take 0 index bytes while enabling index-only scans.
USER_DEPARTMENT_INDEX = (
    "CREATE INDEX IF NOT EXISTS idx_users_department "
    "ON users(department_id) WHERE department_id <> ''"
)
SCAN_SUSPECTED_PARTIAL_INDEX = (
    "CREATE INDEX IF NOT EXISTS storage_idx_checker_totals_suspected "
    "ON scan_checker_totals(scan_id, fp_review_issue_count) "
    "WHERE fp_review_issue_count > 0"
)
SCAN_DIRECT_SUSPECTED_PARTIAL_INDEX = (
    "CREATE INDEX IF NOT EXISTS storage_idx_checker_totals_direct_suspected "
    "ON scan_checker_totals(scan_id, direct_suspected_issue_count) "
    "WHERE direct_suspected_issue_count > 0"
)
SCAN_SUMMARY_UNREADY_INDEX = (
    "CREATE INDEX IF NOT EXISTS idx_scan_summary_unready "
    "ON scan_summary_state(scan_id) WHERE ready = 0"
)

_SORT_DIRECTIONS = {
    "asc": "ASC",
    "desc": "DESC",
}


def _is_unique_violation(error: BaseException) -> bool:
    """Detect unique constraint errors across SQLite and PostgreSQL."""
    if getattr(error, "sqlstate", "") == "23505":
        return True
    if getattr(error, "sqlite_errorname", "") in {
        "SQLITE_CONSTRAINT_UNIQUE",
        "SQLITE_CONSTRAINT_PRIMARYKEY",
    }:
        return True
    if isinstance(error, sqlite3.IntegrityError) and "unique" in str(error).lower():
        return True
    return "duplicate key value violates unique constraint" in str(error).lower()


def _normalize_department_name(name: str) -> str:
    normalized = (name or "").strip()
    if not normalized:
        raise ValueError("部门名称不能为空")
    if len(normalized) > 64:
        raise ValueError("部门名称不能超过 64 个字符")
    return normalized


def normalize_employee_id(employee_id: str | None) -> str:
    normalized = (employee_id or "").strip()
    if len(normalized) > 64:
        raise ValueError("工号备注不能超过 64 个字符")
    return normalized


class UserManagementStoreMixin:
    """Department pool CRUD and index-only user management queries."""

    def _begin_write_locked(self) -> None:
        if not getattr(self, "distributed", False) and not self._conn.in_transaction:
            self._conn.execute("BEGIN IMMEDIATE")

    def _validate_department_locked(self, department_id: str) -> tuple[str, str]:
        """Validate department existence and return (department_id, department_name)."""
        normalized = (department_id or "").strip()
        if not normalized:
            return "", ""
        suffix = " FOR SHARE" if getattr(self, "distributed", False) else ""
        row = self._conn.execute(
            "SELECT department_id, name FROM departments WHERE department_id = ?" + suffix,
            (normalized,),
        ).fetchone()
        if row is None:
            raise DepartmentNotFoundError(normalized)
        return str(row["department_id"]), str(row["name"])

    def get_department_by_id(self, department_id: str) -> Department | None:
        normalized = (department_id or "").strip()
        if not normalized:
            return None
        row = self._conn.execute(
            """\
            SELECT d.department_id,
                   d.name,
                   d.created_at,
                   d.updated_at,
                   (SELECT COUNT(*) FROM users u WHERE u.department_id = d.department_id AND u.department_id <> '') AS user_count
            FROM departments d
            WHERE d.department_id = ?
            """,
            (normalized,),
        ).fetchone()
        if row is None:
            return None
        return Department(
            department_id=str(row["department_id"]),
            name=str(row["name"]),
            user_count=int(row["user_count"] or 0),
            created_at=str(row["created_at"] or ""),
            updated_at=str(row["updated_at"] or ""),
        )

    # -- Department Pool --

    def list_departments(self) -> list[Department]:
        rows = self._conn.execute(
            """\
            SELECT d.department_id,
                   d.name,
                   d.created_at,
                   d.updated_at,
                   COUNT(u.user_id) AS user_count
            FROM departments d
            LEFT JOIN users u
              ON u.department_id = d.department_id AND u.department_id <> ''
            GROUP BY d.department_id, d.name, d.created_at, d.updated_at
            ORDER BY d.created_at ASC, d.department_id ASC
            """
        ).fetchall()
        return [
            Department(
                department_id=str(row["department_id"]),
                name=str(row["name"]),
                user_count=int(row["user_count"] or 0),
                created_at=str(row["created_at"] or ""),
                updated_at=str(row["updated_at"] or ""),
            )
            for row in rows
        ]

    def create_department(self, name: str) -> Department:
        normalized = _normalize_department_name(name)
        department_id = uuid.uuid4().hex
        now = utc_now()
        with self._lock:
            try:
                self._begin_write_locked()
                self._conn.execute(
                    """\
                    INSERT INTO departments (department_id, name, created_at, updated_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (department_id, normalized, now, now),
                )
                self._conn.commit()
            except Exception as exc:
                self._conn.rollback()
                if _is_unique_violation(exc):
                    raise DuplicateDepartmentError(normalized) from exc
                raise
        return Department(
            department_id=department_id,
            name=normalized,
            user_count=0,
            created_at=now,
            updated_at=now,
        )

    def update_department(self, department_id: str, name: str) -> Department | None:
        normalized = _normalize_department_name(name)
        with self._lock:
            try:
                self._begin_write_locked()
                suffix = " FOR UPDATE" if getattr(self, "distributed", False) else ""
                row = self._conn.execute(
                    "SELECT department_id, name, created_at, updated_at "
                    "FROM departments WHERE department_id = ?" + suffix,
                    (department_id,),
                ).fetchone()
                if row is None:
                    self._conn.commit()
                    return None
                updated_at = str(row["updated_at"] or "")
                if str(row["name"]) != normalized:
                    updated_at = utc_now()
                    self._conn.execute(
                        "UPDATE departments SET name = ?, updated_at = ? WHERE department_id = ?",
                        (normalized, updated_at, department_id),
                    )
                count_row = self._conn.execute(
                    "SELECT COUNT(*) AS user_count FROM users "
                    "WHERE department_id = ? AND department_id <> ''",
                    (department_id,),
                ).fetchone()
                user_count = int(count_row["user_count"] or 0) if count_row else 0
                self._conn.commit()
                return Department(
                    department_id=str(row["department_id"]),
                    name=normalized,
                    user_count=user_count,
                    created_at=str(row["created_at"] or ""),
                    updated_at=updated_at,
                )
            except Exception as exc:
                self._conn.rollback()
                if _is_unique_violation(exc):
                    raise DuplicateDepartmentError(normalized) from exc
                raise

    def delete_department(self, department_id: str) -> dict | None:
        with self._lock:
            self._begin_write_locked()
            suffix = " FOR UPDATE" if getattr(self, "distributed", False) else ""
            row = self._conn.execute(
                "SELECT department_id, name FROM departments WHERE department_id = ?" + suffix,
                (department_id,),
            ).fetchone()
            if row is None:
                self._conn.commit()
                return None
            cleared = int(
                self._conn.execute(
                    "UPDATE users SET department_id = '' "
                    "WHERE department_id = ? AND department_id <> ''",
                    (department_id,),
                ).rowcount
                or 0
            )
            self._conn.execute(
                "DELETE FROM departments WHERE department_id = ?",
                (department_id,),
            )
            self._conn.commit()
            return {
                "department_id": str(row["department_id"]),
                "cleared_user_count": max(0, cleared),
            }

    # -- User Profile & Admin Summaries --

    def update_user_profile(
        self,
        user_id: str,
        *,
        employee_id: str | None = None,
        department_id: str | None = None,
    ) -> UserInDB | None:
        normalized_emp = (
            normalize_employee_id(employee_id) if employee_id is not None else None
        )
        with self._lock:
            self._begin_write_locked()
            suffix = " FOR UPDATE" if getattr(self, "distributed", False) else ""
            row = self._conn.execute(
                "SELECT user_id, username, password_hash, role, agent_token, "
                "created_at, employee_id, department_id FROM users WHERE user_id = ?" + suffix,
                (user_id,),
            ).fetchone()
            if row is None:
                self._conn.commit()
                return None
            next_employee_id = (
                normalized_emp
                if normalized_emp is not None
                else str(row["employee_id"] or "")
            )
            raw_department_id = (
                department_id.strip()
                if department_id is not None
                else str(row["department_id"] or "")
            )
            next_department_id, next_department_name = (
                self._validate_department_locked(raw_department_id)
                if raw_department_id
                else ("", "")
            )
            if (
                next_employee_id != str(row["employee_id"] or "")
                or next_department_id != str(row["department_id"] or "")
            ):
                self._conn.execute(
                    "UPDATE users SET employee_id = ?, department_id = ? WHERE user_id = ?",
                    (next_employee_id, next_department_id, user_id),
                )
            self._conn.commit()
            return UserInDB(
                user_id=str(row["user_id"]),
                username=str(row["username"]),
                password_hash=str(row["password_hash"]),
                role=str(row["role"]),
                agent_token=str(row["agent_token"] or ""),
                created_at=str(row["created_at"] or ""),
                employee_id=next_employee_id,
                department_id=next_department_id,
                department_name=next_department_name,
            )

    def _has_unready_summary_scans(self) -> bool:
        """Fast O(1) steady-state check for un-backfilled scan summaries."""
        if (
            self._conn.execute(
                "SELECT 1 FROM scan_summary_state WHERE ready = 0 LIMIT 1"
            ).fetchone()
            is not None
        ):
            return True
        backfilled = self._conn.execute(
            "SELECT 1 FROM schema_migrations "
            "WHERE name = 'scan-summaries-v1' AND status = 'complete'"
        ).fetchone()
        if backfilled is not None:
            return False
        missing = self._conn.execute(
            "SELECT 1 FROM scans s "
            "LEFT JOIN scan_summary_state st ON st.scan_id = s.scan_id "
            "LEFT JOIN scan_deletions del ON del.scan_id = s.scan_id "
            "WHERE s.user_id > '' AND del.scan_id IS NULL AND st.scan_id IS NULL "
            "LIMIT 1"
        ).fetchone()
        return missing is not None

    def _query_admin_users(
        self,
        *,
        user_id: str | None = None,
        department_id: str | None = None,
        sort_by: str = "created_at",
        sort_order: str = "asc",
    ) -> list[AdminUserSummary]:
        direction = _SORT_DIRECTIONS.get((sort_order or "asc").lower())
        if direction is None:
            raise ValueError(f"Unsupported sort_order: {sort_order}")
        if (sort_by or "created_at") not in {
            "created_at",
            "scan_count",
            "suspected_issue_count",
        }:
            raise ValueError(f"Unsupported sort_by: {sort_by}")

        where_parts: list[str] = []
        params: list[object] = []
        if user_id is not None:
            where_parts.append("u.user_id = ?")
            params.append(user_id)
        dept_filter = (department_id or "").strip()
        if dept_filter == UNASSIGNED_DEPARTMENT_FILTER:
            where_parts.append("d.department_id IS NULL")
        elif dept_filter:
            where_parts.append("d.department_id = ?")
            params.append(dept_filter)
        where_sql = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""
        scoped = bool(where_parts)

        has_unready = self._has_unready_summary_scans()

        if not has_unready and not scoped:
            # Steady-state unfiltered fast path: two pure index-only scans
            # (`idx_scans_user_created_cursor` + `idx_scan_checker_totals_suspected`),
            # zero heap fetches on `scans` or `scan_checker_totals`, zero joins to
            # `scan_summary_state`, `vulnerabilities`, or `fp_review_results`.
            order_map = {
                "created_at": f"u.created_at {direction}, u.username ASC, u.user_id ASC",
                "scan_count": f"COALESCE(sc.scan_count, 0) {direction}, u.created_at ASC, u.username ASC, u.user_id ASC",
                "suspected_issue_count": (
                    f"COALESCE(ic.suspected_issue_count, 0) {direction}, "
                    f"COALESCE(sc.scan_count, 0) {direction}, u.created_at ASC, u.username ASC, u.user_id ASC"
                ),
            }
            sql = f"""\
                WITH scan_counts AS (
                    SELECT s.user_id, COUNT(*) AS scan_count
                    FROM scans s
                    LEFT JOIN scan_deletions del ON del.scan_id = s.scan_id
                    WHERE s.user_id > '' AND del.scan_id IS NULL
                    GROUP BY s.user_id
                ),
                issue_counts AS (
                    SELECT s.user_id, SUM(t.fp_review_issue_count + t.direct_suspected_issue_count) AS suspected_issue_count
                    FROM scan_checker_totals t
                    JOIN scans s ON s.scan_id = t.scan_id
                    LEFT JOIN scan_deletions del ON del.scan_id = s.scan_id
                    WHERE (t.fp_review_issue_count > 0 OR t.direct_suspected_issue_count > 0) AND s.user_id > '' AND del.scan_id IS NULL
                    GROUP BY s.user_id
                )
                SELECT u.user_id,
                       u.username,
                       u.role,
                       u.agent_token,
                       u.created_at,
                       COALESCE(u.employee_id, '') AS employee_id,
                       CASE WHEN d.department_id IS NOT NULL THEN d.department_id ELSE '' END AS department_id,
                       COALESCE(d.name, '') AS department_name,
                       COALESCE(sc.scan_count, 0) AS scan_count,
                       COALESCE(ic.suspected_issue_count, 0) AS suspected_issue_count
                FROM users u
                LEFT JOIN departments d
                  ON d.department_id = u.department_id AND u.department_id <> ''
                LEFT JOIN scan_counts sc ON sc.user_id = u.user_id
                LEFT JOIN issue_counts ic ON ic.user_id = u.user_id
                ORDER BY {order_map[sort_by or "created_at"]}
            """
        elif not has_unready and scoped:
            # Steady-state scoped fast path (single user or single department):
            # pushes `target_users` down first so only that user/department's
            # index entries are probed.
            order_map = {
                "created_at": f"tu.created_at {direction}, tu.username ASC, tu.user_id ASC",
                "scan_count": f"COALESCE(uss.scan_count, 0) {direction}, tu.created_at ASC, tu.username ASC, tu.user_id ASC",
                "suspected_issue_count": (
                    f"COALESCE(uss.suspected_issue_count, 0) {direction}, "
                    f"COALESCE(uss.scan_count, 0) {direction}, tu.created_at ASC, tu.username ASC, tu.user_id ASC"
                ),
            }
            sql = f"""\
                WITH target_users AS (
                    SELECT u.user_id,
                           u.username,
                           u.role,
                           u.agent_token,
                           u.created_at,
                           COALESCE(u.employee_id, '') AS employee_id,
                           CASE WHEN d.department_id IS NOT NULL THEN d.department_id ELSE '' END AS department_id,
                           COALESCE(d.name, '') AS department_name
                    FROM users u
                    LEFT JOIN departments d
                      ON d.department_id = u.department_id AND u.department_id <> ''
                    {where_sql}
                ),
                user_scan_stats AS (
                    SELECT s.user_id,
                           COUNT(*) AS scan_count,
                           COALESCE(SUM((
                               SELECT SUM(t.fp_review_issue_count + t.direct_suspected_issue_count)
                               FROM scan_checker_totals t
                               WHERE t.scan_id = s.scan_id AND (t.fp_review_issue_count > 0 OR t.direct_suspected_issue_count > 0)
                           )), 0) AS suspected_issue_count
                    FROM target_users tu
                    JOIN scans s ON s.user_id = tu.user_id
                    LEFT JOIN scan_deletions del ON del.scan_id = s.scan_id
                    WHERE del.scan_id IS NULL
                    GROUP BY s.user_id
                )
                SELECT tu.user_id,
                       tu.username,
                       tu.role,
                       tu.agent_token,
                       tu.created_at,
                       tu.employee_id,
                       tu.department_id,
                       tu.department_name,
                       COALESCE(uss.scan_count, 0) AS scan_count,
                       COALESCE(uss.suspected_issue_count, 0) AS suspected_issue_count
                FROM target_users tu
                LEFT JOIN user_scan_stats uss ON uss.user_id = tu.user_id
                ORDER BY {order_map[sort_by or "created_at"]}
            """
        else:
            # Transitional fallback when some historical scans still have ready = 0:
            # pushes target_users down, uses partial covering index for ready = 1 scans,
            # and evaluates a lightweight window over ONLY ready = 0 FP results with
            # `reason` short-circuiting so large `vulnerability_report` bodies stay untouched.
            order_map = {
                "created_at": f"tu.created_at {direction}, tu.username ASC, tu.user_id ASC",
                "scan_count": f"COALESCE(sc.scan_count, 0) {direction}, tu.created_at ASC, tu.username ASC, tu.user_id ASC",
                "suspected_issue_count": (
                    f"(COALESCE(ri.suspected_issue_count, 0) + COALESCE(li.suspected_issue_count, 0)) {direction}, "
                    f"COALESCE(sc.scan_count, 0) {direction}, tu.created_at ASC, tu.username ASC, tu.user_id ASC"
                ),
            }
            sql = f"""\
                WITH target_users AS (
                    SELECT u.user_id,
                           u.username,
                           u.role,
                           u.agent_token,
                           u.created_at,
                           COALESCE(u.employee_id, '') AS employee_id,
                           CASE WHEN d.department_id IS NOT NULL THEN d.department_id ELSE '' END AS department_id,
                           COALESCE(d.name, '') AS department_name
                    FROM users u
                    LEFT JOIN departments d
                      ON d.department_id = u.department_id AND u.department_id <> ''
                    {where_sql}
                ),
                scoped_scans AS (
                    SELECT s.user_id, s.scan_id, COALESCE(st.ready, 0) AS ready
                    FROM target_users tu
                    JOIN scans s ON s.user_id = tu.user_id
                    LEFT JOIN scan_deletions del ON del.scan_id = s.scan_id
                    LEFT JOIN scan_summary_state st ON st.scan_id = s.scan_id
                    WHERE del.scan_id IS NULL
                ),
                scan_counts AS (
                    SELECT user_id, COUNT(*) AS scan_count
                    FROM scoped_scans
                    GROUP BY user_id
                ),
                ready_issues AS (
                    SELECT ss.user_id, SUM(t.fp_review_issue_count + t.direct_suspected_issue_count) AS suspected_issue_count
                    FROM scoped_scans ss
                    JOIN scan_checker_totals t ON t.scan_id = ss.scan_id
                    WHERE ss.ready = 1 AND (t.fp_review_issue_count > 0 OR t.direct_suspected_issue_count > 0)
                    GROUP BY ss.user_id
                ),
                legacy_ranked AS (
                    SELECT ss.user_id,
                           ss.scan_id,
                           r.vuln_index,
                           r.verdict,
                           ROW_NUMBER() OVER (
                               PARTITION BY ss.scan_id, r.vuln_index
                               ORDER BY j.created_at DESC, r.created_at DESC, r.id DESC
                           ) AS rn
                    FROM scoped_scans ss
                    JOIN fp_review_jobs j ON j.scan_id = ss.scan_id
                    JOIN fp_review_results r ON r.review_id = j.review_id
                    WHERE ss.ready = 0
                      AND r.verdict IN ('tp', 'fp')
                      AND SUBSTR(COALESCE(r.reason, ''), 1, 17) <> 'Review incomplete'
                      AND (
                          CASE
                              WHEN COALESCE(r.reason, '') <> '' THEN 1
                              WHEN LENGTH(COALESCE(r.vulnerability_report, '')) > 0 THEN 1
                              ELSE 0
                          END
                      ) = 1
                ),
                legacy_issues AS (
                    SELECT user_id, SUM(suspected_issue_count) AS suspected_issue_count
                    FROM (
                        SELECT lr.user_id, COUNT(*) AS suspected_issue_count
                        FROM legacy_ranked lr
                        WHERE lr.rn = 1
                          AND lr.verdict = 'tp'
                          AND EXISTS (
                              SELECT 1 FROM vulnerabilities v
                              WHERE v.scan_id = lr.scan_id AND v.idx = lr.vuln_index
                                AND COALESCE(v.engine_id, '') <> 'redline_audit'
                                AND COALESCE(v.analysis_source, '') <> 'redline_audit'
                          )
                        GROUP BY lr.user_id
                        UNION ALL
                        SELECT ss.user_id, COUNT(*) AS suspected_issue_count
                        FROM scoped_scans ss
                        JOIN vulnerabilities v ON v.scan_id = ss.scan_id
                        WHERE ss.ready = 0
                          AND v.provisional = 0
                          AND (CASE WHEN COALESCE(v.ai_verdict, '') <> '' THEN CASE WHEN v.ai_verdict = 'confirmed' THEN 1 ELSE 0 END ELSE v.confirmed END) = 1
                          AND (COALESCE(v.engine_id, '') = 'redline_audit' OR COALESCE(v.analysis_source, '') = 'redline_audit')
                        GROUP BY ss.user_id
                    ) combined_legacy
                    GROUP BY user_id
                )
                SELECT tu.user_id,
                       tu.username,
                       tu.role,
                       tu.agent_token,
                       tu.created_at,
                       tu.employee_id,
                       tu.department_id,
                       tu.department_name,
                       COALESCE(sc.scan_count, 0) AS scan_count,
                       COALESCE(ri.suspected_issue_count, 0) + COALESCE(li.suspected_issue_count, 0) AS suspected_issue_count
                FROM target_users tu
                LEFT JOIN scan_counts sc ON sc.user_id = tu.user_id
                LEFT JOIN ready_issues ri ON ri.user_id = tu.user_id
                LEFT JOIN legacy_issues li ON li.user_id = tu.user_id
                ORDER BY {order_map[sort_by or "created_at"]}
            """

        rows = self._conn.execute(sql, params).fetchall()
        return [
            AdminUserSummary(
                user_id=str(row["user_id"]),
                username=str(row["username"]),
                role=str(row["role"]),
                agent_token=str(row["agent_token"] or ""),
                created_at=str(row["created_at"] or ""),
                employee_id=str(row["employee_id"] or ""),
                department_id=str(row["department_id"] or ""),
                department_name=str(row["department_name"] or ""),
                scan_count=int(row["scan_count"] or 0),
                suspected_issue_count=int(row["suspected_issue_count"] or 0),
            )
            for row in rows
        ]

    def list_admin_users(
        self,
        *,
        department_id: str | None = None,
        sort_by: str = "created_at",
        sort_order: str = "asc",
    ) -> list[AdminUserSummary]:
        return self._query_admin_users(
            department_id=department_id,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    def get_admin_user_summary(self, user_id: str) -> AdminUserSummary | None:
        items = self._query_admin_users(user_id=user_id)
        return items[0] if items else None
