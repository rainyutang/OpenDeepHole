"""PostgreSQL implementation compatible with the existing scan-store contract.

The business methods are inherited from :class:`SqliteScanStore`; this module
provides a DB-API compatibility layer for PostgreSQL and bootstraps the same
fully-migrated relational schema.  API code executes the synchronous contract
through ``run_store_call``, so PostgreSQL I/O never blocks the event loop.

PostgreSQL-only tables provide durable cross-worker Agent commands and SSE
events.  NOTIFY payloads contain row IDs only; table rows remain authoritative.
"""

from __future__ import annotations

import json
import re
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from backend.models import (
    AgentInfo,
    STATIC_CANDIDATE_ENGINE_LABEL,
    THREAT_AUDIT_ENGINE_LABEL,
)

from .sqlite import (
    SqliteScanStore,
    _canonicalize_mining_engine_json,
    _deduplicated_scan_names,
    _retire_agent_opencode_config,
)


_QUESTION_MARK = re.compile(r"\?")
_AUTOINCREMENT = re.compile(
    r"\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b",
    flags=re.IGNORECASE,
)
_SCHEMA_BOOTSTRAP_LOCK_KEY = 5711767769877594435


class _CompatRow(dict):
    """Expose psycopg dict rows with sqlite.Row's integer indexing too."""

    def __getitem__(self, key):
        if isinstance(key, int):
            return tuple(self.values())[key]
        return super().__getitem__(key)


class _Cursor:
    def __init__(self, owner: "_Connection", cursor, *, release_on_fetch: bool) -> None:
        self._owner = owner
        self._cursor = cursor
        self._release_on_fetch = release_on_fetch

    @property
    def rowcount(self) -> int:
        return int(self._cursor.rowcount or 0)

    def _row(self, value):
        return _CompatRow(value) if isinstance(value, dict) else value

    def fetchone(self):
        try:
            return self._row(self._cursor.fetchone())
        finally:
            if self._release_on_fetch:
                self._owner.release_read()

    def fetchall(self):
        try:
            return [self._row(row) for row in self._cursor.fetchall()]
        finally:
            if self._release_on_fetch:
                self._owner.release_read()


class _Connection:
    def __init__(self, pool) -> None:
        self._pool = pool
        self._local = threading.local()

    def _state(self) -> dict[str, Any]:
        state = getattr(self._local, "state", None)
        if state is None:
            state = {"conn": None, "dirty": False, "scope": 0}
            self._local.state = state
        return state

    def _acquire(self):
        state = self._state()
        if state["conn"] is None:
            state["conn"] = self._pool.getconn()
        return state["conn"]

    @staticmethod
    def _sql(sql: str) -> str:
        # SQLite uses ``?`` parameters while psycopg uses ``%s``.  Do not
        # rewrite question marks inside SQL string/identifier literals.
        rendered: list[str] = []
        quote = ""
        index = 0
        while index < len(sql):
            char = sql[index]
            if quote:
                rendered.append(char)
                if char == quote:
                    if index + 1 < len(sql) and sql[index + 1] == quote:
                        rendered.append(sql[index + 1])
                        index += 1
                    else:
                        quote = ""
            elif char in {"'", '"'}:
                quote = char
                rendered.append(char)
            elif char == "?":
                rendered.append("%s")
            else:
                rendered.append(char)
            index += 1
        return "".join(rendered)

    @staticmethod
    def _is_write(sql: str) -> bool:
        first = sql.lstrip().split(None, 1)[0].upper() if sql.strip() else ""
        return first not in {"SELECT", "SHOW", "EXPLAIN"}

    def execute(self, sql: str, params: Iterable[Any] | None = None) -> _Cursor:
        state = self._state()
        conn = self._acquire()
        write = self._is_write(sql)
        if write:
            state["dirty"] = True
        cursor = conn.execute(self._sql(sql), tuple(params or ()))
        return _Cursor(
            self,
            cursor,
            release_on_fetch=(not state["dirty"] and state["scope"] == 0),
        )

    def executemany(self, sql: str, params: Iterable[Iterable[Any]]) -> _Cursor:
        state = self._state()
        conn = self._acquire()
        state["dirty"] = True
        cursor = conn.cursor()
        cursor.executemany(self._sql(sql), [tuple(values) for values in params])
        return _Cursor(self, cursor, release_on_fetch=False)

    def commit(self) -> None:
        state = self._state()
        conn = state["conn"]
        if conn is None:
            return
        conn.commit()
        state["dirty"] = False
        if state["scope"] == 0:
            self._pool.putconn(conn)
            state["conn"] = None

    def rollback(self) -> None:
        state = self._state()
        conn = state["conn"]
        if conn is None:
            return
        conn.rollback()
        state["dirty"] = False
        self._pool.putconn(conn)
        state["conn"] = None

    def release_read(self) -> None:
        state = self._state()
        conn = state["conn"]
        if conn is None or state["dirty"] or state["scope"]:
            return
        conn.rollback()
        self._pool.putconn(conn)
        state["conn"] = None

    def enter_scope(self) -> None:
        state = self._state()
        state["scope"] += 1

    def exit_scope(self, error: BaseException | None) -> None:
        state = self._state()
        state["scope"] = max(0, state["scope"] - 1)
        if state["scope"]:
            return
        conn = state["conn"]
        if conn is None:
            return
        if error is not None:
            conn.rollback()
        elif state["dirty"]:
            conn.commit()
        else:
            conn.rollback()
        state["dirty"] = False
        self._pool.putconn(conn)
        state["conn"] = None

    def close(self) -> None:
        self.rollback()
        self._pool.close()


class _TransactionLock:
    def __init__(self, connection: _Connection) -> None:
        self._connection = connection

    def __enter__(self):
        self._connection.enter_scope()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        # SQLite needs a process-local mutex around its shared connection.
        # PostgreSQL does not: each executor thread owns a pool connection via
        # ``_Connection``'s thread-local state.  Keeping a global RLock here
        # would serialize every query in a worker and effectively turn the
        # configured connection pool back into a single connection.
        self._connection.exit_scope(exc)


_COORDINATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS backend_workers (
    worker_id  TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    last_seen  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_sessions (
    agent_id         TEXT PRIMARY KEY,
    agent_key        TEXT NOT NULL,
    worker_id        TEXT NOT NULL,
    name             TEXT NOT NULL,
    machine_name     TEXT NOT NULL DEFAULT '',
    user_id          TEXT NOT NULL DEFAULT '',
    protocol_version INTEGER NOT NULL DEFAULT 1,
    runtime_hash     TEXT NOT NULL DEFAULT '',
    agent_session_id TEXT NOT NULL DEFAULT '',
    accepting_tasks INTEGER NOT NULL DEFAULT 1,
    connected_at     TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    disconnected_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_agent_sessions_key_live
ON agent_sessions(agent_key, last_seen DESC);

CREATE TABLE IF NOT EXISTS agent_commands (
    id            BIGSERIAL PRIMARY KEY,
    agent_id      TEXT NOT NULL,
    target_worker TEXT NOT NULL,
    payload_json  TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    attempts      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    claimed_at    TEXT,
    delivered_at TEXT,
    error_message TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_agent_commands_worker_pending
ON agent_commands(target_worker, status, id);

CREATE TABLE IF NOT EXISTS agent_rpc_responses (
    request_id   TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_stream_events (
    id            BIGSERIAL PRIMARY KEY,
    scan_id       TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    data_json     TEXT NOT NULL,
    source_worker TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_stream_events_id
ON scan_stream_events(id);
CREATE INDEX IF NOT EXISTS idx_scan_stream_events_scan_id
ON scan_stream_events(scan_id, id);
"""


def _sqlite_schema() -> list[str]:
    """Build the fully migrated SQLite schema and return portable DDL."""
    root_tables = {
        "agents",
        "announcements",
        "feedback_entries",
        "fp_review_jobs",
        "scans",
        "users",
    }
    with tempfile.TemporaryDirectory(prefix="opendeephole-schema-") as directory:
        sqlite_store = SqliteScanStore(Path(directory) / "schema.db")
        rows = sqlite_store._conn.execute(
            """\
            SELECT type, name, sql
            FROM sqlite_master
            WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'
            ORDER BY CASE type WHEN 'table' THEN 0 ELSE 1 END, name
            """
        ).fetchall()
        rows = [
            row
            for row in rows
            if str(row[1]) != "idx_scans_user_scan_name_unique"
        ]
        # PostgreSQL requires referenced tables to exist when a foreign key is
        # declared.  SQLite's catalog ordering is alphabetical, so create the
        # independent roots before all dependent tables and indexes.
        rows = sorted(
            rows,
            key=lambda row: (
                0 if str(row[0]) == "table" and str(row[1]) in root_tables else 1,
                0 if str(row[0]) == "table" else 1,
                str(row[1]),
            ),
        )
        ddl = [str(row[2]) for row in rows]
        sqlite_store.close()
    portable: list[str] = []
    for statement in ddl:
        statement = _AUTOINCREMENT.sub("BIGSERIAL PRIMARY KEY", statement)
        statement = re.sub(
            r"^CREATE\s+TABLE\s+",
            "CREATE TABLE IF NOT EXISTS ",
            statement,
            count=1,
            flags=re.IGNORECASE,
        )
        statement = re.sub(
            r"^CREATE\s+(UNIQUE\s+)?INDEX\s+",
            lambda match: (
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                if match.group(1)
                else "CREATE INDEX IF NOT EXISTS "
            ),
            statement,
            count=1,
            flags=re.IGNORECASE,
        )
        portable.append(statement)
    return portable


class PostgresScanStore(SqliteScanStore):
    """PostgreSQL-backed implementation of the complete synchronous store API."""

    distributed = True

    def __init__(
        self,
        dsn: str,
        *,
        pool_min_size: int = 1,
        pool_max_size: int = 10,
    ) -> None:
        try:
            from psycopg.rows import dict_row
            from psycopg_pool import ConnectionPool
        except ImportError as exc:  # pragma: no cover - depends on deployment extra
            raise RuntimeError(
                "PostgreSQL storage requires psycopg[binary,pool]"
            ) from exc

        self.dsn = dsn
        self.executor_workers = max(2, min(16, int(pool_max_size)))
        self._pool = ConnectionPool(
            conninfo=dsn,
            min_size=max(1, int(pool_min_size)),
            max_size=max(int(pool_min_size), int(pool_max_size)),
            kwargs={"row_factory": dict_row},
            open=True,
        )
        self._conn = _Connection(self._pool)
        self._lock = _TransactionLock(self._conn)
        self._advisory_connections: dict[int, Any] = {}
        self._bootstrap()

    def _bootstrap(self) -> None:
        with self._pool.connection() as connection:
            # Uvicorn workers start concurrently.  Serialize DDL so every
            # worker observes a completely initialized schema.
            connection.execute(
                "SELECT pg_advisory_xact_lock(%s)",
                (_SCHEMA_BOOTSTRAP_LOCK_KEY,),
            )
            deferred_report_batch_index = "idx_vulnerabilities_report_batch"
            for statement in _sqlite_schema():
                if deferred_report_batch_index in statement:
                    continue
                connection.execute(statement)
            for statement in filter(str.strip, _COORDINATION_SCHEMA.split(";")):
                connection.execute(statement)
            # Safe for databases initialized by an earlier pre-release build.
            connection.execute(
                "ALTER TABLE scans ADD COLUMN IF NOT EXISTS "
                "threat_analysis_method TEXT NOT NULL "
                "DEFAULT 'deephole_threat_analysis'"
            )
            connection.execute(
                "ALTER TABLE scans ADD COLUMN IF NOT EXISTS "
                "threat_analysis_method_selection_json TEXT NOT NULL DEFAULT '{}'"
            )
            for statement in (
                "ALTER TABLE scans ADD COLUMN IF NOT EXISTS user_id TEXT DEFAULT ''",
                "ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_name TEXT DEFAULT ''",
                "ALTER TABLE scans ADD COLUMN IF NOT EXISTS project_path TEXT DEFAULT ''",
                "ALTER TABLE scans ADD COLUMN IF NOT EXISTS knowledge_base_enabled INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE scans ADD COLUMN IF NOT EXISTS vulnerability_validation_enabled INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE scans ADD COLUMN IF NOT EXISTS validation_method_id TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE scans ADD COLUMN IF NOT EXISTS validation_method_label TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE scans ADD COLUMN IF NOT EXISTS knowledge_base_mcp_json TEXT",
                "ALTER TABLE scans ADD COLUMN IF NOT EXISTS vulnerability_validation_json TEXT",
                "ALTER TABLE vulnerability_validations ADD COLUMN IF NOT EXISTS validation_method_id TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE vulnerability_validations ADD COLUMN IF NOT EXISTS validation_method_label TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS provisional INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS report_batch_id TEXT NOT NULL DEFAULT ''",
            ):
                connection.execute(statement)
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_report_batch "
                "ON vulnerabilities(scan_id, report_batch_id)"
            )
            connection.execute(
                "UPDATE scans SET user_id = '' WHERE user_id IS NULL"
            )
            historical_scan_rows = connection.execute(
                """\
                SELECT scan_id, user_id, scan_name, project_path
                FROM scans
                ORDER BY created_at ASC, scan_id ASC
                """
            ).fetchall()
            scan_name_updates = _deduplicated_scan_names(historical_scan_rows)
            if scan_name_updates:
                connection.executemany(
                    "UPDATE scans SET scan_name = %s WHERE scan_id = %s",
                    scan_name_updates,
                )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "idx_scans_user_scan_name_unique ON scans(user_id, scan_name)"
            )
            for row in connection.execute(
                "SELECT scan_id, mining_engines_json, mining_engine_runs_json FROM scans"
            ).fetchall():
                selections_json = _canonicalize_mining_engine_json(
                    row["mining_engines_json"],
                )
                runs_json = _canonicalize_mining_engine_json(
                    row["mining_engine_runs_json"],
                )
                if selections_json is None and runs_json is None:
                    continue
                connection.execute(
                    """
                    UPDATE scans
                    SET mining_engines_json = %s, mining_engine_runs_json = %s
                    WHERE scan_id = %s
                    """,
                    (
                        selections_json or row["mining_engines_json"],
                        runs_json or row["mining_engine_runs_json"],
                        row["scan_id"],
                    ),
                )
            for engine_id, engine_label in (
                ("static_candidate", STATIC_CANDIDATE_ENGINE_LABEL),
                ("threat_audit", THREAT_AUDIT_ENGINE_LABEL),
            ):
                connection.execute(
                    """
                    UPDATE vulnerabilities
                    SET engine_label = %s
                    WHERE engine_id = %s AND engine_label <> %s
                    """,
                    (engine_label, engine_id, engine_label),
                )
            connection.execute(
                "ALTER TABLE vulnerabilities ALTER COLUMN engine_label SET DEFAULT "
                "'DeepHole基于代码风险点的漏洞挖掘引擎'"
            )
            connection.execute(
                "ALTER TABLE agent_commands ADD COLUMN IF NOT EXISTS "
                "attempts INTEGER NOT NULL DEFAULT 0"
            )
            connection.execute(
                "ALTER TABLE agent_commands ADD COLUMN IF NOT EXISTS claimed_at TEXT"
            )
            connection.execute(
                "ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS "
                "runtime_hash TEXT NOT NULL DEFAULT ''"
            )
            connection.execute(
                "ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS "
                "agent_session_id TEXT NOT NULL DEFAULT ''"
            )
            connection.execute(
                "ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS "
                "accepting_tasks INTEGER NOT NULL DEFAULT 1"
            )
            connection.execute(
                "ALTER TABLE agents DROP COLUMN IF EXISTS "
                "opencode_runtime_config_json"
            )
            for row in connection.execute(
                "SELECT agent_key, config_json FROM agents"
            ).fetchall():
                migrated_config = _retire_agent_opencode_config(row["config_json"])
                if migrated_config is not None:
                    connection.execute(
                        "UPDATE agents SET config_json = %s WHERE agent_key = %s",
                        (migrated_config, row["agent_key"]),
                    )
            # SQLite uses rowid to break equal created_at ties for FP jobs.
            # PostgreSQL needs an explicit monotonic key to preserve the same
            # "most recently inserted" contract across workers.
            connection.execute(
                "ALTER TABLE fp_review_jobs ADD COLUMN IF NOT EXISTS "
                "created_order BIGSERIAL"
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "idx_fp_review_jobs_created_order "
                "ON fp_review_jobs(created_order)"
            )
            connection.commit()

    def close(self) -> None:
        for key in list(self._advisory_connections):
            self.release_advisory_lock(key)
        self._conn.close()

    # -- leader election -------------------------------------------------

    def try_advisory_lock(self, key: int) -> bool:
        if key in self._advisory_connections:
            return True
        connection = self._pool.getconn()
        try:
            row = connection.execute(
                "SELECT pg_try_advisory_lock(%s) AS acquired",
                (int(key),),
            ).fetchone()
            acquired = bool(row["acquired"])
            # Session-level advisory locks survive COMMIT; closing the
            # transaction avoids leaving the elected leader idle in a
            # long-lived transaction and holding an old MVCC snapshot.
            connection.commit()
            if acquired:
                self._advisory_connections[key] = connection
                return True
        except Exception:
            connection.rollback()
            self._pool.putconn(connection)
            raise
        self._pool.putconn(connection)
        return False

    def release_advisory_lock(self, key: int) -> None:
        connection = self._advisory_connections.pop(key, None)
        if connection is None:
            return
        try:
            connection.execute("SELECT pg_advisory_unlock(%s)", (int(key),))
            connection.commit()
        finally:
            self._pool.putconn(connection)

    # -- SQLite rowid compatibility ------------------------------------

    def create_fp_review_job(
        self,
        review_id: str,
        scan_id: str,
        total: int,
        created_at: str,
        method: str = "adversarial",
    ) -> None:
        with self._lock:
            self._conn.execute(
                """\
                INSERT INTO fp_review_jobs
                    (review_id, scan_id, method, status, created_at, total, processed)
                VALUES (?, ?, ?, 'pending', ?, ?, 0)
                """,
                (review_id, scan_id, method, created_at, total),
            )
            self._conn.commit()

    def get_fp_review_by_scan(self, scan_id: str):
        with self._lock:
            row = self._conn.execute(
                """\
                SELECT *
                FROM fp_review_jobs
                WHERE scan_id = ?
                ORDER BY created_at DESC, created_order DESC
                LIMIT 1
                """,
                (scan_id,),
            ).fetchone()
        return self._row_to_fp_review_job(row) if row is not None else None

    # -- cross-worker Agent sessions and commands ------------------------

    def register_worker(self, worker_id: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                """\
                INSERT INTO backend_workers(worker_id, started_at, last_seen)
                VALUES (?, ?, ?)
                ON CONFLICT(worker_id) DO UPDATE SET last_seen = excluded.last_seen
                """,
                (worker_id, now, now),
            )
            self._conn.commit()

    def register_agent_session(
        self,
        agent: AgentInfo,
        worker_id: str,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                """\
                INSERT INTO agent_sessions (
                    agent_id, agent_key, worker_id, name, machine_name, user_id,
                    protocol_version, runtime_hash, agent_session_id,
                    accepting_tasks, connected_at, last_seen, disconnected_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                ON CONFLICT(agent_id) DO UPDATE SET
                    agent_key = excluded.agent_key,
                    worker_id = excluded.worker_id,
                    name = excluded.name,
                    machine_name = excluded.machine_name,
                    user_id = excluded.user_id,
                    protocol_version = excluded.protocol_version,
                    runtime_hash = excluded.runtime_hash,
                    agent_session_id = excluded.agent_session_id,
                    accepting_tasks = excluded.accepting_tasks,
                    last_seen = excluded.last_seen,
                    disconnected_at = NULL
                """,
                (
                    agent.agent_id,
                    agent.agent_key,
                    worker_id,
                    agent.name,
                    agent.machine_name,
                    agent.user_id,
                    agent.protocol_version,
                    agent.runtime_hash,
                    agent.agent_session_id,
                    1 if agent.accepting_tasks else 0,
                    now,
                    agent.last_seen or now,
                ),
            )
            # A reconnect can move command ownership to another worker.  Only
            # pending rows are retargeted; an already delivering row owns its
            # current attempt and will be retried explicitly on failure.
            self._conn.execute(
                """\
                UPDATE agent_commands
                SET target_worker = ?
                WHERE agent_id = ? AND status = 'pending'
                """,
                (worker_id, agent.agent_id),
            )
            self._conn.commit()

    def touch_agent_session(self, agent_id: str, last_seen: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE agent_sessions SET last_seen = ?, disconnected_at = NULL WHERE agent_id = ?",
                (last_seen, agent_id),
            )
            self._conn.commit()

    def unregister_agent_session(self, agent_id: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                "UPDATE agent_sessions SET disconnected_at = ?, last_seen = ? WHERE agent_id = ?",
                (now, now, agent_id),
            )
            self._conn.commit()

    def get_live_agent_session(
        self,
        *,
        agent_key: str | None = None,
        agent_id: str | None = None,
        stale_seconds: int = 120,
    ) -> dict | None:
        cutoff = (
            datetime.now(timezone.utc) - timedelta(seconds=max(1, stale_seconds))
        ).isoformat()
        if agent_key:
            clause, value = "agent_key = ?", agent_key
        elif agent_id:
            clause, value = "agent_id = ?", agent_id
        else:
            return None
        row = self._conn.execute(
            f"""\
            SELECT * FROM agent_sessions
            WHERE {clause} AND disconnected_at IS NULL AND last_seen > ?
            ORDER BY last_seen DESC
            LIMIT 1
            """,
            (value, cutoff),
        ).fetchone()
        return dict(row) if row is not None else None

    def get_live_agent_session_by_name(
        self,
        agent_name: str,
        *,
        user_id: str | None = None,
        stale_seconds: int = 120,
    ) -> dict | None:
        cutoff = (
            datetime.now(timezone.utc) - timedelta(seconds=max(1, stale_seconds))
        ).isoformat()
        conditions = [
            "name = ?",
            "disconnected_at IS NULL",
            "last_seen > ?",
        ]
        params: list[Any] = [agent_name, cutoff]
        if user_id is not None:
            conditions.append("user_id = ?")
            params.append(user_id)
        row = self._conn.execute(
            f"""\
            SELECT * FROM agent_sessions
            WHERE {' AND '.join(conditions)}
            ORDER BY last_seen DESC
            LIMIT 1
            """,
            params,
        ).fetchone()
        return dict(row) if row is not None else None

    def list_live_agent_names(self, stale_seconds: int = 120) -> list[str]:
        cutoff = (
            datetime.now(timezone.utc) - timedelta(seconds=max(1, stale_seconds))
        ).isoformat()
        rows = self._conn.execute(
            """\
            SELECT DISTINCT name FROM agent_sessions
            WHERE disconnected_at IS NULL AND last_seen > ?
            """,
            (cutoff,),
        ).fetchall()
        return [str(row["name"]) for row in rows]

    def list_live_agent_sessions(self, stale_seconds: int = 120) -> list[dict]:
        cutoff = (
            datetime.now(timezone.utc) - timedelta(seconds=max(1, stale_seconds))
        ).isoformat()
        rows = self._conn.execute(
            """\
            SELECT * FROM agent_sessions
            WHERE disconnected_at IS NULL AND last_seen > ?
            ORDER BY last_seen DESC
            """,
            (cutoff,),
        ).fetchall()
        return [dict(row) for row in rows]

    def enqueue_agent_command(self, agent_id: str, payload: dict) -> int | None:
        session = self.get_live_agent_session(agent_id=agent_id)
        if session is None:
            return None
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            row = self._conn.execute(
                """\
                INSERT INTO agent_commands (
                    agent_id, target_worker, payload_json, status, created_at
                ) VALUES (?, ?, ?, 'pending', ?)
                RETURNING id
                """,
                (
                    agent_id,
                    session["worker_id"],
                    json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                    now,
                ),
            ).fetchone()
            command_id = int(row["id"])
            self._conn.execute(
                "SELECT pg_notify('opendeephole_agent_commands', ?)",
                (str(command_id),),
            )
            self._conn.commit()
        return command_id

    def claim_agent_commands(self, worker_id: str, limit: int = 100) -> list[dict]:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            rows = self._conn.execute(
                """\
                WITH claimed AS (
                    SELECT id FROM agent_commands
                    WHERE target_worker = ? AND status = 'pending'
                    ORDER BY id
                    FOR UPDATE SKIP LOCKED
                    LIMIT ?
                )
                UPDATE agent_commands AS command
                SET status = 'delivering',
                    attempts = command.attempts + 1,
                    claimed_at = ?
                FROM claimed
                WHERE command.id = claimed.id
                RETURNING command.*
                """,
                (worker_id, max(1, int(limit)), now),
            ).fetchall()
            self._conn.commit()
        return [dict(row) for row in rows]

    def finish_agent_command(self, command_id: int, *, error: str = "") -> None:
        with self._lock:
            row = self._conn.execute(
                "SELECT agent_id, attempts FROM agent_commands WHERE id = ?",
                (int(command_id),),
            ).fetchone()
            if row is None:
                return
            session = (
                self.get_live_agent_session(agent_id=str(row["agent_id"]))
                if error
                else None
            )
            retry = bool(error) and int(row["attempts"] or 0) < 3 and session is not None
            status = "pending" if retry else ("failed" if error else "delivered")
            delivered_at = (
                datetime.now(timezone.utc).isoformat()
                if not error
                else None
            )
            target_worker = (
                str(session["worker_id"])
                if retry and session is not None
                else None
            )
            self._conn.execute(
                """\
                UPDATE agent_commands
                SET status = ?, delivered_at = ?, error_message = ?,
                    target_worker = COALESCE(?, target_worker), claimed_at = NULL
                WHERE id = ?
                """,
                (status, delivered_at, error, target_worker, int(command_id)),
            )
            if retry:
                self._conn.execute(
                    "SELECT pg_notify('opendeephole_agent_commands', ?)",
                    (str(command_id),),
                )
            self._conn.commit()

    def recover_stale_agent_commands(self, stale_seconds: int = 30) -> int:
        """Requeue commands left in ``delivering`` by a crashed worker."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(seconds=max(1, stale_seconds))
        ).isoformat()
        with self._lock:
            rows = self._conn.execute(
                """\
                SELECT id, agent_id, attempts FROM agent_commands
                WHERE status = 'delivering' AND claimed_at < ?
                ORDER BY id
                FOR UPDATE SKIP LOCKED
                LIMIT 100
                """,
                (cutoff,),
            ).fetchall()
            recovered = 0
            for row in rows:
                session = self.get_live_agent_session(agent_id=str(row["agent_id"]))
                retry = int(row["attempts"] or 0) < 3 and session is not None
                self._conn.execute(
                    """\
                    UPDATE agent_commands
                    SET status = ?, target_worker = COALESCE(?, target_worker),
                        claimed_at = NULL,
                        error_message = 'delivery worker terminated'
                    WHERE id = ? AND status = 'delivering'
                    """,
                    (
                        "pending" if retry else "failed",
                        str(session["worker_id"]) if retry else None,
                        int(row["id"]),
                    ),
                )
                if retry:
                    self._conn.execute(
                        "SELECT pg_notify('opendeephole_agent_commands', ?)",
                        (str(row["id"]),),
                    )
                    recovered += 1
            self._conn.commit()
        return recovered

    def put_agent_rpc_response(self, request_id: str, payload: dict) -> None:
        now = datetime.now(timezone.utc).isoformat()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        with self._lock:
            self._conn.execute(
                """\
                INSERT INTO agent_rpc_responses(request_id, payload_json, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(request_id) DO UPDATE SET
                    payload_json = excluded.payload_json,
                    created_at = excluded.created_at
                """,
                (
                    request_id,
                    json.dumps(payload, ensure_ascii=False, default=str),
                    now,
                ),
            )
            self._conn.execute(
                "DELETE FROM agent_rpc_responses WHERE created_at < ?",
                (cutoff,),
            )
            self._conn.commit()

    def pop_agent_rpc_response(self, request_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                """\
                DELETE FROM agent_rpc_responses
                WHERE request_id = ?
                RETURNING payload_json
                """,
                (request_id,),
            ).fetchone()
            self._conn.commit()
        if row is None:
            return None
        try:
            payload = json.loads(str(row["payload_json"]))
        except Exception:
            return None
        return payload if isinstance(payload, dict) else None

    def cancel_stale_agent_work(
        self,
        *,
        stale_seconds: int = 120,
        error_message: str,
    ) -> list[str]:
        """Cancel running work whose Agent session has stopped heartbeating."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(seconds=max(1, stale_seconds))
        ).isoformat()
        with self._lock:
            rows = self._conn.execute(
                """\
                UPDATE scans AS scan
                SET status = 'cancelled', error_message = ?, current_candidate = NULL
                WHERE scan.status IN ('pending', 'analyzing', 'auditing')
                  AND scan.agent_id <> ''
                  AND NOT EXISTS (
                      SELECT 1 FROM agent_sessions AS session
                      WHERE session.agent_id = scan.agent_id
                        AND session.last_seen > ?
                  )
                RETURNING scan.scan_id
                """,
                (error_message, cutoff),
            ).fetchall()
            scan_ids = [str(row["scan_id"]) for row in rows]
            if scan_ids:
                placeholders = ", ".join("?" for _ in scan_ids)
                self._conn.execute(
                    f"""\
                    UPDATE fp_review_jobs
                    SET status = CASE
                            WHEN status IN ('pending', 'running') THEN 'error'
                            ELSE status
                        END,
                        error_message = ?
                    WHERE scan_id IN ({placeholders})
                      AND status IN ('pending', 'running')
                    """,
                    (error_message, *scan_ids),
                )
            self._conn.commit()
        return scan_ids

    # -- durable SSE event log ------------------------------------------

    def publish_stream_event(
        self,
        *,
        scan_id: str,
        event_type: str,
        data: Any,
        source_worker: str,
    ) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            row = self._conn.execute(
                """\
                INSERT INTO scan_stream_events (
                    scan_id, event_type, data_json, source_worker, created_at
                ) VALUES (?, ?, ?, ?, ?)
                RETURNING id
                """,
                (
                    scan_id,
                    event_type,
                    json.dumps(data, ensure_ascii=False, default=str, separators=(",", ":")),
                    source_worker,
                    now,
                ),
            ).fetchone()
            event_id = int(row["id"])
            self._conn.execute(
                "SELECT pg_notify('opendeephole_scan_events', ?)",
                (str(event_id),),
            )
            self._conn.execute(
                """\
                DELETE FROM scan_stream_events
                WHERE id < (
                    SELECT COALESCE(MAX(id) - 50000, 0) FROM scan_stream_events
                )
                """
            )
            self._conn.commit()
        return event_id

    def publish_stream_events_batch(
        self,
        events: list[tuple[str, str, Any]],
        *,
        source_worker: str,
    ) -> int:
        if not events:
            return 0
        now = datetime.now(timezone.utc).isoformat()
        rows = [
            (
                scan_id,
                event_type,
                json.dumps(
                    data,
                    ensure_ascii=False,
                    default=str,
                    separators=(",", ":"),
                ),
                source_worker,
                now,
            )
            for scan_id, event_type, data in events
        ]
        with self._lock:
            self._conn.executemany(
                """\
                INSERT INTO scan_stream_events (
                    scan_id, event_type, data_json, source_worker, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                rows,
            )
            latest = self._conn.execute(
                "SELECT COALESCE(MAX(id), 0) AS id FROM scan_stream_events"
            ).fetchone()
            self._conn.execute(
                "SELECT pg_notify('opendeephole_scan_events', ?)",
                (str(latest["id"] or 0),),
            )
            self._conn.execute(
                """\
                DELETE FROM scan_stream_events
                WHERE id < (
                    SELECT COALESCE(MAX(id) - 50000, 0) FROM scan_stream_events
                )
                """
            )
            self._conn.commit()
        return len(rows)

    def list_stream_events(
        self,
        after_id: int,
        limit: int = 1000,
        *,
        scan_id: str | None = None,
    ) -> list[dict]:
        if scan_id is None:
            where = "id > ?"
            params: tuple[Any, ...] = (
                max(0, int(after_id)),
                max(1, int(limit)),
            )
        else:
            where = "id > ? AND scan_id = ?"
            params = (
                max(0, int(after_id)),
                scan_id,
                max(1, int(limit)),
            )
        rows = self._conn.execute(
            f"""\
            SELECT * FROM scan_stream_events
            WHERE {where}
            ORDER BY id
            LIMIT ?
            """,
            params,
        ).fetchall()
        return [dict(row) for row in rows]

    def get_latest_stream_event_id(self) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(MAX(id), 0) AS id FROM scan_stream_events"
        ).fetchone()
        return int(row["id"] or 0)
