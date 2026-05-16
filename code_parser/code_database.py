"""SQLite-backed code index database.

Stores parsed C/C++ structures (functions, structs, global variables,
function calls, variable references) for a single project. The DB file
is created at the path supplied to the constructor.
"""

import sqlite3
from pathlib import Path


class CodeDatabase:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # WAL mode allows concurrent reads during writes; NORMAL reduces fsync overhead
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._create_tables()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _create_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS files (
                file_id   INTEGER PRIMARY KEY AUTOINCREMENT,
                path      TEXT NOT NULL UNIQUE,
                hash      TEXT
            );

            CREATE TABLE IF NOT EXISTS functions (
                function_id  INTEGER PRIMARY KEY AUTOINCREMENT,
                name         TEXT NOT NULL,
                signature    TEXT,
                return_type  TEXT,
                file_id      INTEGER REFERENCES files(file_id),
                start_line   INTEGER,
                end_line     INTEGER,
                is_static    INTEGER DEFAULT 0,
                linkage      TEXT,
                body         TEXT
            );

            CREATE TABLE IF NOT EXISTS structs (
                struct_id   INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL,
                file_id     INTEGER REFERENCES files(file_id),
                start_line  INTEGER,
                end_line    INTEGER,
                definition  TEXT
            );

            CREATE TABLE IF NOT EXISTS function_calls (
                call_id              INTEGER PRIMARY KEY AUTOINCREMENT,
                caller_function_id   INTEGER REFERENCES functions(function_id),
                callee_name          TEXT NOT NULL,
                callee_function_id   INTEGER REFERENCES functions(function_id),
                file_id              INTEGER REFERENCES files(file_id),
                line                 INTEGER,
                column               INTEGER
            );

            CREATE TABLE IF NOT EXISTS global_variables (
                global_var_id  INTEGER PRIMARY KEY AUTOINCREMENT,
                name           TEXT NOT NULL,
                file_id        INTEGER REFERENCES files(file_id),
                start_line     INTEGER,
                end_line       INTEGER,
                is_extern      INTEGER DEFAULT 0,
                is_static      INTEGER DEFAULT 0,
                definition     TEXT
            );

            CREATE TABLE IF NOT EXISTS global_variable_references (
                reference_id   INTEGER PRIMARY KEY AUTOINCREMENT,
                global_var_id  INTEGER REFERENCES global_variables(global_var_id),
                variable_name  TEXT NOT NULL,
                file_id        INTEGER REFERENCES files(file_id),
                function_id    INTEGER REFERENCES functions(function_id),
                line           INTEGER,
                column         INTEGER,
                context        TEXT,
                access_type    TEXT
            );
        """)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Transaction control
    # ------------------------------------------------------------------

    def commit(self) -> None:
        """Commit the current transaction. Call after processing each file."""
        self._conn.commit()

    # ------------------------------------------------------------------
    # Insertion helpers  (no auto-commit — caller controls transactions)
    # ------------------------------------------------------------------

    def get_or_create_file(self, path: str, file_hash: str = "") -> int:
        cur = self._conn.execute(
            "SELECT file_id FROM files WHERE path = ?", (path,)
        )
        row = cur.fetchone()
        if row:
            return row["file_id"]
        cur = self._conn.execute(
            "INSERT INTO files (path, hash) VALUES (?, ?)", (path, file_hash)
        )
        return cur.lastrowid

    def insert_function(
        self,
        name: str,
        signature: str,
        return_type: str,
        file_id: int,
        start_line: int,
        end_line: int,
        is_static: bool,
        linkage: str,
        body: str,
    ) -> int:
        cur = self._conn.execute(
            """INSERT INTO functions
               (name, signature, return_type, file_id, start_line, end_line, is_static, linkage, body)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, signature, return_type, file_id, start_line, end_line,
             1 if is_static else 0, linkage, body),
        )
        return cur.lastrowid

    def insert_struct(
        self,
        name: str,
        file_id: int,
        start_line: int,
        end_line: int,
        definition: str,
    ) -> int:
        cur = self._conn.execute(
            """INSERT INTO structs (name, file_id, start_line, end_line, definition)
               VALUES (?, ?, ?, ?, ?)""",
            (name, file_id, start_line, end_line, definition),
        )
        return cur.lastrowid

    def insert_function_call(
        self,
        caller_function_id: int,
        callee_name: str,
        file_id: int,
        line: int,
        column: int,
        callee_function_id: int | None = None,
    ) -> None:
        self._conn.execute(
            """INSERT INTO function_calls
               (caller_function_id, callee_name, callee_function_id, file_id, line, column)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (caller_function_id, callee_name, callee_function_id, file_id, line, column),
        )

    def insert_global_variable(
        self,
        name: str,
        file_id: int,
        start_line: int,
        end_line: int,
        is_extern: bool,
        is_static: bool,
        definition: str,
    ) -> int:
        cur = self._conn.execute(
            """INSERT INTO global_variables
               (name, file_id, start_line, end_line, is_extern, is_static, definition)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (name, file_id, start_line, end_line,
             1 if is_extern else 0, 1 if is_static else 0, definition),
        )
        return cur.lastrowid

    def insert_global_variable_reference(
        self,
        global_var_id: int,
        variable_name: str,
        file_id: int,
        function_id: int | None,
        line: int,
        column: int,
        context: str,
        access_type: str,
    ) -> None:
        self._conn.execute(
            """INSERT INTO global_variable_references
               (global_var_id, variable_name, file_id, function_id, line, column, context, access_type)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (global_var_id, variable_name, file_id, function_id, line, column, context, access_type),
        )

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    @staticmethod
    def _short_function_name(name: str) -> str:
        """Return the unqualified function name for C++ qualified names."""
        return name.rsplit("::", 1)[-1]

    @staticmethod
    def _path_matches(row_path: str, file_path: str | None) -> bool:
        if not file_path:
            return True
        row_path_norm = row_path.replace("\\", "/")
        file_path_norm = file_path.replace("\\", "/")
        return row_path_norm == file_path_norm or row_path_norm.endswith(f"/{file_path_norm}")

    @staticmethod
    def _escape_like(value: str) -> str:
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    def _filter_rows_by_file(
        self,
        rows: list[sqlite3.Row],
        file_path: str | None,
    ) -> list[sqlite3.Row]:
        if not file_path:
            return rows
        return [row for row in rows if self._path_matches(row["file_path"], file_path)]

    def _select_functions_by_name(self, name: str) -> list[sqlite3.Row]:
        return self._conn.execute(
            """SELECT f.*, fi.path as file_path
               FROM functions f JOIN files fi ON f.file_id = fi.file_id
               WHERE f.name = ?
               ORDER BY fi.path, f.start_line""",
            (name,),
        ).fetchall()

    def _select_functions_by_short_name(self, short_name: str) -> list[sqlite3.Row]:
        return self._conn.execute(
            """SELECT f.*, fi.path as file_path
               FROM functions f JOIN files fi ON f.file_id = fi.file_id
               WHERE f.name = ? OR f.name LIKE ? ESCAPE '\\'
               ORDER BY
                   CASE WHEN f.name = ? THEN 0 ELSE 1 END,
                   fi.path,
                   f.start_line""",
            (short_name, f"%::{self._escape_like(short_name)}", short_name),
        ).fetchall()

    def get_functions_by_name(
        self,
        name: str,
        file_path: str | None = None,
    ) -> list[sqlite3.Row]:
        """Return functions matching *name*.

        C++ qualified names are matched exactly first.  For old indexes that
        stored only the short name, fall back only when the stored signature or
        body still contains the requested qualified name.
        """
        exact_rows = self._filter_rows_by_file(
            self._select_functions_by_name(name),
            file_path,
        )
        if exact_rows:
            return exact_rows

        if "::" in name:
            short_name = self._short_function_name(name)
            candidates = self._filter_rows_by_file(
                self._select_functions_by_name(short_name),
                file_path,
            )
            return [
                row for row in candidates
                if name in (row["signature"] or "") or name in (row["body"] or "")
            ]

        short_rows = self._filter_rows_by_file(
            self._select_functions_by_short_name(name),
            file_path,
        )
        return short_rows

    def get_all_functions(self) -> list[sqlite3.Row]:
        """Return all functions with their file paths."""
        return self._conn.execute(
            """SELECT f.*, fi.path as file_path
               FROM functions f JOIN files fi ON f.file_id = fi.file_id
               ORDER BY fi.path, f.start_line""",
        ).fetchall()

    def get_function_body(self, name: str) -> str | None:
        """Return the body of the first function matching name, or None."""
        row = self._conn.execute(
            "SELECT body FROM functions WHERE name = ? LIMIT 1", (name,)
        ).fetchone()
        return row["body"] if row else None

    def get_calls_from_function(self, function_id: int) -> list[sqlite3.Row]:
        """Return all function calls made from the given function."""
        return self._conn.execute(
            """SELECT fc.*, fi.path as file_path
               FROM function_calls fc JOIN files fi ON fc.file_id = fi.file_id
               WHERE fc.caller_function_id = ?""",
            (function_id,),
        ).fetchall()

    def get_call_sites_by_name(self, callee_name: str) -> list[sqlite3.Row]:
        """Return all call sites where callee_name is called."""
        return self._conn.execute(
            """SELECT fc.*, fi.path as file_path,
                      f.name as caller_name
               FROM function_calls fc
               JOIN files fi ON fc.file_id = fi.file_id
               LEFT JOIN functions f ON fc.caller_function_id = f.function_id
               WHERE fc.callee_name = ?""",
            (callee_name,),
        ).fetchall()

    def get_structs_by_name(self, name: str) -> list[sqlite3.Row]:
        """Return all structs matching the given name."""
        return self._conn.execute(
            """SELECT s.*, fi.path as file_path
               FROM structs s JOIN files fi ON s.file_id = fi.file_id
               WHERE s.name = ?""",
            (name,),
        ).fetchall()

    def get_global_variables_by_name(self, name: str) -> list[sqlite3.Row]:
        """Return all global variables matching the given name."""
        return self._conn.execute(
            """SELECT gv.*, fi.path as file_path
               FROM global_variables gv JOIN files fi ON gv.file_id = fi.file_id
               WHERE gv.name = ?""",
            (name,),
        ).fetchall()

    def get_global_variable_reference_by_name(self, variable_name: str) -> list[sqlite3.Row]:
        """Return all references to the global variable with the given name."""
        return self._conn.execute(
            """SELECT r.*, fi.path as file_path, f.name as function_name
               FROM global_variable_references r
               JOIN files fi ON r.file_id = fi.file_id
               LEFT JOIN functions f ON r.function_id = f.function_id
               WHERE r.variable_name = ?""",
            (variable_name,),
        ).fetchall()

    def checkpoint(self) -> None:
        """Flush WAL into the main DB file so the file can be safely copied.

        In WAL mode, committed data lives in the -wal sidecar until a
        checkpoint merges it back.  Call this before copying/backing up
        the DB file to ensure the copy is self-contained.
        """
        self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
