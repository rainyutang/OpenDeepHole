"""Read-only code-index consumer owned by the generic MCP service.

The SQLite schema is the data contract between graph construction and static
rule analysis; this module deliberately does not import the graph-build
process.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path


class CodeIndexReader:
    COMPLETE_STATUS = "complete"
    INDEXER_VERSION = "ctags-tree-sitter-refs-v2"

    def __init__(self, db_path: str | Path) -> None:
        path = Path(db_path).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"code index does not exist: {path}")
        self.db_path = str(path)
        self._conn = sqlite3.connect(
            f"file:{path.as_posix()}?mode=ro",
            uri=True,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row

    def get_metadata(self, key: str) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM index_metadata WHERE key = ?",
            (key,),
        ).fetchone()
        return row["value"] if row else None

    def is_index_complete(self) -> bool:
        return (
            self.get_metadata("status") == self.COMPLETE_STATUS
            and self.get_metadata("indexer") == self.INDEXER_VERSION
        )

    @staticmethod
    def _short_function_name(name: str) -> str:
        return name.rsplit("::", 1)[-1]

    @staticmethod
    def _path_matches(row_path: str, file_path: str | None) -> bool:
        if not file_path:
            return True
        row_path_norm = row_path.replace("\\", "/")
        file_path_norm = file_path.replace("\\", "/")
        return (
            row_path_norm == file_path_norm
            or row_path_norm.endswith(f"/{file_path_norm}")
            or file_path_norm.endswith(f"/{row_path_norm}")
        )

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
        return [
            row
            for row in rows
            if self._path_matches(row["file_path"], file_path)
        ]

    def _select_functions_by_name(self, name: str) -> list[sqlite3.Row]:
        return self._conn.execute(
            """SELECT f.*, fi.path AS file_path
               FROM functions f JOIN files fi ON f.file_id = fi.file_id
               WHERE f.name = ?
               ORDER BY fi.path, f.start_line""",
            (name,),
        ).fetchall()

    def _select_functions_by_short_name(self, short_name: str) -> list[sqlite3.Row]:
        return self._conn.execute(
            """SELECT f.*, fi.path AS file_path
               FROM functions f JOIN files fi ON f.file_id = fi.file_id
               WHERE f.name = ? OR f.name LIKE ? ESCAPE '\\'
               ORDER BY CASE WHEN f.name = ? THEN 0 ELSE 1 END,
                        fi.path, f.start_line""",
            (short_name, f"%::{self._escape_like(short_name)}", short_name),
        ).fetchall()

    def get_functions_by_name(
        self,
        name: str,
        file_path: str | None = None,
    ) -> list[sqlite3.Row]:
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
                row
                for row in candidates
                if name in (row["signature"] or "")
                or name in (row["body"] or "")
            ]
        return self._filter_rows_by_file(
            self._select_functions_by_short_name(name),
            file_path,
        )

    def get_function_by_location(
        self,
        file_path: str,
        line: int,
    ) -> sqlite3.Row | None:
        rows = self._conn.execute(
            """SELECT f.*, fi.path AS file_path
               FROM functions f JOIN files fi ON f.file_id = fi.file_id
               WHERE fi.path = ?
                 AND f.start_line <= ?
                 AND f.end_line >= ?
               ORDER BY (f.end_line - f.start_line), fi.path
               LIMIT 1""",
            (file_path.replace("\\", "/"), line, line),
        ).fetchall()
        if rows:
            return rows[0]
        candidates = self._conn.execute(
            """SELECT f.*, fi.path AS file_path
               FROM functions f JOIN files fi ON f.file_id = fi.file_id
               WHERE f.start_line <= ? AND f.end_line >= ?
               ORDER BY (f.end_line - f.start_line), fi.path""",
            (line, line),
        ).fetchall()
        return next(
            (
                row
                for row in candidates
                if self._path_matches(row["file_path"], file_path)
            ),
            None,
        )

    def get_all_functions(self) -> list[sqlite3.Row]:
        return self._conn.execute(
            """SELECT f.*, fi.path AS file_path
               FROM functions f JOIN files fi ON f.file_id = fi.file_id
               ORDER BY fi.path, f.start_line"""
        ).fetchall()

    def get_functions_by_path_prefix(self, prefix: str) -> list[sqlite3.Row]:
        normalized = (prefix or "").replace("\\", "/").strip("/")
        if not normalized:
            return self.get_all_functions()
        pslash = f"{normalized}/"
        return self._conn.execute(
            """SELECT f.*, fi.path AS file_path
               FROM functions f JOIN files fi ON f.file_id = fi.file_id
               WHERE fi.path = :prefix OR substr(fi.path, 1, :plen) = :pslash
               ORDER BY fi.path, f.start_line""",
            {"prefix": normalized, "plen": len(pslash), "pslash": pslash},
        ).fetchall()

    def get_function_body(self, name: str) -> str | None:
        row = self._conn.execute(
            "SELECT body FROM functions WHERE name = ? LIMIT 1",
            (name,),
        ).fetchone()
        return row["body"] if row else None

    def get_calls_from_function(self, function_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(
            """SELECT fc.*, fi.path AS file_path
               FROM function_calls fc JOIN files fi ON fc.file_id = fi.file_id
               WHERE fc.caller_function_id = ?""",
            (function_id,),
        ).fetchall()

    def get_call_sites_by_name(self, callee_name: str) -> list[sqlite3.Row]:
        return self._conn.execute(
            """SELECT fc.*, fi.path AS file_path, f.name AS caller_name
               FROM function_calls fc
               JOIN files fi ON fc.file_id = fi.file_id
               LEFT JOIN functions f ON fc.caller_function_id = f.function_id
               WHERE fc.callee_name = ?""",
            (callee_name,),
        ).fetchall()

    def get_structs_by_name(self, name: str) -> list[sqlite3.Row]:
        rows = self._conn.execute(
            """SELECT s.*, fi.path AS file_path
               FROM structs s JOIN files fi ON s.file_id = fi.file_id
               WHERE s.name = ?
               ORDER BY fi.path, s.start_line""",
            (name,),
        ).fetchall()
        if rows or "::" in name:
            return rows
        return self._conn.execute(
            """SELECT s.*, fi.path AS file_path
               FROM structs s JOIN files fi ON s.file_id = fi.file_id
               WHERE s.name LIKE ? ESCAPE '\\'
               ORDER BY fi.path, s.start_line""",
            (f"%::{self._escape_like(name)}",),
        ).fetchall()

    def get_all_structs(self) -> list[sqlite3.Row]:
        return self._conn.execute(
            """SELECT s.*, fi.path AS file_path
               FROM structs s JOIN files fi ON s.file_id = fi.file_id
               ORDER BY fi.path, s.start_line"""
        ).fetchall()

    def get_global_variables_by_name(self, name: str) -> list[sqlite3.Row]:
        return self._conn.execute(
            """SELECT gv.*, fi.path AS file_path
               FROM global_variables gv
               JOIN files fi ON gv.file_id = fi.file_id
               WHERE gv.name = ?""",
            (name,),
        ).fetchall()

    def get_all_global_variables(self) -> list[sqlite3.Row]:
        return self._conn.execute(
            """SELECT gv.*, fi.path AS file_path
               FROM global_variables gv
               JOIN files fi ON gv.file_id = fi.file_id
               ORDER BY fi.path, gv.start_line"""
        ).fetchall()

    def get_global_variable_reference_by_name(
        self,
        variable_name: str,
    ) -> list[sqlite3.Row]:
        return self._conn.execute(
            """SELECT r.*, fi.path AS file_path, f.name AS function_name
               FROM global_variable_references r
               JOIN files fi ON r.file_id = fi.file_id
               LEFT JOIN functions f ON r.function_id = f.function_id
               WHERE r.variable_name = ?""",
            (variable_name,),
        ).fetchall()

    def get_index_stats(self) -> dict[str, int]:
        return {
            name: int(
                self._conn.execute(
                    f"SELECT COUNT(*) AS count FROM {table}"
                ).fetchone()["count"]
            )
            for name, table in (
                ("files", "files"),
                ("functions", "functions"),
                ("structs", "structs"),
                ("global_variables", "global_variables"),
                ("function_calls", "function_calls"),
                ("global_variable_references", "global_variable_references"),
            )
        }

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "CodeIndexReader":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
