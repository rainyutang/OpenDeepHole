"""Persistent code-index store owned by the graph-build process.

Stores code_index.db directly inside the source directory being scanned.
This keeps each index aligned with the exact static-analysis scope.

Storage layout:
    <code_scan_path>/code_index.db
"""

from __future__ import annotations

from pathlib import Path


class IndexStore:
    """Manages code_index.db in the source directory being scanned."""

    def lookup(self, scan_path: Path) -> Path | None:
        """Return the DB path if *scan_path* already has a code_index.db."""
        abs_path = scan_path.resolve()
        db = abs_path / "code_index.db"
        if db.exists():
            return db
        return None

    def db_path(self, scan_path: Path) -> Path:
        """Return the canonical DB path for a scan root (may not exist yet)."""
        return scan_path.resolve() / "code_index.db"

    def remove(self, scan_path: Path) -> bool:
        """Delete the code_index.db for a scan root. Returns True if it existed."""
        db = self.db_path(scan_path)
        if db.exists():
            db.unlink()
            return True
        return False
