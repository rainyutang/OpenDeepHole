"""Persistent code index store.

Maps absolute project paths to their code_index.db files so that
re-scanning the same project (or a sub-directory of it) can skip
the tree-sitter indexing phase entirely.

Storage layout:
    ~/.opendeephole/indexes/
    ├── registry.json                   # path → entry mapping
    └── <16-char-path-hash>/
        └── code_index.db
"""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

_STORE_DIR = Path.home() / ".opendeephole" / "indexes"
_REGISTRY_FILE = _STORE_DIR / "registry.json"


class IndexStore:
    """Thread-unsafe single-process store — fine for the agent's sequential scan model."""

    def __init__(self) -> None:
        _STORE_DIR.mkdir(parents=True, exist_ok=True)
        self._registry: dict[str, dict] = self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def lookup(self, project_path: Path) -> Path | None:
        """Return persistent DB path if *project_path* (or a parent of it) was
        previously indexed.  Returns None if no valid entry is found."""
        abs_path = project_path.resolve()

        # 1. Exact match
        entry = self._registry.get(str(abs_path))
        if entry:
            db = Path(entry["db"])
            if db.exists():
                return db
            # Stale entry — remove it
            self._remove_key(str(abs_path))

        # 2. project_path is a sub-directory of a registered path
        for registered_str, entry in list(self._registry.items()):
            registered = Path(registered_str)
            try:
                if abs_path.is_relative_to(registered):
                    db = Path(entry["db"])
                    if db.exists():
                        return db
                    self._remove_key(registered_str)
            except ValueError:
                continue

        return None

    def save(self, project_path: Path, source_db: Path) -> Path:
        """Copy *source_db* into the persistent store and register *project_path*.

        Returns the path of the stored DB file.
        """
        abs_path = project_path.resolve()
        dest = self._dest_path(abs_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_db, dest)
        self._registry[str(abs_path)] = {
            "db": str(dest),
            "indexed_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
        self._flush()
        return dest

    def list_entries(self) -> list[dict]:
        """Return all registered entries for display / diagnostics."""
        result = []
        for path_str, entry in self._registry.items():
            db = Path(entry["db"])
            result.append({
                "project_path": path_str,
                "db_path": str(db),
                "indexed_at": entry.get("indexed_at", ""),
                "exists": db.exists(),
                "size_mb": round(db.stat().st_size / 1024 / 1024, 2) if db.exists() else 0,
            })
        return result

    def remove(self, project_path: Path) -> bool:
        """Delete entry and its DB file.  Returns True if the entry existed."""
        key = str(project_path.resolve())
        if key not in self._registry:
            return False
        db = Path(self._registry[key]["db"])
        self._remove_key(key)
        try:
            if db.exists():
                db.unlink()
            if db.parent.exists() and not any(db.parent.iterdir()):
                db.parent.rmdir()
        except Exception:
            pass
        return True

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _dest_path(self, abs_path: Path) -> Path:
        h = hashlib.sha256(str(abs_path).encode()).hexdigest()[:16]
        return _STORE_DIR / h / "code_index.db"

    def _load(self) -> dict[str, dict]:
        if _REGISTRY_FILE.exists():
            try:
                return json.loads(_REGISTRY_FILE.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def _flush(self) -> None:
        _REGISTRY_FILE.write_text(
            json.dumps(self._registry, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def _remove_key(self, key: str) -> None:
        self._registry.pop(key, None)
        self._flush()
