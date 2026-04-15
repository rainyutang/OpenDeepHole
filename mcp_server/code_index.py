"""Source code indexing and query helpers for MCP tools."""

import re
from pathlib import Path

_C_CPP_EXTS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh", ".hxx"}


def validate_project_path(projects_dir: str, project_id: str, relative_path: str) -> Path:
    """Validate and resolve a file path within a project directory.

    Raises ValueError on path traversal, FileNotFoundError if missing.
    """
    project_root = Path(projects_dir) / project_id
    if not project_root.is_dir():
        raise FileNotFoundError(f"Project not found: {project_id}")

    resolved = (project_root / relative_path).resolve()
    if not str(resolved).startswith(str(project_root.resolve())):
        raise ValueError(f"Path traversal detected: {relative_path}")
    if not resolved.is_file():
        raise FileNotFoundError(f"File not found: {relative_path}")

    return resolved


def list_project_files(project_root: Path, glob_patterns: str = "**/*.c,**/*.cpp,**/*.h,**/*.hpp") -> list[Path]:
    """List source files matching comma-separated glob patterns."""
    files: list[Path] = []
    for pattern in glob_patterns.split(","):
        pattern = pattern.strip()
        files.extend(project_root.glob(pattern))
    # Deduplicate while preserving order
    seen: set[Path] = set()
    unique: list[Path] = []
    for f in files:
        if f not in seen and f.is_file():
            seen.add(f)
            unique.append(f)
    return unique
