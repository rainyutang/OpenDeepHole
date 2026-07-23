"""Source filtering owned by the code-graph build process."""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator, MutableSequence
from pathlib import Path


OP_DEEP_HOLE_DIR = ".opendeephole"
DEFAULT_SOURCE_SKIP_DIRS = frozenset({
    OP_DEEP_HOLE_DIR,
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "vendor",
    "third_party",
    "3rdparty",
    "thirdparty",
    "external",
    "extern",
    "deps",
    "build",
    "cmake-build-debug",
    "cmake-build-release",
    "out",
    "output",
    "_build",
    ".build",
    "__pycache__",
    ".venv",
    "venv",
})
DEFAULT_SOURCE_SKIP_DIR_PREFIXES = (".opendeephole-index-",)


def should_skip_source_dir_name(
    name: str,
    *,
    skip_dirs: Iterable[str] = DEFAULT_SOURCE_SKIP_DIRS,
    skip_prefixes: Iterable[str] = DEFAULT_SOURCE_SKIP_DIR_PREFIXES,
) -> bool:
    return (
        name == OP_DEEP_HOLE_DIR
        or name in set(skip_dirs)
        or any(name.startswith(prefix) for prefix in skip_prefixes)
    )


def prune_source_dirnames(
    dirnames: MutableSequence[str],
    *,
    skip_dirs: Iterable[str] = DEFAULT_SOURCE_SKIP_DIRS,
    skip_prefixes: Iterable[str] = DEFAULT_SOURCE_SKIP_DIR_PREFIXES,
) -> None:
    dirnames[:] = [
        name
        for name in dirnames
        if not should_skip_source_dir_name(
            name,
            skip_dirs=skip_dirs,
            skip_prefixes=skip_prefixes,
        )
    ]


def iter_source_files(
    root: Path,
    extensions: Iterable[str],
    *,
    skip_dirs: Iterable[str] = DEFAULT_SOURCE_SKIP_DIRS,
    skip_prefixes: Iterable[str] = DEFAULT_SOURCE_SKIP_DIR_PREFIXES,
) -> Iterator[Path]:
    root = Path(root)
    if should_skip_source_dir_name(
        root.name,
        skip_dirs=skip_dirs,
        skip_prefixes=skip_prefixes,
    ):
        return
    normalized_exts = {ext.lower() for ext in extensions}
    for dirpath, dirnames, filenames in os.walk(root):
        prune_source_dirnames(
            dirnames,
            skip_dirs=skip_dirs,
            skip_prefixes=skip_prefixes,
        )
        for filename in filenames:
            path = Path(dirpath) / filename
            if path.suffix.lower() in normalized_exts:
                yield path
