"""Explicit analysis inputs, independent of the Session working directory."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence


def normalize_code_paths(code_root: Path, code_paths: Sequence[str | Path] | None) -> tuple[Path, ...]:
    root = code_root.resolve()
    selected = []
    for value in code_paths or [root]:
        path = Path(value).expanduser().resolve()
        if not path.is_relative_to(root) or not (path.is_file() or path.is_dir()):
            raise ValueError(f"analysis input must be an existing file or directory within code_path: {value}")
        if path not in selected:
            selected.append(path)
    return tuple(selected)


def prepare_method_scope(code_root: Path, artifact_root: Path,
                         code_paths: Sequence[str | Path] | None, is_resume: bool) -> tuple[tuple[Path, ...], bool]:
    selected = normalize_code_paths(code_root, code_paths)
    identity = {"root": str(code_root.resolve()), "paths": sorted(str(path) for path in selected),
                "kinds": {str(path): "directory" if path.is_dir() else "file" for path in selected}}
    context = artifact_root / "analysis-scope.json"
    if is_resume:
        try:
            previous = json.loads(context.read_text(encoding="utf-8"))
            is_resume = previous == identity
        except FileNotFoundError:
            is_resume = selected == (code_root.resolve(),)
        except (OSError, ValueError):
            is_resume = False
    context.parent.mkdir(parents=True, exist_ok=True)
    context.write_text(json.dumps(identity, ensure_ascii=False), encoding="utf-8")
    return selected, is_resume
