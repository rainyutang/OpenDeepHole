"""Resolve the working directory separately from the selected scan targets."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


class ScanPathValidationError(ValueError):
    def __init__(self, errors: Iterable[str]) -> None:
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


@dataclass(frozen=True)
class ScanScope:
    project: Path
    root: Path
    paths: tuple[Path, ...]
    kinds: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.kinds:
            object.__setattr__(self, "kinds", tuple("directory" if path.is_dir() else "file" for path in self.paths))

    def contains(self, path: str | Path) -> bool:
        candidate = Path(path).resolve()
        return any(
            candidate == target
            or (kind == "directory" and target in candidate.parents)
            for target, kind in zip(self.paths, self.kinds)
        )

    def identity(self) -> dict[str, object]:
        return {
            "project_path": str(self.project),
            "code_scan_path": str(self.root),
            "code_scan_paths": sorted(str(path) for path in self.paths),
            "code_scan_path_kinds": {str(path): kind for path, kind in zip(self.paths, self.kinds)},
        }

    def intersect_path(self, path: str | Path) -> tuple[Path, ...]:
        """Intersect an absolute module path with the selected files/directories."""
        candidate = Path(path).resolve()
        if self.contains(candidate):
            return (candidate,)
        return tuple(target for target in self.paths if candidate in target.parents)

    @property
    def is_legacy_directory(self) -> bool:
        return self.paths == (self.root,) and self.kinds == ("directory",)


def resolve_scan_scope(
    project_path: str | Path,
    code_scan_path: str | Path | None = None,
    code_scan_paths: Iterable[str | Path] | None = None,
) -> ScanScope:
    """Validate all selections on the Agent and return their minimum common directory.

    The legacy scalar accepts project-relative paths for local callers. New list
    entries must be absolute, matching the create-scan API contract.
    """
    try:
        project = Path(project_path).expanduser().resolve()
    except (OSError, RuntimeError) as exc:
        raise ScanPathValidationError([f"Project path cannot be resolved: {project_path}: {exc}"]) from exc
    errors: list[str] = []
    if not project.is_dir():
        errors.append(f"Project directory does not exist: {project}")
    else:
        try:
            if not os.access(project, os.R_OK | os.X_OK):
                raise PermissionError("directory is not readable/traversable")
            with os.scandir(project):
                pass
        except OSError as exc:
            errors.append(f"Project directory is inaccessible: {project}: {exc}")
    if isinstance(code_scan_paths, (str, bytes)):
        raise ScanPathValidationError(["code_scan_paths must be a list of absolute paths"])
    selected = list(code_scan_paths) if code_scan_paths is not None else []
    raw_paths = selected or [code_scan_path or project]
    resolved: list[Path] = []
    for value in raw_paths:
        if not str(value).strip():
            errors.append("Code scan path must not be empty")
            continue
        path = Path(str(value).strip()).expanduser()
        if selected and not path.is_absolute():
            errors.append(f"Code scan path must be absolute: {value}")
            continue
        try:
            path = (path if path.is_absolute() else project / path).resolve()
        except (OSError, RuntimeError) as exc:
            errors.append(f"Code scan path cannot be resolved: {value}: {exc}")
            continue
        if not (path.is_dir() or path.is_file()):
            errors.append(f"Code scan path does not exist or is not a file/directory: {path}")
        else:
            try:
                if path.is_dir():
                    if not os.access(path, os.R_OK | os.X_OK):
                        raise PermissionError("directory is not readable/traversable")
                    with os.scandir(path):
                        pass
                else:
                    with path.open("rb"):
                        pass
            except OSError as exc:
                errors.append(f"Code scan path is inaccessible: {path}: {exc}")
        if path != project and project not in path.parents:
            errors.append(f"code_scan_path must be inside project_path: {path}")
        if path not in resolved:
            resolved.append(path)
    if errors:
        raise ScanPathValidationError(errors)
    paths = tuple(
        path for path in resolved
        if not any(other != path and other.is_dir() and other in path.parents for other in resolved)
    )
    root = Path(os.path.commonpath([str(path if path.is_dir() else path.parent) for path in paths]))
    return ScanScope(project=project, root=root, paths=paths)


def scope_identity_matches(identity: object, scope: ScanScope) -> bool:
    """Accept historical metadata only for its original single-directory scope."""
    if not isinstance(identity, dict):
        return False
    if not identity.get("project_path") or not identity.get("code_scan_path"):
        return False
    try:
        if Path(str(identity["code_scan_path"])).resolve() != scope.root:
            return False
        paths = identity.get("code_scan_paths")
        if paths is None:
            if not scope.is_legacy_directory:
                return False
            paths = [identity.get("code_scan_path")]
        stored = resolve_scan_scope(
            str(identity.get("project_path") or ""), code_scan_paths=paths,
        )
        kinds = identity.get("code_scan_path_kinds")
        if kinds is not None and kinds != scope.identity()["code_scan_path_kinds"]:
            return False
        return stored.identity() == scope.identity()
    except (OSError, TypeError, ValueError):
        return False
