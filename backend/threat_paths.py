"""Resolve module scopes without depending on the server's filesystem or OS."""

from __future__ import annotations

import ntpath
import posixpath
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class ModulePathResolution:
    scan_relative: str | None = None
    matched: bool = False


class ModulePathResolver:
    """Use explicit path provenance first, and evidence for legacy repairs.

    ``match`` returns the recorded spelling of a scan-relative path, or None.
    Prefixes may only be repaired against complete evidence (the
    Agent's filesystem or a complete inventory), never by suffix/basename.
    Coverage may opt into project-parent prefixes after the existing rules;
    artifact adaptation keeps its original behavior by default.
    """

    def __init__(
        self, project: str, scan_root: str, *,
        match: Callable[[str], str | None] | None = None,
        allow_repair: bool = False,
        allow_project_parent_prefix: bool = False,
    ) -> None:
        root = scan_root.replace("\\", "/")
        self.windows = bool(ntpath.splitdrive(root)[0])
        self.paths = ntpath if self.windows else posixpath
        self.root = self.paths.normpath(root).replace("\\", "/") if root else ""
        self.project = self.paths.normpath(project.replace("\\", "/")).replace("\\", "/") if project else self.root
        self.match = match
        self.allow_repair = allow_repair
        self.project_prefix = self._relative_to(self.root, self.project)
        self.prefixes = tuple(dict.fromkeys(
            value for value in (self.project_prefix, self.root.lstrip("/"))
            if value and value != "."
        ))
        self.project_parent_prefix = (
            self._relative_to(self.root, self.paths.dirname(self.project))
            if allow_project_parent_prefix and project and self.project_prefix is not None else None
        )

    def canonical(self, value: str) -> str:
        # Inventory names on POSIX may contain literal backslashes. Do not
        # reinterpret those names as directory separators when indexing them.
        value = self.paths.normpath(value)
        return ntpath.normcase(value).replace("\\", "/") if self.windows else value

    def _relative_to(self, value: str, root: str) -> str | None:
        if not root or not self.paths.isabs(root) or not self.paths.isabs(value):
            return None
        value = self.paths.normpath(value).replace("\\", "/")
        root = self.paths.normpath(root).replace("\\", "/").rstrip("/")
        key, prefix = self.canonical(value), self.canonical(root + "/").rstrip("/")
        if key.rstrip("/") == prefix:
            return "."
        # relpath rebuilds path components with ntpath.join, which consumes
        # a duplicated inner drive (C:/root/C:/root/a -> C:root/a). Preserve
        # those components until evidence can prove a complete-prefix repair.
        if key.startswith(prefix + "/"):
            return value[len(root) + 1:]
        return None

    def _strip_prefix(self, value: str, prefix: str) -> str | None:
        key, start = self.canonical(value), self.canonical(prefix)
        if key == start:
            return "."
        if key.startswith(start + "/"):
            return value[len(prefix) + 1:]
        return None

    def resolve(self, value: str, *, base: Literal["project", "scan"] = "project") -> ModulePathResolution:
        raw = value.strip().replace("\\", "/")
        if not raw or "\0" in raw or ".." in raw.split("/"):
            return ModulePathResolution()
        drive = ntpath.splitdrive(raw)[0]
        if drive and (not self.windows or not ntpath.isabs(raw)):
            return ModulePathResolution()
        # Existing audit target normalization collapsed UNC's leading //.
        # Restore it only when the result is inside this exact recorded root.
        if self.root.startswith("//") and raw.startswith("/") and not raw.startswith("//"):
            unc = "//" + raw.lstrip("/")
            if self._relative_to(unc, self.root) is not None:
                raw = unc
        raw = self.paths.normpath(raw).replace("\\", "/")
        if self.paths.isabs(raw):
            candidates = [self._relative_to(raw, self.root)]
        else:
            roots = (self.project, self.root) if base == "project" else (self.root, self.project)
            candidates = [self._relative_to(self.paths.join(root, raw), self.root) for root in roots]

        if self.match:
            for index, candidate in enumerate(candidates):
                if candidate is None or self.paths.isabs(candidate):
                    continue
                if index and candidates[0] is not None and not self.allow_repair:
                    continue
                matched = self.match(candidate)
                if matched is not None:
                    return ModulePathResolution(matched, True)

        if self.match and self.allow_repair:
            prefix_groups = [self.prefixes]
            if (self.project_parent_prefix and self.project_parent_prefix != "."
                    and self.project_parent_prefix not in self.prefixes):
                prefix_groups.append((*self.prefixes, self.project_parent_prefix))
            # Keep existing repairs, including ambiguous results, ahead of the
            # coverage-only fallback. Combining prefix groups from the start
            # could change already correct lightweight analysis mappings.
            for prefixes in prefix_groups:
                pending = [candidate for candidate in candidates if candidate is not None]
                seen = set(pending)
                repaired: dict[str, str] = {}
                while pending:
                    candidate = pending.pop()
                    for prefix in prefixes:
                        shorter = self._strip_prefix(candidate, prefix)
                        if shorter is None or shorter in seen:
                            continue
                        seen.add(shorter)
                        pending.append(shorter)
                        matched = None if self.paths.isabs(shorter) else self.match(shorter)
                        if matched is not None:
                            repaired[self.canonical(matched)] = matched
                if len(repaired) == 1:
                    return ModulePathResolution(next(iter(repaired.values())), True)
                if repaired:
                    return ModulePathResolution()  # Ambiguous: never invent scope.

        # Without evidence, retain the existing project-relative spelling of
        # already adapted native paths. This prevents an extra prefix on resume.
        if (base == "scan" and len(candidates) == 2 and self.project_prefix
                and self.project_prefix != "." and self._strip_prefix(raw, self.project_prefix) is not None):
            candidates.reverse()
        relative = next((candidate for candidate in candidates if candidate is not None), None)
        if relative is not None and self.paths.isabs(relative):
            relative = None
        return ModulePathResolution(relative)
