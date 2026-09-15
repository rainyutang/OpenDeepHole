"""Install complete, versioned business Skills in one Agent-owned directory."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from task_agent.skills import read_skill_name

_MANIFEST = ".opendeephole-skills.json"
_SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".mypy_cache"}


@dataclass(frozen=True)
class SkillSource:
    name: str
    owner: str
    files: dict[str, bytes]

    @property
    def digest(self) -> str:
        value = hashlib.sha256()
        for name, content in sorted(self.files.items()):
            value.update(name.encode("utf-8") + b"\0" + content + b"\0")
        return value.hexdigest()


def skill_source(directory: Path, owner: str) -> SkillSource:
    name = read_skill_name(directory / "SKILL.md")
    files: dict[str, bytes] = {}
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory)
        if any(part in _SKIP_DIRS for part in relative.parts):
            continue
        if path.is_symlink():
            raise ValueError(f"Skill resources must not be symlinks: {path}")
        if path.is_file() and path.suffix not in {".pyc", ".pyo"}:
            files[relative.as_posix()] = path.read_bytes()
    return SkillSource(name, owner, files)


def _runtime_source(source: SkillSource) -> SkillSource:
    """Keep runtime resources, excluding catalog-only scenario documentation."""
    return SkillSource(source.name, source.owner, {
        name: content for name, content in source.files.items()
        if Path(name).name != "SCENARIOS.md"
    })


def rule_skill_sources(roots: list[Path]) -> list[SkillSource]:
    return [
        skill_source(path.parent, f"checker:{checker.name}")
        for root in roots
        for checker in sorted(root.iterdir())
        if (checker / "checker.yaml").is_file()
        for path in sorted((checker / "skills").rglob("SKILL.md"))
    ]


def builtin_skill_sources(runtime_root: Path | None = None) -> list[SkillSource]:
    root = runtime_root or Path(__file__).resolve().parent.parent
    client = root / "deephole_client"
    sources = rule_skill_sources([
        client / "vulnerability_mining/engines/static_candidate/rules",
    ])
    for category, directory in (
        ("fp-review", client / "fp_review/methods"),
        ("threat-analysis", client / "threat_analysis/methods"),
        ("engine", client / "vulnerability_mining/engines"),
        ("system", client / "builtin_skills"),
    ):
        if not directory.is_dir():
            raise ValueError(f"Agent package is missing Skill resources: {directory}")
        for owner in sorted(directory.iterdir()):
            skills = owner if category == "system" else owner / "skills"
            for path in sorted(skills.rglob("SKILL.md")):
                sources.append(skill_source(path.parent, f"{category}:{owner.name}"))
    return sources


def _read_manifest(workspace: Path) -> dict:
    path = workspace / _MANIFEST
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError(f"Invalid managed Skill manifest: {path}")
    return data["skills"]


def _changes(
    workspace: Path, sources: list[SkillSource], *, bundled: bool, replace_existing: bool,
) -> tuple[dict, list[SkillSource], set[str]]:
    installed_root = workspace / ".opencode/skills"
    manifest = _read_manifest(workspace)
    changed: list[SkillSource] = []
    aliases: set[str] = set()
    owners: dict[str, str] = {}
    for source in sources:
        # Keep the original bundled fingerprint so excluding documentation does
        # not look like a package upgrade and overwrite a newer synced Skill.
        bundled_hash = source.digest
        source = _runtime_source(source)
        if source.name in owners:
            raise ValueError(f"Duplicate Skill {source.name!r}: {owners[source.name]}, {source.owner}")
        owners[source.name] = source.owner
        previous = manifest.get(source.name, {})
        if previous and previous["owner"] != source.owner:
            raise ValueError(f"Skill {source.name!r} belongs to {previous['owner']}, not {source.owner}")
        destination = installed_root / source.name
        current = None
        if (destination / "SKILL.md").is_file():
            current = skill_source(destination, source.owner)
        runtime_current = _runtime_source(current) if current is not None else None
        if not previous and not bundled and runtime_current and runtime_current.digest != source.digest:
            raise ValueError(f"Skill conflicts with an unmanaged installation: {source.name}")
        # A local resume must never reinstall its old snapshot over a newer
        # shared version. Unchanged bundled resources also retain synced updates.
        keep = current is not None and (
            not replace_existing
            or (bundled and previous.get("bundled_hash") == bundled_hash)
        )
        effective = runtime_current if keep else source
        assert effective is not None
        entry = {**previous, "owner": source.owner, "hash": effective.digest}
        if bundled:
            entry["bundled_hash"] = bundled_hash
        manifest[source.name] = entry
        if current is None or current.digest != effective.digest:
            changed.append(effective)
        # Older Agents installed checker directories using checker IDs rather
        # than frontmatter names. Only migrate these known managed aliases.
        if source.owner.startswith("checker:"):
            alias = source.owner.split(":", 1)[1]
            old = installed_root / alias / "SKILL.md"
            if alias != source.name and old.is_file() and read_skill_name(old) == source.name:
                aliases.add(alias)
    # Refuse ambiguous user copies instead of depending on OpenCode scan order.
    if installed_root.is_dir():
        for path in installed_root.rglob("SKILL.md"):
            relative = path.relative_to(installed_root)
            if relative.parts[0] in aliases or relative.parts[0] in owners:
                continue
            try:
                name = read_skill_name(path)
            except ValueError:
                continue  # Unrelated user content is left intact.
            if name in owners:
                raise ValueError(f"Duplicate unmanaged Skill {name!r}: {path}")
    return manifest, changed, aliases


def needs_install(
    workspace: Path, sources: list[SkillSource], *, bundled: bool = False,
    replace_existing: bool = True,
) -> bool:
    manifest, changed, aliases = _changes(
        workspace, sources, bundled=bundled, replace_existing=replace_existing,
    )
    return bool(changed or aliases or manifest != _read_manifest(workspace))


def install_skills(
    workspace: Path, sources: list[SkillSource], *, bundled: bool = False,
    replace_existing: bool = True,
) -> bool:
    """Publish a complete tree and its manifest, rolling back failed replacements.

    The caller owns the workspace lock and, for a live Serve, its idle barrier.
    Staging/backup directories stay outside every registered Skill search root.
    """
    manifest, changed, aliases = _changes(
        workspace, sources, bundled=bundled, replace_existing=replace_existing,
    )
    if not changed and not aliases and manifest == _read_manifest(workspace):
        return False
    root = workspace / ".opencode/skills"
    root.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".skill-install-", dir=workspace) as temporary:
        staging = Path(temporary) / "skills"
        backup = Path(temporary) / "previous"
        if root.exists():
            shutil.copytree(root, staging, symlinks=True)
        else:
            staging.mkdir()
        for name in aliases | {item.name for item in changed}:
            target = staging / name
            if target.is_symlink() or target.is_file():
                target.unlink()
            elif target.is_dir():
                shutil.rmtree(target)
        for source in changed:
            for name, content in source.files.items():
                target = staging / source.name / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            if skill_source(staging / source.name, source.owner).digest != source.digest:
                raise ValueError(f"Skill staging verification failed: {source.name}")
        staged_manifest = Path(temporary) / "manifest.json"
        staged_manifest.write_text(
            json.dumps({"version": 1, "skills": manifest}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        had_root = root.exists()
        if had_root:
            os.replace(root, backup)
        try:
            os.replace(staging, root)
            os.replace(staged_manifest, workspace / _MANIFEST)
        except BaseException:
            if root.exists():
                shutil.rmtree(root)
            if had_root:
                os.replace(backup, root)
            raise
    return True
