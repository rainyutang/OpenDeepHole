"""Skill name validation shared by fixed-directory hosts and task checks."""

from __future__ import annotations

from pathlib import Path

import yaml


def read_skill_name(path: Path) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0].strip() != "---":
        raise ValueError(f"Skill is missing YAML frontmatter: {path}")
    end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if end is None:
        raise ValueError(f"Skill has unclosed YAML frontmatter: {path}")
    try:
        metadata = yaml.safe_load("\n".join(lines[1:end]))
    except yaml.YAMLError as exc:
        raise ValueError(f"Skill has invalid YAML frontmatter: {path}") from exc
    name = metadata.get("name") if isinstance(metadata, dict) else None
    if (
        not isinstance(name, str) or not name.strip() or name != name.strip()
        or name in {".", ".."} or any(char in name for char in '/\\:\x00')
    ):
        raise ValueError(f"Skill has an invalid name: {path}")
    return name


def validate_fixed_skills(root: Path, requested_roots: tuple[Path, ...]) -> None:
    """Check availability without registering task paths or comparing old bodies."""
    for requested in requested_roots:
        files = sorted(requested.rglob("SKILL.md"))
        if not files:
            raise ValueError(f"Required Skill directory is empty or missing: {requested}")
        for source in files:
            name = read_skill_name(source)
            installed = root / name / "SKILL.md"
            if not installed.is_file() or read_skill_name(installed) != name:
                raise ValueError(f"Required Skill {name!r} is not installed in {root}")
