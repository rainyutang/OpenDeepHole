"""opencode workspace and configuration generation."""

from __future__ import annotations

import json
import os
from pathlib import Path

from backend.config import get_config
from backend.logger import get_logger
from backend.models import FeedbackEntry
from backend.registry import get_registry

logger = get_logger(__name__)

# Subdirectories in checker dirs that should be symlinked into the workspace
_SKILL_RESOURCE_DIRS = {"references", "scripts", "assets"}


def create_scan_workspace(
    scan_id: str,
    project_dir: Path | None = None,
    feedback_entries: list[FeedbackEntry] | None = None,
) -> Path:
    """Create an opencode workspace for a scan.

    When *project_dir* is given the workspace is placed **inside** the
    project directory so that opencode (and any LSP server it may use) can
    locate and index the actual source files.  The opencode.json and skill
    definitions are written to the project directory.

    Falls back to a scan-specific directory under ``scans_dir`` when no
    project directory is provided.

    Args:
        scan_id: Unique scan identifier.
        project_dir: Project directory (preferred — enables LSP support).

    Returns:
        Path to the workspace directory.
    """
    if project_dir is not None and project_dir.is_dir():
        workspace = project_dir
    else:
        config = get_config()
        workspace = Path(config.storage.scans_dir) / scan_id
        workspace.mkdir(parents=True, exist_ok=True)

    _write_opencode_config(workspace)
    refresh_skills(workspace, project_dir, feedback_entries)

    logger.info("Created opencode workspace: %s", workspace)
    return workspace


def refresh_skills(
    workspace: Path,
    project_dir: Path | None = None,
    feedback_entries: list[FeedbackEntry] | None = None,
) -> None:
    """Regenerate SKILL files in an existing workspace.

    Can be called mid-scan to hot-update skills when the user changes
    the active feedback entries.
    """
    _link_skills(workspace, project_dir, feedback_entries=feedback_entries)


def _write_opencode_config(workspace: Path) -> None:
    """Generate opencode.json with MCP server configuration."""
    config = get_config()
    mcp_url = f"http://localhost:{config.mcp_server.port}/mcp"

    opencode_config = {
        "$schema": "https://opencode.ai/config.json",
        "mcp": {
            "deephole-code": {
                "type": "remote",
                "url": mcp_url,
                "enabled": True,
            }
        },
    }

    config_path = workspace / "opencode.json"
    config_path.write_text(json.dumps(opencode_config, indent=2))


def _link_skills(
    workspace: Path,
    project_dir: Path | None = None,
    feedback_entries: list[FeedbackEntry] | None = None,
) -> None:
    """Create skill definitions from all registered checkers.

    When *feedback_entries* are provided, false-positive entries are grouped
    by vuln_type and appended to the corresponding SKILL as a "历史误报经验"
    section.  Falls back to the legacy ``skill_fp/`` flat files when no
    entries are supplied.
    """
    skills_target = workspace / ".opencode" / "skills"
    skills_target.mkdir(parents=True, exist_ok=True)

    # Group feedback entries by vuln_type for quick lookup
    fp_by_type: dict[str, list[FeedbackEntry]] = {}
    if feedback_entries:
        for fb in feedback_entries:
            if fb.verdict == "false_positive":
                fp_by_type.setdefault(fb.vuln_type, []).append(fb)

    # Legacy fallback directory
    fp_dir = project_dir / "skill_fp" if project_dir else None

    registry = get_registry()
    for name, entry in registry.items():
        # 构建反馈内容（API 和 opencode 模式共用）
        fp_section: str | None = None
        if name in fp_by_type:
            lines = []
            for fb in fp_by_type[name]:
                lines.append(
                    f"\n- {fb.reason or fb.description}\n"
                )
            fp_section = "".join(lines)
        elif fp_dir:
            fp_file = fp_dir / f"{name}.md"
            if fp_file.is_file():
                fp_section = fp_file.read_text(encoding="utf-8")

        link_dir = skills_target / name
        link_dir.mkdir(exist_ok=True)

        # API 模式：将 prompt.txt（合并反馈）写入 PROMPT.md
        if entry.mode == "api":
            if entry.prompt_path and entry.prompt_path.is_file():
                prompt_dest = link_dir / "PROMPT.md"
                if prompt_dest.exists():
                    os.remove(prompt_dest)
                original = entry.prompt_path.read_text(encoding="utf-8")
                if fp_section:
                    merged = (
                        original.rstrip()
                        + "\n\n## 历史误报经验\n\n"
                        + "以下是用户在审计过程中确认的误报案例，"
                        + "分析时应参考这些经验避免重复误判：\n"
                        + fp_section
                    )
                    prompt_dest.write_text(merged, encoding="utf-8")
                    logger.debug("Merged FP experience into prompt for checker %s", name)
                else:
                    prompt_dest.write_text(original, encoding="utf-8")
            continue

        # opencode 模式：原有 SKILL.md 逻辑
        if not entry.skill_path.is_file():
            logger.warning("SKILL.md not found for checker %s", name)
            continue

        skill_dest = link_dir / "SKILL.md"
        if skill_dest.exists():
            os.remove(skill_dest)

        if fp_section:
            original = entry.skill_path.read_text(encoding="utf-8")
            merged = (
                original.rstrip()
                + "\n\n## 历史误报经验\n\n"
                + "以下是用户在审计过程中确认的误报案例，"
                + "分析时应参考这些经验避免重复误判：\n"
                + fp_section
            )
            skill_dest.write_text(merged, encoding="utf-8")
            logger.debug("Merged FP experience into skill for checker %s", name)
        else:
            skill_dest.symlink_to(entry.skill_path.resolve())

        # Symlink whitelisted resource directories (references, scripts, assets)
        for dir_name in _SKILL_RESOURCE_DIRS:
            src = entry.directory / dir_name
            if src.is_dir():
                link_dest = link_dir / dir_name
                if link_dest.exists() or link_dest.is_symlink():
                    os.remove(link_dest)
                link_dest.symlink_to(src.resolve())

    logger.debug("Linked skills for %d checkers", len(registry))


def get_skill_content(workspace: Path, vuln_type: str) -> str | None:
    """Read the current SKILL/PROMPT content for a given vuln_type from a workspace."""
    skill_dir = workspace / ".opencode" / "skills" / vuln_type
    # 优先 SKILL.md（opencode 模式），其次 PROMPT.md（API 模式）
    for filename in ("SKILL.md", "PROMPT.md"):
        path = skill_dir / filename
        if path.is_file():
            return path.resolve().read_text(encoding="utf-8")
    return None
