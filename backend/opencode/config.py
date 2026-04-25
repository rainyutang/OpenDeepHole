"""opencode workspace and configuration generation."""

import json
import os
from pathlib import Path

from backend.config import get_config
from backend.logger import get_logger
from backend.registry import get_registry

logger = get_logger(__name__)


def create_scan_workspace(scan_id: str, project_dir: Path | None = None) -> Path:
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
    _link_skills(workspace, project_dir)

    logger.info("Created opencode workspace: %s", workspace)
    return workspace


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


def _link_skills(workspace: Path, project_dir: Path | None = None) -> None:
    """Create skill definitions from all registered checkers.

    If a project has false positive experiences (skill_fp/<vuln_type>.md),
    the SKILL file is a merged copy (original + FP section) instead of a symlink.
    """
    skills_target = workspace / ".opencode" / "skills"
    skills_target.mkdir(parents=True, exist_ok=True)

    fp_dir = project_dir / "skill_fp" if project_dir else None

    registry = get_registry()
    for name, entry in registry.items():
        if not entry.skill_path.is_file():
            logger.warning("SKILL.md not found for checker %s", name)
            continue

        link_dir = skills_target / name
        link_dir.mkdir(exist_ok=True)

        skill_dest = link_dir / "SKILL.md"
        if skill_dest.exists():
            os.remove(skill_dest)

        # Check for project-specific false positive experiences
        fp_file = fp_dir / f"{name}.md" if fp_dir else None
        if fp_file and fp_file.is_file():
            # Merge original SKILL + false positive experiences
            original = entry.skill_path.read_text(encoding="utf-8")
            fp_content = fp_file.read_text(encoding="utf-8")
            merged = (
                original.rstrip()
                + "\n\n## 历史误报经验\n\n"
                + "以下是用户在审计过程中确认的误报案例，"
                + "分析时应参考这些经验避免重复误判：\n"
                + fp_content
            )
            skill_dest.write_text(merged, encoding="utf-8")
            logger.debug("Merged FP experience into skill for checker %s", name)
        else:
            # No FP experience, symlink as before
            skill_dest.symlink_to(entry.skill_path.resolve())

    logger.debug("Linked skills for %d checkers", len(registry))
