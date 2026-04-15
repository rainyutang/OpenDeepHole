"""opencode workspace and configuration generation."""

import json
import os
from pathlib import Path

from backend.config import get_config
from backend.logger import get_logger
from backend.registry import get_registry

logger = get_logger(__name__)


def create_scan_workspace(scan_id: str) -> Path:
    """Create an isolated opencode workspace for a scan.

    The workspace contains:
    - opencode.json: MCP server config (remote HTTP to localhost)
    - .opencode/skills/: Symlinks to skill definitions from checkers

    No source code is placed in the workspace — opencode accesses
    source via MCP tools using the project_id.

    Args:
        scan_id: Unique scan identifier.

    Returns:
        Path to the workspace directory.
    """
    config = get_config()
    workspace = Path(config.storage.scans_dir) / scan_id
    workspace.mkdir(parents=True, exist_ok=True)

    _write_opencode_config(workspace)
    _link_skills(workspace)

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


def _link_skills(workspace: Path) -> None:
    """Create symlinks to skill definitions from all registered checkers.

    Reads SKILL.md paths from the checker registry instead of a hardcoded directory.
    """
    skills_target = workspace / ".opencode" / "skills"
    skills_target.mkdir(parents=True, exist_ok=True)

    registry = get_registry()
    for name, entry in registry.items():
        if not entry.skill_path.is_file():
            logger.warning("SKILL.md not found for checker %s", name)
            continue

        link_dir = skills_target / name
        link_dir.mkdir(exist_ok=True)

        link_path = link_dir / "SKILL.md"
        if link_path.exists():
            os.remove(link_path)
        link_path.symlink_to(entry.skill_path.resolve())

    logger.debug("Linked skills for %d checkers", len(registry))
