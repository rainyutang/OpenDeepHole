"""Opt-in native discovery smoke test; no Provider or model calls are made."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import shutil
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest

from deephole_client.opencode_integration import get_global_opencode_workspace, managed_opencode_config_path
from deephole_client.skill_catalog import builtin_skill_sources, install_skills, needs_install, skill_source
from task_agent.serve_client import OpenCodeServeKey, OpenCodeServeManager, _config_hash


@pytest.mark.skipif(
    os.environ.get("OPENDEEPHOLE_TEST_OPENCODE_SKILLS") != "1" or not shutil.which("opencode"),
    reason="set OPENDEEPHOLE_TEST_OPENCODE_SKILLS=1 with a local OpenCode executable",
)
def test_native_serve_discovers_complete_catalog_and_refreshes_same_directory(tmp_path):
    async def run():
        workspace = tmp_path / "Agent Workspace With Spaces"
        project = tmp_path / "project"
        project.mkdir()
        config = SimpleNamespace(
            code_graph=SimpleNamespace(enabled=False), product_info=SimpleNamespace(enabled=False),
        )
        with (
            patch("deephole_client.opencode_integration._GLOBAL_WORKSPACE", workspace),
            patch("deephole_client.opencode_integration.get_config", return_value=config),
        ):
            get_global_opencode_workspace()
        content = managed_opencode_config_path(workspace).read_text()
        root = workspace / ".opencode/skills"
        sources = builtin_skill_sources()
        expected = {s.name for s in sources}
        env = {
            "XDG_DATA_HOME": str(tmp_path / "data"),
            "XDG_CACHE_HOME": str(tmp_path / "cache"),
            "XDG_STATE_HOME": str(tmp_path / "state"),
            "OPENCODE_DISABLE_EXTERNAL_SKILLS": "1",
            "OPENCODE_DISABLE_PROJECT_CONFIG": "1",
            "OPENCODE_DISABLE_MODELS_FETCH": "1",
            "OPENCODE_TEST_HOME": str(tmp_path / "opencode-home"),
            "OPENCODE_PURE": "1",
        }
        key = OpenCodeServeKey(
            tool="opencode", executable=shutil.which("opencode"), serve_port_auto=True,
            config_content=content, config_hash=_config_hash(content), env_overrides=tuple(env.items()),
        )
        manager = OpenCodeServeManager()

        async def skills():
            async with httpx.AsyncClient(trust_env=False, timeout=30) as client:
                response = await client.get(manager.base_url + "/skill", params={"directory": str(project)})
                response.raise_for_status()
                result = {item["name"]: item for item in response.json()}
                for name in expected:
                    assert result[name]["location"] == str(root / name / "SKILL.md")
                return result

        try:
            await manager._acquire_session(key, startup_cwd=workspace)
            pid = manager._proc.pid
            await skills()
            for _ in range(3):
                assert await manager._ensure_started(key, startup_cwd=workspace) == "reused"
                assert manager._proc.pid == pid
                await skills()
            original = next(s for s in sources if s.name == "fp-check")
            changed = dataclasses.replace(original, files={
                **original.files, "SKILL.md": original.files["SKILL.md"] + b"\nUPDATED-CATALOG-MARKER\n",
            })
            received = tmp_path / "received"
            received.mkdir()
            (received / "SKILL.md").write_text("---\nname: received-audit\ndescription: Received skill\n---\nNEW-CATALOG-MARKER\n")
            new_sources = [changed, skill_source(received, "checker:received-audit")]
            pending = asyncio.create_task(manager.update_skill_catalog(
                lambda: needs_install(workspace, new_sources),
                lambda: install_skills(workspace, new_sources),
            ))
            await asyncio.sleep(0)
            assert not pending.done()
            assert "received-audit" not in await skills()
            await manager._release_active_session()
            assert await asyncio.wait_for(pending, 20)
            await manager._acquire_session(key, startup_cwd=workspace)
            assert manager._proc.pid != pid
            discovered = await skills()
            assert "UPDATED-CATALOG-MARKER" in discovered["fp-check"]["content"]
            assert "NEW-CATALOG-MARKER" in discovered["received-audit"]["content"]
            assert json.loads(content)["skills"]["paths"] == [str(root)]
            await manager._release_active_session()
        finally:
            await manager.shutdown()

    asyncio.run(run())
