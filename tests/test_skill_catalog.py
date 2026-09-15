from __future__ import annotations

import asyncio
import dataclasses
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from deephole_client.skill_catalog import (
    builtin_skill_sources, install_skills, needs_install, skill_source,
)
from task_agent.host import OpenCodeHostBindings, OpenCodeSessionRuntime
from task_agent.serve_client import OpenCodeServeKey, OpenCodeServeManager, _config_hash
from task_agent.task_service import _runtime_with_task_skills


def source(tmp_path, *, name="demo", body="v1", owner="checker:demo"):
    root = tmp_path / name
    root.mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: Test skill\n---\n{body}\n", encoding="utf-8",
    )
    (root / "references").mkdir(exist_ok=True)
    (root / "references/data.txt").write_text(body, encoding="utf-8")
    return skill_source(root, owner)


def test_complete_builtin_catalog_and_idempotent_initialization(tmp_path):
    sources = builtin_skill_sources()
    names = {s.name for s in sources}
    assert len(names) == len(sources) == 28
    assert {
        "fp-check", "prove-bug", "prove-fp", "final-judge", "npd", "oob-audit",
        "resleak", "value-asset-map", "high-risk-module-map", "high-risk-module-merge",
        "attack-tree-by-asset", "multi-version-vulnerability-audit", "deephole-skill-creator",
    } <= names
    workspace = tmp_path / "Agent With Spaces"
    assert install_skills(workspace, sources, bundled=True)
    paths = list((workspace / ".opencode/skills").rglob("*"))
    assert not any(p.name == "SCENARIOS.md" for p in paths)
    before = {p: p.stat().st_mtime_ns for p in paths}
    assert not install_skills(workspace, sources, bundled=True)
    assert before == {p: p.stat().st_mtime_ns for p in paths}
    for s in sources:
        copied = skill_source(workspace / ".opencode/skills" / s.name, s.owner)
        expected = dict(s.files)
        expected.pop("SCENARIOS.md", None)
        assert copied.files == expected


def test_install_excludes_scenarios_and_preserves_runtime_resources(tmp_path):
    original = source(tmp_path / "source")
    source_root = tmp_path / "source/demo"
    (source_root / "SCENARIOS.md").write_text("Catalog introduction", encoding="utf-8")
    (source_root / "references/SCENARIOS.md").write_text("Nested introduction", encoding="utf-8")
    for name in ("agents/openai.yaml", "assets/example.json", "scripts/check.py"):
        path = source_root / name
        path.parent.mkdir()
        path.write_text(name, encoding="utf-8")
    packaged = skill_source(source_root, original.owner)
    workspace = tmp_path / "workspace"
    assert install_skills(workspace, [packaged])
    installed = workspace / ".opencode/skills/demo"
    assert not list(installed.rglob("SCENARIOS.md"))
    assert (source_root / "SCENARIOS.md").read_text() == "Catalog introduction"
    assert (source_root / "references/SCENARIOS.md").read_text() == "Nested introduction"
    for name, content in original.files.items():
        assert (installed / name).read_bytes() == content
    for name in ("agents/openai.yaml", "assets/example.json", "scripts/check.py"):
        assert (installed / name).read_text() == name
    (source_root / "SCENARIOS.md").write_text("Updated introduction", encoding="utf-8")
    updated = skill_source(source_root, original.owner)
    assert not needs_install(workspace, [updated])
    assert not install_skills(workspace, [updated])


@pytest.mark.parametrize("mode", ["bootstrap", "resume", "dispatch"])
def test_legacy_scenarios_removed_without_reverting_synced_skill(tmp_path, mode):
    workspace = tmp_path / "workspace"
    bundled = source(tmp_path / "bundle")
    (tmp_path / "bundle/demo/SCENARIOS.md").write_text("Bundled introduction", encoding="utf-8")
    bundled = skill_source(tmp_path / "bundle/demo", bundled.owner)
    root = workspace / ".opencode/skills"
    current = source(root, body="v2")
    installed = root / "demo"
    (installed / "SCENARIOS.md").write_text("Legacy introduction", encoding="utf-8")
    (installed / "references/SCENARIOS.md").write_text("Nested introduction", encoding="utf-8")
    legacy = skill_source(installed, current.owner)
    # Reproduce the pre-filter manifest, including the original bundle hash.
    manifest_path = workspace / ".opendeephole-skills.json"
    manifest_path.write_text(json.dumps({"version": 1, "skills": {
        current.name: {"owner": current.owner, "hash": legacy.digest, "bundled_hash": bundled.digest},
    }}), encoding="utf-8")
    source(root, name="user-owned", owner="user")
    user_document = root / "user-owned/SCENARIOS.md"
    user_document.write_text("User introduction", encoding="utf-8")
    incoming = legacy if mode == "dispatch" else bundled
    options = {"bundled": mode == "bootstrap", "replace_existing": mode != "resume"}

    assert needs_install(workspace, [incoming], **options)
    assert install_skills(workspace, [incoming], **options)
    assert not list(installed.rglob("SCENARIOS.md"))
    assert skill_source(installed, current.owner).files == current.files
    assert user_document.read_text() == "User introduction"
    assert json.loads(manifest_path.read_text())["skills"][current.name]["hash"] == current.digest
    assert not needs_install(workspace, [incoming], **options)
    assert not install_skills(workspace, [incoming], **options)


def test_updates_survive_bootstrap_and_local_resume(tmp_path):
    workspace = tmp_path / "workspace"
    old = source(tmp_path / "old")
    new = source(tmp_path / "new", body="v2")
    install_skills(workspace, [old], bundled=True)
    install_skills(workspace, [new])
    assert not install_skills(workspace, [old], bundled=True)
    assert not install_skills(workspace, [old], replace_existing=False)
    assert (workspace / ".opencode/skills/demo/references/data.txt").read_text() == "v2"
    # A deliberately newly dispatched package may roll back a version.
    assert install_skills(workspace, [old])
    assert (workspace / ".opencode/skills/demo/references/data.txt").read_text() == "v1"


def test_conflicts_do_not_change_installed_files(tmp_path):
    workspace = tmp_path / "workspace"
    original = source(tmp_path / "original")
    install_skills(workspace, [original], bundled=True)
    conflict = source(tmp_path / "conflict", owner="fp-review:demo", body="wrong")
    with pytest.raises(ValueError, match="belongs to"):
        install_skills(workspace, [conflict])
    with pytest.raises(ValueError, match="Duplicate Skill"):
        install_skills(workspace, [original, conflict])
    assert (workspace / ".opencode/skills/demo/references/data.txt").read_text() == "v1"


def test_known_alias_is_migrated_and_user_skill_preserved(tmp_path):
    workspace = tmp_path / "workspace"
    root = workspace / ".opencode/skills"
    managed = source(tmp_path / "source", name="memory-analysis", owner="checker:memory")
    source(root, name="user-owned", owner="user")
    legacy = root / "memory"
    legacy.mkdir()
    (legacy / "SKILL.md").write_bytes(managed.files["SKILL.md"])
    install_skills(workspace, [managed], bundled=True)
    assert not legacy.exists()
    assert (root / "memory-analysis/SKILL.md").is_file()
    assert (root / "user-owned/SKILL.md").is_file()


def test_manifest_failure_rolls_back_complete_tree(tmp_path):
    import deephole_client.skill_catalog as catalog

    workspace = tmp_path / "workspace"
    install_skills(workspace, [source(tmp_path / "old")], bundled=True)
    old_manifest = (workspace / ".opendeephole-skills.json").read_bytes()
    original_replace = catalog.os.replace

    def fail_manifest(src, dst):
        if Path(dst).name == ".opendeephole-skills.json":
            raise OSError("simulated manifest failure")
        original_replace(src, dst)

    with patch.object(catalog.os, "replace", side_effect=fail_manifest):
        with pytest.raises(OSError, match="manifest failure"):
            install_skills(workspace, [source(tmp_path / "new", body="v2")])
    assert (workspace / ".opencode/skills/demo/references/data.txt").read_text() == "v1"
    assert (workspace / ".opendeephole-skills.json").read_bytes() == old_manifest


def test_staging_failure_leaves_live_catalog_intact(tmp_path):
    workspace = tmp_path / "workspace"
    install_skills(workspace, [source(tmp_path / "old")], bundled=True)
    new = source(tmp_path / "new", body="v2")
    with patch("deephole_client.skill_catalog.shutil.copytree", side_effect=OSError("disk full")):
        with pytest.raises(OSError, match="disk full"):
            install_skills(workspace, [new])
    assert (workspace / ".opencode/skills/demo/references/data.txt").read_text() == "v1"


def test_task_switch_keeps_fixed_paths_and_standalone_remains_compatible(tmp_path):
    workspace = tmp_path / "workspace"
    first = source(tmp_path / "scan-a", name="first")
    second = source(tmp_path / "scan-b", name="second", owner="fp-review:second")
    install_skills(workspace, [first, second], bundled=True)
    fixed = workspace / ".opencode/skills"
    runtime = OpenCodeSessionRuntime(
        directory=tmp_path, tool="opencode", executable="opencode",
        config_workspace=workspace, config_content=json.dumps({"skills": {"paths": [str(fixed)]}}),
    )
    bindings = OpenCodeHostBindings(
        get_config=lambda: None, get_workspace=lambda: workspace,
        build_session_runtime=lambda *_: runtime, fixed_skill_root=lambda: fixed,
    )
    with patch("task_agent.task_service.get_host_bindings", return_value=bindings):
        for task_root in (tmp_path / "scan-a", tmp_path / "scan-b") * 3:
            result = _runtime_with_task_skills(runtime, (task_root,))
            assert result == runtime
            assert _config_hash(result.config_content) == _config_hash(runtime.config_content)
        missing = tmp_path / "missing"
        source(missing, name="absent")
        with pytest.raises(ValueError, match="not installed"):
            _runtime_with_task_skills(runtime, (missing,))
    with patch("task_agent.task_service.get_host_bindings", return_value=dataclasses.replace(bindings, fixed_skill_root=None)):
        result = _runtime_with_task_skills(runtime, (tmp_path / "scan-a",))
        assert json.loads(result.config_content)["skills"]["paths"] == [str(fixed), str(tmp_path / "scan-a")]


def test_catalog_update_drains_sessions_and_blocks_new_acquisitions(tmp_path):
    async def run():
        workspace = tmp_path / "workspace"
        old = source(tmp_path / "old")
        new = source(tmp_path / "new", body="v2")
        install_skills(workspace, [old], bundled=True)
        manager = OpenCodeServeManager()
        manager._active_sessions = 1
        manager._stop_locked = AsyncMock()
        manager._ensure_started_locked = AsyncMock(return_value="started")
        updater = asyncio.create_task(manager.update_skill_catalog(
            lambda: needs_install(workspace, [new]),
            lambda: install_skills(workspace, [new]),
        ))
        await asyncio.sleep(0)
        next_task = asyncio.create_task(manager._acquire_session(OpenCodeServeKey("opencode", "opencode")))
        await asyncio.sleep(0)
        assert not updater.done() and not next_task.done()
        assert (workspace / ".opencode/skills/demo/references/data.txt").read_text() == "v1"
        manager._stop_locked.assert_not_awaited()
        await manager._release_active_session()
        assert await asyncio.wait_for(updater, 2)
        await asyncio.wait_for(next_task, 2)
        assert (workspace / ".opencode/skills/demo/references/data.txt").read_text() == "v2"
        manager._stop_locked.assert_awaited_once()
        assert manager._dirty
        assert not await manager.update_skill_catalog(lambda: needs_install(workspace, [new]), lambda: pytest.fail("duplicate publication"))

    asyncio.run(run())


def test_cancelled_catalog_update_does_not_install_or_stop_serve():
    async def run():
        manager = OpenCodeServeManager()
        manager._active_sessions = 1
        manager._stop_locked = AsyncMock()
        cancel = asyncio.Event()
        updater = asyncio.create_task(manager.update_skill_catalog(
            lambda: True, lambda: pytest.fail("cancelled update published"), cancel_event=cancel,
        ))
        await asyncio.sleep(0)
        cancel.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(updater, 2)
        manager._stop_locked.assert_not_awaited()
        assert not manager._lock.locked()

    asyncio.run(run())


def test_update_can_be_cancelled_while_waiting_for_another_update():
    async def run():
        manager = OpenCodeServeManager()
        cancel = asyncio.Event()
        await manager._lock.acquire()
        try:
            updater = asyncio.create_task(manager.update_skill_catalog(
                lambda: True, lambda: pytest.fail("cancelled update published"), cancel_event=cancel,
            ))
            await asyncio.sleep(0)
            cancel.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(updater, 2)
            assert manager._lock.locked()
        finally:
            manager._lock.release()

    asyncio.run(run())


def test_transported_rule_package_installs_references_in_fixed_host(tmp_path):
    from backend.checker_sync import build_checker_package
    from backend.registry import CheckerEntry
    from deephole_client.opencode_integration import sync_rule_skill_roots
    from deephole_client.vulnerability_mining.engines.static_candidate.rule_packages import unpack_rule_packages

    async def run():
        workspace = tmp_path / "workspace"
        checker = tmp_path / "rules/custom-rule"
        custom = source(checker / "skills", name="custom-audit", owner="checker:custom-rule")
        (checker / "skills/custom-audit/SCENARIOS.md").write_text("Catalog introduction", encoding="utf-8")
        (checker / "checker.yaml").write_text("name: custom-rule\nmode: opencode\n")
        package = build_checker_package(CheckerEntry(
            name="custom-rule", label="Custom", description="", enabled=True,
            directory=checker, skill_path=checker / "skills/custom-audit/SKILL.md", skill_name=custom.name,
        ))
        unpacked = tmp_path / "scan/rules"
        unpack_rule_packages([package], unpacked)
        assert (unpacked / "custom-rule/skills/custom-audit/SCENARIOS.md").is_file()
        root = workspace / ".opencode/skills"
        bindings = OpenCodeHostBindings(
            get_config=lambda: None, get_workspace=lambda: workspace,
            build_session_runtime=lambda *_: None, fixed_skill_root=lambda: root,
        )
        manager = OpenCodeServeManager()
        manager._stop_locked = AsyncMock()
        with (
            patch("task_agent.host._get_opencode_configuration_state", return_value=("host", None, None)),
            patch("task_agent.host.get_host_bindings", return_value=bindings),
            patch("deephole_client.opencode_integration.get_global_opencode_workspace", return_value=workspace),
            patch("task_agent.serve_client.get_serve_manager", return_value=manager),
        ):
            await sync_rule_skill_roots([unpacked])
            assert skill_source(root / custom.name, custom.owner).files == custom.files
            assert not (root / custom.name / "SCENARIOS.md").exists()
            manager._stop_locked.assert_awaited_once()
            await sync_rule_skill_roots([unpacked])
            manager._stop_locked.assert_awaited_once()

    asyncio.run(run())
