from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from deephole_client import codegraph


@pytest.fixture
def local_graph(tmp_path: Path, monkeypatch):
    project = tmp_path / "project"
    (project / "src" / "module").mkdir(parents=True)
    executable = tmp_path / "codegraph"
    executable.touch()
    monkeypatch.setattr(codegraph, "_ready_projects", set())
    monkeypatch.setattr(codegraph, "_project_locks", {})
    config = {
        "enabled": True,
        "transport": "local",
        "timeout_seconds": 5,
        "local": {
            "executable": str(executable),
            "args": ["serve", "--mcp"],
            "environment": {},
        },
    }
    return project, config


@pytest.mark.parametrize(
    "graph_dirs",
    [
        (".codegraph-wx",),
        (".codegraph",),
        (".codegraph-wx", ".codegraph"),
    ],
)
def test_existing_default_database_skips_init_and_survives_restart(
    local_graph, monkeypatch, graph_dirs,
) -> None:
    project, config = local_graph
    for graph_dir in graph_dirs:
        database = project / graph_dir / "codegraph.db"
        database.parent.mkdir()
        database.touch()
    start = AsyncMock()
    monkeypatch.setattr(codegraph.asyncio, "create_subprocess_exec", start)

    assert asyncio.run(codegraph.prepare_scan_codegraph(config, project))
    start.assert_not_awaited()

    codegraph._ready_projects.clear()
    assert codegraph.is_codegraph_ready(project / "src" / "module")
    assert project.resolve() in codegraph._ready_projects
    assert codegraph.is_codegraph_ready(project)


@pytest.mark.parametrize("graph_dir", [".codegraph-wx", ".codegraph"])
def test_init_accepts_either_default_database_and_serializes_calls(
    local_graph, monkeypatch, graph_dir,
) -> None:
    project, config = local_graph
    process = SimpleNamespace(
        returncode=0,
        communicate=AsyncMock(return_value=(b"", None)),
    )

    async def create_process(*args, cwd, **kwargs):
        assert args[1:] == ("init", "-i")
        assert Path(cwd) == project
        await asyncio.sleep(0)
        database = project / graph_dir / "codegraph.db"
        database.parent.mkdir()
        database.touch()
        return process

    start = AsyncMock(side_effect=create_process)
    monkeypatch.setattr(codegraph.asyncio, "create_subprocess_exec", start)

    async def run():
        return await asyncio.gather(
            codegraph.prepare_scan_codegraph(config, project),
            codegraph.prepare_scan_codegraph(config, project),
        )

    assert asyncio.run(run()) == [True, True]
    start.assert_awaited_once()
    assert project.resolve() in codegraph._ready_projects


@pytest.mark.parametrize("artifact", ["missing", "empty", "database_directory"])
def test_preparation_and_readiness_require_a_database_file(
    local_graph, monkeypatch, artifact,
) -> None:
    project, config = local_graph
    databases = [
        project / ".codegraph-wx" / "codegraph.db",
        project / ".codegraph" / "codegraph.db",
    ]
    for database in databases:
        if artifact == "empty":
            database.parent.mkdir()
        elif artifact == "database_directory":
            database.mkdir(parents=True)
    start = AsyncMock(return_value=SimpleNamespace(
        returncode=0,
        communicate=AsyncMock(return_value=(b"", None)),
    ))
    monkeypatch.setattr(codegraph.asyncio, "create_subprocess_exec", start)
    messages = []

    assert not codegraph.is_codegraph_ready(project / "src" / "module")
    assert not asyncio.run(codegraph.prepare_scan_codegraph(
        config, project, emit=messages.append,
    ))
    start.assert_awaited_once()
    assert all(str(database) in messages[-1] for database in databases)
    assert not codegraph._ready_projects


@pytest.mark.parametrize("graph_dir", [".custom", ".codegraph-wx", ".codegraph"])
def test_explicit_graph_dir_never_falls_back_to_other_default_database(
    local_graph, monkeypatch, graph_dir,
) -> None:
    project, config = local_graph
    config["local"]["environment"]["CODEGRAPH_DIR"] = graph_dir
    for other_dir in (".codegraph-wx", ".codegraph"):
        if other_dir == graph_dir:
            continue
        database = project / other_dir / "codegraph.db"
        database.parent.mkdir()
        database.touch()
    start = AsyncMock(return_value=SimpleNamespace(
        returncode=0,
        communicate=AsyncMock(return_value=(b"", None)),
    ))
    monkeypatch.setattr(codegraph.asyncio, "create_subprocess_exec", start)
    selected_database = project / graph_dir / "codegraph.db"
    selected_database.parent.mkdir()
    messages = []

    async def run():
        assert not await codegraph.prepare_scan_codegraph(
            config, project, emit=messages.append,
        )
        assert str(selected_database) in messages[-1]
        assert " 或 " not in messages[-1]
        selected_database.touch()
        assert await codegraph.prepare_scan_codegraph(config, project)

    asyncio.run(run())
    start.assert_awaited_once()
