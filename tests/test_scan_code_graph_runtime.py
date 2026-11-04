from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from deephole_client import main, scan_code_graph, server


@pytest.fixture(autouse=True)
def isolated_registry(monkeypatch):
    monkeypatch.setattr(scan_code_graph, "_states", {})


def _update(tmp_path: Path, revision: int, enabled: bool = True) -> dict:
    return {
        "scan_id": "live-graph",
        "revision": revision,
        "project_path": str(tmp_path),
        "scan_mode": "custom",
        "code_graph_mcp": {
            "enabled": enabled,
            "name": "codegraph",
            "transport": "remote",
            "remote": {"url": "http://localhost:9000/mcp"},
        },
    }


def test_update_ack_is_fast_and_older_revision_cannot_restore_graph(tmp_path, monkeypatch):
    prepare = AsyncMock(side_effect=AssertionError("ACK must not prepare MCP"))
    monkeypatch.setattr(scan_code_graph.codegraph, "prepare_scan_codegraph", prepare)

    async def run():
        first = _update(tmp_path, 2, False)
        response = await main._handle_command(
            {**first, "type": "code_graph_update", "request_id": "request"},
            None, None, None,
        )
        assert response == {
            "type": "code_graph_result", "scan_id": "live-graph",
            "revision": 2, "ok": True, "request_id": "request",
        }
        older = await main._handle_command(
            {**_update(tmp_path, 1), "type": "code_graph_update"}, None, None, None,
        )
        assert older["revision"] == 2
        graph = await scan_code_graph.resolve_scan_code_graph(
            scan_id="live-graph", project_path=tmp_path,
        )
        assert graph["enabled"] is False
        assert scan_code_graph.code_graph_mcp_revisions() == {"live-graph": 2}

    asyncio.run(run())
    prepare.assert_not_awaited()


@pytest.mark.parametrize("command,handler", [
    ("task", "handle_task"),
    ("resume", "handle_resume"),
    ("fp_review", "handle_fp_review"),
    ("vulnerability_validation", "handle_vulnerability_validation"),
])
def test_dispatch_registers_revision_without_overwriting_newer_update(
    tmp_path, monkeypatch, command, handler,
):
    monkeypatch.setattr(main, "_ensure_runtime_updated_safely", AsyncMock())
    monkeypatch.setattr(server, "scan_command_is_obsolete", lambda *_: False)
    monkeypatch.setattr(server, "prepare_scan_resume", AsyncMock())
    target = AsyncMock()
    monkeypatch.setattr(server, handler, target)
    payload = _update(tmp_path, 1)
    payload["code_graph_mcp_revision"] = payload.pop("revision")
    payload.update(type=command, review_id="review", vuln_index=0)

    async def run():
        await main._handle_command(payload, None, None, None)
        assert scan_code_graph.code_graph_mcp_revisions()["live-graph"] == 1
        scan_code_graph.apply_code_graph_update(_update(tmp_path, 2, False))
        await main._handle_command(payload, None, None, None)
        latest = await scan_code_graph.resolve_scan_code_graph(
            scan_id="live-graph", project_path=tmp_path,
        )
        assert latest["enabled"] is False

    asyncio.run(run())
    assert target.await_count == 2


def test_failed_initialization_runs_once_per_revision_and_preserves_desired_state(tmp_path, monkeypatch):
    prepare = AsyncMock(return_value=False)
    monkeypatch.setattr(scan_code_graph.codegraph, "prepare_scan_codegraph", prepare)

    async def run():
        scan_code_graph.apply_code_graph_update(_update(tmp_path, 1))
        results = await asyncio.gather(*[
            scan_code_graph.resolve_scan_code_graph(scan_id="live-graph", project_path=tmp_path)
            for _ in range(3)
        ])
        assert all(graph["enabled"] is False for graph in results)
        assert prepare.await_count == 1
        assert scan_code_graph._states["live-graph"].config["enabled"] is True
        scan_code_graph.apply_code_graph_update(_update(tmp_path, 2))
        await scan_code_graph.resolve_scan_code_graph(scan_id="live-graph", project_path=tmp_path)
        assert prepare.await_count == 2

    asyncio.run(run())


def test_disabling_during_slow_initialization_releases_waiters_promptly(tmp_path, monkeypatch):
    async def run():
        started, cancelled = asyncio.Event(), asyncio.Event()

        async def prepare(*_args, **_kwargs):
            started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise

        monkeypatch.setattr(scan_code_graph.codegraph, "prepare_scan_codegraph", prepare)
        scan_code_graph.apply_code_graph_update(_update(tmp_path, 1))
        waiter = asyncio.create_task(scan_code_graph.resolve_scan_code_graph(
            scan_id="live-graph", project_path=tmp_path,
        ))
        await started.wait()
        scan_code_graph.apply_code_graph_update(_update(tmp_path, 2, False))
        graph = await asyncio.wait_for(waiter, 1)
        assert graph["enabled"] is False
        await asyncio.wait_for(cancelled.wait(), 1)

    asyncio.run(run())


def test_direct_calls_do_not_retain_scan_ids_and_multi_version_stays_disabled(tmp_path, monkeypatch):
    prepare = AsyncMock(return_value=True)
    monkeypatch.setattr(scan_code_graph.codegraph, "prepare_scan_codegraph", prepare)

    async def run():
        enabled = _update(tmp_path, 0)["code_graph_mcp"]
        first = await scan_code_graph.resolve_scan_code_graph(
            scan_id="direct", project_path=tmp_path, fallback=enabled,
        )
        assert first["enabled"] is True
        assert await scan_code_graph.resolve_scan_code_graph(
            scan_id="direct", project_path=tmp_path, fallback=None,
        ) is None
        assert scan_code_graph.code_graph_mcp_revisions() == {}
        scan_code_graph.apply_code_graph_update(_update(tmp_path, 1))
        assert await scan_code_graph.resolve_scan_code_graph(
            scan_id="live-graph", project_path=tmp_path, scan_mode="multi_version",
        ) is None
        assert prepare.await_count == 1

    asyncio.run(run())


def test_welcome_updates_are_isolated_and_defensively_copied(tmp_path):
    payload = _update(tmp_path, 4)
    failures = scan_code_graph.sync_welcome_code_graph([
        {**payload, "revision": "invalid"}, payload,
    ])
    payload["code_graph_mcp"]["remote"]["url"] = "mutated"
    assert len(failures) == 1
    assert scan_code_graph.code_graph_mcp_revisions() == {"live-graph": 4}
    assert scan_code_graph._states["live-graph"].config["remote"]["url"] != "mutated"
