import asyncio
import json
from pathlib import Path

import pytest

from deephole_client import memory_api_discovery as discovery


class FakeDb:
    def get_all_functions(self):
        return [
            {
                "name": "xmalloc",
                "body": "void *xmalloc(size_t n) { return malloc(n); }",
                "file_path": "alloc.c",
                "start_line": 3,
            },
            {
                "name": "destroy_session",
                "body": "void destroy_session(Session *s) { free(s->buf); free(s); }",
                "file_path": "session.c",
                "start_line": 10,
            },
        ]


@pytest.mark.parametrize("capacity,batches", [(1, 12), (9, 12), (9, 3)])
def test_memory_api_workers_use_model_capacity_and_stop_on_cancel(
    tmp_path: Path, monkeypatch, capacity: int, batches: int,
) -> None:
    from deephole_client.config import AgentConfig, OpenCodeConfig, OpenCodeModelConfig

    cfg = AgentConfig(opencode=OpenCodeConfig(models=[
        OpenCodeModelConfig(id="model", model="provider/model", max_concurrency=capacity),
    ]))
    monkeypatch.setattr(discovery, "get_config", lambda: cfg)
    candidates = [discovery.MemoryApiCandidate(
        candidate_id=str(index), name=f"alloc_{index}", kind="function", file="alloc.c",
        line=index + 1, role_hint="alloc", evidence="malloc",
    ) for index in range(batches)]
    monkeypatch.setattr(discovery, "collect_memory_api_candidates", lambda *_args, **_kwargs: candidates)

    async def run():
        reached = asyncio.Event()
        release = asyncio.Event()
        cancel = asyncio.Event()
        started = 0

        async def batch(**_kwargs):
            nonlocal started
            started += 1
            if started == min(capacity, batches):
                reached.set()
            await release.wait()

        monkeypatch.setattr(discovery, "_run_memory_api_batch", batch)
        task = asyncio.create_task(discovery.ensure_memory_api_artifact(
            project_root=tmp_path, workspace=tmp_path, scan_dir=tmp_path / "scan",
            cancel_event=cancel,
            options=discovery.MemoryApiDiscoveryOptions(batch_size=1, max_candidates=0),
        ))
        try:
            await asyncio.wait_for(reached.wait(), timeout=1)
            assert started == min(capacity, batches)
            cancel.set()
            release.set()
            report = await asyncio.wait_for(task, timeout=1)
            assert report.skipped
            assert started == min(capacity, batches)
            assert not report.artifact_path.exists()
        finally:
            release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(run())


def test_collect_candidates_includes_function_bodies_and_macros(tmp_path: Path) -> None:
    source = tmp_path / "macros.h"
    source.write_text(
        "#define XMALLOC(n) malloc(n)\n"
        "#define SESSION_FREE(s) do { free((s)->buf); free(s); } while (0)\n",
        encoding="utf-8",
    )

    candidates = discovery.collect_memory_api_candidates(tmp_path, db=FakeDb())
    by_name = {candidate.name: candidate for candidate in candidates}

    assert by_name["xmalloc"].kind == "function"
    assert "return malloc(n)" in by_name["xmalloc"].source
    assert by_name["XMALLOC"].kind == "macro"
    assert "malloc(n)" in by_name["XMALLOC"].source


def test_existing_artifact_skips_analysis(tmp_path: Path, monkeypatch) -> None:
    artifact = tmp_path / discovery.ARTIFACT_FILENAME
    artifact.write_text("{}", encoding="utf-8")

    async def fail_batch(**_kwargs):
        raise AssertionError("opencode batch should not run")

    monkeypatch.setattr(discovery, "_run_memory_api_batch", fail_batch)

    report = asyncio.run(
        discovery.ensure_memory_api_artifact(
            project_root=tmp_path,
            workspace=tmp_path,
            scan_dir=tmp_path / "scan",
            db=FakeDb(),
        )
    )

    assert report.skipped is True
    assert artifact.exists()


def test_batches_write_intermediate_files_and_merge_artifact(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "macros.h").write_text("#define XFREE(p) free(p)\n", encoding="utf-8")
    batch_sizes: list[int] = []

    async def fake_batch(**kwargs):
        batch = kwargs["batch"]
        output_path = kwargs["output_path"]
        batch_sizes.append(len(batch))
        results = []
        for candidate in batch:
            is_alloc = "malloc" in candidate.name.lower()
            is_free = "free" in candidate.name.lower()
            results.append(
                {
                    "candidate_id": candidate.candidate_id,
                    "is_memory_api": is_alloc or is_free,
                    "role": "alloc" if is_alloc else "free" if is_free else "not_memory",
                    "pair_with": "XFREE" if is_alloc else "xmalloc" if is_free else "",
                    "confidence": "high",
                    "reason": "test result",
                }
            )
        output_path.write_text(json.dumps({"results": results}), encoding="utf-8")

    monkeypatch.setattr(discovery, "_run_memory_api_batch", fake_batch)

    report = asyncio.run(
        discovery.ensure_memory_api_artifact(
            project_root=tmp_path,
            workspace=tmp_path,
            scan_dir=tmp_path / "scan",
            db=FakeDb(),
            options=discovery.MemoryApiDiscoveryOptions(batch_size=5, max_candidates=0),
        )
    )

    data = json.loads((tmp_path / discovery.ARTIFACT_FILENAME).read_text(encoding="utf-8"))
    names = {item["name"] for item in data["allocators"]}
    free_names = {item["name"] for item in data["deallocators"]}

    assert report.skipped is False
    assert batch_sizes
    assert "xmalloc" in names
    assert "XFREE" in free_names
    assert any(pair["allocator"] == "xmalloc" and pair["deallocator"] == "XFREE" for pair in data["pairs"])


def test_failed_batch_is_recorded_as_unresolved(tmp_path: Path, monkeypatch) -> None:
    async def failing_batch(**_kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(discovery, "_run_memory_api_batch", failing_batch)

    asyncio.run(
        discovery.ensure_memory_api_artifact(
            project_root=tmp_path,
            workspace=tmp_path,
            scan_dir=tmp_path / "scan",
            db=FakeDb(),
            options=discovery.MemoryApiDiscoveryOptions(batch_size=5, max_candidates=0),
        )
    )

    data = json.loads((tmp_path / discovery.ARTIFACT_FILENAME).read_text(encoding="utf-8"))
    unresolved_names = {item["name"] for item in data["unresolved"]}

    assert {"xmalloc", "destroy_session"} <= unresolved_names


def test_memleak_artifact_name_helpers_include_short_names(tmp_path: Path) -> None:
    (tmp_path / discovery.ARTIFACT_FILENAME).write_text(
        json.dumps(
            {
                "allocators": [],
                "deallocators": [{"name": "ns::release_mem"}],
                "pairs": [],
            }
        ),
        encoding="utf-8",
    )

    assert discovery.memory_deallocator_names(tmp_path) == {"ns::release_mem", "release_mem"}
