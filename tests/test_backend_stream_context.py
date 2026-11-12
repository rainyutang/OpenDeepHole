"""Streaming cleanup keeps the originating application runtime across tasks."""

import asyncio

from backend.application import BackendRuntime, get_runtime, runtime_stream, use_runtime


def test_stream_can_be_closed_by_a_different_task_and_runtime():
    async def run():
        origin, reader, closer = BackendRuntime(), BackendRuntime(), BackendRuntime()
        observed = []

        async def chunks():
            try:
                observed.append(("read", get_runtime()))
                yield b"first"
                yield b"second"
            finally:
                observed.append(("close", get_runtime()))

        stream = runtime_stream(chunks(), origin)

        async def read():
            with use_runtime(reader):
                assert await anext(stream) == b"first"
                assert get_runtime() is reader

        async def close():
            with use_runtime(closer):
                await stream.aclose()
                assert get_runtime() is closer

        previous = get_runtime()
        await asyncio.create_task(read())
        await asyncio.create_task(close())
        assert [stage for stage, _ in observed] == ["read", "close"]
        assert all(runtime is origin for _, runtime in observed)
        assert get_runtime() is previous

    asyncio.run(run())


def test_cancelled_stream_cleans_up_with_its_originating_runtime():
    async def run():
        origin, caller = BackendRuntime(), BackendRuntime()
        started = asyncio.Event()
        cleaned = []

        async def chunks():
            try:
                started.set()
                await asyncio.Future()
                yield b"unreachable"
            finally:
                cleaned.append(get_runtime())

        stream = runtime_stream(chunks(), origin)

        async def read():
            with use_runtime(caller):
                try:
                    await anext(stream)
                except asyncio.CancelledError:
                    assert get_runtime() is caller
                    raise

        previous = get_runtime()
        task = asyncio.create_task(read())
        await started.wait()
        task.cancel()
        result, = await asyncio.gather(task, return_exceptions=True)
        assert isinstance(result, asyncio.CancelledError)
        assert len(cleaned) == 1 and cleaned[0] is origin
        assert get_runtime() is previous

    asyncio.run(run())
