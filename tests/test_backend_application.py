"""Dependency isolation and transport-independent service contracts."""

import ast
import asyncio
import httpx
from pathlib import Path
from fastapi import APIRouter, FastAPI
from fastapi.responses import StreamingResponse
from backend.application import (
    ApplicationError,
    BackendRuntime,
    get_runtime,
    get_scan_store,
    run_store_call,
    use_runtime,
)
from backend.report_routes import ApplicationRoute


def test_interleaved_apps_bind_their_own_state_and_error_contract():
    assert str(ApplicationError(409, 'conflict')) == '409: conflict'
    assert ApplicationError(404).detail == 'Not Found'

    async def run():
        router = APIRouter(route_class=ApplicationRoute)

        @router.get('/state')
        async def state():
            before = get_runtime()
            await asyncio.sleep(0)
            assert before is get_runtime()
            return {'name': get_scan_store()}

        @router.get('/error')
        async def error():
            raise ApplicationError(409, {'code': 'conflict'}, {'X-Reason': 'test'})

        @router.get('/stream')
        async def stream():
            async def chunks():
                yield get_scan_store()
                await asyncio.sleep(0)
                yield get_scan_store()
            return StreamingResponse(chunks())

        async def request(name):
            app = FastAPI()
            app.state.backend_runtime = BackendRuntime(store=name)
            app.include_router(router)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
                assert (await client.get('/state')).json() == {'name': name}
                failure = await client.get('/error')
                assert failure.status_code == 409
                assert failure.json() == {'detail': {'code': 'conflict'}}
                assert failure.headers['x-reason'] == 'test'
                assert (await client.get('/stream')).text == name * 2

        previous = get_runtime()
        await asyncio.gather(request('first'), request('second'))
        assert get_runtime() is previous
    asyncio.run(run())


def test_store_callable_keeps_injected_runtime_in_executor():
    async def run():
        runtime = BackendRuntime(store=object())
        with use_runtime(runtime):
            captured = await run_store_call(runtime.store, lambda: get_runtime())
            assert captured is runtime
    asyncio.run(run())


def test_runtime_shutdown_drains_tasks_and_pending_responses():
    async def run():
        runtime = BackendRuntime()
        task = asyncio.create_task(asyncio.sleep(100))
        waiter = asyncio.get_running_loop().create_future()
        runtime.agents.agent_touch_tasks['agent'] = task
        runtime.agents.scan_stop_waiters['request'] = waiter
        await runtime.close()
        assert task.cancelled() and waiter.cancelled()
        assert not runtime.agents.agent_touch_tasks
        assert not runtime.agents.scan_stop_waiters
    asyncio.run(run())


def test_services_do_not_depend_on_http_routes():
    root = Path(__file__).resolve().parents[1] / 'backend'
    for directory in ('scans', 'agents'):
        for path in (root / directory).rglob('*.py'):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.ImportFrom):
                    assert not (node.module or '').startswith(('backend.api', 'fastapi')), path
                elif isinstance(node, ast.Import):
                    assert not any(alias.name.startswith(('backend.api', 'fastapi')) for alias in node.names), path


def test_claimed_distributed_commands_use_local_transport_without_requeue():
    from backend.agents.transport import LocalAgentTransport
    from backend.distributed import _deliver_commands

    class Store:
        finished = []

        def claim_agent_commands(self, worker, limit):
            assert limit == 100
            return [{'id': 1, 'agent_id': 'local', 'payload_json': '{"type":"stop"}'},
                    {'id': 2, 'agent_id': 'remote', 'payload_json': '{"type":"stop"}'}]

        def finish_agent_command(self, command_id, *, error):
            self.finished.append((command_id, error))

        def enqueue_agent_command(self, *_):
            raise AssertionError('Already claimed commands must never be enqueued again')

    class Connection:
        sent = []

        async def send_json(self, value):
            self.sent.append(value)

    async def run():
        store, connection = Store(), Connection()
        runtime = BackendRuntime(store=store)
        runtime.agents.agent_ws['local'] = connection
        with use_runtime(runtime):
            await _deliver_commands(store, LocalAgentTransport(runtime))
        assert connection.sent == [{'type': 'stop'}]
        assert store.finished[0] == (1, '')
        assert store.finished[1][0] == 2
        assert 'no longer owned' in store.finished[1][1]
    asyncio.run(run())


def test_lifespan_preserves_an_explicit_runtime(monkeypatch):
    from contextlib import asynccontextmanager
    from backend import main

    runtime = BackendRuntime(store=object())
    app = FastAPI()
    app.state.backend_runtime = runtime
    entered = []

    @asynccontextmanager
    async def startup(current_app):
        assert current_app is app
        assert get_runtime() is runtime
        assert get_scan_store() is runtime.store
        entered.append(True)
        yield
        assert get_runtime() is runtime

    monkeypatch.setattr(main, '_application_lifespan', startup)

    async def run():
        previous = get_runtime()
        async with main.lifespan(app):
            assert app.state.backend_runtime is runtime
        assert get_runtime() is previous
        assert entered == [True]
    asyncio.run(run())
