"""FastAPI adapters for application-scoped dependencies."""

from starlette.requests import HTTPConnection

from backend.application import get_runtime, use_runtime


async def runtime_scope(connection: HTTPConnection):
    runtime = getattr(connection.app.state, "backend_runtime", None) or get_runtime()
    with use_runtime(runtime):
        yield runtime
