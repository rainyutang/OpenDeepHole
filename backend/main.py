"""FastAPI application entry point."""

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles

import uuid

from backend.api import admin, agent, announcements, auth, checkers, feedback, integration, scan, skills
from backend.auth import hash_password
from backend.config import apply_no_proxy, get_config
from backend.logger import get_logger
from backend.registry import get_registry
from backend.runtime_metrics import RequestMetricsMiddleware, monitor_event_loop_lag
from backend.store import get_scan_store
from backend.store.async_ops import run_store_call, shutdown_store_executor

logger = get_logger(__name__)
_LEADER_LOCK_KEY = 5711767769877594436


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown."""
    config = get_config()
    apply_no_proxy()

    # Ensure storage directories exist
    Path(config.storage.projects_dir).mkdir(parents=True, exist_ok=True)
    Path(config.storage.scans_dir).mkdir(parents=True, exist_ok=True)
    Path(config.storage.user_skills_dir).mkdir(parents=True, exist_ok=True)

    # Initialize scan store and recover from unclean shutdown
    store = get_scan_store()
    distributed = bool(getattr(store, "distributed", False))
    is_leader = (
        await run_store_call(store, "try_advisory_lock", _LEADER_LOCK_KEY)
        if distributed
        else True
    )
    # A PostgreSQL worker can restart while another worker and the Agent still
    # own live work.  Do not invalidate every running row during a rolling
    # restart; the elected leader's durable Agent-session sweep applies the
    # disconnect grace period instead.  SQLite remains a single-process store,
    # so an application restart really does interrupt its in-memory work.
    recovered = (
        await run_store_call(store, "mark_running_as_error")
        if is_leader and not distributed
        else 0
    )
    if recovered:
        logger.warning("Marked %d interrupted scan(s) as error on startup", recovered)

    # Seed default admin user if no users exist
    if is_leader and await run_store_call(store, "count_users") == 0:
        auth_cfg = config.auth
        admin_id = uuid.uuid4().hex
        agent_token = uuid.uuid4().hex
        await run_store_call(
            store,
            "create_user",
            admin_id,
            auth_cfg.default_admin_username,
            await asyncio.to_thread(
                hash_password,
                auth_cfg.default_admin_password,
            ),
            "admin",
            agent_token,
        )
        logger.info(
            "Created default admin user '%s' (change password after first login)",
            auth_cfg.default_admin_username,
        )

    # Discover checkers on startup
    registry = get_registry()
    logger.info("Loaded %d checkers: %s", len(registry), list(registry.keys()))

    from backend.validation_catalog import refresh_validation_catalog

    refresh_validation_catalog()

    runtime_update_task = (
        asyncio.create_task(agent.run_agent_runtime_update_scheduler())
        if is_leader
        else None
    )
    distributed_task = None
    if distributed:
        from backend.distributed import WORKER_ID, run_distributed_runtime
        from backend.sse import configure_distributed_sse

        configure_distributed_sse(store, WORKER_ID)
        distributed_task = asyncio.create_task(
            run_distributed_runtime(store, leader=is_leader)
        )
    event_loop_monitor_task = asyncio.create_task(monitor_event_loop_lag())
    logger.info("DeepHole 2.0 backend started on port %d", config.server.port)
    try:
        yield
    finally:
        if runtime_update_task is not None:
            runtime_update_task.cancel()
            try:
                await runtime_update_task
            except asyncio.CancelledError:
                pass
        if distributed_task is not None:
            distributed_task.cancel()
            await asyncio.gather(distributed_task, return_exceptions=True)
        event_loop_monitor_task.cancel()
        try:
            await event_loop_monitor_task
        except asyncio.CancelledError:
            pass
        await run_store_call(store, "close")
        await shutdown_store_executor()
        logger.info("DeepHole 2.0 backend shutting down")


app = FastAPI(
    title="DeepHole 2.0",
    description="SKILL-based C/C++ source code white-box audit tool",
    version="0.1.0",
    lifespan=lifespan,
)

# 大响应（扫描详情可达数 MB）压缩传输；text/event-stream 由 Starlette 自动豁免
app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=5)
app.add_middleware(RequestMetricsMiddleware)

# API routes
app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(scan.router)
app.include_router(integration.router)
app.include_router(checkers.router)
app.include_router(skills.router)
app.include_router(feedback.router)
app.include_router(announcements.router)
app.include_router(agent.router)
app.include_router(agent.public_router)

# Serve frontend static files (built by Vite)
static_dir = Path(__file__).parent / "static"
if static_dir.is_dir():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")
