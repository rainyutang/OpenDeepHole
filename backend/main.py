"""FastAPI application entry point."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from backend.api import checkers, scan, upload
from backend.config import get_config
from backend.logger import get_logger
from backend.registry import get_registry

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown."""
    config = get_config()

    # Ensure storage directories exist
    Path(config.storage.projects_dir).mkdir(parents=True, exist_ok=True)
    Path(config.storage.scans_dir).mkdir(parents=True, exist_ok=True)

    # Discover checkers on startup
    registry = get_registry()
    logger.info("Loaded %d checkers: %s", len(registry), list(registry.keys()))

    logger.info("OpenDeepHole backend started on port %d", config.server.port)
    yield
    logger.info("OpenDeepHole backend shutting down")


app = FastAPI(
    title="OpenDeepHole",
    description="SKILL-based C/C++ source code white-box audit tool",
    version="0.1.0",
    lifespan=lifespan,
)

# API routes
app.include_router(upload.router)
app.include_router(scan.router)
app.include_router(checkers.router)

# Serve frontend static files (built by Vite)
static_dir = Path(__file__).parent / "static"
if static_dir.is_dir():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")
