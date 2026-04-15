"""Unified logging configuration for OpenDeepHole."""

import logging
import sys
from pathlib import Path

from backend.config import get_config

_initialized = False


def setup_logging() -> None:
    """Initialize logging based on config.yaml settings.

    Sets up both console and file handlers. Call once at application startup.
    """
    global _initialized
    if _initialized:
        return
    _initialized = True

    config = get_config()
    level = getattr(logging, config.logging.level.upper(), logging.INFO)

    root_logger = logging.getLogger("opendeephole")
    root_logger.setLevel(level)

    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    console.setFormatter(formatter)
    root_logger.addHandler(console)

    # File handler
    log_path = Path(config.logging.file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(log_path)
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """Get a logger under the opendeephole namespace.

    Usage:
        logger = get_logger(__name__)
        logger.info("Scan started")
    """
    setup_logging()
    return logging.getLogger(f"opendeephole.{name}")
