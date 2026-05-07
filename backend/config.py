"""Application configuration loaded from config.yaml."""

import os
from pathlib import Path

import yaml
from pydantic import BaseModel


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000


class MCPServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8100


class OpenCodeConfig(BaseModel):
    model: str = "anthropic/claude-sonnet-4-20250514"
    timeout: int = 120
    mock: bool = False  # When True, skip real opencode and return fake results


class StorageConfig(BaseModel):
    projects_dir: str = "/tmp/opendeephole/projects"
    scans_dir: str = "/tmp/opendeephole/scans"
    max_upload_size_mb: int = 2048


class LoggingConfig(BaseModel):
    level: str = "INFO"
    file: str = "logs/opendeephole.log"
    max_size_mb: int = 10
    backup_count: int = 5


class LLMApiConfig(BaseModel):
    """LLM API 直调模式配置（替代 opencode CLI）。"""
    enabled: bool = False
    base_url: str = ""
    api_key: str = ""
    model: str = "gpt-4o-mini"
    temperature: float = 0.1
    timeout: int = 120
    max_retries: int = 3


class AppConfig(BaseModel):
    server: ServerConfig = ServerConfig()
    mcp_server: MCPServerConfig = MCPServerConfig()
    opencode: OpenCodeConfig = OpenCodeConfig()
    storage: StorageConfig = StorageConfig()
    logging: LoggingConfig = LoggingConfig()
    llm_api: LLMApiConfig = LLMApiConfig()


def load_config(config_path: str | None = None) -> AppConfig:
    """Load configuration from config.yaml, with environment variable overrides.

    Search order for config.yaml:
    1. Explicit config_path parameter
    2. CONFIG_PATH environment variable
    3. ./config.yaml (project root)
    """
    if config_path is None:
        config_path = os.environ.get("CONFIG_PATH", "config.yaml")

    path = Path(config_path)
    if path.is_file():
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
    else:
        raw = {}

    # Environment variable overrides
    if model := os.environ.get("OPENCODE_MODEL"):
        raw.setdefault("opencode", {})["model"] = model

    # LLM API environment variable overrides
    if v := os.environ.get("LLM_API_ENABLED"):
        raw.setdefault("llm_api", {})["enabled"] = v.lower() in ("1", "true", "yes")
    if v := os.environ.get("LLM_API_BASE_URL"):
        raw.setdefault("llm_api", {})["base_url"] = v
    if v := os.environ.get("LLM_API_KEY"):
        raw.setdefault("llm_api", {})["api_key"] = v
    if v := os.environ.get("LLM_API_MODEL"):
        raw.setdefault("llm_api", {})["model"] = v

    return AppConfig(**raw)


# Singleton config instance
_config: AppConfig | None = None


def get_config() -> AppConfig:
    """Get the application config singleton."""
    global _config
    if _config is None:
        _config = load_config()
    return _config
