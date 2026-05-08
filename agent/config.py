"""Agent configuration — loaded from agent.yaml."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class LLMApiConfig:
    base_url: str = ""
    api_key: str = ""
    model: str = "claude-sonnet-4-6"
    temperature: float = 0.1
    timeout: int = 120
    max_retries: int = 3


@dataclass
class OpenCodeConfig:
    executable: str = "opencode"  # CLI executable name or full path
    model: str = ""
    timeout: int = 300


@dataclass
class AgentConfig:
    server_url: str = "http://localhost:8000"
    checkers: list = field(default_factory=list)
    mode: str = "api"  # "api" | "opencode"
    llm_api: LLMApiConfig = field(default_factory=LLMApiConfig)
    opencode: OpenCodeConfig = field(default_factory=OpenCodeConfig)
    agent_port: int = 7000
    agent_name: str = ""  # defaults to hostname
    no_proxy: str = ""


def load_config(path: Optional[Path] = None) -> AgentConfig:
    """Load agent config from agent.yaml, searching standard locations."""
    if path is None:
        search_paths = [
            Path("agent.yaml"),
            Path(__file__).parent.parent / "agent.yaml",
        ]
        for p in search_paths:
            if p.is_file():
                path = p
                break

    raw: dict = {}
    if path and Path(path).is_file():
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

    llm_fields = {f.name for f in dataclasses.fields(LLMApiConfig)}
    oc_fields = {f.name for f in dataclasses.fields(OpenCodeConfig)}

    llm_raw = {k: v for k, v in raw.get("llm_api", {}).items() if k in llm_fields}
    oc_raw = {k: v for k, v in raw.get("opencode", {}).items() if k in oc_fields}

    return AgentConfig(
        server_url=raw.get("server_url", "http://localhost:8000"),
        checkers=raw.get("checkers", []),
        mode=raw.get("mode", "api"),
        llm_api=LLMApiConfig(**llm_raw),
        opencode=OpenCodeConfig(**oc_raw),
        agent_port=raw.get("agent_port", 7000),
        agent_name=raw.get("agent_name", ""),
        no_proxy=raw.get("no_proxy", ""),
    )
