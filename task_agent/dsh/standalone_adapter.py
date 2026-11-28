"""Standalone YAML adapter for ``serve.tool: deepseek_harness``."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..host import OpenCodeSessionRuntime
from ..runtime_backend import DEFAULT_DSH_PROFILE, TOOL_DEEPSEEK_HARNESS


@dataclass(frozen=True)
class StandaloneDshSettings:
    """Validated DeepSeek Harness fields parsed from standalone ``task-agent.yaml``."""

    dsh_executable: str = ""
    dsh_profile: str = DEFAULT_DSH_PROFILE
    dsh_home: Path | None = None


def parse_standalone_dsh_settings(
    serve: Mapping[str, Any],
    *,
    base_dir: Path,
    workspace_dir: Path,
) -> StandaloneDshSettings:
    """Validate optional DSH keys in the ``serve`` section of standalone YAML."""
    profile = str(serve.get("dsh_profile") or DEFAULT_DSH_PROFILE).strip()
    if profile != DEFAULT_DSH_PROFILE:
        raise ValueError(
            f"serve.dsh_profile must be {DEFAULT_DSH_PROFILE!r}, got {profile!r}"
        )
    dsh_executable = str(
        serve.get("dsh_executable") or serve.get("executable") or ""
    ).strip()
    if dsh_executable == "dsh":
        dsh_executable = ""
    raw_home = str(serve.get("dsh_home") or "").strip()
    if raw_home:
        candidate = Path(raw_home).expanduser()
        if not candidate.is_absolute():
            candidate = base_dir / candidate
        dsh_home = candidate.resolve()
    else:
        dsh_home = (workspace_dir / ".opendeephole-dsh-home").resolve()
    dsh_home.mkdir(parents=True, exist_ok=True)
    return StandaloneDshSettings(
        dsh_executable=dsh_executable,
        dsh_profile=profile,
        dsh_home=dsh_home,
    )


def build_standalone_dsh_runtime(
    *,
    directory: Path,
    model: str,
    workspace_dir: Path,
    opencode_config: dict[str, Any],
    environment: Mapping[str, str],
    settings: StandaloneDshSettings,
) -> OpenCodeSessionRuntime:
    """Construct an ``OpenCodeSessionRuntime`` targeting DeepSeek Harness."""
    dsh_home = settings.dsh_home or (workspace_dir / ".opendeephole-dsh-home").resolve()
    dsh_home.mkdir(parents=True, exist_ok=True)
    providers = (
        opencode_config.get("provider")
        if isinstance(opencode_config.get("provider"), dict)
        else {}
    )
    return OpenCodeSessionRuntime(
        directory=Path(directory).resolve(),
        tool=TOOL_DEEPSEEK_HARNESS,
        executable=settings.dsh_executable or "dsh",
        opencode_version="1",
        model=model,
        config_workspace=workspace_dir,
        config_content=json.dumps(opencode_config, ensure_ascii=False),
        env_overrides={
            key: value
            for key, value in environment.items()
            if key != "OPENCODE_SERVE_PORT"
        },
        backend_options={
            "dsh_home": str(dsh_home),
            "dsh_executable": settings.dsh_executable,
            "dsh_profile": settings.dsh_profile,
            "llm_providers": providers,
        },
    )
