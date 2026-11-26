"""Bridge DeepHole AgentConfig (providers, model pool, no_proxy) into materialized Javelin workspaces."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

from deephole_client.config import _merged_no_proxy_environment, active_opencode_executable
from deephole_client.opencode_integration import writable_edit_patterns

_TEMPLATE_PATH = Path(__file__).resolve().parent / "templates" / "opencode.base.json"
_BASE_TEMPLATE_CACHE: dict[str, Any] | None = None


def _load_base_template() -> dict[str, Any]:
    global _BASE_TEMPLATE_CACHE
    if _BASE_TEMPLATE_CACHE is None:
        _BASE_TEMPLATE_CACHE = json.loads(_TEMPLATE_PATH.read_text(encoding="utf-8"))
    return json.loads(json.dumps(_BASE_TEMPLATE_CACHE))


def _expanded_path_patterns(directory: Path) -> list[str]:
    """Return cross-platform (native + POSIX forward-slash) glob patterns for OpenCode permissions."""
    resolved = directory.resolve()
    posix_base = resolved.as_posix().rstrip("/")
    patterns = list(writable_edit_patterns(resolved))
    for extra in (posix_base, f"{posix_base}/*", f"{posix_base}/**"):
        if extra not in patterns:
            patterns.append(extra)
    return patterns


def compute_javelin_worker_concurrency(config: Any) -> int:
    """Compute bounded Javelin worker concurrency: max(1, min(model_capacity, 4))."""
    opencode_cfg = getattr(config, "opencode", None)
    models = getattr(opencode_cfg, "models", None) or []
    total = 0
    for item in models:
        enabled = item.get("enabled", True) if isinstance(item, dict) else getattr(item, "enabled", True)
        if not enabled:
            continue
        raw_cap = item.get("max_concurrency", 1) if isinstance(item, dict) else getattr(item, "max_concurrency", 1)
        try:
            total += max(1, int(raw_cap or 1))
        except (TypeError, ValueError):
            total += 1
    if total <= 0:
        total = 1
    return max(1, min(total, 4))


def select_primary_javelin_model(config: Any) -> str:
    """Pick the highest-capability enabled provider/model from AgentConfig, or 'default'."""
    opencode_cfg = getattr(config, "opencode", None)
    models = getattr(opencode_cfg, "models", None) or []
    rank = {"high": 3, "medium": 2, "low": 1}
    candidates: list[tuple[int, float, str]] = []
    for item in models:
        enabled = item.get("enabled", True) if isinstance(item, dict) else getattr(item, "enabled", True)
        if not enabled:
            continue
        use_default = item.get("use_default_model", False) if isinstance(item, dict) else getattr(item, "use_default_model", False)
        if use_default:
            candidates.append((0, 0.0, "default"))
            continue
        model_str = str((item.get("model") if isinstance(item, dict) else getattr(item, "model", "")) or "").strip()
        if not model_str or "/" not in model_str:
            continue
        cap = str((item.get("capability") if isinstance(item, dict) else getattr(item, "capability", "high")) or "high").lower()
        weight = float((item.get("weight") if isinstance(item, dict) else getattr(item, "weight", 1.0)) or 1.0)
        candidates.append((rank.get(cap, 2), weight, model_str))
    if candidates:
        candidates.sort(key=lambda t: (t[0], t[1]), reverse=True)
        return candidates[0][2]

    direct_model = str(getattr(opencode_cfg, "model", "") or "").strip()
    if direct_model and "/" in direct_model:
        return direct_model

    providers = getattr(config, "llm_providers", None) or {}
    if isinstance(providers, dict):
        for pid, pdata in providers.items():
            pmodels = pdata.get("models") if isinstance(pdata, dict) else None
            if isinstance(pmodels, dict):
                for mid in pmodels:
                    return f"{pid}/{mid}"
            elif isinstance(pmodels, list) and pmodels:
                return f"{pid}/{pmodels[0]}"
    return "default"


def build_javelin_opencode_config(
    config: Any,
    *,
    workspace_root: Path,
    target_project_path: Path | None = None,
    runtime_data_root: Path | None = None,
) -> dict[str, Any]:
    """Generate controlled .opencode/opencode.json without mutating third_party/Javelin."""
    data = _load_base_template()
    ws = workspace_root.resolve()
    skills_dir = (ws / ".opencode" / "skills").resolve()
    data["skills"] = {"paths": [str(skills_dir)]}

    raw_read = data["permission"].get("read")
    read_perms = dict(raw_read) if isinstance(raw_read, dict) else {"*": "allow"}
    raw_ext = data["permission"].get("external_directory")
    ext_perms = dict(raw_ext) if isinstance(raw_ext, dict) else {"*": "allow"}
    edit_perms = {"*": "deny"}

    for writable in [ws, *([runtime_data_root.resolve()] if runtime_data_root else [])]:
        for pat in _expanded_path_patterns(writable):
            read_perms[pat] = "allow"
            ext_perms[pat] = "allow"
            edit_perms[pat] = "allow"

    if target_project_path is not None:
        resolved_target = target_project_path.resolve()
        for pat in _expanded_path_patterns(resolved_target):
            read_perms[pat] = "allow"
            ext_perms[pat] = "allow"
            # Target audited Java source tree is strictly read-only for edit tools
            edit_perms[pat] = "deny"

    data["permission"]["read"] = read_perms
    data["permission"]["external_directory"] = ext_perms
    data["permission"]["edit"] = edit_perms

    providers = getattr(config, "llm_providers", None)
    if not providers:
        try:
            from deephole_client.llm_runtime import active_providers

            providers = active_providers()
        except Exception:
            providers = None
    if isinstance(providers, dict) and providers:
        try:
            from task_agent.llm_config import normalize_llm_providers

            data["provider"] = normalize_llm_providers(providers)
        except Exception:
            data["provider"] = providers

    selected = select_primary_javelin_model(config)
    if selected and selected != "default":
        data["model"] = selected

    # Register Javelin's built-in local MCP servers inside the materialized workspace
    mcp_map = dict(data.get("mcp") or {})
    product_mem_mcp = ws / ".opencode" / "mcp" / "product-memory-mcp.mjs"
    if product_mem_mcp.is_file():
        mcp_map.setdefault(
            "audit-memory",
            {
                "type": "local",
                "command": ["node", str(product_mem_mcp)],
                "enabled": True,
            },
        )
    data["mcp"] = mcp_map
    return data


def _chmod_private_best_effort(path: Path) -> None:
    with contextlib.suppress(OSError):
        path.chmod(0o600)


def write_javelin_opencode_config(
    config: Any,
    *,
    workspace_root: Path,
    target_project_path: Path | None = None,
    runtime_data_root: Path | None = None,
) -> Path:
    """Atomically write 0600 .opencode/opencode.json only when content digest changes."""
    cfg_obj = build_javelin_opencode_config(
        config,
        workspace_root=workspace_root,
        target_project_path=target_project_path,
        runtime_data_root=runtime_data_root,
    )
    rendered = json.dumps(cfg_obj, ensure_ascii=False, indent=2) + "\n"
    new_digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()

    dest = workspace_root.resolve() / ".opencode" / "opencode.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_file():
        try:
            existing_digest = hashlib.sha256(dest.read_bytes()).hexdigest()
            if existing_digest == new_digest:
                _chmod_private_best_effort(dest)
                return dest
        except OSError:
            pass

    tmp = dest.with_name(f".opencode.json.{os.getpid()}.tmp")
    tmp.write_text(rendered, encoding="utf-8")
    _chmod_private_best_effort(tmp)
    os.replace(tmp, dest)
    _chmod_private_best_effort(dest)
    return dest


def resolve_opencode_binary(config: Any) -> str:
    """Resolve the configured OpenCode/NGA executable path if present."""
    opencode_cfg = getattr(config, "opencode", None) if config is not None else None
    exe_name = active_opencode_executable(opencode_cfg) if opencode_cfg is not None else "opencode"
    resolved = shutil.which(exe_name) or (exe_name if Path(exe_name).is_file() else "")
    return str(Path(resolved).resolve()) if resolved else ""


def build_javelin_child_env(config: Any) -> dict[str, str]:
    """Construct child process environment with loopback NO_PROXY and resolved opencode PATH/BIN."""
    env = dict(os.environ)
    opencode_cfg = getattr(config, "opencode", None)
    proxy_url = str(getattr(opencode_cfg, "proxy_url", "") or "").strip() if opencode_cfg is not None else ""
    if proxy_url:
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            env[key] = proxy_url

    configured_no_proxy = ",".join(
        part
        for part in (
            str(getattr(config, "no_proxy", "") or "").strip(),
            str(getattr(opencode_cfg, "no_proxy", "") or "").strip(),
            "127.0.0.1,localhost,::1",
        )
        if part
    )
    env.update(_merged_no_proxy_environment(configured_no_proxy, env))

    resolved_bin = resolve_opencode_binary(config)
    if resolved_bin:
        env["OPENCODE_BIN_PATH"] = resolved_bin
        env["OPENCODE_BIN"] = resolved_bin
        exe_dir = str(Path(resolved_bin).parent)
        path_key = "Path" if ("Path" in env and "PATH" not in env) else "PATH"
        path_parts = env.get(path_key, "").split(os.pathsep) if env.get(path_key) else []
        if exe_dir not in path_parts:
            env[path_key] = os.pathsep.join([exe_dir, *path_parts])
        if path_key != "PATH":
            env["PATH"] = env[path_key]

    # Never inject NODE_PATH; materialized .opencode/node_modules must satisfy ESM natively
    env.pop("NODE_PATH", None)
    return env
