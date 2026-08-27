"""Best-effort Codex CLI preparation for the Agent runtime."""

from __future__ import annotations

import asyncio
import hashlib
import json
import locale
import os
import shutil
import signal
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Sequence

from .codex_profiles import CodexModelProfile, sync_codex_profiles


CODEX_INSTALL_TIMEOUT_SECONDS = 120.0
CODEX_PROBE_TIMEOUT_SECONDS = 10.0
_OUTPUT_DETAIL_LIMIT = 2000
_NPM_INSTALL_STEPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("npm set strict-ssl false", ("set", "strict-ssl", "false")),
    (
        "npm config set registry",
        (
            "config",
            "set",
            "registry",
            "https://mirrors.tools.huawei.com/npm/",
        ),
    ),
    ("npm cache clean -f", ("cache", "clean", "-f")),
    (
        "npm install -g @openai/codex",
        ("install", "-g", "@openai/codex"),
    ),
)


@dataclass(frozen=True)
class CodexRuntimeState:
    """Process-local Codex availability established during Agent startup."""

    available: bool
    command: tuple[str, ...] = ()
    executable: str = ""
    version: str = ""
    error: str = ""
    models: tuple[CodexModelProfile, ...] = ()
    model_config_warnings: tuple[str, ...] = ()
    model_config_error: str = ""


@dataclass(frozen=True)
class _ProcessResult:
    returncode: int
    stdout: str
    stderr: str


class _CodexSetupError(RuntimeError):
    pass


_runtime_state: CodexRuntimeState | None = None
_last_platform_model_fingerprint: str | None = None


def _is_windows() -> bool:
    return os.name == "nt"


def _batch_aware_argv(argv: Sequence[str]) -> tuple[str, ...]:
    """Wrap Windows batch shims so fixed argv can be launched reliably."""
    command = tuple(str(item) for item in argv)
    if (
        _is_windows()
        and command
        and Path(command[0]).suffix.lower() in {".bat", ".cmd"}
    ):
        return (
            os.environ.get("COMSPEC") or "cmd.exe",
            "/d",
            "/c",
            "call",
            *command,
        )
    return command


def _node_executable(prefix: Path) -> str:
    """Resolve Node beside an npm shim before falling back to PATH."""
    sibling = prefix / "node.exe"
    if sibling.is_file():
        return str(sibling)
    return str(shutil.which("node") or "")


def _npm_command(executable: str) -> tuple[str, ...]:
    """Prefer npm's JavaScript launcher over a Windows batch shim."""
    resolved = Path(executable).expanduser()
    if not _is_windows() or resolved.suffix.lower() not in {".bat", ".cmd"}:
        return (str(resolved),)

    launchers = [
        resolved.parent / "node_modules" / "npm" / "bin" / "npm-cli.js",
    ]
    configured_launcher = str(os.environ.get("NPM_CLI_JS") or "").strip()
    if configured_launcher:
        launchers.append(Path(configured_launcher).expanduser())
    node = _node_executable(resolved.parent)
    if node:
        for launcher in launchers:
            if launcher.is_file():
                return (node, str(launcher))
    # _run_process applies the cmd.exe /d /c call fallback at launch time.
    return (str(resolved),)


def _windows_output_encodings() -> tuple[str, ...]:
    return (
        "oem",
        "mbcs",
        locale.getpreferredencoding(False),
    )


def _decode_process_output(value: bytes) -> str:
    """Decode Node UTF-8 output and localized Windows cmd diagnostics."""
    if not value:
        return ""
    encodings = ["utf-8"]
    if _is_windows():
        encodings.extend(_windows_output_encodings())
    seen: set[str] = set()
    for encoding in encodings:
        normalized = str(encoding or "").strip().lower()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        try:
            return value.decode(normalized)
        except (LookupError, UnicodeDecodeError):
            continue
    return value.decode("utf-8", errors="replace")


async def _stop_process(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    if _is_windows():
        # npm is normally reached through npm.cmd.  Killing only cmd.exe can
        # orphan the Node installer, so terminate the entire owned tree.
        try:
            killer = await asyncio.create_subprocess_exec(
                "taskkill",
                "/PID",
                str(process.pid),
                "/T",
                "/F",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                await asyncio.wait_for(killer.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                killer.kill()
                await killer.wait()
        except OSError:
            try:
                process.kill()
            except OSError:
                pass
        try:
            await asyncio.wait_for(process.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            try:
                process.kill()
            except OSError:
                pass
        return

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        pass
    try:
        await asyncio.wait_for(process.wait(), timeout=2.0)
        return
    except asyncio.TimeoutError:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        await asyncio.wait_for(process.wait(), timeout=2.0)
    except asyncio.TimeoutError:
        # Never let a broken process-control edge case defeat the caller's
        # bounded Agent startup.  The owned process has already received the
        # strongest platform-appropriate termination signal available here.
        pass


async def _run_process(
    argv: Sequence[str],
    *,
    timeout: float,
) -> _ProcessResult:
    process_argv = _batch_aware_argv(argv)
    process_kwargs = {
        "stdout": asyncio.subprocess.PIPE,
        "stderr": asyncio.subprocess.PIPE,
    }
    if not _is_windows():
        process_kwargs["start_new_session"] = True
    process = await asyncio.create_subprocess_exec(
        *process_argv,
        **process_kwargs,
    )
    communication = asyncio.create_task(process.communicate())
    try:
        done, _pending = await asyncio.wait(
            {communication},
            timeout=max(0.0, float(timeout)),
        )
        if communication not in done:
            await _stop_process(process)
            if not communication.done():
                communication.cancel()
            await asyncio.gather(communication, return_exceptions=True)
            raise asyncio.TimeoutError
        stdout, stderr = communication.result()
    except BaseException:
        await _stop_process(process)
        if not communication.done():
            communication.cancel()
        await asyncio.gather(communication, return_exceptions=True)
        raise
    return _ProcessResult(
        returncode=int(process.returncode or 0),
        stdout=_decode_process_output(stdout),
        stderr=_decode_process_output(stderr),
    )


def _result_detail(result: _ProcessResult) -> str:
    detail = (result.stderr.strip() or result.stdout.strip()).strip()
    if not detail:
        return "no error output"
    if len(detail) > _OUTPUT_DETAIL_LIMIT:
        detail = detail[-_OUTPUT_DETAIL_LIMIT:]
    return " ".join(detail.splitlines())


def _codex_command(executable: str) -> tuple[str, ...]:
    """Return an argv prefix that marked engines can safely extend."""
    resolved = Path(executable).expanduser()
    if not _is_windows() or resolved.suffix.lower() not in {".bat", ".cmd"}:
        return (str(resolved),)

    # npm creates codex.cmd beside node.exe and the global node_modules tree.
    # Calling the JS launcher through Node avoids asking every Python engine to
    # reproduce cmd.exe quoting when it appends its own Codex arguments.
    prefix = resolved.parent
    launcher = (
        prefix
        / "node_modules"
        / "@openai"
        / "codex"
        / "bin"
        / "codex.js"
    )
    node = _node_executable(prefix)
    if node and launcher.is_file():
        return (node, str(launcher))
    return _batch_aware_argv((str(resolved),))


async def _probe_codex(
    executable: str,
    *,
    timeout: float,
) -> CodexRuntimeState:
    command = _codex_command(executable)
    result = await _run_process(
        (*command, "--version"),
        timeout=timeout,
    )
    if result.returncode != 0:
        raise _CodexSetupError(
            "codex --version failed with exit code "
            f"{result.returncode}: {_result_detail(result)}"
        )
    version_output = (result.stdout.strip() or result.stderr.strip()).strip()
    version = version_output.splitlines()[0] if version_output else "unknown"
    return CodexRuntimeState(
        available=True,
        command=command,
        executable=str(Path(executable).expanduser()),
        version=version,
    )


def _remaining_seconds(deadline: float, stage: str) -> float:
    remaining = deadline - asyncio.get_running_loop().time()
    if remaining <= 0:
        raise _CodexSetupError(
            f"Codex setup timed out before {stage}"
        )
    return remaining


async def _run_install_step(
    npm_command: Sequence[str],
    args: Sequence[str],
    *,
    label: str,
    deadline: float,
) -> _ProcessResult:
    try:
        result = await _run_process(
            (*npm_command, *args),
            timeout=_remaining_seconds(deadline, label),
        )
    except asyncio.TimeoutError as exc:
        raise _CodexSetupError(
            f"Codex setup timed out during {label}"
        ) from exc
    if result.returncode != 0:
        raise _CodexSetupError(
            f"{label} failed with exit code {result.returncode}: "
            f"{_result_detail(result)}"
        )
    return result


def _prepend_npm_global_bin(prefix: Path) -> None:
    bin_dir = prefix if _is_windows() else prefix / "bin"
    current = os.environ.get("PATH", "")
    entries = [item for item in current.split(os.pathsep) if item]
    normalized = os.path.normcase(os.path.abspath(str(bin_dir)))
    if any(
        os.path.normcase(os.path.abspath(item)) == normalized
        for item in entries
    ):
        return
    os.environ["PATH"] = os.pathsep.join([str(bin_dir), *entries])


async def _install_codex(
    npm: str,
    *,
    timeout_seconds: float,
) -> CodexRuntimeState:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    npm_command = _npm_command(npm)
    for label, args in _NPM_INSTALL_STEPS:
        await _run_install_step(
            npm_command,
            args,
            label=label,
            deadline=deadline,
        )

    prefix_result = await _run_install_step(
        npm_command,
        ("prefix", "--global"),
        label="npm prefix --global",
        deadline=deadline,
    )
    prefix_text = prefix_result.stdout.strip().splitlines()
    if not prefix_text or not prefix_text[-1].strip():
        raise _CodexSetupError(
            "npm prefix --global returned an empty path"
        )
    _prepend_npm_global_bin(Path(prefix_text[-1].strip()).expanduser())

    executable = shutil.which("codex")
    if not executable:
        raise _CodexSetupError(
            "npm reported success but codex is still not available in PATH"
        )
    try:
        return await _probe_codex(
            executable,
            timeout=_remaining_seconds(deadline, "codex --version"),
        )
    except asyncio.TimeoutError as exc:
        raise _CodexSetupError(
            "Codex setup timed out during codex --version"
        ) from exc


def _print_unavailable(error: str) -> None:
    print(
        "Warning: Codex CLI is unavailable: "
        f"{error}. Codex-dependent mining engines will be disabled; "
        "Agent startup will continue.",
        flush=True,
    )


def _value(item: Any, name: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def _normalize_model_ids(model_ids: Sequence[str] | str) -> tuple[str, ...]:
    values: Sequence[str] = (
        (model_ids,) if isinstance(model_ids, str) else model_ids
    )
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_model_id in values:
        model_id = str(raw_model_id or "").strip()
        if not model_id or model_id in seen:
            continue
        seen.add(model_id)
        normalized.append(model_id)
    return tuple(normalized)


def configured_codex_model_ids(config: Any) -> tuple[str, ...]:
    """Return ordered enabled explicit models from the applied Agent config."""
    opencode = _value(config, "opencode")
    models = _value(opencode, "models", ()) or ()
    selected: list[str] = []
    for model in models:
        if not bool(_value(model, "enabled", True)):
            continue
        if bool(_value(model, "use_default_model", False)):
            continue
        selected.append(str(_value(model, "model", "") or ""))
    return _normalize_model_ids(selected)


def _effective_opencode_config(config: Any) -> dict[str, Any]:
    from .opencode_integration import build_opencode_session_runtime

    runtime = build_opencode_session_runtime(
        _value(config, "opencode"),
        directory=Path.cwd(),
    )
    raw = str(runtime.config_content or "{}").strip() or "{}"
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("effective OpenCode config must be an object")
    return parsed


def _model_config_fingerprint(
    selected: tuple[str, ...],
    opencode_config: dict[str, Any],
) -> str:
    providers = opencode_config.get("provider")
    relevant_providers: dict[str, Any] = {}
    for canonical_id in selected:
        provider_id, separator, model_id = canonical_id.partition("/")
        provider = (
            providers.get(provider_id)
            if separator and isinstance(providers, dict)
            else None
        )
        if not isinstance(provider, dict):
            relevant_providers[canonical_id] = None
            continue
        models = provider.get("models")
        relevant_providers[canonical_id] = {
            "name": provider.get("name"),
            "options": provider.get("options"),
            "model": (
                models.get(model_id)
                if isinstance(models, dict)
                else None
            ),
        }
    serialized = json.dumps(
        {
            "model_ids": selected,
            "providers": relevant_providers,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def sync_platform_codex_models(
    config: Any,
    *,
    model_ids: Sequence[str] | str | None = None,
    force: bool = False,
    reason: str = "platform configuration",
) -> CodexRuntimeState:
    """Reconcile Codex with platform-selected models without blocking Agent work."""
    global _last_platform_model_fingerprint, _runtime_state

    selected = (
        configured_codex_model_ids(config)
        if model_ids is None
        else _normalize_model_ids(model_ids)
    )
    state = get_codex_runtime_state()
    if _runtime_state is None:
        _runtime_state = state
    if not state.available:
        error = state.error or "Codex CLI is unavailable"
        _runtime_state = replace(state, model_config_error=error)
        print(
            "Warning: Codex model synchronization skipped: "
            f"{error}. Trigger: {reason}.",
            flush=True,
        )
        return _runtime_state

    try:
        opencode_config = _effective_opencode_config(config) if selected else {}
        fingerprint = _model_config_fingerprint(selected, opencode_config)
        if not force and fingerprint == _last_platform_model_fingerprint:
            return get_codex_runtime_state()
        result = sync_codex_profiles(
            codex_version=state.version,
            opencode_config=opencode_config,
            selected_model_ids=selected,
        )
    except Exception as exc:
        error = (
            "unexpected model profile synchronization failure "
            f"({type(exc).__name__})"
        )
        _runtime_state = replace(state, model_config_error=error)
        print(
            "Warning: Codex model synchronization failed: "
            f"{error}. Existing managed configuration was left unchanged. "
            f"Trigger: {reason}.",
            flush=True,
        )
        return _runtime_state

    for warning in result.warnings:
        print(f"Warning: {warning}", flush=True)
    if result.error:
        _runtime_state = replace(
            state,
            model_config_warnings=result.warnings,
            model_config_error=result.error,
        )
        print(
            "Warning: Codex model synchronization failed: "
            f"{result.error}. Existing managed configuration was left "
            f"unchanged. Trigger: {reason}.",
            flush=True,
        )
        return _runtime_state

    _last_platform_model_fingerprint = fingerprint
    _runtime_state = replace(
        state,
        models=result.models,
        model_config_warnings=result.warnings,
        model_config_error="",
    )
    if result.models:
        print(
            "Codex model profiles ready: synchronized "
            f"{len(result.models)} platform model(s). Trigger: {reason}.",
            flush=True,
        )
        if result.managed_default_model is not None:
            print(
                "Codex default model ready: "
                f"{result.managed_default_model.id}.",
                flush=True,
            )
        elif result.user_default_preserved:
            print(
                "Codex default model unchanged: existing user configuration "
                "was preserved; platform models remain available as managed "
                "profiles.",
                flush=True,
            )
    else:
        print(
            "Codex managed model profiles removed: the platform has no "
            f"enabled explicit model. Trigger: {reason}.",
            flush=True,
        )
    return _runtime_state


async def initialize_codex_runtime(
    *,
    timeout_seconds: float = CODEX_INSTALL_TIMEOUT_SECONDS,
) -> CodexRuntimeState:
    """Check/install Codex once for this Agent process without aborting it."""
    global _runtime_state
    if _runtime_state is not None:
        return _runtime_state

    executable = shutil.which("codex")
    if executable:
        try:
            _runtime_state = await _probe_codex(
                executable,
                timeout=CODEX_PROBE_TIMEOUT_SECONDS,
            )
            print(
                f"Codex CLI ready: {_runtime_state.version}",
                flush=True,
            )
            return _runtime_state
        except asyncio.CancelledError:
            raise
        except Exception:
            # A broken executable is treated the same as a missing one so the
            # requested npm installation gets one chance to repair it.
            pass

    print(
        "Codex CLI is not available; installing with npm "
        f"(timeout: {int(timeout_seconds)} seconds)...",
        flush=True,
    )
    npm = shutil.which("npm")
    if not npm:
        _runtime_state = CodexRuntimeState(
            available=False,
            error="npm was not found in PATH",
        )
        _print_unavailable(_runtime_state.error)
        return _runtime_state

    try:
        installed_state = await _install_codex(
            npm,
            timeout_seconds=max(0.0, float(timeout_seconds)),
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        error = str(exc).strip() or type(exc).__name__
        _runtime_state = CodexRuntimeState(
            available=False,
            error=error,
        )
        _print_unavailable(error)
        return _runtime_state

    _runtime_state = installed_state
    print(
        f"Codex CLI installed successfully: {_runtime_state.version}",
        flush=True,
    )
    return _runtime_state


def get_codex_runtime_state() -> CodexRuntimeState:
    """Return startup state, with a PATH-only fallback for direct callers."""
    if _runtime_state is not None:
        return _runtime_state
    executable = shutil.which("codex")
    if executable:
        return CodexRuntimeState(
            available=True,
            command=_codex_command(executable),
            executable=executable,
        )
    return CodexRuntimeState(
        available=False,
        error="Codex availability was not initialized for this process",
    )


def _reset_codex_runtime_state_for_tests() -> None:
    global _last_platform_model_fingerprint, _runtime_state
    _runtime_state = None
    _last_platform_model_fingerprint = None


__all__ = [
    "CODEX_INSTALL_TIMEOUT_SECONDS",
    "CodexModelProfile",
    "CodexRuntimeState",
    "configured_codex_model_ids",
    "get_codex_runtime_state",
    "initialize_codex_runtime",
    "sync_platform_codex_models",
]
