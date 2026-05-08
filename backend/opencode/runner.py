"""opencode CLI runner — invokes opencode for AI-powered vulnerability analysis."""

import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

from backend.config import get_config
from backend.logger import get_logger
from backend.models import Candidate, Vulnerability

logger = get_logger(__name__)

# Regex to strip ANSI escape sequences from CLI output
_ANSI_RE = re.compile(
    r'\x1b\[[0-9;]*[a-zA-Z]'    # CSI sequences: ESC[...X
    r'|\x1b\][^\x07]*\x07'      # OSC sequences: ESC]...BEL
    r'|\x1b\[\?[0-9;]*[a-zA-Z]' # Private CSI: ESC[?...X
    r'|\x1b[()][A-Z0-9]'        # Character set selection
    r'|\x1b='                    # Keypad mode
    r'|\x1b>'                    # Keypad mode
    r'|\r'                       # Carriage return (from \r\n or spinner overwrites)
)


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences and control characters from text."""
    return _ANSI_RE.sub('', text)


async def run_audit(
    workspace: Path,
    candidate: Candidate,
    project_id: str,
    on_output=None,
    cancel_event: asyncio.Event | None = None,
) -> Vulnerability | None:
    """Run opencode to analyze a single candidate vulnerability.

    Supports two modes (selected via config):
    - opencode CLI mode (default): invokes opencode subprocess with MCP tools
    - LLM API mode (llm_api.enabled=true): direct API call with function calling

    Args:
        workspace: Path to the opencode workspace (contains opencode.json + skills).
        candidate: The candidate vulnerability to analyze.
        project_id: Project identifier for MCP tool calls.
        on_output: Optional callback(line: str) called for each output line in real-time.
        cancel_event: Optional asyncio.Event; when set, the subprocess is killed.

    Returns:
        A Vulnerability if analysis succeeded, None otherwise.
    """
    config = get_config()

    if config.opencode.mock:
        return _mock_result(candidate)

    # 按 checker 的 mode 决定调用方式
    from backend.registry import get_registry
    registry = get_registry()
    checker_entry = registry.get(candidate.vuln_type)
    use_api = (
        config.llm_api.enabled
        and checker_entry is not None
        and checker_entry.mode == "api"
    )

    if use_api:
        from backend.opencode.llm_api_runner import run_audit_via_api
        return await run_audit_via_api(
            candidate, project_id,
            prompt_path=checker_entry.prompt_path,
            on_output=on_output,
            cancel_event=cancel_event,
        )

    skill_name = candidate.vuln_type
    result_id = uuid4().hex

    prompt = (
        f"Using the `{skill_name}-analysis` skill, analyze the potential "
        f"{candidate.vuln_type.upper()} vulnerability at "
        f"{candidate.file}:{candidate.line} in function `{candidate.function}`. "
        f"The project_id is `{project_id}`. "
        f"Details: {candidate.description}\n\n"
        f"Your result_id is `{result_id}`. "
        f"When you have finished your analysis, you MUST call the submit_result tool "
        f"with this result_id and your findings."
    )

    log_path = workspace / f"opencode_{result_id}.log"

    logger.info(
        "Running opencode audit: %s:%d (%s) result_id=%s",
        candidate.file, candidate.line, candidate.vuln_type, result_id,
    )

    try:
        await _invoke_opencode(
            workspace, prompt, config.opencode.timeout,
            log_path=log_path, on_line=on_output, cancel_event=cancel_event,
        )
    except asyncio.TimeoutError:
        logger.error("opencode timed out for %s:%d", candidate.file, candidate.line)
        return Vulnerability(
            file=candidate.file,
            line=candidate.line,
            function=candidate.function,
            vuln_type=candidate.vuln_type,
            severity="unknown",
            description=candidate.description,
            ai_analysis="Analysis timed out",
            confirmed=False,
        )
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("opencode failed for %s:%d", candidate.file, candidate.line)
        return None

    return _read_result(result_id, candidate)


def _resolve_opencode() -> str:
    """Return the full path to the opencode executable.

    Uses the name/path from config (opencode.executable, default "opencode").
    On Windows, opencode is typically installed as opencode.cmd (npm package).
    CreateProcess does not resolve .cmd/.bat extensions automatically, so we
    use shutil.which which honours PATHEXT on Windows.
    """
    name = get_config().opencode.executable or "opencode"
    resolved = shutil.which(name)
    if resolved is None:
        raise FileNotFoundError(
            f"opencode executable '{name}' not found in PATH. "
            "Check the opencode.executable setting in config.yaml (or agent.yaml)."
        )
    return resolved


async def _invoke_opencode(
    workspace: Path,
    prompt: str,
    timeout: int,
    log_path: Path | None = None,
    on_line=None,
    cancel_event: asyncio.Event | None = None,
) -> None:
    """Invoke opencode CLI, stream output line-by-line, write to log file.

    Uses subprocess.Popen in a thread executor instead of
    asyncio.create_subprocess_exec to avoid the asyncio child-watcher
    requirement on Linux (which raises NotImplementedError in some
    environments regardless of Python version).
    """
    config = get_config()
    opencode_exe = _resolve_opencode()
    cmd = [opencode_exe, "run", "--dir", str(workspace)]
    if config.opencode.model:
        cmd += ["--model", config.opencode.model]
    cmd.append(prompt)

    logger.debug("opencode command: %s", " ".join(cmd))

    env = os.environ.copy()
    env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"

    kwargs: dict = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW

    loop = asyncio.get_running_loop()
    # Queue carries output lines; None is the end-of-stream sentinel.
    queue: asyncio.Queue[str | None] = asyncio.Queue()
    proc_holder: list[subprocess.Popen | None] = [None]

    def _stream() -> int:
        """Blocking: run opencode, push lines into the asyncio queue."""
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            **kwargs,
        )
        proc_holder[0] = proc
        try:
            assert proc.stdout is not None
            for raw in proc.stdout:
                line = _strip_ansi(raw.decode("utf-8", errors="replace").rstrip())
                if line:
                    loop.call_soon_threadsafe(queue.put_nowait, line)
        finally:
            try:
                proc.stdout.close()
            except Exception:
                pass
            proc.wait()
            loop.call_soon_threadsafe(queue.put_nowait, None)
        return proc.returncode

    def _kill() -> None:
        proc = proc_holder[0]
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass

    stream_future = loop.run_in_executor(None, _stream)

    # Watcher: kill proc immediately when cancel_event fires.
    async def _cancel_watcher() -> None:
        if cancel_event:
            await cancel_event.wait()
            _kill()

    watcher = asyncio.create_task(_cancel_watcher()) if cancel_event else None

    log_lines: list[str] = []
    deadline = loop.time() + timeout
    timed_out = False

    try:
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                _kill()
                timed_out = True
                break
            try:
                line = await asyncio.wait_for(queue.get(), timeout=min(remaining, 1.0))
            except asyncio.TimeoutError:
                continue
            if line is None:  # end-of-stream sentinel
                break
            log_lines.append(line)
            logger.debug("[opencode] %s", line)
            if on_line:
                on_line(line)
    finally:
        if watcher:
            watcher.cancel()
        if log_path and log_lines:
            try:
                log_path.write_text("\n".join(log_lines), encoding="utf-8")
            except Exception:
                pass

    await stream_future  # wait for thread to exit cleanly

    if timed_out:
        raise asyncio.TimeoutError()

    proc = proc_holder[0]
    returncode = proc.returncode if proc is not None else -1
    cancelled = cancel_event is not None and cancel_event.is_set()
    if not cancelled and returncode != 0:
        logger.error("opencode exited with code %d", returncode)
        raise RuntimeError(f"opencode exited with code {returncode}")


def _read_result(result_id: str, candidate: Candidate) -> Vulnerability | None:
    """Read the result file written by the submit_result MCP tool."""
    config = get_config()
    result_path = Path(config.storage.scans_dir) / f"{result_id}.json"

    if not result_path.exists():
        logger.warning(
            "submit_result was not called for %s:%d (result_id=%s)",
            candidate.file, candidate.line, result_id,
        )
        return None

    try:
        data = json.loads(result_path.read_text())
    except Exception:
        logger.error("Failed to parse result file for result_id=%s", result_id)
        return None

    return Vulnerability(
        file=candidate.file,
        line=candidate.line,
        function=candidate.function,
        vuln_type=candidate.vuln_type,
        severity=data.get("severity", "unknown"),
        description=data.get("description", candidate.description),
        ai_analysis=data.get("ai_analysis", ""),
        confirmed=data.get("confirmed", False),
    )


async def run_audit_batch(
    workspace: Path,
    candidates: list[Candidate],
    project_id: str,
    on_output=None,
    cancel_event: asyncio.Event | None = None,
) -> list[Vulnerability | None]:
    """Run batch audit for multiple candidates in the same function.

    In LLM API mode, sends all candidates in one LLM call.
    In opencode CLI mode, falls back to sequential single-candidate calls.
    """
    config = get_config()

    if config.opencode.mock:
        return [_mock_result(c) for c in candidates]

    # 按 checker 的 mode 决定调用方式
    from backend.registry import get_registry
    registry = get_registry()
    checker_entry = registry.get(candidates[0].vuln_type) if candidates else None
    use_api = (
        config.llm_api.enabled
        and checker_entry is not None
        and checker_entry.mode == "api"
    )

    if use_api:
        from backend.opencode.llm_api_runner import run_batch_audit_via_api
        return await run_batch_audit_via_api(
            candidates, project_id,
            prompt_path=checker_entry.prompt_path,
            on_output=on_output,
            cancel_event=cancel_event,
        )

    # opencode CLI 模式：退化为逐个调用
    results = []
    for candidate in candidates:
        if cancel_event and cancel_event.is_set():
            results.append(None)
            continue
        vuln = await run_audit(
            workspace, candidate, project_id,
            on_output=on_output,
            cancel_event=cancel_event,
        )
        results.append(vuln)
    return results


def _mock_result(candidate: Candidate) -> Vulnerability:
    """Return a fake analysis result for testing without opencode."""
    logger.debug("Mock opencode result for %s:%d", candidate.file, candidate.line)
    return Vulnerability(
        file=candidate.file,
        line=candidate.line,
        function=candidate.function,
        vuln_type=candidate.vuln_type,
        severity="high",
        description=candidate.description,
        ai_analysis=(
            f"[MOCK] Potential {candidate.vuln_type.upper()} detected: "
            f"{candidate.description}. "
            f"This is a mock result — configure opencode for real analysis."
        ),
        confirmed=True,
    )
