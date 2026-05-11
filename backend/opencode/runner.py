"""opencode CLI runner — invokes opencode for AI-powered vulnerability analysis."""

import asyncio
import json
import os
import re
import signal
import shlex
import shutil
import subprocess
import sys
import threading
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
    timeout: int | None = None,
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
        timeout: Per-candidate timeout in seconds. Falls back to config if not provided.

    Returns:
        A Vulnerability if analysis succeeded, None otherwise.
    """
    config = get_config()

    if config.opencode.mock:
        return _mock_result(candidate)

    effective_timeout = timeout if timeout is not None else config.opencode.timeout

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
        # 优先使用 workspace 中合并了反馈的 prompt
        merged_prompt = workspace / ".opencode" / "skills" / candidate.vuln_type / "PROMPT.md"
        prompt_path = merged_prompt if merged_prompt.is_file() else checker_entry.prompt_path
        return await run_audit_via_api(
            candidate, project_id,
            prompt_path=prompt_path,
            on_output=on_output,
            cancel_event=cancel_event,
        )

    # Skill directory is .opencode/skills/<name>/ where <name> == vuln_type.
    # Use checker_entry.skill_name if explicitly set, otherwise fall back to
    # vuln_type so the name matches the actual directory opencode will look up.
    skill_name = (
        checker_entry.skill_name
        if checker_entry and checker_entry.skill_name
        else candidate.vuln_type
    )
    max_retries = config.opencode.max_retries

    for attempt in range(1, max_retries + 2):  # attempt 1 .. max_retries+1
        result_id = f"result-{uuid4().hex}"

        prompt = (
            f"使用 `{skill_name}` 技能，分析位于 "
            f"{candidate.file}:{candidate.line} 函数 `{candidate.function}` 中"
            f"潜在的 {candidate.vuln_type.upper()} 漏洞。"
            f"project_id 为 `{project_id}`。"
            f"详情：{candidate.description}\n\n"
            f"你的 result_id 是 `{result_id}`。"
            f"分析完成后，你**必须**使用此 result_id 调用 submit_result MCP 工具提交你的结论。\n\n"
            f"**重要：你必须直接完成所有分析工作，禁止使用子 Agent（sub-agent）或委托任何子任务。"
            f"所有 MCP 工具调用（包括 submit_result）必须由你自己直接执行。**"
        )

        log_path = workspace / f"opencode_{result_id}.log"

        if on_output:
            on_output(f"[opencode] 初始提示词:\n{prompt}")

        logger.info(
            "Running opencode audit: %s:%d (%s) result_id=%s timeout=%ds attempt=%d/%d",
            candidate.file, candidate.line, candidate.vuln_type, result_id,
            effective_timeout, attempt, max_retries + 1,
        )

        try:
            await _invoke_opencode(
                workspace, prompt, effective_timeout,
                log_path=log_path, on_line=on_output, cancel_event=cancel_event,
            )
        except asyncio.TimeoutError:
            # Timeout — no retry; check if result was submitted before kill
            logger.error("opencode timed out for %s:%d (timeout=%ds)", candidate.file, candidate.line, effective_timeout)
            result = _read_result(result_id, candidate)
            if result is not None:
                logger.info("Result file found despite timeout — using submitted result")
                return result
            return Vulnerability(
                file=candidate.file,
                line=candidate.line,
                function=candidate.function,
                vuln_type=candidate.vuln_type,
                severity="unknown",
                description=candidate.description,
                ai_analysis="Analysis timed out",
                confirmed=False,
                ai_verdict="timeout",
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Process error (e.g. certificate error, crash) — may retry
            logger.exception("opencode failed for %s:%d (attempt %d)", candidate.file, candidate.line, attempt)
            if attempt <= max_retries:
                logger.info("Retrying opencode for %s:%d ...", candidate.file, candidate.line)
                if on_output:
                    on_output(f"[retry {attempt}/{max_retries}] opencode error: {exc}")
                continue
            return None

        # Process completed — check result
        result = _read_result(result_id, candidate)
        if result is not None:
            return result

        # submit_result was not called — retry if attempts remain
        if attempt <= max_retries:
            logger.warning(
                "opencode did not call submit_result for %s:%d (attempt %d), retrying...",
                candidate.file, candidate.line, attempt,
            )
            if on_output:
                on_output(f"[retry {attempt}/{max_retries}] No result submitted, retrying...")
            continue

        logger.warning("opencode did not call submit_result for %s:%d after %d attempts", candidate.file, candidate.line, attempt)
        return None

    return None  # should not reach here


def _resolve_opencode() -> str:
    """Return the full path to the opencode executable.

    Uses the name/path from config (opencode.executable, default "opencode").
    Falls back to a bash login shell lookup so that executables installed in
    non-standard locations (e.g. ~/.bun/bin, ~/.local/bin) that are added to
    PATH by ~/.profile or ~/.bash_profile are found even when the Python
    process was started without sourcing those files.
    """
    name = get_config().opencode.executable or "opencode"
    # Direct resolution: works when the binary is already in the current PATH
    resolved = shutil.which(name)
    if resolved:
        return resolved
    # Login-shell fallback: sources ~/.profile / ~/.bash_profile which typically
    # extend PATH for user-installed tools (npm, bun, pipx, etc.)
    if sys.platform != "win32":
        try:
            result = subprocess.run(
                ["bash", "-lc", f"command -v {shlex.quote(name)}"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                path = result.stdout.strip()
                if path:
                    logger.debug("opencode resolved via login shell: %s", path)
                    return path
        except Exception:
            pass
    raise FileNotFoundError(
        f"opencode executable '{name}' not found in PATH. "
        "Check the opencode.executable setting in agent.yaml."
    )


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

    logger.debug("opencode command (prompt via stdin): %s", " ".join(cmd))

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
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
            start_new_session=True,
            **kwargs,
        )
        proc_holder[0] = proc
        try:
            # 独立线程写 stdin，避免阻塞 stdout 读取
            def _feed():
                try:
                    proc.stdin.write(prompt)
                    proc.stdin.close()
                except Exception:
                    pass
            threading.Thread(target=_feed, daemon=True).start()

            assert proc.stdout is not None
            while True:
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        break
                    continue
                line = _strip_ansi(line.rstrip())
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
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
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
    deadline = asyncio.get_event_loop().time() + timeout
    timed_out = False

    try:
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                timed_out = True
                _kill()
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
            try:
                await watcher
            except asyncio.CancelledError:
                pass
        if log_path and log_lines:
            try:
                log_path.write_text("\n".join(log_lines), encoding="utf-8")
            except Exception:
                pass

    await stream_future  # wait for thread to exit cleanly

    if timed_out:
        raise asyncio.TimeoutError()

    proc = proc_holder[0]
    if proc and proc.returncode not in (0, None):
        logger.error("opencode exited with code %d", proc.returncode)
        raise RuntimeError(f"opencode exited with code {proc.returncode}")


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

    confirmed = data.get("confirmed", False)
    return Vulnerability(
        file=candidate.file,
        line=candidate.line,
        function=candidate.function,
        vuln_type=candidate.vuln_type,
        severity=data.get("severity", "unknown"),
        description=data.get("description", candidate.description),
        ai_analysis=data.get("ai_analysis", ""),
        confirmed=confirmed,
        ai_verdict="confirmed" if confirmed else "not_confirmed",
    )


async def run_audit_batch(
    workspace: Path,
    candidates: list[Candidate],
    project_id: str,
    on_output=None,
    cancel_event: asyncio.Event | None = None,
    timeout: int | None = None,
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
        # 优先使用 workspace 中合并了反馈的 prompt
        merged_prompt = workspace / ".opencode" / "skills" / candidates[0].vuln_type / "PROMPT.md"
        prompt_path = merged_prompt if merged_prompt.is_file() else checker_entry.prompt_path
        return await run_batch_audit_via_api(
            candidates, project_id,
            prompt_path=prompt_path,
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
            timeout=timeout,
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
        ai_verdict="confirmed",
    )
