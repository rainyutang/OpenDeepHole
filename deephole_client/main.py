"""DeepHole 2.0 Agent Daemon — WebSocket client that connects to the web server.

The agent connects to the server, receives task/stop/resume commands via WebSocket,
and pushes scan events and results back via HTTP POST.

Usage:
    python -m deephole_client.main [OPTIONS]

    --server URL          Web server URL (overrides agent.yaml server_url)
    --name NAME           Agent display name (overrides agent.yaml agent_name)
    --config FILE         Path to config file (default: ./agent.yaml)

Examples:
    python -m deephole_client.main
    python -m deephole_client.main --server http://192.168.1.10:8000
    python -m deephole_client.main --name "my-server" --config /etc/opendeephole/agent.yaml
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import socket
import sys
from pathlib import Path

from task_agent.output_format import with_local_timestamp


_WS_MAX_MESSAGE_ENV = "OPENDEEPHOLE_WS_MAX_MESSAGE_MB"
_DEFAULT_WS_MAX_MESSAGE_MB = 64
_MIB = 1024 * 1024


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _ws_max_message_mb() -> int:
    """Return the bounded Agent receive limit for server WebSocket messages."""
    return _env_int(_WS_MAX_MESSAGE_ENV, _DEFAULT_WS_MAX_MESSAGE_MB)


def _ws_message_too_big_hint(error: Exception, max_message_mb: int) -> str:
    """Return an actionable hint for WebSocket close code 1009 errors."""
    detail = str(error).lower()
    if not any(
        marker in detail
        for marker in ("1009", "message too big", "frame exceeds limit")
    ):
        return ""
    return (
        f"Agent WebSocket receive limit is {max_message_mb} MiB; increase "
        f"{_WS_MAX_MESSAGE_ENV} and restart the Agent if larger commands are expected"
    )


async def _send_ws_json(ws, lock: asyncio.Lock, payload: dict) -> None:
    """Serialize Agent-originated frames so long commands cannot race heartbeat sends."""
    message = json.dumps(payload)
    async with lock:
        await ws.send(message)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="agent",
        description="DeepHole 2.0 agent daemon — connects to web server and executes scan tasks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--server", metavar="URL", help="Web server URL (overrides agent.yaml)")
    parser.add_argument("--name", metavar="NAME", help="Agent display name shown on web UI")
    parser.add_argument("--config", metavar="FILE", help="Path to agent.yaml config file")
    return parser.parse_args()


async def _handle_command(msg: dict, config, task_manager, reporter) -> dict | None:
    """Dispatch a command message from the server to the appropriate handler."""
    import deephole_client.server as agent_server

    cmd_type = msg.get("type")

    if cmd_type == "task":
        from deephole_client.updater import ensure_runtime_updated
        await ensure_runtime_updated(msg.get("agent_runtime_update"), msg)
        if msg.get("runtime_update_only"):
            post_update_command = msg.get("post_update_command")
            if isinstance(post_update_command, dict):
                return await _handle_command(post_update_command, config, task_manager, reporter)
            return None
        await agent_server.handle_task(
            scan_id=msg["scan_id"],
            project_path=msg["project_path"],
            code_scan_path=msg.get("code_scan_path"),
            checkers=msg.get("checkers", []),
            scan_name=msg.get("scan_name", ""),
            scan_mode=msg.get("scan_mode", "custom"),
            threat_analysis_enabled=bool(
                msg.get("threat_analysis_enabled")
            ),
            threat_analysis_method=str(
                msg.get("threat_analysis_method")
                or "deephole_threat_analysis"
            ),
            product=msg.get("product", ""),
            validation_environment=msg.get("validation_environment", ""),
            vulnerability_validation=(
                msg.get("vulnerability_validation")
                if isinstance(msg.get("vulnerability_validation"), dict)
                else None
            ),
            code_graph_mcp=(
                msg.get("code_graph_mcp")
                if isinstance(msg.get("code_graph_mcp"), dict)
                else None
            ),
            knowledge_base_mcp=(
                msg.get("knowledge_base_mcp")
                if isinstance(msg.get("knowledge_base_mcp"), dict)
                else None
            ),
            feedback_entries=msg.get("feedback_entries", []),
            checker_packages=msg.get("checker_packages", []),
            mining_engines=(
                msg.get("mining_engines")
                if isinstance(msg.get("mining_engines"), list)
                else None
            ),
            codex_model_ids=(
                msg.get("codex_model_ids")
                if isinstance(msg.get("codex_model_ids"), list)
                else None
            ),
        )
    elif cmd_type == "stop":
        await agent_server.handle_stop(msg["scan_id"])
    elif cmd_type == "resume":
        from deephole_client.updater import ensure_runtime_updated
        await ensure_runtime_updated(msg.get("agent_runtime_update"), msg)
        manifest_url = str(msg.get("resume_manifest_url") or "").strip()
        if manifest_url:
            manifest = await reporter.fetch_resume_manifest(manifest_url)
            msg = {
                **manifest,
                "type": "resume",
                "scan_id": msg["scan_id"],
            }
        await agent_server.handle_resume(
            scan_id=msg["scan_id"],
            project_path=msg.get("project_path"),
            code_scan_path=msg.get("code_scan_path"),
            checkers=msg.get("checkers"),
            scan_name=msg.get("scan_name"),
            scan_mode=msg.get("scan_mode"),
            threat_analysis_enabled=(
                bool(msg.get("threat_analysis_enabled"))
                if "threat_analysis_enabled" in msg
                else None
            ),
            threat_analysis_method=(
                str(msg.get("threat_analysis_method") or "")
                if "threat_analysis_method" in msg
                else None
            ),
            product=msg.get("product"),
            validation_environment=msg.get("validation_environment"),
            vulnerability_validation=(
                msg.get("vulnerability_validation")
                if isinstance(msg.get("vulnerability_validation"), dict)
                else None
            ),
            code_graph_mcp=(
                msg.get("code_graph_mcp")
                if isinstance(msg.get("code_graph_mcp"), dict)
                else None
            ),
            knowledge_base_mcp=(
                msg.get("knowledge_base_mcp")
                if isinstance(msg.get("knowledge_base_mcp"), dict)
                else None
            ),
            feedback_entries=msg.get("feedback_entries"),
            checker_packages=msg.get("checker_packages"),
            mining_engines=(
                msg.get("mining_engines")
                if isinstance(msg.get("mining_engines"), list)
                else None
            ),
            retry_candidates=msg.get("retry_candidates"),
            retry_total_candidates=msg.get("retry_total_candidates"),
            retry_processed_offset=int(msg.get("retry_processed_offset") or 0),
            resume_threat_analysis=bool(msg.get("resume_threat_analysis")),
            retry_mining_engine_ids=(
                msg.get("retry_mining_engine_ids")
                if isinstance(msg.get("retry_mining_engine_ids"), list)
                else None
            ),
            retry_threat_audit_task_ids=msg.get("retry_threat_audit_task_ids"),
            codex_model_ids=(
                msg.get("codex_model_ids")
                if isinstance(msg.get("codex_model_ids"), list)
                else None
            ),
        )
    elif cmd_type == "fp_review":
        from deephole_client.updater import ensure_runtime_updated
        await ensure_runtime_updated(msg.get("agent_runtime_update"), msg)
        await agent_server.handle_fp_review(
            scan_id=msg["scan_id"],
            review_id=msg["review_id"],
            method=str(msg.get("method") or "adversarial"),
            project_path=msg["project_path"],
            code_scan_path=str(msg.get("code_scan_path") or msg["project_path"]),
            vulnerabilities=msg.get("vulnerabilities", []),
            feedback_entries=msg.get("feedback_entries", []),
            processed_offset=int(msg.get("processed_offset") or 0),
            code_graph_mcp=(
                msg.get("code_graph_mcp")
                if isinstance(msg.get("code_graph_mcp"), dict)
                else None
            ),
            knowledge_base_mcp=(
                msg.get("knowledge_base_mcp")
                if isinstance(msg.get("knowledge_base_mcp"), dict)
                else None
            ),
            scan_mode=msg.get("scan_mode", "custom"),
        )
    elif cmd_type == "vulnerability_validation":
        from deephole_client.updater import ensure_runtime_updated
        try:
            await ensure_runtime_updated(msg.get("agent_runtime_update"), msg)
        except Exception as exc:
            from backend.models import VulnerabilityValidation
            from datetime import datetime, timezone

            now = datetime.now(timezone.utc).isoformat()
            await reporter.report_vulnerability_validation(
                msg["scan_id"],
                VulnerabilityValidation(
                    scan_id=msg["scan_id"],
                    vuln_index=int(msg["vuln_index"]),
                    status="error",
                    running=False,
                    product=msg.get("product", ""),
                    validation_method_id=msg.get("validation_method_id", ""),
                    validation_method_label=msg.get("validation_method_label", ""),
                    validation_success=False,
                    requires_human_intervention=True,
                    validation_output=f"Agent runtime update failed: {exc}",
                    final_output=f"Agent runtime update failed: {exc}",
                    finished_at=now,
                    updated_at=now,
                ),
            )
            return None
        await agent_server.handle_vulnerability_validation(
            scan_id=msg["scan_id"],
            vuln_index=int(msg["vuln_index"]),
            project_path=msg.get("project_path", ""),
            code_scan_path=msg.get("code_scan_path", ""),
            product=msg.get("product", ""),
            validation_method_id=msg.get("validation_method_id", ""),
            validation_method_label=msg.get("validation_method_label", ""),
            validation_values=(
                msg.get("validation_values")
                if isinstance(msg.get("validation_values"), dict)
                else {}
            ),
            validation_policy=(
                msg.get("validation_policy")
                if isinstance(msg.get("validation_policy"), dict)
                else {}
            ),
            vulnerability=msg.get("vulnerability") or {},
            report_markdown=msg.get("report_markdown", ""),
            code_graph_mcp=(
                msg.get("code_graph_mcp")
                if isinstance(msg.get("code_graph_mcp"), dict)
                else None
            ),
            knowledge_base_mcp=(
                msg.get("knowledge_base_mcp")
                if isinstance(msg.get("knowledge_base_mcp"), dict)
                else None
            ),
            scan_mode=msg.get("scan_mode", "custom"),
        )
    elif cmd_type == "vulnerability_validation_stop":
        await agent_server.handle_vulnerability_validation_stop(
            scan_id=msg["scan_id"],
            vuln_index=int(msg["vuln_index"]),
        )
    elif cmd_type == "fp_review_stop":
        await agent_server.handle_fp_review_stop(
            scan_id=msg["scan_id"],
            review_id=msg["review_id"],
        )
    elif cmd_type == "feedback_selection_update":
        await agent_server.handle_feedback_selection_update(
            scan_id=msg["scan_id"],
            feedback_entries=msg.get("feedback_entries", []),
        )
    elif cmd_type == "feedback_update":
        # Feedback is persisted by the backend and supplied explicitly in each
        # candidate-audit or FP-review call.
        return None
    elif cmd_type == "config":
        from deephole_client.config import apply_remote_config, save_config
        if msg.get("config"):
            apply_remote_config(config, msg["config"])
            try:
                await _apply_live_config_update(config)
            except Exception as e:
                print(f"Config updated from server (warning: live runtime refresh failed: {e})")
            try:
                save_config(config)
                print("Config updated from server and persisted to agent.yaml")
            except Exception as e:
                print(f"Config updated from server (warning: failed to persist: {e})")
    elif cmd_type == "opencode_models":
        return await agent_server.handle_opencode_models(
            request_id=msg.get("request_id", ""),
            refresh=bool(msg.get("refresh")),
        )
    elif cmd_type == "mcp_probe":
        return await agent_server.handle_mcp_probe(
            request_id=str(msg.get("request_id") or ""),
            target=str(msg.get("target") or ""),
            mcp_config=msg.get("mcp_config") if isinstance(msg.get("mcp_config"), dict) else {},
            projects_tool=str(msg.get("projects_tool") or ""),
        )
    elif cmd_type == "mcp_status":
        return await agent_server.handle_mcp_status(
            request_id=str(msg.get("request_id") or ""),
        )
    elif cmd_type == "mcp_reload":
        return await agent_server.handle_mcp_reload(
            request_id=str(msg.get("request_id") or ""),
            target=str(msg.get("target") or ""),
        )
    elif cmd_type == "skill_create":
        from deephole_client.updater import ensure_runtime_updated
        await ensure_runtime_updated(msg.get("agent_runtime_update"), msg)
        return await agent_server.handle_skill_create(
            request_id=msg.get("request_id", ""),
            name=msg.get("name", ""),
            description=msg.get("description", ""),
            user_input=msg.get("input", ""),
            skill_creator_package=(
                msg.get("deephole_skill_creator_package")
                or msg.get("skill_creator_package")
                or {}
            ),
        )
    else:
        print(f"Unknown command type: {cmd_type!r}")
    return None


async def _apply_live_config_update(config) -> None:
    """Apply server-managed model/API config to already loaded backend state."""
    from deephole_client.config import apply_network_env
    from deephole_client.platform_runtime import refresh_platform_runtime_config
    from task_agent.model_pool import (
        notify_model_pool_config_changed,
        refresh_configured_model_pool,
    )
    from task_agent.serve_client import get_serve_manager, mark_serve_config_dirty

    apply_network_env(config)
    refresh_platform_runtime_config(config)
    from deephole_client.opencode_integration import (
        build_managed_mcp_runtime_specs,
        configure_opencode_component,
        refresh_global_opencode_config,
    )
    configure_opencode_component()
    refresh_global_opencode_config()
    from deephole_client.codex_runtime import sync_platform_codex_models_async
    await sync_platform_codex_models_async(
        config,
        reason="platform model configuration",
    )
    get_serve_manager().update_managed_mcp_configs(
        build_managed_mcp_runtime_specs(config)
    )
    mark_serve_config_dirty()
    await refresh_configured_model_pool(
        config.opencode,
        global_concurrency=config.opencode_concurrency,
    )
    await notify_model_pool_config_changed()
    # Increasing an environment limit should start already queued validations
    # immediately; lowering it only affects subsequent dispatches.
    from deephole_client.server import refresh_validation_scheduling
    refresh_validation_scheduling()


async def _ws_loop(config, task_manager, reporter) -> None:
    """WebSocket connection loop with automatic reconnect."""
    import websockets
    import deephole_client.server as agent_server
    from deephole_client.config import apply_network_env, apply_remote_config, remote_config_dict
    from deephole_client.vulnerability_validation import (
        run_vulnerability_validation,
    )
    from deephole_client.updater import compute_runtime_hash, load_pending_commands, pending_scan_snapshots

    name = config.agent_name or socket.gethostname()
    ws_url = config.server_url.replace("http://", "ws://").replace("https://", "wss://")
    ws_url = ws_url.rstrip("/") + "/api/agent/ws"
    ping_interval = _env_int("OPENDEEPHOLE_WS_PING_INTERVAL", 30)
    ping_timeout = _env_int("OPENDEEPHOLE_WS_PING_TIMEOUT", 120)
    heartbeat_interval = _env_int("OPENDEEPHOLE_AGENT_HEARTBEAT_INTERVAL", 30)
    watchdog_timeout = _env_int("OPENDEEPHOLE_AGENT_WATCHDOG_TIMEOUT", 120)
    max_message_mb = _ws_max_message_mb()
    max_message_bytes = max_message_mb * _MIB

    reconnect_delay = 2

    while True:
        try:
            print(f"Connecting to {ws_url} ...")
            async with websockets.connect(
                ws_url,
                ping_interval=ping_interval,
                ping_timeout=ping_timeout,
                max_size=max_message_bytes,
            ) as ws:
                ws_send_lock = asyncio.Lock()
                # Handshake
                validator_result = await run_vulnerability_validation(
                    operation="catalog",
                )
                hello_msg = {
                    "type": "hello",
                    "protocol_versions": [2, 1],
                    "capabilities": {
                        "final_vulnerability_callbacks": True,
                    },
                    "name": name,
                    "machine_name": socket.gethostname(),
                    "config": remote_config_dict(config),
                    "validator_catalog": validator_result["catalog"],
                    "runtime_hash": compute_runtime_hash(),
                    "agent_session_id": reporter.agent_session_id,
                    "active_scans": task_manager.active_snapshots() + pending_scan_snapshots(),
                    "active_fp_reviews": agent_server.active_fp_review_snapshots(),
                    "active_validations": agent_server.active_validation_snapshots(),
                }
                if config.owner_token:
                    hello_msg["owner_token"] = config.owner_token
                await _send_ws_json(ws, ws_send_lock, hello_msg)

                welcome_raw = await asyncio.wait_for(ws.recv(), timeout=15.0)
                welcome = json.loads(welcome_raw)

                if welcome.get("type") != "welcome":
                    print(f"Unexpected handshake response: {welcome}")
                    continue

                agent_id = welcome["agent_id"]
                agent_server._agent_id = agent_id
                reporter.set_agent_id(agent_id)
                reporter.set_protocol_version(int(welcome.get("protocol_version") or 1))

                if welcome.get("config"):
                    from deephole_client.config import save_config
                    apply_remote_config(config, welcome["config"])
                    try:
                        await _apply_live_config_update(config)
                    except Exception as e:
                        print(f"Config received from server (warning: live runtime refresh failed: {e})")
                    try:
                        save_config(config)
                    except Exception as e:
                        print(f"Config received from server (warning: failed to persist: {e})")

                reconnect_delay = 2  # reset backoff on successful connect
                print(f"  Connected. Agent ID: {agent_id}")
                print()

                pending_commands = load_pending_commands(clear=True)

                loop = asyncio.get_running_loop()
                last_seen = loop.time()
                command_queue: asyncio.Queue[dict | None] = asyncio.Queue()

                async def _heartbeat() -> None:
                    while True:
                        await asyncio.sleep(heartbeat_interval)
                        try:
                            await _send_ws_json(
                                ws,
                                ws_send_lock,
                                {"type": "heartbeat"},
                            )
                        except Exception as exc:
                            print(with_local_timestamp(
                                "HEARTBEAT_SEND_FAILED "
                                f"error={type(exc).__name__}: {exc}",
                                prefix="[agent_connection]",
                            ), flush=True)
                            with contextlib.suppress(Exception):
                                await ws.close(
                                    code=4002,
                                    reason="agent heartbeat send failed",
                                )
                            raise

                async def _watchdog() -> None:
                    nonlocal last_seen
                    while True:
                        await asyncio.sleep(max(1, min(heartbeat_interval, 10)))
                        idle = loop.time() - last_seen
                        if idle > watchdog_timeout:
                            print(with_local_timestamp(
                                "WATCHDOG_TIMEOUT "
                                f"no_server_message_seconds={idle:.0f} "
                                f"watchdog_timeout_seconds={watchdog_timeout} "
                                f"heartbeat_interval_seconds={heartbeat_interval}; reconnecting",
                                prefix="[agent_connection]",
                            ), flush=True)
                            await ws.close(code=4001, reason="agent heartbeat watchdog timeout")
                            return

                async def _command_worker() -> None:
                    while True:
                        msg = await command_queue.get()
                        if msg is None:
                            return
                        try:
                            response = await _handle_command(msg, config, task_manager, reporter)
                            if response:
                                await _send_ws_json(ws, ws_send_lock, response)
                        except Exception as e:
                            print(f"Error handling command: {e}")

                pool_status_stop = asyncio.Event()
                heartbeat_task = asyncio.create_task(_heartbeat())
                watchdog_task = asyncio.create_task(_watchdog())
                worker_task = asyncio.create_task(_command_worker())
                pool_status_task = asyncio.create_task(
                    reporter.publish_agent_opencode_pool_until(pool_status_stop)
                )

                try:
                    for command in pending_commands:
                        await command_queue.put(command)
                    # Message loop
                    async for raw_msg in ws:
                        last_seen = loop.time()
                        try:
                            msg = json.loads(raw_msg)
                        except Exception as e:
                            print(f"Error parsing server message: {e}")
                            continue
                        if msg.get("type") == "heartbeat_ack":
                            continue
                        await command_queue.put(msg)
                finally:
                    pool_status_stop.set()
                    heartbeat_task.cancel()
                    watchdog_task.cancel()
                    pool_status_task.cancel()
                    await command_queue.put(None)
                    worker_task.cancel()
                    for task in (heartbeat_task, watchdog_task, worker_task, pool_status_task):
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass

        except Exception as e:
            message = f"Connection lost: {e}."
            hint = _ws_message_too_big_hint(e, max_message_mb)
            if hint:
                message += f" {hint}."
            print(with_local_timestamp(
                f"{message} Reconnecting in {reconnect_delay}s...",
                prefix="[agent_connection]",
            ), flush=True)
            await asyncio.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, 60)


async def _main() -> None:
    args = _parse_args()

    # Load config
    from deephole_client.config import apply_network_env, load_config
    config_path = Path(args.config) if args.config else None
    config = load_config(config_path)
    from deephole_client.opencode_integration import configure_opencode_component
    configure_opencode_component()

    # Apply CLI overrides
    if args.server:
        config.server_url = args.server
    if args.name:
        config.agent_name = args.name

    # Apply no_proxy early so httpx respects it
    apply_network_env(config)

    name = config.agent_name or socket.gethostname()

    print("DeepHole 2.0 Agent Daemon")
    print(f"  Name    : {name}")
    print(f"  Server  : {config.server_url}")
    print()

    # Codex is an optional mining-engine dependency.  Prepare it before the
    # Agent connects so every task in this process sees one stable result;
    # failures are reported locally and never prevent the Agent from starting.
    from deephole_client.codex_runtime import initialize_codex_runtime
    await initialize_codex_runtime()
    print()

    from deephole_client.reporter import Reporter
    from deephole_client.task_manager import TaskManager
    import deephole_client.server as agent_server

    reporter = Reporter(config.server_url)
    reporter.set_agent_name(name)
    task_manager = TaskManager()

    # Inject runtime globals into the deephole_client.server coordinator.
    agent_server._config = config
    agent_server._reporter = reporter
    agent_server._task_manager = task_manager

    try:
        await _ws_loop(config, task_manager, reporter)
    finally:
        try:
            from task_agent import shutdown_opencode
            await shutdown_opencode()
        except Exception as exc:
            print(f"Warning: failed to stop OpenCode serve: {exc}")
        await reporter.close()


def main() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main()
