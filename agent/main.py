"""OpenDeepHole Agent Daemon — WebSocket client that connects to the web server.

The agent connects to the server, receives task/stop/resume commands via WebSocket,
and pushes scan events and results back via HTTP POST.

Usage:
    python -m agent.main [OPTIONS]

    --server URL          Web server URL (overrides agent.yaml server_url)
    --name NAME           Agent display name (overrides agent.yaml agent_name)
    --config FILE         Path to config file (default: ./agent.yaml)

Examples:
    python -m agent.main
    python -m agent.main --server http://192.168.1.10:8000
    python -m agent.main --name "my-server" --config /etc/opendeephole/agent.yaml
"""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
import sys
from pathlib import Path


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="agent",
        description="OpenDeepHole agent daemon — connects to web server and executes scan tasks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--server", metavar="URL", help="Web server URL (overrides agent.yaml)")
    parser.add_argument("--name", metavar="NAME", help="Agent display name shown on web UI")
    parser.add_argument("--config", metavar="FILE", help="Path to agent.yaml config file")
    return parser.parse_args()


async def _handle_command(msg: dict, config, task_manager, reporter) -> None:
    """Dispatch a command message from the server to the appropriate handler."""
    import agent.server as agent_server

    cmd_type = msg.get("type")

    if cmd_type == "task":
        await agent_server.handle_task(
            scan_id=msg["scan_id"],
            project_path=msg["project_path"],
            checkers=msg.get("checkers", []),
            scan_name=msg.get("scan_name", ""),
            feedback_entries=msg.get("feedback_entries", []),
            checker_packages=msg.get("checker_packages", []),
        )
    elif cmd_type == "stop":
        await agent_server.handle_stop(msg["scan_id"])
    elif cmd_type == "resume":
        await agent_server.handle_resume(
            scan_id=msg["scan_id"],
            project_path=msg.get("project_path"),
            checkers=msg.get("checkers"),
            scan_name=msg.get("scan_name"),
            feedback_entries=msg.get("feedback_entries"),
            checker_packages=msg.get("checker_packages"),
        )
    elif cmd_type == "fp_review":
        await agent_server.handle_fp_review(
            scan_id=msg["scan_id"],
            review_id=msg["review_id"],
            project_path=msg["project_path"],
            vulnerabilities=msg.get("vulnerabilities", []),
            feedback_entries=msg.get("feedback_entries", []),
        )
    elif cmd_type == "feedback_selection_update":
        await agent_server.handle_feedback_selection_update(
            scan_id=msg["scan_id"],
            feedback_entries=msg.get("feedback_entries", []),
        )
    elif cmd_type == "feedback_update":
        entry = msg.get("entry")
        if entry:
            from agent.fp_reviewer import update_local_feedback
            update_local_feedback(entry)
    elif cmd_type == "config":
        from agent.config import apply_remote_config, save_config
        if msg.get("config"):
            apply_remote_config(config, msg["config"])
            try:
                save_config(config)
                print("Config updated from server and persisted to agent.yaml")
            except Exception as e:
                print(f"Config updated from server (warning: failed to persist: {e})")
    else:
        print(f"Unknown command type: {cmd_type!r}")


async def _ws_loop(config, task_manager, reporter) -> None:
    """WebSocket connection loop with automatic reconnect."""
    import websockets
    import agent.server as agent_server
    from agent.config import apply_remote_config, remote_config_dict

    name = config.agent_name or socket.gethostname()
    ws_url = config.server_url.replace("http://", "ws://").replace("https://", "wss://")
    ws_url = ws_url.rstrip("/") + "/api/agent/ws"

    reconnect_delay = 2

    while True:
        try:
            print(f"Connecting to {ws_url} ...")
            async with websockets.connect(ws_url, ping_interval=30, ping_timeout=10) as ws:
                # Handshake
                hello_msg = {
                    "type": "hello",
                    "name": name,
                    "config": remote_config_dict(config),
                    "active_scans": task_manager.active_snapshots(),
                }
                if config.owner_token:
                    hello_msg["owner_token"] = config.owner_token
                await ws.send(json.dumps(hello_msg))

                welcome_raw = await asyncio.wait_for(ws.recv(), timeout=15.0)
                welcome = json.loads(welcome_raw)

                if welcome.get("type") != "welcome":
                    print(f"Unexpected handshake response: {welcome}")
                    continue

                agent_id = welcome["agent_id"]
                agent_server._agent_id = agent_id

                if welcome.get("config"):
                    from agent.config import save_config
                    apply_remote_config(config, welcome["config"])
                    try:
                        save_config(config)
                    except Exception as e:
                        print(f"Config received from server (warning: failed to persist: {e})")

                reconnect_delay = 2  # reset backoff on successful connect
                print(f"  Connected. Agent ID: {agent_id}")
                print()

                # Message loop
                async for raw_msg in ws:
                    try:
                        msg = json.loads(raw_msg)
                        await _handle_command(msg, config, task_manager, reporter)
                    except Exception as e:
                        print(f"Error handling command: {e}")

        except Exception as e:
            print(f"Connection lost: {e}. Reconnecting in {reconnect_delay}s...")
            await asyncio.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, 60)


async def _main() -> None:
    args = _parse_args()

    # Load config
    from agent.config import load_config
    config_path = Path(args.config) if args.config else None
    config = load_config(config_path)

    # Apply CLI overrides
    if args.server:
        config.server_url = args.server
    if args.name:
        config.agent_name = args.name

    # Apply no_proxy early so httpx respects it
    if config.no_proxy:
        import os
        os.environ.setdefault("no_proxy", config.no_proxy)
        os.environ.setdefault("NO_PROXY", config.no_proxy)

    name = config.agent_name or socket.gethostname()

    print("OpenDeepHole Agent Daemon")
    print(f"  Name    : {name}")
    print(f"  Server  : {config.server_url}")
    print()

    from agent.reporter import Reporter
    from agent.task_manager import TaskManager
    import agent.server as agent_server

    reporter = Reporter(config.server_url)
    task_manager = TaskManager()

    # Inject globals into agent.server module
    agent_server._config = config
    agent_server._reporter = reporter
    agent_server._task_manager = task_manager

    try:
        await _ws_loop(config, task_manager, reporter)
    finally:
        await reporter.close()


def main() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main()
