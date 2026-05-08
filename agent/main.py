"""OpenDeepHole Agent Daemon — persistent HTTP server that receives scan tasks.

Usage:
    python -m agent.main [OPTIONS]

    --server URL          Web server URL (overrides agent.yaml server_url)
    --port INT            Agent HTTP port (overrides agent.yaml agent_port, default 7000)
    --name NAME           Agent display name (overrides agent.yaml agent_name)
    --config FILE         Path to config file (default: ./agent.yaml)

Examples:
    python -m agent.main
    python -m agent.main --server http://192.168.1.10:8000 --port 7001
    python -m agent.main --name "my-server" --config /etc/opendeephole/agent.yaml
"""

from __future__ import annotations

import argparse
import asyncio
import socket
import sys
from pathlib import Path


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="agent",
        description="OpenDeepHole agent daemon — listens for scan tasks from the web server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--server", metavar="URL", help="Web server URL (overrides agent.yaml)")
    parser.add_argument("--port", metavar="INT", type=int, help="Agent HTTP listen port (default 7000)")
    parser.add_argument("--name", metavar="NAME", help="Agent display name shown on web UI")
    parser.add_argument("--config", metavar="FILE", help="Path to agent.yaml config file")
    return parser.parse_args()


async def _heartbeat_loop(reporter, agent_id: str) -> None:
    """Send heartbeat to server every 30 seconds."""
    while True:
        await reporter.heartbeat(agent_id)
        await asyncio.sleep(30)


async def _main() -> None:
    args = _parse_args()

    # Load config
    from agent.config import load_config
    config_path = Path(args.config) if args.config else None
    config = load_config(config_path)

    # Apply CLI overrides
    if args.server:
        config.server_url = args.server
    if args.port:
        config.agent_port = args.port
    if args.name:
        config.agent_name = args.name

    # Apply no_proxy early so httpx respects it for all outbound calls (register, heartbeat, etc.)
    if config.no_proxy:
        import os
        os.environ.setdefault("no_proxy", config.no_proxy)
        os.environ.setdefault("NO_PROXY", config.no_proxy)

    port = config.agent_port
    name = config.agent_name or socket.gethostname()

    print(f"OpenDeepHole Agent Daemon")
    print(f"  Name    : {name}")
    print(f"  Server  : {config.server_url}")
    print(f"  Port    : {port}")
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

    # Register with server
    agent_id = None
    try:
        from agent.config import apply_remote_config
        agent_id, remote_cfg = await reporter.register_agent(port=port, name=name)
        print(f"  Registered as agent_id: {agent_id}")
        if remote_cfg:
            apply_remote_config(config, remote_cfg)
            print(f"  Config loaded from server")
        print()
    except Exception as e:
        print(f"Warning: failed to register with server: {e}")
        print("Agent will start but may not receive tasks from the server.")
        print()

    # Expose agent_id so server.py can use it for config refresh
    agent_server._agent_id = agent_id

    # Start heartbeat loop as background task
    heartbeat_task = None
    if agent_id:
        heartbeat_task = asyncio.create_task(_heartbeat_loop(reporter, agent_id))

    # Start uvicorn HTTP server (blocks until shutdown)
    import uvicorn
    uv_config = uvicorn.Config(
        agent_server.app,
        host="0.0.0.0",
        port=port,
        log_level="warning",
    )
    server = uvicorn.Server(uv_config)

    try:
        await server.serve()
    finally:
        if heartbeat_task:
            heartbeat_task.cancel()
        if agent_id:
            await reporter.unregister_agent(agent_id)
            print(f"\nUnregistered agent {agent_id}")
        await reporter.close()


def main() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main()
