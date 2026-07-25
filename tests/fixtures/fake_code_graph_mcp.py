"""Deterministic Streamable HTTP code-graph MCP used by integration tests.

Run manually:

    python tests/fixtures/fake_code_graph_mcp.py --port 9010 --marker scan-a
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--call-log", default="")
    return parser.parse_args()


def main() -> None:
    args = _args()
    marker = str(args.marker)
    call_log = Path(args.call_log).resolve() if args.call_log else None
    mcp = FastMCP(
        f"Fake Code Graph {marker}",
        instructions=(
            "Use static_read for deterministic source-graph lookups. "
            f"This server is bound to marker {marker}."
        ),
        host=args.host,
        port=args.port,
        stateless_http=True,
        json_response=True,
    )

    @mcp.tool()
    def static_read(query: str) -> dict[str, object]:
        """Return deterministic graph nodes for the requested symbol or path."""
        result = {
            "marker": marker,
            "query": query,
            "nodes": [
                {"id": f"{marker}:entry", "kind": "function"},
                {"id": f"{marker}:sink", "kind": "function"},
            ],
            "edges": [
                {
                    "source": f"{marker}:entry",
                    "target": f"{marker}:sink",
                    "kind": "calls",
                },
            ],
        }
        if call_log is not None:
            call_log.parent.mkdir(parents=True, exist_ok=True)
            with call_log.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(result, ensure_ascii=False) + "\n")
        return result

    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
