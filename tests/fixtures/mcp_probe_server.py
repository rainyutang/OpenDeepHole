"""Minimal JSON-RPC stdio MCP used by the MCP probe integration test."""

import json
import os
import sys


def _reply(request_id, result) -> None:
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        _reply(message["id"], {
            "protocolVersion": message["params"]["protocolVersion"],
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "probe-test", "version": "1"},
        })
    elif method == "tools/list":
        _reply(message["id"], {"tools": [{
            "name": os.environ.get("PROBE_TOOL_NAME", "missing_environment"),
            "description": "A tool that is discovered but never called",
            "inputSchema": {"type": "object", "properties": {}},
        }]})
