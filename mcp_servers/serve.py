"""MCP server-plane entrypoint (Phase 0 foundation).

Purpose
-------
Gives the ``mcp-server`` Docker service a real, runnable process and a health
surface, so the Compose topology (TDD §27/§28) is complete from the foundation.

Phase 0 transport note
----------------------
DECISION D-03 selects streamable HTTP (official MCP SDK) for the production wire
transport; that is wired in a later phase. To keep the foundation dependency-light
and container-buildable *today*, this entrypoint exposes the baseline tool
registry over a tiny stdlib HTTP surface:

  * ``GET /health``      -> {"status": "online", "mode": <mode>}
  * ``GET /tools/list``  -> the baseline tool definitions (always-safe tools)

It performs NO tool execution over the wire in Phase 0 (the backend calls tools
in-process). No vulnerable behaviour is present here (SEC-004). The mode is read
from ``MCP_MODE`` but both modes are baseline-safe until later phases add tools.
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mcp_servers.common import build_baseline_registry

_MODE = os.environ.get("MCP_MODE", "secure")
_registry = build_baseline_registry()


class _Handler(BaseHTTPRequestHandler):
    """Minimal read-only surface describing the MCP server plane."""

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        if self.path == "/health":
            self._send(200, {"status": "online", "mode": _MODE})
        elif self.path == "/tools/list":
            self._send(200, {"tools": _registry.list_definitions()})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, *args) -> None:  # keep container logs quiet
        return


def main() -> None:
    host = os.environ.get("MCP_BIND_HOST", "0.0.0.0")
    port = int(os.environ.get("MCP_BIND_PORT", "9000"))
    server = ThreadingHTTPServer((host, port), _Handler)
    print(f"[mcp-server] listening on {host}:{port} mode={_MODE}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
