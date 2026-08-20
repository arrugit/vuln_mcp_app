"""MCP bridge service (TDD §7 / §8).

Wraps the MCP client for the API layer: lists servers/tools from the DB catalog,
exposes tool detail (including trusted-vs-poisoned versions for the MCP03 diff,
FR-013), and performs tool calls through the client while recording telemetry.

Infrastructure only (SEC-004). Phase 0 registers just the legit tools, so calls
here are benign in every mode.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from sqlmodel import Session, select

from ..mcp_client import MCPClient
from ..models import MCPServer, MCPTool, ToolVersion
from .telemetry_service import TelemetryService


class MCPService:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._telemetry = TelemetryService(session)

    # --- catalog reads ---------------------------------------------------
    def list_servers(self) -> list[MCPServer]:
        return list(self._session.exec(select(MCPServer)))

    def list_tools(self, server_id: Optional[int] = None) -> list[MCPTool]:
        stmt = select(MCPTool)
        if server_id is not None:
            stmt = stmt.where(MCPTool.server_id == server_id)
        return list(self._session.exec(stmt))

    def get_tool(self, tool_id: int) -> Optional[MCPTool]:
        return self._session.get(MCPTool, tool_id)

    def get_tool_versions(self, tool_id: int) -> list[ToolVersion]:
        """Return all stored versions (trusted + poisoned) for the MCP03 diff."""
        stmt = (
            select(ToolVersion)
            .where(ToolVersion.tool_id == tool_id)
            .order_by(ToolVersion.version)
        )
        return list(self._session.exec(stmt))

    def get_tool_by_name(self, name: str) -> Optional[MCPTool]:
        return self._session.exec(select(MCPTool).where(MCPTool.name == name)).first()

    # --- live MCP calls --------------------------------------------------
    def call_tool_by_id(
        self,
        tool_id: int,
        args: Dict[str, Any],
        *,
        mode: str,
        lab_run_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Invoke a catalogued tool through the MCP client.

        Raises ``KeyError`` for an unknown tool id / name (API maps to 404).
        """
        tool = self._session.get(MCPTool, tool_id)
        if tool is None:
            raise KeyError(tool_id)
        client = MCPClient(mode=mode, telemetry=self._telemetry)
        return client.call_tool(tool.name, args, lab_run_id=lab_run_id)

    @staticmethod
    def parse_json_field(value: str) -> Any:
        """Best-effort parse of a stored JSON string column for API responses."""
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value
