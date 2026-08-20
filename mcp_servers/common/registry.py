"""Tool registry abstraction (TDD §8, §14).

This models the MCP server's tool registry in a transport-agnostic way. In
Phase 0 the backend's MCP client speaks to this registry *in-process* (a dev
transport); DECISION D-03 upgrades the wire transport to streamable HTTP in a
later phase without changing this contract.

Everything here is ordinarily secure (SEC-004):
  * tool definitions are plain data;
  * ``call`` dispatches to a registered handler;
  * unknown tools raise a clean ``KeyError`` (turned into a 4xx upstream).

No poisoned metadata, exec sink, or ownership-free lookup exists here. Those are
added only inside ``mcp_servers.vulnerable`` in the relevant lab's phase.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

# A tool handler takes the call arguments and returns a JSON-serialisable result.
ToolHandler = Callable[[Dict[str, Any]], Dict[str, Any]]


@dataclass
class Tool:
    """An MCP tool definition + its server-side handler.

    ``trust_status`` mirrors the DB ``ToolVersion.trust_status`` so the registry
    and catalog agree. In Phase 0 every registered tool is ``trusted``.
    """

    name: str
    description: str
    input_schema: Dict[str, Any]
    handler: ToolHandler
    output_schema: Dict[str, Any] = field(default_factory=dict)
    risk: str = "none"
    trust_status: str = "trusted"

    def definition(self) -> Dict[str, Any]:
        """Return the MCP-style definition surfaced by ``tools/list``."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "outputSchema": self.output_schema,
        }


@dataclass
class ToolResult:
    """Result of a ``tools/call`` — mirrors what the wire transport would carry."""

    tool: str
    result: Dict[str, Any]
    # Optional constructed command (used by MCP05 later); None for benign tools.
    constructed_command: Optional[str] = None
    # Neutral security tag for telemetry (never a verdict); None normally.
    security_event: Optional[str] = None


class ToolRegistry:
    """A small, careful in-memory registry of MCP tools."""

    def __init__(self) -> None:
        self._tools: Dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def has(self, name: str) -> bool:
        return name in self._tools

    def get(self, name: str) -> Tool:
        return self._tools[name]

    def list_definitions(self) -> list[Dict[str, Any]]:
        """Back the MCP ``tools/list`` call — returns every tool definition."""
        return [t.definition() for t in self._tools.values()]

    def names(self) -> list[str]:
        return list(self._tools.keys())

    def call(self, name: str, args: Dict[str, Any]) -> ToolResult:
        """Dispatch a ``tools/call`` to the registered handler.

        Raises ``KeyError`` for unknown tools; the API layer maps that to a 404.
        """
        tool = self._tools[name]  # KeyError -> handled upstream
        payload = tool.handler(args or {})
        return ToolResult(tool=name, result=payload)


def build_baseline_registry() -> ToolRegistry:
    """Construct a registry containing only the always-safe legit tools.

    Imported lazily to avoid a circular import at module load time.
    """
    from .tools_legit import register_legit_tools

    registry = ToolRegistry()
    register_legit_tools(registry)
    return registry
