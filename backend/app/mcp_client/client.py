"""MCP client wrapper (TDD §7 / §8).

Responsibilities
----------------
* perform ``tools/list`` and ``tools/call`` against the MCP server;
* record every request/response into telemetry (FR-014).

Phase 0 transport
-----------------
DECISION D-03 targets streamable HTTP for the wire. During the foundation the
client talks to the tool registry *in-process* (a dev transport) so the whole
control plane is testable without a running container. The public method shape
(``list_tools`` / ``call_tool``) is transport-agnostic, so swapping to the SDK
HTTP client later does not ripple into the services/API.

This client is infrastructure (SEC-004). It selects the vulnerable or secure
registry purely by the requested ``mode`` — in Phase 0 both registries contain
only the always-safe legit tools, so no mode is exploitable yet.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:
    # Type-only import. Importing the services package at runtime here would form
    # a cycle (services -> mcp_service -> mcp_client). With `from __future__ import
    # annotations`, the annotation below is a string, so no runtime import is
    # needed — the caller passes a TelemetryService instance we just duck-type.
    from ..services.telemetry_service import TelemetryService

# Import the two server builders. They live in the physically separate
# vulnerable/ and secure/ trees (D-04); Phase 0 both return baseline-safe tools.
from mcp_servers.common import ToolRegistry
from mcp_servers.vulnerable import build_vulnerable_registry
from mcp_servers.secure import build_secure_registry


def registry_for_mode(mode: str) -> ToolRegistry:
    """Return the tool registry for a behaviour mode.

    ``"vulnerable"`` -> vulnerable tree; anything else -> secure tree. In Phase 0
    both trees are baseline-safe, so this is a clean seam for later phases.
    """
    if mode == "vulnerable":
        return build_vulnerable_registry()
    return build_secure_registry()


class MCPClient:
    """Transport-agnostic MCP client used by the control plane."""

    def __init__(
        self,
        mode: str = "secure",
        telemetry: Optional[TelemetryService] = None,
    ) -> None:
        self._mode = mode
        self._registry = registry_for_mode(mode)
        self._telemetry = telemetry

    @property
    def mode(self) -> str:
        return self._mode

    def list_tools(self, lab_run_id: Optional[int] = None) -> list[Dict[str, Any]]:
        """MCP ``tools/list`` — returns tool definitions, recording telemetry."""
        if self._telemetry is not None:
            self._telemetry.record(
                direction="client->server",
                method="tools/list",
                payload={},
                lab_run_id=lab_run_id,
                mode=self._mode,
            )
        definitions = self._registry.list_definitions()
        if self._telemetry is not None:
            self._telemetry.record(
                direction="server->client",
                method="tools/list",
                payload={"tools": definitions},
                lab_run_id=lab_run_id,
                mode=self._mode,
            )
        return definitions

    def call_tool(
        self,
        name: str,
        args: Dict[str, Any],
        lab_run_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """MCP ``tools/call`` — dispatches to the server and records telemetry.

        Raises ``KeyError`` if the tool is unknown (API maps to 404).
        """
        if self._telemetry is not None:
            self._telemetry.record(
                direction="client->server",
                method="tools/call",
                payload={"name": name, "arguments": args},
                lab_run_id=lab_run_id,
                mode=self._mode,
            )
        result = self._registry.call(name, args)
        if self._telemetry is not None:
            self._telemetry.record(
                direction="server->client",
                method="tools/call",
                payload={"name": name, "result": result.result},
                lab_run_id=lab_run_id,
                mode=self._mode,
                security_event=result.security_event,
            )
        return {
            "name": result.tool,
            "result": result.result,
            "constructed_command": result.constructed_command,
        }
