"""In-backend MCP client (TDD §7 mcp_client, §8)."""
from .client import MCPClient, registry_for_mode

__all__ = ["MCPClient", "registry_for_mode"]
