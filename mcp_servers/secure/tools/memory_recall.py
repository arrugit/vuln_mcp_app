"""Secure ``memory.recall`` tool — MCP10 lab, SECURE variant.

Returns remembered context entries for a query. The security-relevant decision is
*whose* entries it returns: this secure variant scopes the lookup to the caller's
own session (``store.entries_for(session_token)``), so one user can never see
another user's memory. The vulnerable variant (added in Phase B) omits that scope.
"""
from __future__ import annotations

from typing import Any, Dict

from mcp_servers.common.registry import Tool, ToolRegistry

CLEAN_MEMORY_RECALL_DEFINITION: Dict[str, Any] = {
    "name": "memory.recall",
    "description": "Recall remembered context entries for the calling session.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "session_token": {"type": "string"},
            "query": {"type": "string"},
        },
        "required": ["session_token"],
    },
    "outputSchema": {
        "type": "object",
        "properties": {
            "session_token": {"type": "string"},
            "entries": {"type": "array"},
            "count": {"type": "integer"},
        },
    },
}


def clean_memory_recall(args: Dict[str, Any]) -> Dict[str, Any]:
    """Return ONLY the caller's own remembered entries (session-scoped)."""
    from labs.mcp10_context_oversharing.fixtures import get_context_store

    token = str(args.get("session_token", ""))
    # Authorization: scope strictly to the caller's session.
    entries = get_context_store().entries_for(token)
    return {"session_token": token, "entries": entries, "count": len(entries)}


def register_memory_recall(registry: ToolRegistry) -> None:
    """Register the secure memory.recall tool (idempotent-safe)."""
    if registry.has("memory.recall"):
        return
    registry.register(
        Tool(
            name="memory.recall",
            description=CLEAN_MEMORY_RECALL_DEFINITION["description"],
            input_schema=CLEAN_MEMORY_RECALL_DEFINITION["inputSchema"],
            output_schema=CLEAN_MEMORY_RECALL_DEFINITION["outputSchema"],
            handler=clean_memory_recall,
            risk="none",
            trust_status="trusted",
        )
    )
