# INTENTIONALLY VULNERABLE — VULN-MCP10-001 — see docs/GROUND-TRUTH.md
"""Vulnerable ``memory.recall`` tool — MCP10 Context Over-Sharing (VULNERABLE).

Same feature as the secure variant: recall remembered context entries. The
difference is a single missing authorization step.

The handler takes the caller's ``session_token`` but then reads memory WITHOUT
scoping to that session:

    entries = store.all_entries()     # every session's entries — no owner filter

So a recall from Session B returns Session A's entries too, including User A's
``DEMO_SECRET_A``. This is a classic broken-access-control / IDOR mistake — the
ownership check the secure variant performs (``store.entries_for(token)``) was
simply left out. The ``session_token`` is accepted and echoed back, which makes
the omission easy to miss in review.
"""
from __future__ import annotations

from typing import Any, Dict

from mcp_servers.common.registry import Tool, ToolRegistry

# Metadata is identical in spirit to the trusted tool; the flaw is in the handler
# (a missing WHERE-owner filter), not the tool definition.
MEMORY_RECALL_DEFINITION: Dict[str, Any] = {
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


def memory_recall(args: Dict[str, Any]) -> Dict[str, Any]:
    """Recall entries — but without scoping to the caller's session."""
    from labs.mcp10_context_oversharing.fixtures import get_context_store

    token = str(args.get("session_token", ""))
    # The caller identifies itself, but the lookup never filters by owner:
    # it returns EVERY session's entries. That missing scope is the flaw.
    entries = get_context_store().all_entries()
    return {"session_token": token, "entries": entries, "count": len(entries)}


def register_vulnerable_memory_recall(registry: ToolRegistry) -> None:
    """Register the vulnerable memory.recall (vulnerable mode only)."""
    if registry.has("memory.recall"):
        registry.unregister("memory.recall")
    registry.register(
        Tool(
            name="memory.recall",
            description=MEMORY_RECALL_DEFINITION["description"],
            input_schema=MEMORY_RECALL_DEFINITION["inputSchema"],
            output_schema=MEMORY_RECALL_DEFINITION["outputSchema"],
            handler=memory_recall,
            risk="high",
            trust_status="poisoned",
        )
    )
