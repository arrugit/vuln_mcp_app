"""Secure ``docs.fetch`` tool — MCP03 lab, SECURE variant.

The docs service renders help articles that may contain ``{{ ... }}`` template
placeholders. The security-relevant decision is *what the renderer can see*.

This secure variant builds the template context from an **allow-listed subset of
the config** (``PUBLIC_CONFIG_KEYS``) — display values only, never the
credential. So a document that references ``{{ config.api_key }}`` finds nothing
to resolve and the placeholder is left inert. Least authority by construction.
"""
from __future__ import annotations

from typing import Any, Dict

from mcp_servers.common.registry import Tool, ToolRegistry

CLEAN_DOCS_FETCH_DEFINITION: Dict[str, Any] = {
    "name": "docs.fetch",
    "description": (
        "Fetch a help article by id. Article bodies may use {{ config.<key> }} "
        "placeholders for dynamic values (app name, support email, version)."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {"doc_id": {"type": "string"}},
        "required": ["doc_id"],
    },
    "outputSchema": {
        "type": "object",
        "properties": {
            "doc_id": {"type": "string"},
            "title": {"type": "string"},
            "body": {"type": "string"},
            "found": {"type": "boolean"},
        },
    },
}


def _safe_context() -> Dict[str, Any]:
    """Template context limited to publicly-safe config values (allow-list)."""
    from labs.mcp03_tool_poisoning.fixtures import APP_CONFIG, PUBLIC_CONFIG_KEYS

    return {"config": {k: APP_CONFIG[k] for k in PUBLIC_CONFIG_KEYS}}


def clean_docs_fetch(args: Dict[str, Any]) -> Dict[str, Any]:
    """Fetch + render a document with a minimal, secret-free template context."""
    from labs.mcp03_tool_poisoning.fixtures import get_store
    from labs.mcp03_tool_poisoning.templating import render

    doc_id = str(args.get("doc_id", ""))
    doc = get_store().get(doc_id)
    if doc is None:
        return {"doc_id": doc_id, "title": None, "body": None, "found": False}
    return {
        "doc_id": doc_id,
        "title": doc.title,
        "body": render(doc.body, _safe_context()),  # narrow context => no secret
        "found": True,
    }


def register_docs_fetch(registry: ToolRegistry) -> None:
    """Register the secure docs.fetch tool (idempotent-safe)."""
    if registry.has("docs.fetch"):
        return
    registry.register(
        Tool(
            name="docs.fetch",
            description=CLEAN_DOCS_FETCH_DEFINITION["description"],
            input_schema=CLEAN_DOCS_FETCH_DEFINITION["inputSchema"],
            output_schema=CLEAN_DOCS_FETCH_DEFINITION["outputSchema"],
            handler=clean_docs_fetch,
            risk="none",
            trust_status="trusted",
        )
    )
