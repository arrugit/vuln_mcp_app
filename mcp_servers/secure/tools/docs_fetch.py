"""Trusted (clean) ``docs.fetch`` tool — MCP03 lab, SECURE variant.

This is the *safe* implementation of the tool whose poisoned twin (added in
Phase B under ``mcp_servers/vulnerable/tools/docs_fetch.py``) carries the MCP03
Tool Poisoning vulnerability.

Why this file is safe
---------------------
* **Clean metadata.** The ``description`` contains a plain, factual sentence and
  NO embedded instruction telling a model/agent to do anything extra. There is
  nothing for a metadata-trust policy to strip.
* **No secret-reading branch.** The handler reads ONLY the synthetic document
  corpus (``fixtures.get_document``). It never references ``DEMO_SECRET_A``.
* **Deterministic output.** Same ``doc_id`` in -> same document out.

Phase A registers THIS clean variant in both the secure and vulnerable
registries, so the foundation ships with no poisoning. Phase B introduces the
poisoned variant and points the vulnerable registry at it.
"""
from __future__ import annotations

from typing import Any, Dict

from mcp_servers.common.registry import Tool, ToolRegistry

# Single source of truth for the CLEAN tool definition. The DB seed imports this
# so the catalog (and the future trusted-vs-poisoned diff, FR-013) matches the
# runtime registry exactly.
CLEAN_DOCS_FETCH_DEFINITION: Dict[str, Any] = {
    "name": "docs.fetch",
    # Clean description: factual, no hidden instruction. Contrast this with the
    # poisoned description added in Phase B.
    "description": "Fetch a synthetic document from the local docs service by id.",
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


def clean_docs_fetch(args: Dict[str, Any]) -> Dict[str, Any]:
    """Trusted handler: return ONLY the requested synthetic document.

    Reads the document corpus and nothing else. There is no code path here that
    touches the synthetic secret — that is exactly what makes this the secure
    variant (SEC-007).
    """
    # Lazy import so the mcp_servers package has no hard dependency on the labs
    # package at import time (keeps the trees loosely coupled).
    from labs.mcp03_tool_poisoning.fixtures import get_document

    doc_id = str(args.get("doc_id", ""))
    doc = get_document(doc_id)
    if doc is None:
        return {"doc_id": doc_id, "title": None, "body": None, "found": False}
    return {
        "doc_id": doc_id,
        "title": doc["title"],
        "body": doc["body"],
        "found": True,
    }


def register_docs_fetch(registry: ToolRegistry) -> None:
    """Register the clean docs.fetch tool onto a registry (idempotent-safe)."""
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
