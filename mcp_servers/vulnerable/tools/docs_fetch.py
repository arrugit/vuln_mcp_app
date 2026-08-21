# INTENTIONALLY VULNERABLE — VULN-MCP03-001 — see docs/GROUND-TRUTH.md
"""Vulnerable ``docs.fetch`` tool — MCP03 lab (VULNERABLE variant).

Same feature as the secure variant: fetch a help article and render its
``{{ ... }}`` placeholders. The difference is a single, easy-to-miss wiring
mistake in how the render context is built.

The developer wanted articles to be able to show dynamic values, so they passed
"the config" straight into the template context:

    context = {"config": APP_CONFIG}     # whole config in scope

``APP_CONFIG`` also contains the integration credential (``api_key``). Nothing
here reads the secret on purpose — but because the *entire* config is reachable
from templates, any article body that contains ``{{ config.api_key }}`` (an
internal doc that shipped with exactly that placeholder, or a document a user
adds) renders the credential into the returned article. This is an over-broad
template context — a common, accidental information-disclosure bug. The secure
variant fixes it by allow-listing which config keys templates can see.
"""
from __future__ import annotations

from typing import Any, Dict

from mcp_servers.common.registry import Tool, ToolRegistry

# The stored definition is deliberately identical in spirit to the trusted one:
# the metadata looks fine; the flaw is in the handler wiring, not the docs.
DOCS_FETCH_DEFINITION: Dict[str, Any] = {
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


def docs_fetch(args: Dict[str, Any]) -> Dict[str, Any]:
    """Fetch + render a document — but with the full config in template scope."""
    from labs.mcp03_tool_poisoning.fixtures import APP_CONFIG, get_store
    from labs.mcp03_tool_poisoning.templating import render

    doc_id = str(args.get("doc_id", ""))
    doc = get_store().get(doc_id)
    if doc is None:
        return {"doc_id": doc_id, "title": None, "body": None, "found": False}

    # The bug: the ENTIRE app config (credential included) is exposed to the
    # template renderer. A body containing {{ config.api_key }} will resolve it.
    render_context = {"config": APP_CONFIG}
    return {
        "doc_id": doc_id,
        "title": doc.title,
        "body": render(doc.body, render_context),
        "found": True,
    }


def register_poisoned_docs_fetch(registry: ToolRegistry) -> None:
    """Register the vulnerable docs.fetch (vulnerable mode only)."""
    if registry.has("docs.fetch"):
        registry.unregister("docs.fetch")
    registry.register(
        Tool(
            name="docs.fetch",
            description=DOCS_FETCH_DEFINITION["description"],
            input_schema=DOCS_FETCH_DEFINITION["inputSchema"],
            output_schema=DOCS_FETCH_DEFINITION["outputSchema"],
            handler=docs_fetch,
            risk="high",
            trust_status="poisoned",
        )
    )
