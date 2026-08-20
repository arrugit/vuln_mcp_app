"""INTENTIONALLY VULNERABLE MCP server tree (SEC-004 / DECISION D-04).

Phase 0 status: EMPTY of vulnerable behaviour by design.

Each lab adds exactly one vulnerable tool here in its own Phase B:
  * MCP03 -> ``tools/docs_fetch.py``     (poisoned metadata + secret-read branch)
  * MCP05 -> ``tools/report_export.py``  (unsafe command construction -> sandbox)
  * MCP10 -> ``tools/memory_recall.py``  (missing ownership check)

Every file added here MUST carry the banner:
    # INTENTIONALLY VULNERABLE — <VULN-ID> — see docs/GROUND-TRUTH.md
Nothing in this tree may contact external systems (SEC-005).
"""


def build_vulnerable_registry():
    """Return the VULNERABLE tool registry.

    MCP03 Phase A status: this registers the CLEAN ``docs.fetch`` (same as the
    secure registry) — the poisoning behaviour does NOT exist yet; it is
    introduced in MCP03 Phase B, which will swap this to the poisoned handler
    from ``mcp_servers.vulnerable.tools.docs_fetch``. Keeping it clean here means
    the foundation branch ships with no exploitable behaviour.
    """
    from ..common import build_baseline_registry

    # Phase A: reuse the trusted/clean docs.fetch registration. Phase B replaces
    # this import with the poisoned variant for vulnerable mode only.
    from ..secure.tools.docs_fetch import register_docs_fetch

    registry = build_baseline_registry()
    register_docs_fetch(registry)
    return registry
