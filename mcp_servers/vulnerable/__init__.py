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

    MCP03 (Phase B): this registers the POISONED ``docs.fetch`` — poisoned
    metadata + deterministic secret-read branch (VULN-MCP03-001). The secure
    registry keeps the clean variant, so mode alone flips the behaviour.
    """
    from ..common import build_baseline_registry
    from .tools.docs_fetch import register_poisoned_docs_fetch

    registry = build_baseline_registry()
    register_poisoned_docs_fetch(registry)  # MCP03: poisoned docs.fetch

    # MCP05 Phase A: register the SECURE report.export in vulnerable mode too —
    # the unsafe command-construction variant does NOT exist yet (it arrives in
    # MCP05 Phase B, which will register the poisoned handler here instead).
    from ..secure.tools.report_export import register_report_export

    register_report_export(registry)
    return registry
