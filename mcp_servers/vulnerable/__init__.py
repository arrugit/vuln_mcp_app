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

    # MCP05 (Phase B): register the UNSAFE report.export (shell concatenation).
    from .tools.report_export import register_unsafe_report_export

    register_unsafe_report_export(registry)

    # MCP10 Phase A: register the SECURE memory.recall in vulnerable mode too —
    # the missing-ownership-check variant arrives in MCP10 Phase B, which will
    # register the vulnerable handler here instead.
    from ..secure.tools.memory_recall import register_memory_recall

    register_memory_recall(registry)
    return registry
