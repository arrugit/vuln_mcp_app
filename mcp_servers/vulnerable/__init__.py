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
    """Return a registry with the baseline safe tools only (Phase 0).

    Later phases extend this to register the lab-specific vulnerable tools when
    a lab is set to VULNERABLE mode. Keeping it baseline-only here guarantees the
    foundation ships with no exploitable behaviour.
    """
    from ..common import build_baseline_registry

    return build_baseline_registry()
