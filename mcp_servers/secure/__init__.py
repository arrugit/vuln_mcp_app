"""Genuinely-fixed SECURE MCP server tree (SEC-004 / SEC-007).

Phase 0 status: baseline safe tools only.

Each lab adds its secure counterpart here in its own Phase B. SECURE mode MUST
apply the real control (metadata sanitisation/trust policy, input validation +
parameterised exec, session-scoped authorization) — never merely hide symptoms
(SEC-007). Secure-mode tests (TST-004) assert the vulnerability is *prevented*.
"""


def build_secure_registry():
    """Return the SECURE tool registry.

    Baseline safe tools + the lab-specific *secure* tool variants implemented so
    far. MCP03 (Phase A) adds the clean ``docs.fetch``. This registry must never
    contain a poisoned tool (SEC-007).
    """
    from ..common import build_baseline_registry
    from .tools.docs_fetch import register_docs_fetch

    registry = build_baseline_registry()
    register_docs_fetch(registry)  # MCP03: trusted/clean docs.fetch
    return registry
