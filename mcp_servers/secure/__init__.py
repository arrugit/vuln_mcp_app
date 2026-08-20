"""Genuinely-fixed SECURE MCP server tree (SEC-004 / SEC-007).

Phase 0 status: baseline safe tools only.

Each lab adds its secure counterpart here in its own Phase B. SECURE mode MUST
apply the real control (metadata sanitisation/trust policy, input validation +
parameterised exec, session-scoped authorization) — never merely hide symptoms
(SEC-007). Secure-mode tests (TST-004) assert the vulnerability is *prevented*.
"""


def build_secure_registry():
    """Return a registry with the baseline safe tools only (Phase 0).

    Later phases extend this to register the lab-specific *secure* tool variants.
    """
    from ..common import build_baseline_registry

    return build_baseline_registry()
