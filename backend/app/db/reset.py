"""Reset mechanism (TDD §24 / RST-001..004).

Reset restores the known baseline so experiments are repeatable and post-reset
re-runs reproduce identical evidence (NFR-002, TST-005). It is idempotent and
safe to run repeatedly (RST-002).

Phase 0 provides the *global* reset scaffolding (clear runtime tables +
re-seed). Per-lab reset hooks (flip MCP03 active version, wipe sandbox /work,
re-seed synthetic sessions) are layered on in each lab's phases — the ordering
here is already the one TDD §24 prescribes.
"""
from __future__ import annotations

from sqlmodel import Session, delete

from ..models import (
    ContextEntry,
    Context,
    Evidence,
    LabRun,
    Session as SessionRow,
    TelemetryEvent,
    ToolCall,
)
from .seed import seed_baseline

# Runtime tables that accumulate per-run state and must be cleared on reset.
# Order matters: children before parents to respect foreign keys.
_RUNTIME_TABLES_IN_ORDER = [
    Evidence,
    TelemetryEvent,
    ToolCall,
    LabRun,
    ContextEntry,
    Context,
    SessionRow,
]


def clear_runtime_state(session: Session) -> None:
    """Delete all per-run/telemetry/evidence/context rows (transactional)."""
    for model in _RUNTIME_TABLES_IN_ORDER:
        session.exec(delete(model))
    session.commit()


def reset_database(session: Session) -> None:
    """Full baseline reset: clear runtime state, then re-seed the catalog.

    Returns nothing; callers observe success by the absence of an exception and
    by re-reading the now-baseline tables. This deliberately emits NO verdict
    (SEC-006).
    """
    clear_runtime_state(session)
    # Re-seed is idempotent: catalog rows persist, only runtime state was wiped.
    seed_baseline(session)
