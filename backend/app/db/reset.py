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

from sqlmodel import Session, delete, select

from ..models import (
    ContextEntry,
    Context,
    Evidence,
    Lab,
    LabRun,
    MCPTool,
    Session as SessionRow,
    TelemetryEvent,
    ToolCall,
    ToolVersion,
)
from .seed import BASELINE_MODES, seed_baseline

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


def sync_docs_fetch_active_version(session: Session, mode: str) -> None:
    """Flip which stored ``docs.fetch`` version is active to match ``mode``.

    Vulnerable -> ``poisoned`` active; secure -> ``trusted`` active. This keeps
    the tool viewer's diff honest about what is currently served (TDD §14). It is
    display metadata only; actual behaviour is decided by the per-mode registry.
    """
    tool = session.exec(select(MCPTool).where(MCPTool.name == "docs.fetch")).first()
    if tool is None:
        return
    versions = session.exec(
        select(ToolVersion).where(ToolVersion.tool_id == tool.id)
    ).all()
    want = "poisoned" if mode == "vulnerable" else "trusted"
    active_id = None
    for version in versions:
        version.is_active = version.trust_status == want
        session.add(version)
        if version.is_active:
            active_id = version.id
    if active_id is not None:
        tool.current_version_id = active_id
        session.add(tool)
    session.commit()


def apply_baseline_modes(session: Session) -> None:
    """Restore every lab's mode to its documented baseline (RST-001).

    Because ``seed_baseline`` only *creates* missing rows, an existing lab whose
    mode was toggled would not be restored by re-seeding alone. Reset therefore
    explicitly re-applies the baseline and re-syncs the active tool version.
    """
    labs = session.exec(select(Lab)).all()
    for lab in labs:
        baseline = BASELINE_MODES.get(lab.slug, "secure")
        lab.mode = baseline
        session.add(lab)
    session.commit()
    # MCP03 baseline drives the active docs.fetch version.
    sync_docs_fetch_active_version(
        session, BASELINE_MODES.get("mcp03-tool-poisoning", "secure")
    )


def reset_database(session: Session) -> None:
    """Full baseline reset: clear runtime state, re-seed, restore baseline modes.

    Returns nothing; callers observe success by the absence of an exception and
    by re-reading the now-baseline tables. This deliberately emits NO verdict
    (SEC-006). Idempotent (RST-002); post-reset re-runs reproduce identical
    evidence (NFR-002).
    """
    clear_runtime_state(session)
    # Re-seed is idempotent: catalog rows persist, only runtime state was wiped.
    seed_baseline(session)
    # Restore toggled modes + active tool version to the documented baseline.
    apply_baseline_modes(session)
