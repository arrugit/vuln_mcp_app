"""Per-lab attack orchestrators + a slug-based dispatcher.

Each lab gets one orchestrator that reproduces its vulnerability deterministically
(FR-020) and records telemetry + evidence. The dispatcher maps a lab's ``slug``
to its orchestrator so the generic ``POST /api/labs/{id}/attack`` endpoint can
drive any lab.

Phase status
------------
* MCP03 -> :func:`mcp03_service.run_attack` (Phase A: clean flow, no leak yet).
* MCP05 / MCP10 -> not implemented; the dispatcher returns a clear stub so the
  API contract stays stable until those labs are built.
"""
from __future__ import annotations

from typing import Any, Callable, Dict

from sqlmodel import Session

from ...models import Lab
from . import mcp03_service, mcp05_service

# slug -> orchestrator(session, lab, params) -> result dict
_DISPATCH: Dict[str, Callable[[Session, Lab, Dict[str, Any]], Dict[str, Any]]] = {
    "mcp03-tool-poisoning": mcp03_service.run_attack,
    "mcp05-command-injection": mcp05_service.run_attack,
}


def run_lab_attack(
    session: Session, lab: Lab, params: Dict[str, Any]
) -> Dict[str, Any]:
    """Dispatch an attack run to the lab's orchestrator (or a stub)."""
    orchestrator = _DISPATCH.get(lab.slug)
    if orchestrator is None:
        return {
            "implemented": False,
            "note": f"attack orchestration for {lab.slug} is not implemented yet",
        }
    return orchestrator(session, lab, params)


__all__ = ["run_lab_attack", "mcp03_service", "mcp05_service"]
