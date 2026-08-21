"""MCP10 Context Over-Sharing — attack orchestrator.

Drives the full lab path:

    Frontend -> Backend -> MCP Client -> MCP Server (registry) -> memory.recall
              -> Context Store -> Evidence + Telemetry

Phase A behaviour (NO vulnerability yet)
----------------------------------------
It performs the exact exploit call shape — ``memory.recall`` as Session B — but
Phase A registers only the SECURE (session-scoped) recall, so Session B gets only
its own entries and no foreign secret appears. Evidence records ``context_recall``.

Phase B registers the vulnerable variant; the SAME orchestrator then observes
Session A's ``DEMO_SECRET_A`` in Session B's result and records ``context_leak``.
"""
from __future__ import annotations

from typing import Any, Dict

from sqlmodel import Session

from ...mcp_client import MCPClient
from ...models import Lab
from ..evidence_service import EvidenceService
from ..lab_service import LabService
from ..telemetry_service import TelemetryService

from labs.mcp10_context_oversharing.fixtures import (
    DEMO_SECRET_A,
    SESSION_B_TOKEN,
)


def run_attack(session: Session, lab: Lab, params: Dict[str, Any]) -> Dict[str, Any]:
    """Run the MCP10 attack simulation as the caller session (default: B)."""
    caller = str(params.get("session_token") or SESSION_B_TOKEN)
    query = str(params.get("query") or "what do you remember?")

    labs = LabService(session)
    telemetry = TelemetryService(session)
    evidence = EvidenceService(session)
    run = labs.start_run(lab.id, trigger=f"memory.recall session={caller}")

    client = MCPClient(mode=lab.mode, telemetry=telemetry)
    client.list_tools(lab_run_id=run.id)
    call = client.call_tool(
        "memory.recall", {"session_token": caller, "query": query}, lab_run_id=run.id
    )
    result = call["result"]
    entries = result.get("entries", [])

    # A leak = any returned entry owned by a DIFFERENT session than the caller.
    foreign = [e for e in entries if e.get("session_token") != caller]
    leaked = len(foreign) > 0

    if leaked:
        kind = "context_leak"
        observable = "foreign session data returned"
    else:
        kind = "context_recall"
        observable = "only caller's own entries returned"

    evidence.record(
        lab_run_id=run.id,
        kind=kind,
        observable=observable,
        raw_signal={
            "caller_session": caller,
            "returned_count": len(entries),
            "foreign_entries": foreign,
        },
    )

    if leaked:
        telemetry.record(
            direction="server->client",
            method="tools/call",
            payload={"name": "memory.recall", "signal": "foreign session data returned"},
            lab_run_id=run.id,
            mode=lab.mode,
            security_event="context_leak",
        )

    return {
        "lab_run_id": run.id,
        "mode": lab.mode,
        "tool_call": {"name": "memory.recall", "args": {"session_token": caller, "query": query}},
        "result": result,
        "leaked_from_other_session": leaked,
        "contains_foreign_secret": DEMO_SECRET_A in str(entries),
        "evidence_ref": f"/api/evidence?lab_run_id={run.id}",
        "telemetry_ref": f"/api/labs/{lab.id}/telemetry?lab_run_id={run.id}",
    }
