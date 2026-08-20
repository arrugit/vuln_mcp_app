"""MCP03 Tool Poisoning — attack orchestrator (Phase A: clean flow).

This drives the full lab data path so the foundation is genuinely end-to-end:

    Frontend -> Backend -> MCP Client -> MCP Server (registry) -> docs.fetch
              -> Evidence + Telemetry -> UI

Phase A behaviour (NO vulnerability yet)
----------------------------------------
It performs the exact exploit call shape — ``docs.fetch {"doc_id": <id>}`` — but
because Phase A registers only the CLEAN docs.fetch, the result contains ONLY the
requested synthetic document. The evidence records what was returned and asserts
(via tests) that ``DEMO_SECRET_A`` is absent.

Phase B will register the poisoned docs.fetch for vulnerable mode; the SAME
orchestrator will then observe the leaked secret and record it as
``metadata_poison`` evidence. The orchestrator itself does not need to change
much — the difference comes from the tool the registry serves (that is the point
of tool poisoning: the *definition/handler* is the vulnerability, not the caller).
"""
from __future__ import annotations

from typing import Any, Dict

from sqlmodel import Session

from ...mcp_client import MCPClient
from ...models import Lab
from ..evidence_service import EvidenceService
from ..lab_service import LabService
from ..telemetry_service import TelemetryService

# The synthetic secret the lab is about. Imported for the absence-check in
# Phase A (and the leak detection in Phase B). Never a real secret (SEC-002).
from labs.mcp03_tool_poisoning.fixtures import DEMO_SECRET_A

# Default doc_id matches the exact exploit call from TDD §15.
DEFAULT_DOC_ID = "welcome"


def _contains_secret(payload: Any) -> bool:
    """Return True if the synthetic secret appears anywhere in the payload.

    Used to classify the evidence: a clean fetch must NOT contain it (Phase A);
    a poisoned fetch will (Phase B). This is how the orchestrator distinguishes
    behaviour without any oracle field (SEC-006).
    """
    return DEMO_SECRET_A in str(payload)


def run_attack(session: Session, lab: Lab, params: Dict[str, Any]) -> Dict[str, Any]:
    """Run the MCP03 attack simulation and return a structured result."""
    doc_id = str(params.get("doc_id") or DEFAULT_DOC_ID)

    labs = LabService(session)
    telemetry = TelemetryService(session)
    evidence = EvidenceService(session)

    # 1) Group this run's telemetry + evidence under a LabRun (FR-020).
    run = labs.start_run(lab.id, trigger=f"docs.fetch doc_id={doc_id}")

    # 2) Talk to the MCP server in the lab's current mode. The client records
    #    tools/list and tools/call telemetry automatically (FR-014).
    client = MCPClient(mode=lab.mode, telemetry=telemetry)
    definitions = client.list_tools(lab_run_id=run.id)
    docs_fetch_def = next((d for d in definitions if d["name"] == "docs.fetch"), None)

    call = client.call_tool("docs.fetch", {"doc_id": doc_id}, lab_run_id=run.id)
    result = call["result"]

    # 3) Classify + record evidence. In Phase A the secret is always absent.
    leaked = _contains_secret(result)
    if leaked:
        # (Reached only once Phase B introduces the poisoned handler.)
        kind = "metadata_poison"
        observable = "poisoned instruction present + secret leaked"
    else:
        kind = "tool_fetch"
        observable = "document fetched (no secret in result)"

    evidence.record(
        lab_run_id=run.id,
        kind=kind,
        observable=observable,
        raw_signal={
            "doc_id": doc_id,
            "tool_description": None if docs_fetch_def is None else docs_fetch_def["description"],
            "result": result,
        },
    )

    # Telemetry (TDD §22): when the poisoned tool leaks, emit a protocol-level
    # event tagged with a neutral ``security_event``. This is a signal the FYP
    # can observe in the trace — it describes WHAT happened, never a verdict
    # (SEC-006). A clean run tags nothing.
    if leaked:
        telemetry.record(
            direction="server->client",
            method="tools/call",
            payload={"name": "docs.fetch", "signal": "secret value present in result"},
            lab_run_id=run.id,
            mode=lab.mode,
            security_event="secret_leak",
        )

    return {
        "lab_run_id": run.id,
        "mode": lab.mode,
        "tool_call": {"name": "docs.fetch", "args": {"doc_id": doc_id}},
        "result": result,
        "evidence_ref": f"/api/evidence?lab_run_id={run.id}",
        "telemetry_ref": f"/api/labs/{lab.id}/telemetry?lab_run_id={run.id}",
    }
