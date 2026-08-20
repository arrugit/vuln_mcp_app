"""MCP05 Command Injection — attack orchestrator.

Drives the full lab path:

    Frontend -> Backend -> MCP Client -> MCP Server (registry) -> report.export
              -> Sandbox (constrained subprocess runner) -> Evidence + Telemetry

Phase A behaviour (NO vulnerability yet)
----------------------------------------
It performs the exact exploit call shape — ``report.export {"filename": <payload>}``
— but Phase A registers only the SECURE report.export (validate + argv), so the
injection payload is rejected/inert and the ``/work/marker`` side effect never
occurs. Evidence records ``command_exec`` with ``marker_present=False``.

Phase B registers the unsafe variant for vulnerable mode; the SAME orchestrator
will then observe ``marker_present=True`` and record ``command_injection``.
"""
from __future__ import annotations

from typing import Any, Dict

from sqlmodel import Session

from ...mcp_client import MCPClient
from ...models import Lab
from ..evidence_service import EvidenceService
from ..lab_service import LabService
from ..telemetry_service import TelemetryService

# The documented payload is the default trigger (FR-051a).
from labs.mcp05_command_injection.fixtures import INJECTION_PAYLOAD


def run_attack(session: Session, lab: Lab, params: Dict[str, Any]) -> Dict[str, Any]:
    """Run the MCP05 attack simulation and return a structured result."""
    filename = str(params.get("filename") or INJECTION_PAYLOAD)

    labs = LabService(session)
    telemetry = TelemetryService(session)
    evidence = EvidenceService(session)

    run = labs.start_run(lab.id, trigger=f"report.export filename={filename}")

    client = MCPClient(mode=lab.mode, telemetry=telemetry)
    client.list_tools(lab_run_id=run.id)
    call = client.call_tool("report.export", {"filename": filename}, lab_run_id=run.id)
    result = call["result"]

    marker_present = bool(result.get("marker_present"))
    if marker_present:
        # (Reached only once Phase B introduces the unsafe shell path.)
        kind = "command_injection"
        observable = "extra command executed (marker created in /work)"
    else:
        kind = "command_exec"
        observable = "no injection (marker absent)"

    evidence.record(
        lab_run_id=run.id,
        kind=kind,
        observable=observable,
        raw_signal={
            "filename": filename,
            "constructed_command": result.get("constructed_command"),
            "marker_present": marker_present,
            "rejected": result.get("rejected", False),
            "stdout": result.get("stdout", ""),
        },
    )

    if marker_present:
        telemetry.record(
            direction="server->client",
            method="tools/call",
            payload={"name": "report.export", "signal": "sandbox marker created"},
            lab_run_id=run.id,
            mode=lab.mode,
            security_event="command_injection",
        )

    return {
        "lab_run_id": run.id,
        "mode": lab.mode,
        "tool_call": {"name": "report.export", "args": {"filename": filename}},
        "result": result,
        "evidence_ref": f"/api/evidence?lab_run_id={run.id}",
        "telemetry_ref": f"/api/labs/{lab.id}/telemetry?lab_run_id={run.id}",
    }
