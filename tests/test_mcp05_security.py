"""MCP05 security tests (TDD §32).

  * test_mcp05_command_injection()      — vuln mode: payload creates /work/marker
  * test_mcp05_secure_blocks_injection() — secure mode: no marker
  * determinism after reset (TST-005)
  * blast radius stays inside the ephemeral sandbox dir
"""
from __future__ import annotations

import json

from backend.app.mcp_client import registry_for_mode
from backend.app.services import EvidenceService, LabService, TelemetryService
from backend.app.services.labs import run_lab_attack
from backend.app.db.reset import reset_database
from labs.mcp05_command_injection.fixtures import INJECTION_PAYLOAD, SAFE_FILENAME


def _mcp05(session):
    return LabService(session).get_lab_by_slug("mcp05-command-injection")


# --- registry-level behaviour ----------------------------------------------
def test_vulnerable_report_export_uses_shell_and_leaks_marker():
    reg = registry_for_mode("vulnerable")
    out = reg.call("report.export", {"filename": INJECTION_PAYLOAD}).result
    assert out["marker_present"] is True
    # The recorded constructed command shows the injected separator.
    assert "; echo PWNED" in out["constructed_command"]


def test_secure_report_export_neutralises_same_payload():
    reg = registry_for_mode("secure")
    out = reg.call("report.export", {"filename": INJECTION_PAYLOAD}).result
    assert out["marker_present"] is False
    assert out["rejected"] is True


def test_vulnerable_benign_filename_creates_no_marker():
    """A normal filename in vulnerable mode does not create a marker — the marker
    only appears when the payload injects an extra command."""
    reg = registry_for_mode("vulnerable")
    out = reg.call("report.export", {"filename": SAFE_FILENAME}).result
    assert out["marker_present"] is False


# --- the security test (TDD §32) -------------------------------------------
def test_mcp05_command_injection(session):
    """VULNERABLE mode: the separator payload executes an extra command that
    creates /work/marker; the constructed command is recorded."""
    lab = _mcp05(session)
    LabService(session).set_mode(lab.id, "vulnerable")
    lab = _mcp05(session)

    result = run_lab_attack(session, lab, {"filename": INJECTION_PAYLOAD})
    assert result["result"]["marker_present"] is True

    ev = EvidenceService(session).list_for_run(result["lab_run_id"])
    assert ev[0].kind == "command_injection"
    raw = json.loads(ev[0].raw_signal)
    assert "; echo PWNED" in raw["constructed_command"]

    # Telemetry tags the extra execution.
    tags = {e.security_event for e in TelemetryService(session).list_for_run(result["lab_run_id"])}
    assert "command_injection" in tags


def test_mcp05_secure_blocks_injection(session):
    """SECURE mode: same payload, no marker, no injection evidence."""
    lab = _mcp05(session)
    LabService(session).set_mode(lab.id, "secure")
    lab = _mcp05(session)

    result = run_lab_attack(session, lab, {"filename": INJECTION_PAYLOAD})
    assert result["result"]["marker_present"] is False
    ev = EvidenceService(session).list_for_run(result["lab_run_id"])
    assert ev[0].kind == "command_exec"


# --- determinism after reset (TST-005) -------------------------------------
def _run_and_capture(session):
    reset_database(session)
    lab = _mcp05(session)  # baseline mode is vulnerable
    result = run_lab_attack(session, lab, {"filename": INJECTION_PAYLOAD})
    ev = EvidenceService(session).list_for_run(result["lab_run_id"])[0]
    signal = json.loads(ev.raw_signal)
    return {"kind": ev.kind, "observable": ev.observable, "marker": signal["marker_present"]}


def test_mcp05_repeatable_evidence_after_reset(session):
    first = _run_and_capture(session)
    second = _run_and_capture(session)
    assert first == second
    assert first["kind"] == "command_injection"
    assert first["marker"] is True


# --- containment: marker lands in the ephemeral dir, cleaned up -------------
def test_marker_is_confined_to_ephemeral_sandbox_dir():
    """The injection creates the marker inside the throwaway work dir, which is
    removed when the sandbox context exits — nothing persists on the host."""
    from sandbox.runner import SandboxRunner
    import os

    with SandboxRunner() as sb:
        sb.run_shell("convert " + INJECTION_PAYLOAD + " out.pdf")
        assert sb.marker_present() is True
        workdir = sb.workdir
    # After exit the whole dir (marker included) is gone.
    assert workdir is not None and not os.path.exists(workdir)
