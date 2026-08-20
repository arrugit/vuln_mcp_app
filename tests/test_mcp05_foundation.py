"""MCP05 Phase A (foundation) tests.

Phase A wires the report.export lab end-to-end in SECURE form (validate + argv).
These tests assert the tool is registered, the sandbox runner works, the secure
handler rejects/neutralises the injection payload, and NO marker is ever created
(the injection itself is Phase B).
"""
from __future__ import annotations

from backend.app.mcp_client import registry_for_mode
from backend.app.services import LabService
from backend.app.services.labs import run_lab_attack
from labs.mcp05_command_injection.fixtures import (
    INJECTION_PAYLOAD,
    SAFE_FILENAME,
    is_safe_filename,
)
from sandbox.runner import SandboxRunner


# --- sandbox runner ---------------------------------------------------------
def test_sandbox_runs_convert_and_creates_no_marker():
    with SandboxRunner() as sb:
        result = sb.run_argv(sb.convert_argv(SAFE_FILENAME))
    assert result.exit_code == 0
    assert result.marker_present is False
    assert result.timed_out is False


def test_sandbox_translates_work_token():
    with SandboxRunner() as sb:
        # A /work path in argv is mapped to the ephemeral dir (forward slashes so
        # it is valid both as argv and inside a POSIX shell); the marker helper
        # points at that same dir.
        assert sb.marker_path.name == "marker"
        wd_posix = str(sb.workdir).replace("\\", "/")
        assert sb._translate("/work/marker") == f"{wd_posix}/marker"


def test_sandbox_cleans_up_workdir():
    with SandboxRunner() as sb:
        wd = sb.workdir
    import os

    assert wd is not None and not os.path.exists(wd)


# --- validation -------------------------------------------------------------
def test_filename_allowlist_rejects_payload():
    assert is_safe_filename(SAFE_FILENAME) is True
    assert is_safe_filename(INJECTION_PAYLOAD) is False
    for bad in ("a b", "a;b", "a|b", "../etc", "a>b", ""):
        assert is_safe_filename(bad) is False


# --- registry / registration -----------------------------------------------
def test_report_export_registered_in_both_modes():
    for mode in ("vulnerable", "secure"):
        assert registry_for_mode(mode).has("report.export")


def test_secure_report_export_rejects_injection_payload():
    reg = registry_for_mode("secure")
    out = reg.call("report.export", {"filename": INJECTION_PAYLOAD}).result
    assert out["rejected"] is True
    assert out["marker_present"] is False


def test_secure_report_export_runs_valid_file():
    reg = registry_for_mode("secure")
    out = reg.call("report.export", {"filename": SAFE_FILENAME}).result
    assert out["rejected"] is False
    assert out["marker_present"] is False
    assert out["ok"] is True


# --- DB catalog -------------------------------------------------------------
def test_report_export_seeded_with_both_versions(client):
    """FR-013: both stored versions exist; at the MCP05 baseline (vulnerable)
    the unsafe (poisoned) version is active."""
    tools = client.get("/api/mcp/tools").json()
    tool = next((t for t in tools if t["name"] == "report.export"), None)
    assert tool is not None
    detail = client.get(f"/api/mcp/tools/{tool['id']}").json()
    statuses = {v["trust_status"] for v in detail["versions"]}
    assert statuses == {"trusted", "poisoned"}
    active = [v for v in detail["versions"] if v["is_active"]]
    assert len(active) == 1 and active[0]["trust_status"] == "poisoned"


# --- orchestrator end-to-end (secure path; no marker) ----------------------
def test_mcp05_attack_secure_records_evidence_without_marker(session):
    lab = LabService(session).get_lab_by_slug("mcp05-command-injection")
    # Pin the secure behaviour explicitly (baseline is now vulnerable).
    LabService(session).set_mode(lab.id, "secure")
    lab = LabService(session).get_lab_by_slug("mcp05-command-injection")
    result = run_lab_attack(session, lab, {"filename": INJECTION_PAYLOAD})
    assert result["result"]["marker_present"] is False

    from backend.app.services import EvidenceService

    ev = EvidenceService(session).list_for_run(result["lab_run_id"])
    assert len(ev) == 1
    assert ev[0].kind == "command_exec"  # neutralised in secure mode
