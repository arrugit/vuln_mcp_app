"""MCP10 security tests (TDD §32).

  * test_mcp10_context_oversharing()   — vuln: Session B receives Session A's data
  * test_mcp10_secure_prevents_leak()  — secure: B sees only B
  * determinism after reset (TST-005)
"""
from __future__ import annotations

import json

from backend.app.mcp_client import registry_for_mode
from backend.app.services import EvidenceService, LabService, TelemetryService
from backend.app.services.labs import run_lab_attack
from backend.app.db.reset import reset_database
from labs.mcp10_context_oversharing.fixtures import (
    DEMO_SECRET_A,
    SESSION_A_TOKEN,
    SESSION_B_TOKEN,
    reset_context_store,
)


def _mcp10(session):
    return LabService(session).get_lab_by_slug("mcp10-context-oversharing")


# --- registry-level behaviour ----------------------------------------------
def test_vulnerable_recall_returns_foreign_session_data():
    reset_context_store()
    out = registry_for_mode("vulnerable").call(
        "memory.recall", {"session_token": SESSION_B_TOKEN}
    ).result
    tokens = {e["session_token"] for e in out["entries"]}
    assert SESSION_A_TOKEN in tokens  # B got A's entries
    assert DEMO_SECRET_A in str(out["entries"])  # incl. A's secret


def test_secure_recall_scopes_to_caller():
    reset_context_store()
    out = registry_for_mode("secure").call(
        "memory.recall", {"session_token": SESSION_B_TOKEN}
    ).result
    tokens = {e["session_token"] for e in out["entries"]}
    assert tokens == {SESSION_B_TOKEN}
    assert DEMO_SECRET_A not in str(out["entries"])


# --- the security test (TDD §32) -------------------------------------------
def test_mcp10_context_oversharing(session):
    """VULNERABLE mode: Session B's recall returns Session A's DEMO_SECRET_A."""
    lab = _mcp10(session)
    LabService(session).set_mode(lab.id, "vulnerable")
    lab = _mcp10(session)

    result = run_lab_attack(session, lab, {"session_token": SESSION_B_TOKEN})
    assert result["leaked_from_other_session"] is True
    assert result["contains_foreign_secret"] is True

    ev = EvidenceService(session).list_for_run(result["lab_run_id"])
    assert ev[0].kind == "context_leak"
    assert DEMO_SECRET_A in json.dumps(json.loads(ev[0].raw_signal))

    tags = {e.security_event for e in TelemetryService(session).list_for_run(result["lab_run_id"])}
    assert "context_leak" in tags


def test_mcp10_secure_prevents_leak(session):
    """SECURE mode: Session B sees only Session B; no foreign secret."""
    lab = _mcp10(session)
    LabService(session).set_mode(lab.id, "secure")
    lab = _mcp10(session)

    result = run_lab_attack(session, lab, {"session_token": SESSION_B_TOKEN})
    assert result["leaked_from_other_session"] is False
    assert result["contains_foreign_secret"] is False
    ev = EvidenceService(session).list_for_run(result["lab_run_id"])
    assert ev[0].kind == "context_recall"


# --- determinism after reset (TST-005) -------------------------------------
def _run_and_capture(session):
    reset_database(session)
    lab = _mcp10(session)  # baseline mode is vulnerable
    result = run_lab_attack(session, lab, {"session_token": SESSION_B_TOKEN})
    ev = EvidenceService(session).list_for_run(result["lab_run_id"])[0]
    return {"kind": ev.kind, "signal": json.loads(ev.raw_signal)}


def test_mcp10_repeatable_evidence_after_reset(session):
    first = _run_and_capture(session)
    second = _run_and_capture(session)
    assert first == second
    assert first["kind"] == "context_leak"
    assert DEMO_SECRET_A in json.dumps(first["signal"])
