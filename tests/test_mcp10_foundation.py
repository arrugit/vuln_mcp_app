"""MCP10 Phase A (foundation) tests.

Phase A wires memory.recall end-to-end in SECURE (session-scoped) form. These
tests assert the tool is registered, a recall returns only the caller's own
entries, and NO foreign session data / secret leaks yet (the missing-ownership
bug is Phase B).
"""
from __future__ import annotations

from backend.app.mcp_client import registry_for_mode
from backend.app.services import LabService
from backend.app.services.labs import run_lab_attack
from labs.mcp10_context_oversharing.fixtures import (
    DEMO_SECRET_A,
    SESSION_A_TOKEN,
    SESSION_B_TOKEN,
    reset_context_store,
)


def test_memory_recall_registered_in_both_modes():
    for mode in ("vulnerable", "secure"):
        assert registry_for_mode(mode).has("memory.recall")


def test_secure_recall_returns_only_callers_entries():
    reset_context_store()
    reg = registry_for_mode("secure")
    out_b = reg.call("memory.recall", {"session_token": SESSION_B_TOKEN}).result
    tokens = {e["session_token"] for e in out_b["entries"]}
    assert tokens == {SESSION_B_TOKEN}
    assert DEMO_SECRET_A not in str(out_b["entries"])


def test_secure_recall_session_a_sees_its_own_secret_only():
    reset_context_store()
    reg = registry_for_mode("secure")
    out_a = reg.call("memory.recall", {"session_token": SESSION_A_TOKEN}).result
    # A legitimately sees its own secret; B never should (tested above).
    assert DEMO_SECRET_A in str(out_a["entries"])


def test_memory_recall_seeded_with_trusted_version(client):
    tools = client.get("/api/mcp/tools").json()
    tool = next((t for t in tools if t["name"] == "memory.recall"), None)
    assert tool is not None
    detail = client.get(f"/api/mcp/tools/{tool['id']}").json()
    assert len(detail["versions"]) == 1
    assert detail["versions"][0]["trust_status"] == "trusted"


def test_sessions_endpoint_lists_synthetic_users(client):
    labs = client.get("/api/labs").json()
    lab_id = next(l["id"] for l in labs if l["owasp_id"] == "MCP10")
    sessions = client.get(f"/api/labs/{lab_id}/sessions").json()
    labels = {s["user_label"] for s in sessions}
    assert {"User A", "User B"} <= labels


def test_mcp10_attack_secure_records_evidence_without_leak(session):
    lab = LabService(session).get_lab_by_slug("mcp10-context-oversharing")
    # Pin secure mode explicitly (baseline becomes vulnerable in Phase B).
    LabService(session).set_mode(lab.id, "secure")
    lab = LabService(session).get_lab_by_slug("mcp10-context-oversharing")
    result = run_lab_attack(session, lab, {"session_token": SESSION_B_TOKEN})
    assert result["leaked_from_other_session"] is False

    from backend.app.services import EvidenceService

    ev = EvidenceService(session).list_for_run(result["lab_run_id"])
    assert ev[0].kind == "context_recall"
