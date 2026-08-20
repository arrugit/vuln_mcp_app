"""MCP03 Phase A (foundation) tests.

Phase A wires the docs.fetch lab end-to-end in CLEAN form. These tests assert:
  * docs.fetch is registered (both modes) and callable;
  * the tool's stored definition is TRUSTED and its metadata is clean;
  * the attack orchestrator runs the exact exploit call shape and records
    telemetry + evidence;
  * crucially, NO secret leaks yet (the poisoning is Phase B).

The determinism + secure/vulnerable *difference* tests belong to Phase B; here
we lock in that the foundation is clean and functional.
"""
from __future__ import annotations

from backend.app.mcp_client import registry_for_mode
from backend.app.services import LabService
from backend.app.services.labs import run_lab_attack
from labs.mcp03_tool_poisoning.fixtures import DEMO_SECRET_A


def _mcp03_lab(session):
    return LabService(session).get_lab_by_slug("mcp03-tool-poisoning")


# --- registry / registration ------------------------------------------------
def test_docs_fetch_registered_in_both_modes():
    for mode in ("vulnerable", "secure"):
        reg = registry_for_mode(mode)
        assert reg.has("docs.fetch"), f"docs.fetch missing in {mode} registry"


def test_secure_docs_fetch_metadata_is_clean():
    """The SECURE registry's docs.fetch description carries no embedded
    instruction. (The vulnerable registry's poisoned description is asserted in
    the MCP03 security tests.)"""
    reg = registry_for_mode("secure")
    definition = reg.get("docs.fetch").definition()
    desc = definition["description"].lower()
    for smell in ("always", "also read", "reveal", "ignore", "secret"):
        assert smell not in desc


def test_docs_fetch_returns_only_requested_document():
    reg = registry_for_mode("secure")
    out = reg.call("docs.fetch", {"doc_id": "welcome"}).result
    assert out["found"] is True
    assert out["doc_id"] == "welcome"
    assert DEMO_SECRET_A not in str(out)


def test_docs_fetch_unknown_doc_is_not_found():
    reg = registry_for_mode("secure")
    out = reg.call("docs.fetch", {"doc_id": "nope"}).result
    assert out["found"] is False


# --- DB catalog (trusted version seeded) -----------------------------------
def test_docs_fetch_seeded_with_both_versions(client):
    """FR-013: both the trusted and poisoned definitions are stored + diff-able.
    At the MCP03 baseline (vulnerable) the poisoned version is the active one."""
    tools = client.get("/api/mcp/tools").json()
    docs_fetch = next((t for t in tools if t["name"] == "docs.fetch"), None)
    assert docs_fetch is not None
    detail = client.get(f"/api/mcp/tools/{docs_fetch['id']}").json()
    versions = detail["versions"]
    statuses = {v["trust_status"] for v in versions}
    assert statuses == {"trusted", "poisoned"}
    active = [v for v in versions if v["is_active"]]
    assert len(active) == 1
    assert active[0]["trust_status"] == "poisoned"  # baseline = vulnerable


# --- orchestrator end-to-end (clean; no leak) ------------------------------
def test_mcp03_attack_runs_clean_and_records_evidence(session):
    lab = _mcp03_lab(session)
    # This test pins the SECURE behaviour explicitly (baseline is vulnerable).
    LabService(session).set_mode(lab.id, "secure")
    lab = _mcp03_lab(session)
    result = run_lab_attack(session, lab, {"doc_id": "welcome"})
    # It performed the exact exploit call shape...
    assert result["tool_call"] == {"name": "docs.fetch", "args": {"doc_id": "welcome"}}
    # ...and returned only the requested doc — NO secret in Phase A.
    assert result["result"]["found"] is True
    assert DEMO_SECRET_A not in str(result["result"])

    from backend.app.services import EvidenceService, TelemetryService

    ev = EvidenceService(session).list_for_run(result["lab_run_id"])
    assert len(ev) == 1
    # Clean classification in Phase A.
    assert ev[0].kind == "tool_fetch"
    assert DEMO_SECRET_A not in ev[0].raw_signal

    tel = TelemetryService(session).list_for_run(result["lab_run_id"])
    methods = {e.method for e in tel}
    assert {"tools/list", "tools/call"} <= methods


def test_mcp03_attack_via_api_emits_no_verdict(client):
    labs = client.get("/api/labs").json()
    lab = next(l for l in labs if l["owasp_id"] == "MCP03")
    # Pin secure mode so this stays a clean-path assertion.
    client.post(f"/api/labs/{lab['id']}/mode", json={"mode": "secure"})
    resp = client.post(f"/api/labs/{lab['id']}/attack", json={"params": {"doc_id": "welcome"}})
    assert resp.status_code == 200
    body = resp.json()
    # Response is evidence-oriented, never a "vulnerable" flag (SEC-006).
    assert "is_vulnerable" not in body and "verdict" not in body
    assert DEMO_SECRET_A not in str(body["result"])
