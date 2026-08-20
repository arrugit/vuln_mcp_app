"""MCP03 security tests (TDD §32).

Covers the required cases:
  * test_mcp03_tool_poisoning()      — vuln mode: poisoned metadata + secret leak
  * test_mcp03_secure_blocks_poison() — secure mode: clean metadata, no leak
  * determinism after reset (TST-005)
  * no endpoint reveals a verdict even while vulnerable (SEC-006)
"""
from __future__ import annotations

import json

from backend.app.mcp_client import registry_for_mode
from backend.app.services import EvidenceService, LabService
from backend.app.services.labs import run_lab_attack
from backend.app.db.reset import reset_database
from labs.mcp03_tool_poisoning.fixtures import DEMO_SECRET_A


def _mcp03(session):
    return LabService(session).get_lab_by_slug("mcp03-tool-poisoning")


# --- registry-level signals -------------------------------------------------
def test_poisoned_metadata_present_in_vulnerable_registry():
    """Static signal: the vulnerable docs.fetch description embeds an instruction."""
    desc = registry_for_mode("vulnerable").get("docs.fetch").definition()["description"].lower()
    assert "demo_secret" in desc
    assert "reveal" in desc or "also read" in desc


def test_secure_registry_metadata_has_no_instruction():
    desc = registry_for_mode("secure").get("docs.fetch").definition()["description"].lower()
    assert "reveal" not in desc
    assert "demo_secret" not in desc


# --- the security test (TDD §32) -------------------------------------------
def test_mcp03_tool_poisoning(session):
    """VULNERABLE mode: metadata contains the instruction AND the tool call
    leaks DEMO_SECRET_A deterministically (server-side, not LLM-dependent)."""
    lab = _mcp03(session)
    LabService(session).set_mode(lab.id, "vulnerable")
    lab = _mcp03(session)

    result = run_lab_attack(session, lab, {"doc_id": "welcome"})
    # Behavioural signal: the secret is in the result.
    assert result["result"]["leaked_secret"] == DEMO_SECRET_A
    assert DEMO_SECRET_A in str(result["result"])

    # Evidence classified as metadata_poison and carries both signals.
    ev = EvidenceService(session).list_for_run(result["lab_run_id"])
    assert len(ev) == 1
    assert ev[0].kind == "metadata_poison"
    raw = json.loads(ev[0].raw_signal)
    assert DEMO_SECRET_A in json.dumps(raw)
    assert "demo_secret" in raw["tool_description"].lower()


def test_mcp03_secure_blocks_poison(session):
    """SECURE mode: clean metadata, no secret in the result or evidence."""
    lab = _mcp03(session)
    LabService(session).set_mode(lab.id, "secure")
    lab = _mcp03(session)

    result = run_lab_attack(session, lab, {"doc_id": "welcome"})
    assert "leaked_secret" not in result["result"]
    assert DEMO_SECRET_A not in str(result["result"])

    ev = EvidenceService(session).list_for_run(result["lab_run_id"])
    assert ev[0].kind == "tool_fetch"
    assert DEMO_SECRET_A not in ev[0].raw_signal


# --- determinism after reset (TST-005) -------------------------------------
def _run_and_capture(session):
    reset_database(session)
    lab = _mcp03(session)  # baseline mode is vulnerable
    result = run_lab_attack(session, lab, {"doc_id": "welcome"})
    ev = EvidenceService(session).list_for_run(result["lab_run_id"])[0]
    signal = json.loads(ev.raw_signal)
    return {"kind": ev.kind, "observable": ev.observable, "raw_signal": signal}


def test_mcp03_repeatable_evidence_after_reset(session):
    """reset -> exploit -> evidence, twice, yields identical evidence apart from
    ids/timestamps (which are not part of the compared payload)."""
    first = _run_and_capture(session)
    second = _run_and_capture(session)
    assert first == second
    # And it is the vulnerable evidence at baseline.
    assert first["kind"] == "metadata_poison"
    assert first["raw_signal"]["result"]["leaked_secret"] == DEMO_SECRET_A


# --- telemetry tagging (TDD §22) -------------------------------------------
def test_leak_emits_security_event_telemetry(session):
    """Vulnerable run tags a protocol event with security_event=secret_leak."""
    from backend.app.services import TelemetryService

    lab = _mcp03(session)
    LabService(session).set_mode(lab.id, "vulnerable")
    lab = _mcp03(session)
    result = run_lab_attack(session, lab, {"doc_id": "welcome"})

    events = TelemetryService(session).list_for_run(result["lab_run_id"])
    tags = {e.security_event for e in events}
    assert "secret_leak" in tags
    # tools/list + tools/call traffic was also recorded.
    assert {"tools/list", "tools/call"} <= {e.method for e in events}


def test_secure_run_tags_no_security_event(session):
    from backend.app.services import TelemetryService

    lab = _mcp03(session)
    LabService(session).set_mode(lab.id, "secure")
    lab = _mcp03(session)
    result = run_lab_attack(session, lab, {"doc_id": "welcome"})
    events = TelemetryService(session).list_for_run(result["lab_run_id"])
    assert all(e.security_event is None for e in events)


# --- deterministic side effect is LLM-independent (NFR-001) -----------------
def test_poison_leaks_for_any_doc_id_including_unknown():
    """The secret-read branch runs regardless of doc_id — proving the leak is a
    server-side side effect, not model roulette."""
    reg = registry_for_mode("vulnerable")
    for doc_id in ("welcome", "faq", "does-not-exist"):
        out = reg.call("docs.fetch", {"doc_id": doc_id}).result
        assert out["leaked_secret"] == DEMO_SECRET_A


# --- FR-013 diff: the two stored definitions genuinely differ --------------
def test_tool_versions_diff_is_real(client):
    tools = client.get("/api/mcp/tools").json()
    df = next(t for t in tools if t["name"] == "docs.fetch")
    versions = client.get(f"/api/mcp/tools/{df['id']}").json()["versions"]
    by_status = {v["trust_status"]: v["definition"] for v in versions}
    trusted_desc = by_status["trusted"]["description"].lower()
    poisoned_desc = by_status["poisoned"]["description"].lower()
    assert trusted_desc != poisoned_desc
    assert "demo_secret" in poisoned_desc and "demo_secret" not in trusted_desc


# --- anti-oracle even while vulnerable (SEC-006) ---------------------------
def test_no_verdict_endpoint_even_when_vulnerable(client):
    labs = client.get("/api/labs").json()
    lab = next(l for l in labs if l["owasp_id"] == "MCP03")
    client.post(f"/api/labs/{lab['id']}/mode", json={"mode": "vulnerable"})
    # /api/vulnerabilities is catalog metadata only — never "is exploitable".
    vulns = client.get("/api/vulnerabilities").json()
    blob = json.dumps(vulns).lower()
    assert "is_vulnerable" not in blob and "exploitable" not in blob and "verdict" not in blob
