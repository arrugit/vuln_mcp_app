"""MCP03 security tests (TDD §32) — realistic template-disclosure variant.

The MCP03 flaw is an over-broad template render context: the vulnerable
``docs.fetch`` exposes the whole app config (including ``api_key``) to the
``{{ }}`` renderer, so any article referencing ``{{ config.api_key }}`` — a
seeded internal doc, or one a user adds — discloses the credential. The secure
variant allow-lists the template context, so the same article renders inert.
"""
from __future__ import annotations

import json

from backend.app.mcp_client import registry_for_mode
from backend.app.services import EvidenceService, LabService, TelemetryService
from backend.app.services.labs import run_lab_attack
from backend.app.db.reset import reset_database
from labs.mcp03_tool_poisoning.fixtures import DEMO_SECRET_A, get_store, reset_store

LEAKY_DOC = "onboarding-notes"  # seeded doc whose body references {{ config.api_key }}


def _mcp03(session):
    return LabService(session).get_lab_by_slug("mcp03-tool-poisoning")


# --- registry-level behaviour ----------------------------------------------
def test_vulnerable_fetch_discloses_secret_via_template():
    reset_store()
    out = registry_for_mode("vulnerable").call("docs.fetch", {"doc_id": LEAKY_DOC}).result
    # The credential is rendered into the article body — no explicit leak field.
    assert DEMO_SECRET_A in out["body"]


def test_secure_fetch_renders_same_doc_inert():
    reset_store()
    out = registry_for_mode("secure").call("docs.fetch", {"doc_id": LEAKY_DOC}).result
    assert DEMO_SECRET_A not in out["body"]
    # The unresolved placeholder is simply left as-is by the narrow context.
    assert "{{ config.api_key }}" in out["body"]


def test_public_docs_do_not_leak_in_either_mode():
    reset_store()
    for mode in ("vulnerable", "secure"):
        out = registry_for_mode(mode).call("docs.fetch", {"doc_id": "welcome"}).result
        assert DEMO_SECRET_A not in out["body"]
        assert "Acme Docs Service" in out["body"]  # public value still renders


def test_user_added_doc_is_the_realistic_entry_point():
    """A user-supplied article containing the placeholder discloses the secret in
    vulnerable mode (untrusted content -> over-broad template scope)."""
    reset_store()
    get_store().add(doc_id="mine", title="mine", body="key is {{ config.api_key }}")
    vuln = registry_for_mode("vulnerable").call("docs.fetch", {"doc_id": "mine"}).result
    secure = registry_for_mode("secure").call("docs.fetch", {"doc_id": "mine"}).result
    assert DEMO_SECRET_A in vuln["body"]
    assert DEMO_SECRET_A not in secure["body"]
    reset_store()


# --- the security test (TDD §32) -------------------------------------------
def test_mcp03_tool_poisoning(session):
    """VULNERABLE mode: fetching the internal doc discloses DEMO_SECRET_A in the
    returned body; evidence is classified as metadata_poison."""
    lab = _mcp03(session)
    LabService(session).set_mode(lab.id, "vulnerable")
    lab = _mcp03(session)

    result = run_lab_attack(session, lab, {"doc_id": LEAKY_DOC})
    assert DEMO_SECRET_A in result["result"]["body"]

    ev = EvidenceService(session).list_for_run(result["lab_run_id"])
    assert ev[0].kind == "metadata_poison"
    assert DEMO_SECRET_A in json.dumps(json.loads(ev[0].raw_signal))


def test_mcp03_secure_blocks_poison(session):
    """SECURE mode: same doc, no secret in the body or evidence."""
    lab = _mcp03(session)
    LabService(session).set_mode(lab.id, "secure")
    lab = _mcp03(session)

    result = run_lab_attack(session, lab, {"doc_id": LEAKY_DOC})
    assert DEMO_SECRET_A not in result["result"]["body"]

    ev = EvidenceService(session).list_for_run(result["lab_run_id"])
    assert ev[0].kind == "tool_fetch"


# --- telemetry tagging (TDD §22) -------------------------------------------
def test_disclosure_emits_security_event_telemetry(session):
    lab = _mcp03(session)
    LabService(session).set_mode(lab.id, "vulnerable")
    lab = _mcp03(session)
    result = run_lab_attack(session, lab, {"doc_id": LEAKY_DOC})
    tags = {e.security_event for e in TelemetryService(session).list_for_run(result["lab_run_id"])}
    assert "secret_leak" in tags


# --- determinism after reset (TST-005) -------------------------------------
def _run_and_capture(session):
    reset_database(session)
    lab = _mcp03(session)  # baseline mode is vulnerable
    result = run_lab_attack(session, lab, {"doc_id": LEAKY_DOC})
    ev = EvidenceService(session).list_for_run(result["lab_run_id"])[0]
    return {"kind": ev.kind, "signal": json.loads(ev.raw_signal)}


def test_mcp03_repeatable_evidence_after_reset(session):
    first = _run_and_capture(session)
    second = _run_and_capture(session)
    assert first == second
    assert first["kind"] == "metadata_poison"
    assert DEMO_SECRET_A in json.dumps(first["signal"])


# --- anti-oracle even while vulnerable (SEC-006) ---------------------------
def test_no_verdict_endpoint_even_when_vulnerable(client):
    labs = client.get("/api/labs").json()
    lab = next(l for l in labs if l["owasp_id"] == "MCP03")
    client.post(f"/api/labs/{lab['id']}/mode", json={"mode": "vulnerable"})
    vulns = client.get("/api/vulnerabilities").json()
    blob = json.dumps(vulns).lower()
    assert "is_vulnerable" not in blob and "exploitable" not in blob and "verdict" not in blob
