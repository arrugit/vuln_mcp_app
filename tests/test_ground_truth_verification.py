"""Ground-truth verification (TDD §33).

These tests double as machine-checkable verifiers of the answer key in
`docs/GROUND-TRUTH.md`: for every IMPLEMENTED lab they assert the documented
vulnerable behaviour, the secure neutralisation, deterministic replay after
reset, and the anti-oracle invariant — all in one place, parametrised over the
labs. New labs add a row to ``GROUND_TRUTH`` when they are built.
"""
from __future__ import annotations

import json

import pytest

from backend.app.db.reset import reset_database
from backend.app.services import EvidenceService, LabService
from backend.app.services.labs import run_lab_attack

# The answer key, mirrored from docs/GROUND-TRUTH.md. Each row is one implemented
# vulnerability: how to trigger it and what evidence proves success vs. secure.
GROUND_TRUTH = [
    {
        "slug": "mcp03-tool-poisoning",
        "vuln_code": "VULN-MCP03-001",
        "params": {"doc_id": "welcome"},
        "vuln_kind": "metadata_poison",
        "secure_kind": "tool_fetch",
        # A predicate over the attack result proving the exploit worked.
        "proof": lambda r: r["result"].get("leaked_secret") == "DEMO_SECRET_A",
        "secure_proof": lambda r: "leaked_secret" not in r["result"],
    },
    {
        "slug": "mcp05-command-injection",
        "vuln_code": "VULN-MCP05-001",
        "params": {"filename": "a.txt; echo PWNED > /work/marker"},
        "vuln_kind": "command_injection",
        "secure_kind": "command_exec",
        "proof": lambda r: r["result"].get("marker_present") is True,
        "secure_proof": lambda r: r["result"].get("marker_present") is False,
    },
]


@pytest.fixture(params=GROUND_TRUTH, ids=[g["vuln_code"] for g in GROUND_TRUTH])
def gt(request):
    return request.param


def _lab(session, slug):
    return LabService(session).get_lab_by_slug(slug)


def test_vulnerable_behaviour_matches_ground_truth(session, gt):
    lab = _lab(session, gt["slug"])
    LabService(session).set_mode(lab.id, "vulnerable")
    lab = _lab(session, gt["slug"])
    result = run_lab_attack(session, lab, gt["params"])
    assert gt["proof"](result), f"{gt['vuln_code']} did not produce its documented proof"
    ev = EvidenceService(session).list_for_run(result["lab_run_id"])
    assert ev[0].kind == gt["vuln_kind"]


def test_secure_mode_neutralises(session, gt):
    lab = _lab(session, gt["slug"])
    LabService(session).set_mode(lab.id, "secure")
    lab = _lab(session, gt["slug"])
    result = run_lab_attack(session, lab, gt["params"])
    assert gt["secure_proof"](result)
    ev = EvidenceService(session).list_for_run(result["lab_run_id"])
    assert ev[0].kind == gt["secure_kind"]


def test_deterministic_replay_after_reset(session, gt):
    def run_once():
        reset_database(session)
        lab = _lab(session, gt["slug"])  # baseline = vulnerable
        result = run_lab_attack(session, lab, gt["params"])
        ev = EvidenceService(session).list_for_run(result["lab_run_id"])[0]
        return {"kind": ev.kind, "signal": json.loads(ev.raw_signal)}

    assert run_once() == run_once()


def test_no_oracle_for_any_lab(client, gt):
    """Even mid-exploit, no endpoint hands out a verdict for this lab."""
    labs = client.get("/api/labs").json()
    lab_id = next(l["id"] for l in labs if l["slug"] == gt["slug"])
    client.post(f"/api/labs/{lab_id}/attack", json={"params": gt["params"]})
    body = json.dumps(client.get("/api/vulnerabilities").json()).lower()
    for token in ("is_vulnerable", "exploitable", "verdict", "is_present"):
        assert token not in body
