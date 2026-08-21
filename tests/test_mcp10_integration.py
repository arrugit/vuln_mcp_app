"""MCP10 integration tests (TDD §31) — full path through the HTTP control plane."""
from __future__ import annotations

from labs.mcp10_context_oversharing.fixtures import DEMO_SECRET_A, SESSION_B_TOKEN


def _mcp10_id(client) -> int:
    labs = client.get("/api/labs").json()
    return next(l["id"] for l in labs if l["owasp_id"] == "MCP10")


def test_full_oversharing_flow_vulnerable(client):
    lab_id = _mcp10_id(client)
    resp = client.post(
        f"/api/labs/{lab_id}/attack", json={"params": {"session_token": SESSION_B_TOKEN}}
    ).json()
    assert resp["leaked_from_other_session"] is True
    assert DEMO_SECRET_A in str(resp["result"]["entries"])

    ev = client.get(f"/api/evidence?lab_run_id={resp['lab_run_id']}").json()
    assert ev[0]["kind"] == "context_leak"
    tel = client.get(f"/api/labs/{lab_id}/telemetry?lab_run_id={resp['lab_run_id']}").json()
    assert any(e["security_event"] == "context_leak" for e in tel)


def test_mode_toggle_flips_active_memory_recall_version(client):
    lab_id = _mcp10_id(client)
    tid = next(t["id"] for t in client.get("/api/mcp/tools").json() if t["name"] == "memory.recall")

    def active() -> str:
        vs = client.get(f"/api/mcp/tools/{tid}").json()["versions"]
        return next(v["trust_status"] for v in vs if v["is_active"])

    client.post(f"/api/labs/{lab_id}/mode", json={"mode": "secure"})
    assert active() == "trusted"
    client.post(f"/api/labs/{lab_id}/mode", json={"mode": "vulnerable"})
    assert active() == "poisoned"


def test_secure_mode_full_flow_no_leak(client):
    lab_id = _mcp10_id(client)
    client.post(f"/api/labs/{lab_id}/mode", json={"mode": "secure"})
    resp = client.post(
        f"/api/labs/{lab_id}/attack", json={"params": {"session_token": SESSION_B_TOKEN}}
    ).json()
    assert resp["leaked_from_other_session"] is False
    assert DEMO_SECRET_A not in str(resp["result"]["entries"])


def test_reset_restores_vulnerable_baseline_and_clears_evidence(client):
    lab_id = _mcp10_id(client)
    client.post(f"/api/labs/{lab_id}/mode", json={"mode": "secure"})
    client.post(f"/api/labs/{lab_id}/attack", json={"params": {"session_token": SESSION_B_TOKEN}})
    assert client.get("/api/evidence").json() != []
    client.post(f"/api/labs/{lab_id}/reset")
    assert client.get(f"/api/labs/{lab_id}").json()["mode"] == "vulnerable"
    assert client.get("/api/evidence").json() == []


def test_all_three_labs_emit_distinct_evidence(client):
    labs = {l["owasp_id"]: l["id"] for l in client.get("/api/labs").json()}
    r3 = client.post(f"/api/labs/{labs['MCP03']}/attack", json={"params": {"doc_id": "onboarding-notes"}}).json()
    r5 = client.post(f"/api/labs/{labs['MCP05']}/attack", json={"params": {"filename": "a.txt; echo PWNED > /work/marker"}}).json()
    r10 = client.post(f"/api/labs/{labs['MCP10']}/attack", json={"params": {"session_token": SESSION_B_TOKEN}}).json()
    k = lambda r: client.get(f"/api/evidence?lab_run_id={r['lab_run_id']}").json()[0]["kind"]
    assert k(r3) == "metadata_poison"
    assert k(r5) == "command_injection"
    assert k(r10) == "context_leak"
