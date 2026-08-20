"""MCP03 integration tests (TDD §31).

Exercises the full path through the HTTP control plane:
    Frontend(API) -> Backend -> MCP Client -> MCP Server (registry) ->
    docs.fetch -> Evidence + Telemetry -> API reads.
"""
from __future__ import annotations

from labs.mcp03_tool_poisoning.fixtures import DEMO_SECRET_A


def _mcp03_id(client) -> int:
    labs = client.get("/api/labs").json()
    return next(l["id"] for l in labs if l["owasp_id"] == "MCP03")


def test_full_attack_flow_vulnerable(client):
    lab_id = _mcp03_id(client)
    # Baseline is vulnerable; run the exact exploit call.
    resp = client.post(
        f"/api/labs/{lab_id}/attack", json={"params": {"doc_id": "welcome"}}
    ).json()
    assert resp["result"]["leaked_secret"] == DEMO_SECRET_A
    run_id = resp["lab_run_id"]

    # Evidence endpoint reflects the leak.
    evidence = client.get(f"/api/evidence?lab_run_id={run_id}").json()
    assert evidence[0]["kind"] == "metadata_poison"

    # Telemetry endpoint returns the protocol trace incl. the tagged event.
    telemetry = client.get(f"/api/labs/{lab_id}/telemetry?lab_run_id={run_id}").json()
    methods = {e["method"] for e in telemetry}
    assert {"tools/list", "tools/call"} <= methods
    assert any(e["security_event"] == "secret_leak" for e in telemetry)


def test_mode_toggle_flips_active_tool_version(client):
    lab_id = _mcp03_id(client)
    tools = client.get("/api/mcp/tools").json()
    df_id = next(t["id"] for t in tools if t["name"] == "docs.fetch")

    def active_status() -> str:
        versions = client.get(f"/api/mcp/tools/{df_id}").json()["versions"]
        return next(v["trust_status"] for v in versions if v["is_active"])

    client.post(f"/api/labs/{lab_id}/mode", json={"mode": "secure"})
    assert active_status() == "trusted"
    client.post(f"/api/labs/{lab_id}/mode", json={"mode": "vulnerable"})
    assert active_status() == "poisoned"


def test_secure_mode_full_flow_has_no_leak(client):
    lab_id = _mcp03_id(client)
    client.post(f"/api/labs/{lab_id}/mode", json={"mode": "secure"})
    resp = client.post(
        f"/api/labs/{lab_id}/attack", json={"params": {"doc_id": "welcome"}}
    ).json()
    assert "leaked_secret" not in resp["result"]
    evidence = client.get(f"/api/evidence?lab_run_id={resp['lab_run_id']}").json()
    assert evidence[0]["kind"] == "tool_fetch"


def test_reset_restores_vulnerable_baseline_and_clears_evidence(client):
    lab_id = _mcp03_id(client)
    # Toggle away + generate evidence.
    client.post(f"/api/labs/{lab_id}/mode", json={"mode": "secure"})
    client.post(f"/api/labs/{lab_id}/attack", json={"params": {"doc_id": "welcome"}})
    assert client.get("/api/evidence").json() != []

    client.post(f"/api/labs/{lab_id}/reset")
    # Baseline mode restored, evidence cleared.
    assert client.get(f"/api/labs/{lab_id}").json()["mode"] == "vulnerable"
    assert client.get("/api/evidence").json() == []
