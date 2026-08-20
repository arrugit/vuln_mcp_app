"""MCP05 integration tests (TDD §31).

Full path through the HTTP control plane:
    API -> Backend -> MCP Client -> MCP Server (registry) -> report.export ->
    Sandbox -> Evidence + Telemetry -> API reads.
"""
from __future__ import annotations

from labs.mcp05_command_injection.fixtures import INJECTION_PAYLOAD


def _mcp05_id(client) -> int:
    labs = client.get("/api/labs").json()
    return next(l["id"] for l in labs if l["owasp_id"] == "MCP05")


def test_full_injection_flow_vulnerable(client):
    lab_id = _mcp05_id(client)
    resp = client.post(
        f"/api/labs/{lab_id}/attack", json={"params": {"filename": INJECTION_PAYLOAD}}
    ).json()
    assert resp["result"]["marker_present"] is True
    run_id = resp["lab_run_id"]

    evidence = client.get(f"/api/evidence?lab_run_id={run_id}").json()
    assert evidence[0]["kind"] == "command_injection"

    telemetry = client.get(f"/api/labs/{lab_id}/telemetry?lab_run_id={run_id}").json()
    assert any(e["security_event"] == "command_injection" for e in telemetry)
    assert {"tools/list", "tools/call"} <= {e["method"] for e in telemetry}


def test_mode_toggle_flips_active_report_export_version(client):
    lab_id = _mcp05_id(client)
    tools = client.get("/api/mcp/tools").json()
    tid = next(t["id"] for t in tools if t["name"] == "report.export")

    def active_status() -> str:
        versions = client.get(f"/api/mcp/tools/{tid}").json()["versions"]
        return next(v["trust_status"] for v in versions if v["is_active"])

    client.post(f"/api/labs/{lab_id}/mode", json={"mode": "secure"})
    assert active_status() == "trusted"
    client.post(f"/api/labs/{lab_id}/mode", json={"mode": "vulnerable"})
    assert active_status() == "poisoned"


def test_secure_mode_full_flow_no_marker(client):
    lab_id = _mcp05_id(client)
    client.post(f"/api/labs/{lab_id}/mode", json={"mode": "secure"})
    resp = client.post(
        f"/api/labs/{lab_id}/attack", json={"params": {"filename": INJECTION_PAYLOAD}}
    ).json()
    assert resp["result"]["marker_present"] is False
    assert resp["result"]["rejected"] is True
    evidence = client.get(f"/api/evidence?lab_run_id={resp['lab_run_id']}").json()
    assert evidence[0]["kind"] == "command_exec"


def test_reset_restores_vulnerable_baseline_and_clears_evidence(client):
    lab_id = _mcp05_id(client)
    client.post(f"/api/labs/{lab_id}/mode", json={"mode": "secure"})
    client.post(f"/api/labs/{lab_id}/attack", json={"params": {"filename": INJECTION_PAYLOAD}})
    assert client.get("/api/evidence").json() != []

    client.post(f"/api/labs/{lab_id}/reset")
    assert client.get(f"/api/labs/{lab_id}").json()["mode"] == "vulnerable"
    assert client.get("/api/evidence").json() == []


def _tool_id(client, name: str) -> int:
    return next(t["id"] for t in client.get("/api/mcp/tools").json() if t["name"] == name)


def test_direct_tool_call_respects_lab_mode(client):
    """POST /api/mcp/tools/{id}/call runs under the owning lab's current mode,
    so this endpoint behaves like the real MCP surface (not always-secure)."""
    lab_id = _mcp05_id(client)
    tid = _tool_id(client, "report.export")

    # Baseline vulnerable -> direct call injects.
    out = client.post(f"/api/mcp/tools/{tid}/call", json={"args": {"filename": INJECTION_PAYLOAD}}).json()
    assert out["mode"] == "vulnerable"
    assert out["result"]["marker_present"] is True

    # Toggle secure -> same direct call is neutralised.
    client.post(f"/api/labs/{lab_id}/mode", json={"mode": "secure"})
    out2 = client.post(f"/api/mcp/tools/{tid}/call", json={"args": {"filename": INJECTION_PAYLOAD}}).json()
    assert out2["mode"] == "secure"
    assert out2["result"]["marker_present"] is False


def test_direct_call_to_legit_tool_is_secure(client):
    """A non-lab legit tool defaults to secure mode and behaves normally."""
    tid = _tool_id(client, "notes.search")
    out = client.post(f"/api/mcp/tools/{tid}/call", json={"args": {"query": "synthetic"}}).json()
    assert out["mode"] == "secure"
    assert "matches" in out["result"]


def test_both_labs_coexist_independently(client):
    """MCP03 and MCP05 both emit their own distinct evidence — the two locked/
    active labs do not interfere."""
    labs = client.get("/api/labs").json()
    m3 = next(l["id"] for l in labs if l["owasp_id"] == "MCP03")
    m5 = next(l["id"] for l in labs if l["owasp_id"] == "MCP05")
    r3 = client.post(f"/api/labs/{m3}/attack", json={"params": {"doc_id": "welcome"}}).json()
    r5 = client.post(f"/api/labs/{m5}/attack", json={"params": {"filename": INJECTION_PAYLOAD}}).json()
    k3 = client.get(f"/api/evidence?lab_run_id={r3['lab_run_id']}").json()[0]["kind"]
    k5 = client.get(f"/api/evidence?lab_run_id={r5['lab_run_id']}").json()[0]["kind"]
    assert k3 == "metadata_poison"
    assert k5 == "command_injection"
