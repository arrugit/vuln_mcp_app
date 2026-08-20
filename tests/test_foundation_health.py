"""Health endpoint tests (FR-005). Health reports status, never a verdict."""
from __future__ import annotations


def test_health_reports_up(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["backend"] == "up"
    assert body["mcp_server"] == "online"


def test_health_has_no_vulnerability_verdict(client):
    """SEC-006: health must not contain any is-vulnerable style field."""
    body = client.get("/api/health").json()
    forbidden = {"is_vulnerable", "vulnerable", "vuln_status", "is_present", "verdict"}
    assert forbidden.isdisjoint(body.keys())


def test_root_describes_target_role(client):
    body = client.get("/").json()
    assert body["app"] == "vuln_mcp_app"
    assert "not a scanner" in body["role"]
