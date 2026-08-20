"""Lab catalog + lifecycle tests (FR-002/003/004)."""
from __future__ import annotations

EXPECTED_OWASP = {"MCP03", "MCP05", "MCP10"}


def test_catalog_has_exactly_three_labs(client):
    """FR-050: exactly three planted vulnerabilities, one per category."""
    labs = client.get("/api/labs").json()
    assert len(labs) == 3
    assert {lab["owasp_id"] for lab in labs} == EXPECTED_OWASP


def test_labs_are_ordered(client):
    labs = client.get("/api/labs").json()
    owasp_order = [lab["owasp_id"] for lab in labs]
    assert owasp_order == ["MCP03", "MCP05", "MCP10"]


def test_lab_detail_is_descriptive(client):
    labs = client.get("/api/labs").json()
    lab_id = labs[0]["id"]
    detail = client.get(f"/api/labs/{lab_id}").json()
    assert detail["vulnerability"]["vuln_code"] == "VULN-MCP03-001"
    assert "component" in detail["vulnerability"]
    # SEC-006: descriptor must not disclose exploitability.
    assert "is_present" not in detail["vulnerability"]


def test_mode_toggle_changes_mode(client):
    labs = client.get("/api/labs").json()
    lab_id = labs[0]["id"]
    resp = client.post(f"/api/labs/{lab_id}/mode", json={"mode": "vulnerable"})
    assert resp.status_code == 200
    assert resp.json()["mode"] == "vulnerable"
    # And it persists on detail read.
    assert client.get(f"/api/labs/{lab_id}").json()["mode"] == "vulnerable"


def test_mode_toggle_rejects_invalid_enum(client):
    labs = client.get("/api/labs").json()
    lab_id = labs[0]["id"]
    resp = client.post(f"/api/labs/{lab_id}/mode", json={"mode": "banana"})
    # Pydantic pattern validation -> 422 before the handler runs.
    assert resp.status_code == 422


def test_missing_lab_returns_404(client):
    assert client.get("/api/labs/9999").status_code == 404


def test_attack_stub_creates_run_without_evidence(client):
    """Phase 0: /attack creates a run but emits no evidence yet."""
    labs = client.get("/api/labs").json()
    lab_id = labs[0]["id"]
    resp = client.post(f"/api/labs/{lab_id}/attack", json={"trigger": "noop"})
    assert resp.status_code == 200
    run_id = resp.json()["lab_run_id"]
    evidence = client.get(f"/api/evidence?lab_run_id={run_id}").json()
    assert evidence == []
