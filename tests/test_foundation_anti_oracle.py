"""Anti-oracle tests (SEC-006, TDD §32 test_no_endpoint_reveals_vuln_status).

The target must NEVER expose an endpoint or field that hands the FYP a verdict.
This test locks that invariant in from the foundation so later phases cannot
accidentally introduce an oracle.
"""
from __future__ import annotations

# Paths that would constitute an oracle if they existed (PRD §13 forbids them).
FORBIDDEN_PATHS = [
    "/is-vulnerable",
    "/api/is-vulnerable",
    "/vulnerability-status",
    "/scan-result",
    "/api/scan-result",
    "/api/vulnerability-status",
]

# Substrings that would leak a verdict if present in any JSON response value/key.
FORBIDDEN_TOKENS = {"is_vulnerable", "is_present", "verdict", "scan_result"}


def test_no_oracle_endpoints_exist(client):
    for path in FORBIDDEN_PATHS:
        resp = client.get(path)
        assert resp.status_code == 404, f"oracle-like path resolved: {path}"


def test_openapi_declares_no_oracle_routes(client):
    spec = client.get("/openapi.json").json()
    for path in spec.get("paths", {}):
        lowered = path.lower()
        assert "is-vulnerable" not in lowered
        assert "scan-result" not in lowered
        assert "vulnerability-status" not in lowered


def _keys_and_values(obj):
    """Yield every key and string value recursively for scanning."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _keys_and_values(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _keys_and_values(item)
    elif isinstance(obj, str):
        yield obj


def test_descriptive_endpoints_have_no_verdict_fields(client):
    """/api/vulnerabilities is catalog metadata only — no exploitability flag."""
    for endpoint in ("/api/vulnerabilities", "/api/labs", "/api/health"):
        body = client.get(endpoint).json()
        tokens = {t.lower() for t in _keys_and_values(body)}
        assert FORBIDDEN_TOKENS.isdisjoint(tokens), f"verdict leaked via {endpoint}"
