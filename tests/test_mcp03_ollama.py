"""MCP03 optional Ollama-backed live demo tests.

The deterministic fallback is always tested. The live test runs only when a local
Ollama is actually reachable, so the suite never depends on it (NFR-001/003).
"""
from __future__ import annotations

import httpx
import pytest

OLLAMA_URL = "http://127.0.0.1:11434"


def _ollama_up() -> bool:
    try:
        return httpx.get(f"{OLLAMA_URL}/api/tags", timeout=2.0).status_code == 200
    except Exception:
        return False


def test_llm_probe_unavailable_when_disabled(client):
    """With ENABLE_LOCAL_LLM off (default), the endpoint degrades gracefully."""
    labs = client.get("/api/labs").json()
    lab_id = next(l["id"] for l in labs if l["owasp_id"] == "MCP03")
    resp = client.post(f"/api/labs/{lab_id}/llm", json={"doc_id": "product-review"})
    assert resp.status_code == 200
    assert resp.json()["available"] is False


def test_llm_probe_rejected_for_non_mcp03(client):
    labs = client.get("/api/labs").json()
    lab_id = next(l["id"] for l in labs if l["owasp_id"] == "MCP05")
    resp = client.post(f"/api/labs/{lab_id}/llm", json={"doc_id": "x"})
    assert resp.status_code == 400


@pytest.mark.skipif(not _ollama_up(), reason="local Ollama not reachable")
def test_llm_probe_live_vulnerable(monkeypatch, temp_db):
    """When Ollama is up: the vulnerable path returns a structured LLM result.

    We assert the plumbing (structured output incl. injection_followed), not that
    a specific model always obeys — LLMs vary, which is exactly why the core lab
    stays deterministic and this path is optional.
    """
    monkeypatch.setenv("ENABLE_LOCAL_LLM", "true")
    monkeypatch.setenv("OLLAMA_URL", OLLAMA_URL)  # pin, ignore any stale .env
    from backend.app.config import get_settings
    from backend.app.services.labs.mcp03_service import run_llm_probe
    from backend.app.services import LabService
    from backend.app.db import database as db_module
    from sqlmodel import Session

    get_settings.cache_clear()
    with Session(db_module.get_engine()) as session:
        lab = LabService(session).get_lab_by_slug("mcp03-tool-poisoning")
        LabService(session).set_mode(lab.id, "vulnerable")
        lab = LabService(session).get_lab_by_slug("mcp03-tool-poisoning")
        out = run_llm_probe(session, lab, "product-review")
    get_settings.cache_clear()
    assert out["available"] is True
    assert "llm_output" in out and isinstance(out["injection_followed"], bool)
