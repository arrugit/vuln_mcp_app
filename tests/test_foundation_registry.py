"""MCP tool registry tests (TDD §30 test_tool_registry_loads_versions analogue)."""
from __future__ import annotations

import pytest

from backend.app.mcp_client import registry_for_mode
from mcp_servers.common import build_baseline_registry


def test_baseline_registry_loads_legit_tools():
    reg = build_baseline_registry()
    assert set(reg.names()) == {"notes.search", "notes.summarize"}
    for definition in reg.list_definitions():
        assert "name" in definition and "inputSchema" in definition


def test_both_modes_are_baseline_safe_in_phase0():
    """Phase 0: vulnerable and secure registries are identical + benign."""
    vuln = registry_for_mode("vulnerable")
    secure = registry_for_mode("secure")
    assert vuln.names() == secure.names() == ["notes.search", "notes.summarize"]


def test_unknown_tool_raises_keyerror():
    reg = build_baseline_registry()
    with pytest.raises(KeyError):
        reg.call("does.not.exist", {})


def test_legit_tool_is_deterministic():
    reg = build_baseline_registry()
    a = reg.call("notes.summarize", {"note_id": "note-1"})
    b = reg.call("notes.summarize", {"note_id": "note-1"})
    assert a.result == b.result
    assert a.result["found"] is True
