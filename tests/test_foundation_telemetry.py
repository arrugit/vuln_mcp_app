"""Telemetry capture tests (FR-014). MCP08-as-infra, not a lab."""
from __future__ import annotations

from backend.app.mcp_client import MCPClient
from backend.app.services import LabService, TelemetryService


def test_client_records_tools_list_telemetry(session):
    telemetry = TelemetryService(session)
    client = MCPClient(mode="secure", telemetry=telemetry)
    run = LabService(session).start_run(LabService(session).list_labs()[0].id)

    defs = client.list_tools(lab_run_id=run.id)
    names = {d["name"] for d in defs}
    assert {"notes.search", "notes.summarize"} <= names

    events = telemetry.list_for_run(run.id)
    methods = [e.method for e in events]
    directions = [e.direction for e in events]
    assert methods == ["tools/list", "tools/list"]
    assert directions == ["client->server", "server->client"]


def test_client_records_tools_call_telemetry(session):
    telemetry = TelemetryService(session)
    client = MCPClient(mode="secure", telemetry=telemetry)
    run = LabService(session).start_run(LabService(session).list_labs()[0].id)

    result = client.call_tool("notes.search", {"query": "synthetic"}, lab_run_id=run.id)
    assert result["name"] == "notes.search"
    # Deterministic legit behaviour: the query matches every synthetic note.
    assert len(result["result"]["matches"]) >= 1

    events = telemetry.list_for_run(run.id)
    assert [e.method for e in events] == ["tools/call", "tools/call"]


def test_telemetry_has_no_verdict_field(session):
    telemetry = TelemetryService(session)
    event = telemetry.record(direction="client->server", method="tools/list", payload={})
    # security_event may be tagged later, but is None for benign traffic.
    assert event.security_event is None
