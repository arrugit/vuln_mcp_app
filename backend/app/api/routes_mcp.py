"""MCP endpoints (TDD §12): servers, tools, tool detail (with versions), call.

Tool detail exposes ALL stored versions (trusted + poisoned) so the MCP03 diff
(FR-013) is inspectable — this is metadata about stored artefacts, not a runtime
verdict (SEC-006). Phase 0 has only trusted versions of the legit tools.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session

from ..schemas import ToolCallRequest
from ..services import MCPService
from .deps import db_session

router = APIRouter(prefix="/mcp", tags=["mcp"])


@router.get("/servers")
def list_servers(session: Session = Depends(db_session)) -> list[dict]:
    service = MCPService(session)
    return [
        {"id": s.id, "name": s.name, "transport": s.transport, "status": s.status}
        for s in service.list_servers()
    ]


@router.get("/tools")
def list_tools(
    server_id: int | None = None, session: Session = Depends(db_session)
) -> list[dict]:
    service = MCPService(session)
    return [
        {
            "id": t.id,
            "server_id": t.server_id,
            "name": t.name,
            "description": t.description,
            "input_schema": service.parse_json_field(t.input_schema),
            "risk": t.risk,
        }
        for t in service.list_tools(server_id)
    ]


@router.get("/tools/{tool_id}")
def get_tool(tool_id: int, session: Session = Depends(db_session)) -> dict:
    service = MCPService(session)
    tool = service.get_tool(tool_id)
    if tool is None:
        raise HTTPException(status_code=404, detail="tool not found")
    versions = service.get_tool_versions(tool_id)
    return {
        "id": tool.id,
        "server_id": tool.server_id,
        "name": tool.name,
        "description": tool.description,
        "input_schema": service.parse_json_field(tool.input_schema),
        "output_schema": service.parse_json_field(tool.output_schema),
        "risk": tool.risk,
        "versions": [
            {
                "version": v.version,
                "trust_status": v.trust_status,
                "is_active": v.is_active,
                "definition": service.parse_json_field(v.definition),
            }
            for v in versions
        ],
    }


@router.post("/tools/{tool_id}/call")
def call_tool(
    tool_id: int,
    body: ToolCallRequest,
    session: Session = Depends(db_session),
) -> dict:
    service = MCPService(session)
    tool = service.get_tool(tool_id)
    if tool is None:
        raise HTTPException(status_code=404, detail="tool not found")
    # A direct tool call runs under the owning lab's current mode (lab tools) or
    # secure (legit tools) — so this endpoint behaves like the real MCP surface.
    mode = service.resolve_mode_for_tool(tool)
    try:
        result = service.call_tool_by_id(tool_id, body.args, mode=mode)
    except KeyError:
        raise HTTPException(status_code=404, detail="tool not found")
    return {**result, "mode": mode}
