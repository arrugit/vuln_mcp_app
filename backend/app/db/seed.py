"""Baseline seed data (TDD §9, §24 reset re-seed).

Phase 0 scope
-------------
This seeds ONLY the ordinarily-secure baseline:

* the catalog of exactly three labs (FR-002) with ``status="pending"``;
* their *descriptive* vulnerability rows (component/attack-surface metadata —
  NO "is_present" verdict, SEC-006);
* one local MCP server registry row;
* the always-safe legit control tools ``notes.search`` / ``notes.summarize``
  (TDD §13) — these are never vulnerable in any mode.

NO poisoned metadata, NO exec tool, NO leaked context is seeded here. Those are
introduced by each lab's own Phase A, keeping the foundation clean (SEC-004).
Each lab-specific fixture will extend this baseline, not rewrite it.
"""
from __future__ import annotations

import json

from sqlmodel import Session, select

from ..models import Lab, MCPServer, MCPTool, ToolVersion, Vulnerability

# --- Legit, always-safe tool definitions (TDD §13 control tools) -----------
# These exist so the MCP surface looks realistic and so the FYP has benign
# tools to compare against. They contain no instructions and touch no secrets.
LEGIT_TOOLS = [
    {
        "name": "notes.search",
        "description": "Search the local synthetic notes corpus by keyword.",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
        "output_schema": {
            "type": "object",
            "properties": {"matches": {"type": "array"}},
        },
        "risk": "none",
    },
    {
        "name": "notes.summarize",
        "description": "Return a short deterministic summary of a synthetic note.",
        "input_schema": {
            "type": "object",
            "properties": {"note_id": {"type": "string"}},
            "required": ["note_id"],
        },
        "output_schema": {
            "type": "object",
            "properties": {"summary": {"type": "string"}},
        },
        "risk": "none",
    },
]

# --- Lab catalog (exactly three; FR-050) -----------------------------------
LAB_CATALOG = [
    {
        "slug": "mcp03-tool-poisoning",
        "title": "MCP03 — Tool Poisoning",
        "owasp_id": "MCP03",
        "severity": "High",
        "difficulty": "Low",
        "order_index": 0,
        "vuln_code": "VULN-MCP03-001",
        "component": "MCP tool definition / metadata (docs.fetch)",
        "attack_surface": "Trust in MCP tool definitions / metadata",
    },
    {
        "slug": "mcp05-command-injection",
        "title": "MCP05 — Command Injection & Execution",
        "owasp_id": "MCP05",
        "severity": "Critical",
        "difficulty": "Medium",
        "order_index": 1,
        "vuln_code": "VULN-MCP05-001",
        "component": "Command construction path (report.export) into sandbox",
        "attack_surface": "Untrusted input -> command construction -> sandboxed exec",
    },
    {
        "slug": "mcp10-context-oversharing",
        "title": "MCP10 — Context Injection & Over-Sharing",
        "owasp_id": "MCP10",
        "severity": "High",
        "difficulty": "Low",
        "order_index": 2,
        "vuln_code": "VULN-MCP10-001",
        "component": "Context store access scoping (memory.recall)",
        "attack_surface": "Session/context isolation boundary",
    },
]

# Name of the single local MCP server registered in Phase 0.
SERVER_NAME = "local-mcp-server"


def _tool_definition_json(tool: dict) -> str:
    """Serialise a legit tool's full definition (for its trusted ToolVersion)."""
    return json.dumps(
        {
            "name": tool["name"],
            "description": tool["description"],
            "inputSchema": tool["input_schema"],
            "outputSchema": tool["output_schema"],
        },
        sort_keys=True,
    )


def _seed_docs_fetch_tool(session: Session, *, server_id: int) -> None:
    """Seed the MCP03 ``docs.fetch`` tool with its TRUSTED version (Phase A).

    The DB catalog row + ``tool_versions`` back the tool viewer and the future
    trusted-vs-poisoned diff (FR-013). Phase A seeds only the ``trusted`` version
    (``is_active=True``). Phase B adds the ``poisoned`` version and flips
    ``is_active`` by mode/reset — WITHOUT changing this trusted baseline.

    The definition is imported from the single source of truth in the secure
    tools module so the catalog matches the runtime registry exactly.
    """
    from mcp_servers.secure.tools.docs_fetch import CLEAN_DOCS_FETCH_DEFINITION

    existing = session.exec(
        select(MCPTool).where(MCPTool.name == "docs.fetch")
    ).first()
    if existing is not None:
        return

    tool = MCPTool(
        server_id=server_id,
        name="docs.fetch",
        description=CLEAN_DOCS_FETCH_DEFINITION["description"],
        input_schema=json.dumps(CLEAN_DOCS_FETCH_DEFINITION["inputSchema"], sort_keys=True),
        output_schema=json.dumps(CLEAN_DOCS_FETCH_DEFINITION["outputSchema"], sort_keys=True),
        # Descriptor: docs.fetch is the MCP03 lab tool. "low" flags it as a lab
        # surface worth inspecting; it is NOT a verdict about exploitability.
        risk="low",
    )
    session.add(tool)
    session.commit()
    session.refresh(tool)

    version = ToolVersion(
        tool_id=tool.id,
        version=1,
        definition=json.dumps(CLEAN_DOCS_FETCH_DEFINITION, sort_keys=True),
        trust_status="trusted",
        is_active=True,
    )
    session.add(version)
    session.commit()
    session.refresh(version)
    tool.current_version_id = version.id
    session.add(tool)
    session.commit()


def seed_baseline(session: Session) -> None:
    """Populate the baseline catalog if it is not already present.

    Idempotent (RST-002): existing rows are left untouched so repeated calls do
    not duplicate data. :func:`app.db.reset.reset_database` clears tables first
    to guarantee a pristine baseline.
    """
    # --- MCP server registry row -----------------------------------------
    server = session.exec(
        select(MCPServer).where(MCPServer.name == SERVER_NAME)
    ).first()
    if server is None:
        settings_transport = "in-process"  # dev transport in Phase 0 (D-03 later)
        server = MCPServer(
            name=SERVER_NAME, transport=settings_transport, status="online"
        )
        session.add(server)
        session.commit()
        session.refresh(server)

    # --- Legit control tools (+ their trusted versions) ------------------
    for tool_spec in LEGIT_TOOLS:
        existing = session.exec(
            select(MCPTool).where(MCPTool.name == tool_spec["name"])
        ).first()
        if existing is not None:
            continue
        tool = MCPTool(
            server_id=server.id,
            name=tool_spec["name"],
            description=tool_spec["description"],
            input_schema=json.dumps(tool_spec["input_schema"], sort_keys=True),
            output_schema=json.dumps(tool_spec["output_schema"], sort_keys=True),
            risk=tool_spec["risk"],
        )
        session.add(tool)
        session.commit()
        session.refresh(tool)
        version = ToolVersion(
            tool_id=tool.id,
            version=1,
            definition=_tool_definition_json(tool_spec),
            trust_status="trusted",
            is_active=True,
        )
        session.add(version)
        session.commit()
        session.refresh(version)
        tool.current_version_id = version.id
        session.add(tool)
        session.commit()

    # --- MCP03 lab tool: docs.fetch (trusted version only in Phase A) ----
    _seed_docs_fetch_tool(session, server_id=server.id)

    # --- Lab catalog + descriptive vulnerability rows --------------------
    for spec in LAB_CATALOG:
        lab = session.exec(select(Lab).where(Lab.slug == spec["slug"])).first()
        if lab is None:
            lab = Lab(
                slug=spec["slug"],
                title=spec["title"],
                owasp_id=spec["owasp_id"],
                severity=spec["severity"],
                difficulty=spec["difficulty"],
                mode="secure",       # inert in Phase 0 (no vuln code yet)
                status="pending",     # implementation lands in later phases
                order_index=spec["order_index"],
            )
            session.add(lab)
            session.commit()
            session.refresh(lab)
        vuln = session.exec(
            select(Vulnerability).where(Vulnerability.vuln_code == spec["vuln_code"])
        ).first()
        if vuln is None:
            vuln = Vulnerability(
                lab_id=lab.id,
                vuln_code=spec["vuln_code"],
                owasp_id=spec["owasp_id"],
                component=spec["component"],
                attack_surface=spec["attack_surface"],
            )
            session.add(vuln)
            session.commit()
