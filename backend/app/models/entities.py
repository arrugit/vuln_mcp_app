"""Database entities (TDD §9 tables, §10 ER diagram).

Design notes
------------
* All timestamps are stored in UTC and set explicitly (never rely on DB clock)
  so determinism tests can normalise them out (NFR-002 / TST-005).
* JSON-ish columns (schemas, payloads, results) are stored as TEXT holding a
  JSON string; the service layer serialises/deserialises.
* CRITICAL (SEC-006): no table has an "is_vulnerable"/"is_present" flag.
  ``ToolVersion.trust_status`` describes a *version artefact* (trusted vs
  poisoned definition) so the MCP03 diff (FR-013) is inspectable — it is
  metadata about a stored artefact, not a runtime verdict about the whole app.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    """Explicit UTC 'now' so timestamps are consistent and testable."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Catalog: labs + their ground-truth-linked vulnerability descriptors
# ---------------------------------------------------------------------------
class Lab(SQLModel, table=True):
    """One row per vulnerability lab (FR-002/FR-003).

    ``mode`` drives runtime behaviour (FR-004). In Phase 0 no vulnerable
    behaviour exists yet, so ``mode`` is inert and every lab ships
    ``status="pending"``.
    """

    __tablename__ = "labs"

    id: Optional[int] = Field(default=None, primary_key=True)
    slug: str = Field(index=True, unique=True)
    title: str
    owasp_id: str  # e.g. "MCP03"
    severity: str  # Critical | High | Medium | Low | Info (UX-003 tokens)
    difficulty: str  # Low | Medium | High
    # Behaviour mode; per-lab override of the global MCP_MODE default.
    mode: str = Field(default="secure")
    # Lifecycle status for the UI catalog. NOT a vulnerability verdict.
    status: str = Field(default="pending")
    order_index: int = Field(default=0)


class Vulnerability(SQLModel, table=True):
    """Ground-truth linkage row (TDD §9).

    Descriptive metadata ONLY. There is intentionally no "is_present" column
    (SEC-006): the app describes *what kind* of vulnerability a lab is about,
    never whether it is currently exploitable.
    """

    __tablename__ = "vulnerabilities"

    id: Optional[int] = Field(default=None, primary_key=True)
    lab_id: int = Field(foreign_key="labs.id", index=True)
    vuln_code: str = Field(index=True, unique=True)  # VULN-MCP03-001
    owasp_id: str
    component: str  # vulnerable component descriptor
    attack_surface: str


# ---------------------------------------------------------------------------
# MCP plane: servers, tools, and (trusted vs poisoned) tool versions
# ---------------------------------------------------------------------------
class MCPServer(SQLModel, table=True):
    __tablename__ = "mcp_servers"

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    transport: str  # e.g. streamable-http (D-03) / in-process (dev)
    status: str = Field(default="online")


class MCPTool(SQLModel, table=True):
    """A tool exposed by an MCP server.

    In Phase 0 only the always-safe legit control tools are registered
    (notes.search / notes.summarize, TDD §13). Lab-specific tools
    (docs.fetch, report.export, memory.recall) are added in each lab's Phase A.
    """

    __tablename__ = "mcp_tools"

    id: Optional[int] = Field(default=None, primary_key=True)
    server_id: int = Field(foreign_key="mcp_servers.id", index=True)
    name: str = Field(index=True)
    description: str = ""
    input_schema: str = "{}"   # JSON string
    output_schema: str = "{}"  # JSON string
    risk: str = Field(default="none")  # descriptor only (none|low|med|high)
    current_version_id: Optional[int] = Field(default=None)


class ToolVersion(SQLModel, table=True):
    """Trusted vs poisoned tool definitions (FR-013 diff).

    ``trust_status`` labels a *stored definition artefact*, enabling the MCP03
    trusted-vs-poisoned diff view. It is not a live verdict about the running
    system (SEC-006). Phase 0 seeds only ``trusted`` versions.
    """

    __tablename__ = "tool_versions"

    id: Optional[int] = Field(default=None, primary_key=True)
    tool_id: int = Field(foreign_key="mcp_tools.id", index=True)
    version: int = Field(default=1)
    definition: str = "{}"  # JSON string of the full tool definition
    trust_status: str = Field(default="trusted")  # trusted | poisoned
    is_active: bool = Field(default=True, index=True)


# ---------------------------------------------------------------------------
# Context store (backs MCP10) — synthetic data only (SEC-002)
# ---------------------------------------------------------------------------
class Session(SQLModel, table=True):
    __tablename__ = "sessions"

    id: Optional[int] = Field(default=None, primary_key=True)
    user_label: str  # "User A" / "User B" — synthetic
    session_token: str = Field(index=True, unique=True)


class Context(SQLModel, table=True):
    __tablename__ = "contexts"

    id: Optional[int] = Field(default=None, primary_key=True)
    session_id: int = Field(foreign_key="sessions.id", index=True)
    name: str  # e.g. "Orion"


class ContextEntry(SQLModel, table=True):
    """A single context item. In the MCP10 lab one entry holds the synthetic
    ``DEMO_SECRET_A``; in Phase 0 the store is empty until the lab seeds it."""

    __tablename__ = "context_entries"

    id: Optional[int] = Field(default=None, primary_key=True)
    context_id: int = Field(foreign_key="contexts.id", index=True)
    key: str
    value: str  # synthetic value (SEC-002)
    visibility: str = Field(default="private")


# ---------------------------------------------------------------------------
# Runtime records: lab runs, tool calls, telemetry, evidence
# ---------------------------------------------------------------------------
class LabRun(SQLModel, table=True):
    """One attack/simulation run; groups the evidence + telemetry it produced."""

    __tablename__ = "lab_runs"

    id: Optional[int] = Field(default=None, primary_key=True)
    lab_id: int = Field(foreign_key="labs.id", index=True)
    session_id: Optional[int] = Field(default=None, foreign_key="sessions.id")
    mode: str  # mode the run executed under (vulnerable | secure)
    trigger: str = ""
    status: str = Field(default="completed")
    started_at: datetime = Field(default_factory=utcnow)


class ToolCall(SQLModel, table=True):
    """A recorded MCP tool invocation (MCP05 evidence carries the command)."""

    __tablename__ = "tool_calls"

    id: Optional[int] = Field(default=None, primary_key=True)
    lab_run_id: Optional[int] = Field(default=None, foreign_key="lab_runs.id", index=True)
    tool_id: Optional[int] = Field(default=None, foreign_key="mcp_tools.id")
    args: str = "{}"  # JSON string
    constructed_command: Optional[str] = None
    result: str = "{}"  # JSON string
    created_at: datetime = Field(default_factory=utcnow)


class TelemetryEvent(SQLModel, table=True):
    """MCP protocol trace (FR-014). MCP08-as-infra only — never a fourth lab.

    Each MCP interaction (tools/list, definitions, tools/call, result) is one
    row so the S7 console can render a CLIENT<->SERVER trace.
    """

    __tablename__ = "telemetry_events"

    id: Optional[int] = Field(default=None, primary_key=True)
    lab_run_id: Optional[int] = Field(default=None, foreign_key="lab_runs.id", index=True)
    ts: datetime = Field(default_factory=utcnow)
    direction: str  # client->server | server->client
    method: str  # tools/list | tools/call | ...
    payload: str = "{}"  # JSON string
    mode: Optional[str] = None
    security_event: Optional[str] = None  # tag set only when relevant


class Evidence(SQLModel, table=True):
    """Emitted evidence (EV-001..003). It is EVIDENCE, never a verdict (EV-002).

    ``kind`` names the class of observable (e.g. metadata_poison,
    command_injection, context_leak); ``observable`` is a human-readable
    summary; ``raw_signal`` is the JSON payload the owner/FYP inspects.
    """

    __tablename__ = "evidence"

    id: Optional[int] = Field(default=None, primary_key=True)
    lab_run_id: int = Field(foreign_key="lab_runs.id", index=True)
    kind: str
    observable: str
    raw_signal: str = "{}"  # JSON string
    created_at: datetime = Field(default_factory=utcnow)
