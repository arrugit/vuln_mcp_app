"""SQLModel entities for the control plane (TDD §9 / §10).

The schema is deliberately DESCRIPTIVE. Per SEC-006 / GT-003 there is NO field
anywhere that states whether a vulnerability is currently "present" or
"exploitable" — the FYP must infer that from behaviour and emitted evidence, not
read it from a column. `Vulnerability.component` / `.attack_surface` are catalog
metadata (the same a scanner could infer), never a verdict.
"""
from .entities import (
    Lab,
    Vulnerability,
    MCPServer,
    MCPTool,
    ToolVersion,
    Session,
    Context,
    ContextEntry,
    ToolCall,
    TelemetryEvent,
    LabRun,
    Evidence,
)

__all__ = [
    "Lab",
    "Vulnerability",
    "MCPServer",
    "MCPTool",
    "ToolVersion",
    "Session",
    "Context",
    "ContextEntry",
    "ToolCall",
    "TelemetryEvent",
    "LabRun",
    "Evidence",
]
