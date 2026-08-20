"""Service layer (TDD §7): lab lifecycle, telemetry capture, evidence recording,
reset orchestration, and the MCP bridge.

Services hold the *infrastructure* logic. They are ordinarily secure (SEC-004);
no vulnerable behaviour lives here. Lab-specific attack orchestration is added
per lab in later phases and will call into these primitives.
"""
from .telemetry_service import TelemetryService
from .evidence_service import EvidenceService
from .lab_service import LabService
from .mcp_service import MCPService

__all__ = ["TelemetryService", "EvidenceService", "LabService", "MCPService"]
