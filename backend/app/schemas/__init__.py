"""Pydantic request/response schemas for the control-plane API (TDD §12).

These enforce strict validation on the infrastructure surface (SEC-004). None of
them carry a vulnerability verdict (SEC-006) — e.g. ``HealthResponse`` reports
environment status, and ``mode`` is only present when ``EXPOSE_HEALTH_MODE`` is
enabled (DECISION D-05).
"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class ModeRequest(BaseModel):
    """Body for POST /api/labs/{id}/mode — strict enum (FR-004)."""

    mode: str = Field(pattern="^(vulnerable|secure)$")


class StartRequest(BaseModel):
    mode: Optional[str] = Field(default=None, pattern="^(vulnerable|secure)$")


class AttackRequest(BaseModel):
    """Body for POST /api/labs/{id}/attack (per-lab schema refined later)."""

    trigger: str = ""
    params: dict[str, Any] = Field(default_factory=dict)


class ToolCallRequest(BaseModel):
    """Body for POST /api/mcp/tools/{id}/call."""

    args: dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    """GET /api/health — environment status, never a vuln verdict (FR-005)."""

    backend: str
    mcp_server: str
    # Present only when EXPOSE_HEALTH_MODE is true (D-05); otherwise None.
    mode: Optional[str] = None
