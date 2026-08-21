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


class AddDocRequest(BaseModel):
    """Body for POST /api/labs/{id}/docs — add your own MCP03 help article.

    Validation is minimal on purpose: the body is untrusted user content (that
    is the realistic entry point for a crafted template payload).
    """

    doc_id: str = Field(min_length=1, max_length=64, pattern=r"^[\w.-]+$")
    title: str = Field(default="Untitled", max_length=200)
    body: str = Field(max_length=4000)


class LlmProbeRequest(BaseModel):
    """Body for POST /api/labs/{id}/llm — optional Ollama-backed demo."""

    doc_id: str = Field(default="product-review", max_length=64)


class HealthResponse(BaseModel):
    """GET /api/health — environment status, never a vuln verdict (FR-005)."""

    backend: str
    mcp_server: str
    # Present only when EXPOSE_HEALTH_MODE is true (D-05); otherwise None.
    mode: Optional[str] = None
