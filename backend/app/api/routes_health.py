"""GET /api/health (FR-005, TDD §12).

Reports environment status ONLY. It never reveals whether a vulnerability is
"present" (SEC-006). The optional ``mode`` field is a convenience for the owner
and is gated by ``EXPOSE_HEALTH_MODE`` (DECISION D-05); set it false for stricter
black-box evaluation so ``mode`` cannot act as an oracle.
"""
from __future__ import annotations

from fastapi import APIRouter

from ..config import get_settings
from ..schemas import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    settings = get_settings()
    # ``mode`` reflects environment configuration for owner operability only.
    mode = settings.mcp_mode if settings.expose_health_mode else None
    return HealthResponse(backend="up", mcp_server="online", mode=mode)
