"""API routers (TDD §11/§12). Two analyzable surfaces: this HTTP control plane
and (later) the MCP transport. NO endpoint discloses vulnerability status
(SEC-006). Infra endpoints are strictly validated (SEC-004)."""
from fastapi import APIRouter

from .routes_health import router as health_router
from .routes_labs import router as labs_router
from .routes_mcp import router as mcp_router
from .routes_evidence import router as evidence_router
from .routes_vulnerabilities import router as vulnerabilities_router

api_router = APIRouter(prefix="/api")
api_router.include_router(health_router)
api_router.include_router(labs_router)
api_router.include_router(mcp_router)
api_router.include_router(evidence_router)
api_router.include_router(vulnerabilities_router)

__all__ = ["api_router"]
